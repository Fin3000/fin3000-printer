#!/usr/bin/python3 -I
"""Polkit-authorized, fixed-scope setup. No document, account or token access."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import uuid
import cups

PACKAGE = Path("/usr/lib/fin3000-printer")
STATE = Path("/var/lib/fin3000-printer/setup")
MAPPINGS = Path("/etc/fin3000-printer/installations")
LOCAL = Path("/etc/apparmor.d/local/usr.sbin.cupsd")
PROFILE = Path("/etc/apparmor.d/fin3000-printer")
PARENT = Path("/etc/apparmor.d/usr.sbin.cupsd")
CUPSD = Path("/etc/cups/cupsd.conf")
INCLUDE = "#include if exists <local/usr.sbin.cupsd>"
POLICY_DIGEST = "c4bde470a6103f77f07b14359ec541af3c5df4917f7befe41e385b7c654d416c"
TRANSITION = ("/usr/lib/cups/backend/fin3000 Px -> fin3000-printer-backend,\n"
              "signal peer=fin3000-printer-backend,\n"
              "unix peer=(label=fin3000-printer-backend),\n")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
       "CUPS_SERVER": "/run/cups/cups.sock", "CUPS_USER": "root"}
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


class SetupError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise SetupError(code)


def canonical(data):
    return json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "INSTALLATION_DRIFT")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, TypeError, UnicodeError):
        raise SetupError("INSTALLATION_DRIFT") from None


def installation(uid, user, home, generation):
    require(type(uid) is int and 1000 <= uid <= 60000 and user.pw_uid == uid
            and USER.fullmatch(user.pw_name) and UUID.fullmatch(generation)
            and stat.S_ISDIR(home.st_mode) and home.st_uid == uid, "DESKTOP_USER_REQUIRED")
    return {"version": 1, "uid": uid, "username": user.pw_name, "generation": generation,
            "queue": f"Fin3000-{uid}", "socketPath": f"/run/user/{uid}/fin3000-printer/ingest.sock",
            "homeDevice": home.st_dev, "homeInode": home.st_ino}


def uri(mapping):
    return f"fin3000:/{mapping['uid']}/{mapping['generation']}"


def verify_queue(attributes, mapping):
    require(isinstance(attributes, dict)
            and attributes.get("device-uri") == uri(mapping)
            and attributes.get("printer-op-policy") == "authenticated"
            and attributes.get("printer-error-policy") == "abort-job"
            and attributes.get("printer-is-shared") is False
            and attributes.get("requesting-user-name-allowed") == [mapping["username"]], "QUEUE_DRIFT")


def marker(mapping):
    identity = f"{mapping['uid']} {mapping['generation']}"
    return (f"# BEGIN Fin3000 Printer {identity}\n{TRANSITION}# END Fin3000 Printer {identity}\n").encode()


def policy_change(raw, mapping, *, remove=False):
    """Touch only this exact generation block; preserve every other byte."""
    block = marker(mapping)
    prefix = f"# BEGIN Fin3000 Printer {mapping['uid']} ".encode()
    ending = f"# END Fin3000 Printer {mapping['uid']} ".encode()
    if block in raw:
        require(raw.count(block) == raw.count(prefix) == raw.count(ending) == 1, "APPARMOR_DRIFT")
        return raw.replace(block, b"", 1) if remove else raw
    require(prefix not in raw and ending not in raw, "APPARMOR_DRIFT")
    if remove:
        return raw
    # Do not glue a policy rule or comment to an unterminated administrator line.
    require(not raw or raw.endswith(b"\n"), "APPARMOR_DRIFT")
    return raw + block


def policy_contract(cups_config, parent):
    blocks = re.findall(rb"<Policy authenticated>.*?</Policy>", cups_config, re.S)
    require(len(blocks) == 1 and hashlib.sha256(blocks[0]).hexdigest() == POLICY_DIGEST,
            "CUPS_POLICY_UNSUPPORTED")
    require(parent.count(INCLUDE.encode()) == 1, "APPARMOR_LAYOUT_UNSUPPORTED")


def trusted_directory(path):
    for candidate in reversed((path, *path.parents)):
        info = candidate.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "SYSTEM_PATH_UNSAFE")


def read_file(path, maximum=1024 * 1024):
    trusted_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= maximum, "SYSTEM_PATH_UNSAFE")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
        require(len(raw) <= maximum, "SYSTEM_PATH_UNSAFE")
        return raw
    finally:
        os.close(descriptor)


def replace_file(path, value, before, mode):
    """Root-only parent and global lease exclude unprivileged rename races."""
    require(read_file(path) == before, "SYSTEM_FILE_CHANGED")
    descriptor, temporary = tempfile.mkstemp(prefix=".fin3000-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        require(read_file(path) == before, "SYSTEM_FILE_CHANGED")
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(arguments):
    try:
        result = subprocess.run([str(value) for value in arguments], env=ENV, cwd="/",
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, "SYSTEM_COMMAND_FAILED")
        return result.stdout
    except (subprocess.TimeoutExpired, OSError):
        raise SetupError("SYSTEM_COMMAND_FAILED") from None


def active_desktop(uid):
    sessions = run(["/usr/bin/loginctl", "show-user", str(uid), "--property=Sessions", "--value"]).decode().split()
    for session in sessions[:32]:
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session), "DESKTOP_SESSION_REQUIRED")
        try:
            raw = run(["/usr/bin/loginctl", "show-session", session,
                       "--property=Active", "--property=Remote", "--property=Type",
                       "--property=Class", "--property=User"]).decode()
        except SetupError:
            # A short-lived SSH/session may disappear after show-user. It is
            # never desktop evidence; inspect the remaining local sessions.
            continue
        properties = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        if (properties.get("Active") == "yes" and properties.get("Remote") == "no"
                and properties.get("Type") == "wayland" and properties.get("Class") == "user"
                and properties.get("User") == str(uid)):
            return
    raise SetupError("DESKTOP_SESSION_REQUIRED")


class System:
    """Fixed production paths. Tests inject an in-memory port, never a root path override."""
    def __init__(self, uid):
        self.uid = uid
        self.mapping_path = MAPPINGS / f"{uid}.json"
        self.journal_path = STATE / f"{uid}.json"
        self.cups = cups
        cups.setServer("/run/cups/cups.sock")
        cups.setUser("root")
        self.connection = cups.Connection()

    def read_journal(self):
        raw = read_file(self.journal_path, 16384)
        return decode(raw) if raw is not None else None

    def journal(self, value):
        replace_file(self.journal_path, canonical(value), read_file(self.journal_path), 0o600)

    def mapping(self):
        raw = read_file(self.mapping_path, 4096)
        return decode(raw) if raw is not None else None

    def put_mapping(self, mapping):
        raw = read_file(self.mapping_path, 4096)
        require(raw is None or decode(raw) == mapping, "INSTALLATION_DRIFT")
        replace_file(self.mapping_path, canonical(mapping), raw, 0o644)

    def remove_mapping(self, mapping):
        require(self.mapping() in (None, mapping), "INSTALLATION_DRIFT")
        self.mapping_path.unlink(missing_ok=True)
        sync_directory(self.mapping_path.parent)

    def policies(self, mapping, *, remove=False):
        config, parent = read_file(CUPSD), read_file(PARENT)
        require(config is not None and parent is not None, "CUPS_UNAVAILABLE")
        policy_contract(config, parent)
        before = read_file(LOCAL)
        changed = policy_change(before or b"", mapping, remove=remove)
        # Validate the candidate graph BEFORE changing even our local drop-in.
        candidate = parent.replace(INCLUDE.encode(), changed)
        descriptor, temporary = tempfile.mkstemp(prefix=".policy-check-", dir=STATE)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(candidate)
            run(["/usr/sbin/apparmor_parser", "-Q", "-T", "-I", "/etc/apparmor.d", temporary])
            run(["/usr/sbin/apparmor_parser", "-Q", "-T", PROFILE])
        finally:
            Path(temporary).unlink(missing_ok=True)
        if changed != before:
            replace_file(LOCAL, changed, before, 0o644)
        # Parse the exact on-disk graph before loading it. No service restart,
        # cupsd.conf edit or replacement of the distribution's parent profile.
        run(["/usr/sbin/apparmor_parser", "-Q", "-T", PROFILE])
        run(["/usr/sbin/apparmor_parser", "-Q", "-T", PARENT])
        require(read_file(CUPSD) == config and read_file(PARENT) == parent, "SYSTEM_FILE_CHANGED")
        run(["/usr/sbin/apparmor_parser", "--replace", "--skip-cache", PROFILE])
        run(["/usr/sbin/apparmor_parser", "--replace", "--skip-cache", PARENT])

    def queue(self, mapping):
        try:
            return self.connection.getPrinterAttributes(mapping["queue"], requested_attributes=[
                "device-uri", "printer-op-policy", "printer-error-policy", "printer-is-shared",
                "requesting-user-name-allowed"])
        except self.cups.IPPError as error:
            if error.args[0] == self.cups.IPP_NOT_FOUND:
                return None
            raise SetupError("CUPS_UNAVAILABLE") from None

    def add_queue(self, mapping):
        require(self.queue(mapping) is None, "QUEUE_NAME_OCCUPIED")
        run(["/usr/sbin/lpadmin", "-p", mapping["queue"], "-E", "-v", uri(mapping),
             "-P", PACKAGE / "platforms/linux/fin3000.ppd", "-D", "An Fin3000 senden (Cloud-Upload)",
             "-o", "printer-is-shared=false", "-u", f"allow:{mapping['username']}",
             "-o", "printer-op-policy=authenticated", "-o", "printer-error-policy=abort-job"])

    def remove_queue(self, mapping):
        attributes = self.queue(mapping)
        if attributes is None:
            return
        verify_queue(attributes, mapping)
        self.connection.rejectJobs(mapping["queue"], reason="Fin3000 removal in progress")
        # pycups keys results by job-id; without requesting it a nonempty
        # response can become {} and falsely authorize deletion of active jobs.
        jobs = self.connection.getJobs(which_jobs="not-completed", requested_attributes=["job-id", "job-printer-uri"])
        require(all(isinstance(value.get("job-printer-uri"), str) for value in jobs.values()), "CUPS_UNAVAILABLE")
        require(not any(value.get("job-printer-uri", "").endswith("/printers/" + mapping["queue"])
                        for value in jobs.values()), "PRINT_JOBS_PENDING")
        run(["/usr/sbin/lpadmin", "-x", mapping["queue"]])
        require(self.queue(mapping) is None, "QUEUE_REMOVE_FAILED")


def configure(system, expected):
    journal, existing = system.read_journal(), system.mapping()
    if journal is not None:
        validate_journal(journal, expected)
    if journal is None or journal.get("phase") == "removed":
        require(existing is None and system.queue(expected) is None, "QUEUE_NAME_OCCUPIED")
        journal = {"version": 1, "phase": "preparing", "mapping": expected}
        system.journal(journal)  # Before any mapping, policy or queue mutation.
    else:
        require(journal["phase"] != "removing", "REMOVAL_INCOMPLETE")
    mapping = journal["mapping"]
    require(existing in (None, mapping), "INSTALLATION_DRIFT")
    attributes = system.queue(mapping)
    if attributes is not None:
        verify_queue(attributes, mapping)
    system.put_mapping(mapping)
    system.policies(mapping)
    if attributes is None:
        system.add_queue(mapping)
    verify_queue(system.queue(mapping), mapping)
    journal["phase"] = "ready"
    system.journal(journal)
    return mapping


def validate_journal(journal, expected):
    require(isinstance(journal, dict) and set(journal) == {"version", "phase", "mapping"}
            and type(journal["version"]) is int and journal["version"] == 1 and journal["phase"] in {"preparing", "ready", "removing", "removed"}
            and isinstance(journal["mapping"], dict), "INSTALLATION_DRIFT")
    mapping = journal["mapping"]
    require(isinstance(mapping.get("generation"), str) and UUID.fullmatch(mapping["generation"])
            and mapping == {**expected, "generation": mapping["generation"]}, "INSTALLATION_DRIFT")


def remove(system, expected):
    journal = system.read_journal()
    require(journal is not None, "INSTALLATION_NOT_OWNED")
    validate_journal(journal, expected)
    mapping = journal["mapping"]
    require(system.mapping() in (None, mapping), "INSTALLATION_DRIFT")
    journal["phase"] = "removing"
    system.journal(journal)
    system.remove_queue(mapping)
    system.policies(mapping, remove=True)
    system.remove_mapping(mapping)
    # Keep a tiny root-only tombstone; reinstall gets a NEW generation. User
    # recovery state and secrets are deliberately never read or deleted here.
    journal["phase"] = "removed"
    system.journal(journal)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in {"configure", "remove"}, "COMMAND_INVALID")
    require(os.getuid() == os.geteuid() == 0 and sys.flags.isolated, "POLKIT_REQUIRED")
    calling_uid = os.environ.get("PKEXEC_UID", "")
    require(re.fullmatch(r"[1-9][0-9]{3,4}", calling_uid), "POLKIT_REQUIRED")
    uid = int(calling_uid)
    user = pwd.getpwuid(uid)
    expected = installation(uid, user, os.stat(user.pw_dir, follow_symlinks=False), str(uuid.uuid4()))
    os.environ.clear()
    os.environ.update(ENV)
    os.umask(0o077)
    release = platform.freedesktop_os_release()
    require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") in {"24.04", "26.04"}
            and platform.machine() == "x86_64", "OS_UNSUPPORTED")
    active_desktop(uid)
    for path in (STATE, MAPPINGS):
        trusted_directory(path)  # Package owns these; no arbitrary mkdir here.
    for path in (PROFILE, PACKAGE / "platforms/linux/fin3000.ppd", Path("/usr/lib/cups/backend/fin3000")):
        require(read_file(path, 2 * 1024 * 1024) is not None, "PACKAGE_INCOMPLETE")
    require(Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y", "APPARMOR_REQUIRED")
    lock_path = STATE / "setup.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "SYSTEM_PATH_UNSAFE")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        system = System(uid)
        if sys.argv[1] == "configure":
            configure(system, expected)
        else:
            remove(system, expected)
        print('{"ok":true}')
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, ValueError) as error:
        code = str(error) if isinstance(error, SetupError) else "SETUP_UNAVAILABLE"
        print(json.dumps({"ok": False, "code": code}, separators=(",", ":")))
        sys.exit(1)

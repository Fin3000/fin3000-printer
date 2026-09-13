#!/usr/bin/python3 -I
"""Fixed Polkit action: install one authenticated package. No arbitrary argv.

The package owns APT configuration. This helper NEVER creates, restores or
reenables sources, changes trust, edits a printer or accesses a user account.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass
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

import apt

PACKAGE = Path("/usr/lib/fin3000-printer-setup")
SOURCES = Path("/etc/apt/sources.list.d/fin3000-printer.sources")
PREFERENCES = Path("/etc/apt/preferences.d/fin3000-printer.pref")
KEYRING = Path("/usr/share/keyrings/fin3000-printer-archive-keyring.gpg")
STORE = Path("/var/lib/fin3000-printer/installer")
APT_ARCHIVES = Path("/var/cache/apt/archives")
DPKG_LOCK = Path("/var/lib/dpkg/lock-frontend")
READY = Path("/var/lib/fin3000-printer/lifecycle/ready")
MAX_PACKAGE = 256 * 1024 * 1024
VERSION = re.compile(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8",
       "DEBIAN_FRONTEND": "noninteractive"}
OPTIONS = ["-o", "Acquire::AllowInsecureRepositories=false",
           "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
           "-o", "APT::Get::AllowUnauthenticated=false",
           "-o", "APT::Get::allow-downgrades=false", "-o", "APT::Get::force-yes=false",
           "-o", "APT::Get::allow-remove-essential=false", "-o", "APT::Get::allow-change-held-packages=false",
           "-o", "Acquire::https::Verify-Peer=true", "-o", "Acquire::https::Verify-Host=true",
           "-o", "Acquire::https::AllowRedirect=false", "-o", "Acquire::https::Timeout=20",
           "-o", "Acquire::http::Timeout=20", "-o", "Acquire::Retries=1",
           "-o", "Acquire::Check-Date=true", "-o", "Acquire::Check-Valid-Until=true",
           "-o", "DPkg::Options::=--force-confold"]


class InstallError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise InstallError(code)


def read_trusted(path, limit=65536):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "INSTALL_SOURCE_CHANGED")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and 0 < info.st_size <= limit, "INSTALL_SOURCE_CHANGED")
        value = source.read(limit + 1)
        require(len(value) == info.st_size, "INSTALL_SOURCE_CHANGED")
        return value


@dataclass(frozen=True)
class CachedPackage:
    version: str
    sha256: str
    size: int

    def __post_init__(self):
        require(isinstance(self.version, str) and VERSION.fullmatch(self.version)
                and isinstance(self.sha256, str) and re.fullmatch(r"[0-9a-f]{64}", self.sha256)
                and type(self.size) is int and 0 < self.size <= MAX_PACKAGE,
                "INSTALL_CACHE_UNSAFE")

    @property
    def filename(self):
        return f"{self.sha256}.deb"

    @property
    def apt_filename(self):
        return f"fin3000-printer_{self.version}_amd64.deb"


@dataclass(frozen=True)
class InstallJournal:
    current: CachedPackage | None = None
    previous: CachedPackage | None = None
    pending: CachedPackage | None = None


def unique_json(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "INSTALL_CACHE_UNSAFE")
        result[name] = value
    return result


def private_directory(path):
    """Walk/create fixed root-owned ancestors without following symlinks."""
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            created = False
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(part, 0o700 if part == path.name else 0o755, dir_fd=parent)
                created = True
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_mode & 0o022:
                os.close(child)
                raise InstallError("INSTALL_CACHE_UNSAFE")
            if created:
                try:
                    # main() uses umask 077. Preserve private leaf storage but
                    # keep newly created shared ancestors traversable for the
                    # unprivileged package lifecycle reader. Never chmod an
                    # existing administrator-owned directory.
                    os.fchmod(child, 0o700 if part == path.name else 0o755)
                    os.fsync(child)
                    os.fsync(parent)
                except BaseException:
                    os.close(child)
                    raise
            os.close(parent); parent = child
        require(stat.S_IMODE(os.fstat(parent).st_mode) == 0o700, "INSTALL_CACHE_UNSAFE")
        return parent
    except BaseException:
        os.close(parent)
        raise


@contextmanager
def installer_lock():
    # Stable across bootstrap replacement and reboot; never replace/unlink this
    # inode. This serializes our GUI helpers, not arbitrary administrator APT.
    parent = private_directory(STORE)
    descriptor = None
    try:
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            descriptor = os.open("lease", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
            os.fsync(descriptor); os.fsync(parent)
        except FileExistsError:
            descriptor = os.open("lease", flags, dir_fd=parent)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "INSTALL_CACHE_UNSAFE")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def atomic_store(name, value):
    require(name == "journal.json" or re.fullmatch(r"[0-9a-f]{64}\.deb", name), "INSTALL_CACHE_UNSAFE")
    # Private parent is verified by installer_lock. No user-controlled paths or
    # content, and no in-place truncation of the only recovery record.
    descriptor, temporary = tempfile.mkstemp(prefix=".writing-", dir=STORE)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, STORE / name)
        parent = os.open(STORE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        # Only this call's exact, exclusively created temporary file.
        if os.path.lexists(temporary):
            os.unlink(temporary)


def load_journal():
    try:
        raw = read_trusted(STORE / "journal.json")
    except FileNotFoundError:
        return InstallJournal()
    try:
        data = json.loads(raw, object_pairs_hook=unique_json)
        require(isinstance(data, dict) and set(data) == {"schema", "current", "previous", "pending"}
                and type(data["schema"]) is int and data["schema"] == 1, "INSTALL_CACHE_UNSAFE")
        values = {}
        for name in ("current", "previous", "pending"):
            item = data[name]
            require(item is None or isinstance(item, dict) and set(item) == {"version", "sha256", "size"},
                    "INSTALL_CACHE_UNSAFE")
            values[name] = None if item is None else CachedPackage(**item)
        require(values["current"] is not None or values["previous"] is None, "INSTALL_CACHE_UNSAFE")
        return InstallJournal(**values)
    except (ValueError, TypeError):
        raise InstallError("INSTALL_CACHE_UNSAFE") from None


def save_journal(journal):
    atomic_store("journal.json", (json.dumps({"schema": 1, **asdict(journal)}, sort_keys=True) + "\n").encode())


def cached_bytes(package):
    data = read_trusted(STORE / package.filename, MAX_PACKAGE)
    require(len(data) == package.size and hashlib.sha256(data).hexdigest() == package.sha256,
            "INSTALL_CACHE_UNSAFE")
    return data


def collect_cache(journal):
    """Under installer_lock, reclaim only unreferenced content-addressed DEBs.

    Check the durable record and active recovery originals FIRST. Never
    follow links, delete unknown files, change the journal or remove the lease.
    Run before acquisition, not after dpkg: cleanup failure cannot turn an
    already successful installation into a reported installation failure.
    """
    require(journal == load_journal(), "INSTALL_CACHE_UNSAFE")
    keep = {record.filename for record in (journal.current, journal.previous, journal.pending)
            if record is not None}
    # Previous is retained but never consumed by recovery. Damage to that
    # historical original must not prevent repair/update of a valid current.
    for record in (journal.current, journal.pending):
        if record is not None:
            cached_bytes(record)
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    parent = private_directory(STORE)
    try:
        with os.scandir(parent) as entries:
            names = [entry.name for entry in entries
                     if entry.name not in keep and re.fullmatch(r"[0-9a-f]{64}\.deb", entry.name)]
        for name in names:
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= MAX_PACKAGE):
                    continue
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                     dir_fd=parent)
                with os.fdopen(descriptor, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if before != info:
                        continue
                    digest, size = hashlib.sha256(), 0
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_PACKAGE:
                            break
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
                # Reading can update atime. Bind only identity/content/ownership
                # fields, including ctime, before deleting this exact name.
                if (identity(before) != identity(after)
                        or identity(after) != identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        or size != before.st_size or digest.hexdigest() + ".deb" != name):
                    continue
                os.unlink(name, dir_fd=parent)
            except OSError:
                # Best-effort housekeeping of obsolete files only. Journal,
                # active recovery bytes and store validation above stay strict.
                continue
        os.fsync(parent)
    finally:
        os.close(parent)


@contextmanager
def apt_archive_directory():
    """Temporary public-package workspace with trusted, traversable ancestors."""
    for parent in reversed((APT_ARCHIVES, *APT_ARCHIVES.parents)):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and info.st_mode & stat.S_IXOTH,
                "INSTALL_CACHE_UNSAFE")
    with tempfile.TemporaryDirectory(prefix=".fin3000-", dir=APT_ARCHIVES) as temporary:
        directory = Path(temporary)
        # This directory contains public distribution packages only. Nothing
        # from the private journal, a user account or a recovery export goes here.
        directory.chmod(0o755)
        yield directory


@contextmanager
def prepared_archives(package):
    """Expose public DEB bytes to APT, never our private journal or originals.

    Seed an isolated APT archive with its canonical package filename. APT
    verifies this cached archive against its index instead of downloading the
    same package again. Missing OS dependencies retain normal APT acquisition.
    """
    data = cached_bytes(package)
    with apt_archive_directory() as directory:
        target = directory / package.apt_filename
        with target.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
        require(read_trusted(target, MAX_PACKAGE) == data, "INSTALL_CACHE_UNSAFE")
        yield directory


def retain_candidate(candidate):
    version = candidate_version(candidate)
    record = CachedPackage(version, candidate.sha256, candidate.size)
    # apt-get download does not install/configure packages or resolve/remove
    # dependencies. Authentication stays with APT; compare its signed index
    # SHA256 and size again before retaining the exact original DEB.
    with apt_archive_directory() as temporary:
        downloaded = temporary / record.apt_filename
        sandbox = pwd.getpwnam("_apt")
        require(sandbox.pw_uid != 0, "INSTALL_CACHE_UNSAFE")
        # APT tests directory writability with mkstemp before dropping rights;
        # a writable precreated file alone cannot keep its sandbox enabled.
        # This exclusively created workspace contains only the public download.
        descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(descriptor, sandbox.pw_uid, sandbox.pw_gid)
            os.fchmod(descriptor, 0o700)
            run_apt(["-o", "APT::Sandbox::User=_apt", "download", f"fin3000-printer={version}"],
                    directory=str(temporary))
        finally:
            try:
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o700)
            finally:
                os.close(descriptor)
        data = read_trusted(downloaded, MAX_PACKAGE)
        require(len(data) == record.size and hashlib.sha256(data).hexdigest() == record.sha256,
                "INSTALL_CACHE_UNSAFE")
        # Inspect the immutable root-private copy, not bytes that the download
        # worker previously had permission to write.
        atomic_store(record.filename, data)
        # Read control metadata only. No extraction or execution of maintainer scripts.
        result = subprocess.run(["/usr/bin/dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n",
                                 str(STORE / record.filename)], cwd="/", env=ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        require(result.returncode == 0 and result.stdout == f"fin3000-printer\t{version}\tamd64\n".encode(),
                "INSTALL_CACHE_UNSAFE")
    cached_bytes(record)
    return record


@contextmanager
def dpkg_frontend_lock():
    # Dpkg's documented frontend lock protocol. Keep the POSIX lock in this
    # parent while the child acquires dpkg's separate backend lock normally.
    # No lock deletion, Debug::NoLocking or bypass of another package manager.
    for parent in reversed(DPKG_LOCK.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "INSTALL_CACHE_UNSAFE")
    fd = os.open(DPKG_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022, "INSTALL_CACHE_UNSAFE")
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def installed_status(*, missing_ok=False):
    result = subprocess.run(["/usr/bin/dpkg-query", "--show", "--showformat=${Status}\t${Version}\n", "fin3000-printer"],
                            cwd="/", env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30)
    if missing_ok and result.returncode == 1 and not result.stdout:
        return None
    require(result.returncode == 0, "INSTALL_RECOVERY_REQUIRED")
    fields = result.stdout.decode("ascii").strip().split("\t")
    require(len(fields) == 2 and VERSION.fullmatch(fields[1]), "INSTALL_RECOVERY_REQUIRED")
    return fields[0], fields[1]


def apt_preflight_options():
    # This fixed package-owned hook runs while APT holds its normal frontend
    # lock, after acquisition but before any dpkg mutation. No global APT edit.
    hook = str(PACKAGE / "install.py")
    return ["-o", f"DPkg::Pre-Install-Pkgs::={hook} --apt-preflight",
            "-o", f"DPkg::Tools::Options::{hook}::Version=1",
            "-o", f"DPkg::Tools::Options::{hook}::InfoFD=0"]


def verify_apt_transaction():
    """Read-only guard for the exact pending transaction under APT's lock."""
    require(os.environ.get("DPKG_FRONTEND_LOCKED") == "true"
            and os.environ.get("APT_HOOK_INFO_FD") == "0", "INSTALL_NOT_AUTHORIZED")
    check_configuration()
    journal = load_journal()
    require(journal.pending is not None, "INSTALL_RECOVERY_REQUIRED")
    cached_bytes(journal.pending)
    status = installed_status(missing_ok=True)
    if journal.current is not None:
        require(status == ("install ok installed", journal.current.version), "INSTALL_RECOVERY_REQUIRED")
        cached_bytes(journal.current)
    else:
        require(status is None or status[1] == journal.pending.version and status[0] in {
            "install ok installed", "install ok unpacked", "install ok half-configured",
            "install reinstreq half-installed"}, "INSTALL_RECOVERY_REQUIRED")
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024 and b"\x00" not in raw, "INSTALL_PACKAGE_FAILED")
    paths = raw.decode("ascii").splitlines()
    require(len(paths) <= 4096, "INSTALL_PACKAGE_FAILED")
    matched = 0
    for name in paths:
        path = Path(name)
        require(path.is_absolute() and path.parent.parent == APT_ARCHIVES
                and re.fullmatch(r"\.fin3000-[a-z0-9_]+", path.parent.name)
                and path.name not in {".", ".."}, "INSTALL_PACKAGE_FAILED")
        # Only our printer must match the recorded identity. Ubuntu dependencies
        # retain APT's standard signature/hash and solver policy.
        if path.name.startswith("fin3000-printer_"):
            require(path.name == journal.pending.apt_filename, "INSTALL_PACKAGE_FAILED")
            data = read_trusted(path, MAX_PACKAGE)
            require(len(data) == journal.pending.size
                    and hashlib.sha256(data).hexdigest() == journal.pending.sha256,
                    "INSTALL_PACKAGE_FAILED")
            matched += 1
    # A half-configured retry can only configure, without unpacking a DEB.
    require(matched == 1 or matched == 0 and status is not None
            and status[1] == journal.pending.version
            and status[0] in {"install ok unpacked", "install ok half-configured",
                              "install reinstreq half-installed"}, "INSTALL_PACKAGE_FAILED")


def install_cached(record, *, reinstall=True):
    """One explicit APT attempt; dependencies retain the normal Ubuntu trust path."""
    check_configuration()
    with prepared_archives(record) as archives:
        run_apt([*apt_preflight_options(), "-o", f"Dir::Cache::archives={archives}", "--yes", "--no-remove", "--no-install-recommends",
                 *(["--reinstall"] if reinstall else []), "install", str(archives / record.apt_filename)], installing=True)
    # Check actual configured dpkg status, not merely APT's installed-version
    # object, which also exists for partially configured packages.
    require(installed_status() == ("install ok installed", record.version)
            and read_trusted(READY) == b"1\n", "INSTALL_PACKAGE_FAILED")
    cached_bytes(record)


def resume_initial_install(journal):
    require(journal.current is None and journal.previous is None and journal.pending is not None,
            "INSTALL_RECOVERY_REQUIRED")
    cached_bytes(journal.pending)
    status = installed_status(missing_ok=True)
    require(status is None or status[1] == journal.pending.version and status[0] in {
        "install ok installed", "install ok unpacked", "install ok half-configured",
        "install reinstreq half-installed"}, "INSTALL_RECOVERY_REQUIRED")
    # A failed initial dependency download may leave no package at all. Reuse
    # the authenticated original instead of requiring an impossible rollback.
    # This can download missing Ubuntu dependencies, but never a new printer
    # candidate, alter trust, or discard the pending record on another failure.
    # APT's --reinstall fails for a half-configured local package without an
    # archive candidate ("No file name"). Normal install completes its pending
    # configuration/dependencies; it also installs a still-absent target.
    # An already configured package instead needs a real reinstall: otherwise
    # APT does nothing and cannot reopen activation after an interrupted repair.
    install_cached(journal.pending, reinstall=status is not None and status[0] == "install ok installed")
    save_journal(InstallJournal(current=journal.pending))
    return "INSTALL_COMPLETE"


def restore_previous(journal):
    require(journal.current is not None and journal.pending is not None, "INSTALL_RECOVERY_REQUIRED")
    cached_bytes(journal.current)
    with dpkg_frontend_lock():
        check_configuration()
        status, version = installed_status()
        # A different admin update/removal is not our interrupted transaction.
        # Never resurrect an explicitly removed package or downgrade another release.
        require(version in {journal.current.version, journal.pending.version}
                and status in {"install ok installed", "install ok unpacked", "install ok half-configured",
                               "install reinstreq half-installed"}, "INSTALL_RECOVERY_REQUIRED")
        cached_bytes(journal.current)
        result = subprocess.run(["/usr/bin/dpkg", "--force-confold", "--install", str(STORE / journal.current.filename)],
                                cwd="/", env={**ENV, "DPKG_FRONTEND_LOCKED": "true"},
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=None)
        require(result.returncode == 0 and installed_status() == ("install ok installed", journal.current.version)
                and read_trusted(READY) == b"1\n", "INSTALL_RECOVERY_REQUIRED")
        save_journal(InstallJournal(journal.current, journal.previous))
    return "INSTALL_RESTORED"


def check_configuration():
    # Deliberately exact. Even Enabled:no must stop; never undo administrator intent.
    require(read_trusted(SOURCES) == read_trusted(PACKAGE / "fin3000-printer.sources")
            and read_trusted(PREFERENCES) == read_trusted(PACKAGE / "fin3000-printer.pref"),
            "INSTALL_SOURCE_CHANGED")
    require(hashlib.sha256(read_trusted(KEYRING, 2 * 1024 * 1024)).hexdigest().encode()
            == read_trusted(PACKAGE / "archive-keyring.sha256").strip(), "INSTALL_SOURCE_CHANGED")


def candidate_version(candidate):
    require(candidate is not None and candidate.architecture == "amd64"
            and candidate.downloadable and VERSION.fullmatch(candidate.version), "INSTALL_NO_RELEASE")
    remote = [origin for origin in candidate.origins if origin.site]
    require(remote and all(origin.trusted and origin.site == "fin3000.com"
            and origin.origin == "Fin3000" and origin.label == "Fin3000"
            and origin.archive == "stable" and origin.component == "main" for origin in remote),
            "INSTALL_WRONG_ORIGIN")
    expected = f"https://fin3000.com/tools/apt/pool/main/fin3000-printer_{candidate.version}_amd64.deb"
    require(candidate.uris and all(uri == expected for uri in candidate.uris), "INSTALL_WRONG_ORIGIN")
    return candidate.version


def run_apt(arguments, *, installing=False, directory="/"):
    # Never terminate dpkg midway because a UI/network timer elapsed. Transport
    # timeouts remain finite; a failed package configuration is reported by APT.
    try:
        result = subprocess.run(["/usr/bin/apt-get", *OPTIONS, *arguments], cwd=directory, env=ENV,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=None if installing else 180)
    except subprocess.TimeoutExpired:
        raise InstallError("INSTALL_UPDATE_FAILED") from None
    require(result.returncode == 0, "INSTALL_PACKAGE_FAILED" if installing else "INSTALL_UPDATE_FAILED")


def install():
    check_configuration()
    journal = load_journal()
    # Recovery must still work when the failed candidate has disappeared or
    # become corrupt. Do not make housekeeping a prerequisite for rollback.
    if journal.pending is None:
        collect_cache(journal)
    # Select recovery BEFORE any release lookup, including after a reboot.
    # Existing-version rollback is offline; first-install retry may still need
    # authenticated Ubuntu dependencies that the original attempt could not fetch.
    # The user explicitly started this action; never auto-launch at login.
    if journal.pending is not None:
        return restore_previous(journal) if journal.current is not None else resume_initial_install(journal)
    if journal.current is not None:
        cached_bytes(journal.current)
    run_apt(["-o", f"Dir::Etc::sourcelist={SOURCES}", "-o", "Dir::Etc::sourceparts=-",
             "-o", "APT::Get::List-Cleanup=0", "-o", "APT::Update::Error-Mode=any", "update"])
    cache = apt.Cache()
    require("fin3000-printer" in cache, "INSTALL_NO_RELEASE")
    package = cache["fin3000-printer"]
    candidate_version(package.candidate)
    # Do not implicitly downgrade an installed newer version.
    require(not package.is_installed or not package.candidate < package.installed, "INSTALL_NO_DOWNGRADE")
    require((not package.is_installed and journal.current is None)
            or (package.is_installed and journal.current is not None
                and journal.current.version == package.installed.version), "INSTALL_RECOVERY_REQUIRED")
    retained = retain_candidate(package.candidate)
    check_configuration()
    pending = InstallJournal(journal.current, journal.previous, retained)
    save_journal(pending)
    try:
        install_cached(retained)
    except InstallError:
        if journal.current is not None:
            return restore_previous(pending)
        raise
    # Reinstalling the same bytes repairs this version; it must not replace
    # the known previous version with a second reference to the current one.
    previous = journal.previous if retained == journal.current else journal.current
    save_journal(InstallJournal(retained, previous))
    return "INSTALL_COMPLETE"


def main():
    try:
        require(os.getuid() == os.geteuid() == 0, "INSTALL_NOT_AUTHORIZED")
        if sys.argv[1:] == ["--apt-preflight"]:
            verify_apt_transaction()
            return 0
        require(len(sys.argv) == 1, "INSTALL_NOT_AUTHORIZED")
        release = platform.freedesktop_os_release()
        require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") in ("24.04", "26.04")
                and platform.machine() == "x86_64", "INSTALL_UNSUPPORTED_OS")
        os.umask(0o077)
        with installer_lock():
            result = install()
        print(result, flush=True)
        return 0
    except BlockingIOError:
        print("INSTALL_BUSY", flush=True)
    except InstallError as error:
        print(str(error), flush=True)
    except (OSError, ValueError, KeyError, SystemError, subprocess.TimeoutExpired):
        print("INSTALL_PACKAGE_FAILED", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())

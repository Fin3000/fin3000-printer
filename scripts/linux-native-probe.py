#!/usr/bin/python3
"""Explicit, temporary Ubuntu system-CUPS experiment. Never uploads anything.

--check compiles/parses only, without privilege or host configuration changes.
--run-synthetic requires normal administrator authentication via pkexec. It
adds exactly one unshared queue and a narrowly confined backend, exercises a
generated PDF, then restores its configuration. --cleanup recovers an
interrupted run, refusing to overwrite subsequent administrator changes.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import tempfile

import cups

REPO = Path(__file__).resolve().parent.parent
QUEUE = "Fin3000NativeSyntheticProbe"
PROFILE = "fin3000-native-probe"
BACKEND = Path("/usr/lib/cups/backend/fin3000nativeprobe")
POLICY = Path("/etc/apparmor.d/fin3000-native-probe")
LOCAL = Path("/etc/apparmor.d/local/usr.sbin.cupsd")
CUPSD = Path("/etc/cups/cupsd.conf")
STATE = Path("/var/lib/fin3000-native-probe")
RUNTIME = Path("/run/fin3000-native-probe")
LIMIT = 1024 * 1024
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "CUPS_SERVER": "/run/cups/cups.sock"}
MARKER = "FIN3000 SYNTHETIC ONLY - NOT AN INVOICE"
BACKEND_SOURCE_SHA256 = "24e9a3668d771a1807531f648c20e5c9f1b814dc72d7f1e63f53fd9706b1dc3f"
AUTHENTICATED_POLICY_SHA256 = "c4bde470a6103f77f07b14359ec541af3c5df4917f7befe41e385b7c654d416c"
# pycups drops jobs without an explicitly requested job-id from its result map.
JOB_FIELDS = ["job-id", "job-state", "job-state-reasons", "job-printer-uri", "job-hold-until",
              "time-at-creation", "time-at-processing", "time-at-completed",
              "job-impressions-completed", "job-media-sheets-completed"]


def run(args, *, uid=None, **kwargs):
    identity = {} if uid is None else {"user": uid, "group": pwd.getpwuid(uid).pw_gid, "extra_groups": []}
    return subprocess.run([str(x) for x in args], env=ENV, timeout=20, check=True,
                          capture_output=True, **identity, **kwargs)


def account(uid):
    user = pwd.getpwuid(uid)
    if uid < 1000 or uid > 60000 or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user.pw_name):
        raise RuntimeError("An explicit ordinary desktop account is required")
    return user


def apparmor_policy():
    return f"""#include <tunables/global>
profile {PROFILE} {BACKEND} flags=(attach_disconnected) {{
  {BACKEND} mr,
  /etc/ld.so.cache r,
  /dev/null rw,
  /{{usr/,}}lib/x86_64-linux-gnu/{{ld-linux-x86-64.so*,libc.so*}} mr,
  /proc/*/attr/current r,
  /var/spool/cups/d[0-9]*-[0-9]* r,
  {RUNTIME}/ingest.sock rw,
  unix (create, getopt, setopt) type=seqpacket addr=none,
  unix (connect, send, receive) type=seqpacket peer=(label=unconfined),
  deny unix (connect, send, receive) type=seqpacket peer=(addr=@**),
  signal (receive) peer=/usr/sbin/cupsd,
  signal (receive) peer=unconfined,
  signal (send) set=chld peer=/usr/sbin/cupsd,
  # Deliberate negative controls in the fixture must fail before any reads.
  deny /etc/shadow r,
  deny network inet,
  deny network inet6,
}}
"""


def apparmor_transition():
    return f"\n# Fin3000 temporary synthetic probe\n{BACKEND} Px -> {PROFILE},\nsignal peer={PROFILE},\nunix peer=(label={PROFILE}),\n"


def verify_existing_policy(config):
    # Reuse the reviewed OS policy; never write/reload cupsd.conf. An unfamiliar
    # policy must be investigated, not guessed to be equivalent or overwritten.
    blocks = re.findall(r"<Policy authenticated>.*?</Policy>", config, re.S)
    if len(blocks) != 1 or digest(blocks[0].encode()) != AUTHENTICATED_POLICY_SHA256:
        raise RuntimeError("The existing authenticated CUPS policy needs review")
    if re.findall(r"^DefaultAuthType\s+(\S+)\s*$", config, re.M) != ["Basic"]:
        raise RuntimeError("Unsupported CUPS authentication configuration")


def connection():
    cups.setServer("/run/cups/cups.sock")
    return cups.Connection()


def jobs_snapshot():
    jobs = connection().getJobs(which_jobs="not-completed", requested_attributes=JOB_FIELDS)
    return {str(key): value for key, value in jobs.items()
            if not value.get("job-printer-uri", "").endswith("/printers/" + QUEUE)}


def require_idle_jobs(jobs):
    # IPP state 6 is processing-stopped, NOT actively processing (5). No
    # scheduler reload or job operation is performed, so stopped jobs stay put.
    for job in jobs.values():
        if job.get("job-state") == 6:
            continue
        if job.get("job-state") == 4 and job.get("job-hold-until") == "indefinite":
            continue
        raise RuntimeError("Pending/running or unknown print jobs: wait for idle, do not disrupt them")


def own_job_ids():
    return sorted(key for key, value in connection().getJobs(which_jobs="all", requested_attributes=["job-id", "job-printer-uri"]).items()
                  if value.get("job-printer-uri", "").endswith("/printers/" + QUEUE))


def queue_attributes():
    # printers.conf is saved asynchronously and can omit a newly created queue.
    # The running scheduler is the authority for cleanup, not its disk cache.
    try:
        return connection().getPrinterAttributes(QUEUE, requested_attributes=[
            "device-uri", "printer-op-policy", "printer-is-shared", "requesting-user-name-allowed"])
    except cups.IPPError as error:
        if error.args[0] == cups.IPP_NOT_FOUND:
            return None
        raise


def remove_test_queue(uid):
    attributes = queue_attributes()
    if attributes is None:
        return
    if (attributes.get("device-uri") != "fin3000nativeprobe:/local"
            or attributes.get("printer-op-policy") != "authenticated"
            or attributes.get("printer-is-shared") is not False
            or attributes.get("requesting-user-name-allowed") != [account(uid).pw_name]):
        raise RuntimeError("Probe queue changed by administrator; not removed")
    run(["/usr/sbin/lpadmin", "-x", QUEUE])
    if queue_attributes() is not None:
        raise RuntimeError("Probe queue still exists; recovery journal retained")


def require_unused_queue():
    # lpstat -p exits 1 when a clean desktop has no printers at all. Only the
    # exact live IPP target matters; other failures must still fail closed.
    if queue_attributes() is not None:
        raise RuntimeError("Queue name already exists")


def unauthorized_request(claimed, authorization):
    # Deliberately malformed credentials in a synthetic-only Print-Job, using
    # the same small IPP fixture as the container test, not a product IPP stack.
    body = b"\x02\x00\x00\x02\x00\x00\x00\x01\x01"
    for tag, name, value in [(0x47, "attributes-charset", "utf-8"), (0x48, "attributes-natural-language", "en"),
                             (0x45, "printer-uri", f"ipp://localhost/printers/{QUEUE}"),
                             (0x42, "requesting-user-name", claimed), (0x49, "document-format", "application/pdf")]:
        name, value = name.encode(), value.encode()
        body += bytes([tag]) + struct.pack("!H", len(name)) + name + struct.pack("!H", len(value)) + value
    body += b"\x03" + pdf_fixture()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect("/run/cups/cups.sock")
        headers = f"POST /printers/{QUEUE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        if authorization:
            headers += f"Authorization: {authorization}\r\n"
        client.sendall(headers.encode() + b"\r\n" + body)
        response = http.client.HTTPResponse(client)
        response.begin()
        data = response.read(LIMIT)
        return {"http": response.status, "ipp": struct.unpack("!H", data[2:4])[0] if response.status == 200 and len(data) >= 8 else None}


def negative_admission_tests(uid):
    user, foreign = account(uid), pwd.getpwnam("nobody")
    before = own_job_ids()
    results = []
    cases = [(foreign, user.pw_name, f"PeerCred {user.pw_name}", {"http": 401, "ipp": None}),
             (foreign, foreign.pw_name, f"PeerCred {foreign.pw_name}", {"http": 200, "ipp": cups.IPP_NOT_AUTHORIZED}),
             (foreign, user.pw_name, None, {"http": 401, "ipp": None}),
             (user, user.pw_name, None, {"http": 401, "ipp": None})]
    for identity, claimed, auth, expected in cases:
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            signal.alarm(5)
            try:
                os.setgroups([])
                os.setgid(identity.pw_gid)
                os.setuid(identity.pw_uid)
                os.write(write_fd, json.dumps(unauthorized_request(claimed, auth)).encode())
                os._exit(0)
            except Exception:
                os._exit(1)
        os.close(write_fd)
        try:
            if not select.select([read_fd], [], [], 6)[0]:
                raise RuntimeError("Negative admission test timed out")
            result = json.loads(os.read(read_fd, 4096))
        finally:
            os.close(read_fd)
            try:
                os.kill(child, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        if result != expected:
            raise RuntimeError(f"Unexpected admission outcome: {result}, expected {expected}")
        results.append(result)
    if own_job_ids() != before:
        raise RuntimeError("Rejected requests created a print job")
    return results


def pdf_fixture():
    # Same byte contract as the unprivileged/container fixture, without importing
    # another user-writable Python module into a privileged process.
    stream = b"BT /F1 12 Tf 30 780 Td (FIN3000 SYNTHETIC ONLY - NOT AN INVOICE) Tj ET\n"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream"]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    pdf += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    return pdf + f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()


def backend_source():
    fd = os.open(REPO / "tests/fixtures/linux-native-backend.c", os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise RuntimeError("Expected a regular C fixture")
        data = file.read(65537)
    if digest(data) != BACKEND_SOURCE_SHA256:
        raise RuntimeError("Backend fixture changed; independent review/hash update required before elevation")
    return data


def prepare(directory, uid):
    user = account(uid)
    # The elevated invocation owns this 0700 staging directory. The compiler
    # sees only the digest-verified C snapshot, never a mutable worktree path.
    source = directory / "backend.c"
    source.write_bytes(backend_source())
    os.chmod(source, 0o600)
    run(["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong",
         "-fPIE", "-pie", "-Wl,-z,relro,-z,now", f"-DPROBE_UID={uid}", f'-DPROBE_USER="{user.pw_name}"',
         source, "-o", directory / "backend"], cwd=directory)
    (directory / "apparmor").write_text(apparmor_policy())
    parent = Path("/etc/apparmor.d/usr.sbin.cupsd").read_text()
    include = "#include if exists <local/usr.sbin.cupsd>"
    if parent.count(include) != 1:
        raise RuntimeError("Unsupported CUPS AppArmor include layout")
    (directory / "parent-profile").write_text(parent.replace(include, include + apparmor_transition()))
    for file in ["apparmor", "parent-profile"]:
        run(["/usr/sbin/apparmor_parser", "--skip-kernel-load", "--skip-cache", "-I", "/etc/apparmor.d", directory / file])
    (directory / "probe.pdf").write_bytes(pdf_fixture())
    (directory / "probe.ppd").write_text('''*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "F3PROBE.PPD"
*Manufacturer: "Fin3000"
*Product: "(Synthetic probe)"
*ModelName: "Fin3000 Synthetic Probe"
*NickName: "Fin3000 Synthetic Probe"
*ShortNickName: "Synthetic Probe"
*PSVersion: "(3010.000) 0"
*LanguageLevel: "3"
*cupsFilter2: "application/pdf application/pdf 0 gziptoany"
''')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_snapshot(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f"Unsafe system file: {path}")
        return {"hex": file.read().hex(), "mode": stat.S_IMODE(info.st_mode), "gid": info.st_gid}


def atomic_write(path, data, mode, gid=0):
    fd, temporary = tempfile.mkstemp(prefix=".fin3000-probe-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            os.fchmod(file.fileno(), mode)
            os.fchown(file.fileno(), 0, gid)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def journal_write(journal):
    atomic_write(STATE / "journal.json", json.dumps(journal).encode(), 0o600)


def tracked_write(journal, path, data, mode=0o644, *, append=False):
    if path not in {LOCAL, POLICY, BACKEND}:
        raise RuntimeError("Unexpected write target")
    before = regular_snapshot(path)
    if path in {BACKEND, POLICY} and before is not None:
        raise RuntimeError(f"New probe target appeared during preparation: {path}")
    if append:
        if before:
            data = bytes.fromhex(before["hex"]) + data
            mode = before["mode"]
    entry = {"path": str(path), "before": before, "sha256": digest(data)}
    journal["files"].append(entry)
    journal_write(journal)  # Write-ahead recovery; a failed write is harmless.
    if regular_snapshot(path) != before:
        raise RuntimeError(f"Configuration changed during preparation: {path}")
    atomic_write(path, data, mode, before["gid"] if before else 0)


def restore_entry(entry):
    path = Path(entry["path"])
    if path not in {LOCAL, POLICY, BACKEND}:
        raise RuntimeError("Recovery journal contains an unexpected target")
    current = regular_snapshot(path)
    before = entry["before"]
    if current == before:
        return
    if current is None or digest(bytes.fromhex(current["hex"])) != entry["sha256"]:
        raise RuntimeError(f"Administrator changed {path}; retained backup in {STATE}, not overwritten")
    if before is None:
        path.unlink()
    else:
        atomic_write(path, bytes.fromhex(before["hex"]), before["mode"], before["gid"])


def cleanup():
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("Unsafe recovery state")
    snapshot = regular_snapshot(STATE / "journal.json")
    if snapshot is None:
        raise RuntimeError("Missing recovery journal; no automatic removal")
    journal = json.loads(bytes.fromhex(snapshot["hex"]))
    if journal.get("queue") != QUEUE:
        raise RuntimeError("Invalid recovery identity")
    # Preflight all shared-file drift before restoring any file.
    for entry in journal["files"]:
        if Path(entry["path"]) not in {LOCAL, POLICY, BACKEND}:
            raise RuntimeError("Unexpected recovery target")
        current = regular_snapshot(Path(entry["path"]))
        if current != entry["before"] and (current is None or digest(bytes.fromhex(current["hex"])) != entry["sha256"]):
            raise RuntimeError(f"Configuration drift; recovery retained at {STATE}")
    remove_test_queue(journal["uid"])
    # Restore AppArmor parent policy, then unload our standalone backend profile.
    for entry in journal["files"]:
        if Path(entry["path"]) == LOCAL:
            restore_entry(entry)
    run(["/usr/sbin/apparmor_parser", "--replace", "--skip-cache", "/etc/apparmor.d/usr.sbin.cupsd"])
    if POLICY.exists():
        loaded = Path("/sys/kernel/security/apparmor/profiles").read_text()
        if f"{PROFILE} (enforce)" in loaded:
            run(["/usr/sbin/apparmor_parser", "--remove", "--skip-cache", POLICY])
    for entry in reversed(journal["files"]):
        if Path(entry["path"]) != LOCAL:
            restore_entry(entry)
    if digest(CUPSD.read_bytes()) != journal["cupsConfigSha256"]:
        raise RuntimeError("CUPS configuration changed externally; not overwritten")
    if jobs_snapshot() != journal["existingJobs"]:
        raise RuntimeError("Existing jobs changed; no attempt to modify or restore those jobs")
    if run(["/usr/bin/lpstat", "-d"]).stdout.decode() != journal["default"]:
        raise RuntimeError("Default printer changed externally; not overwritten")
    # Runtime contains only this test socket. Do not recursively remove a user-writable directory.
    if RUNTIME.exists():
        (RUNTIME / "ingest.sock").unlink(missing_ok=True)
        RUNTIME.rmdir()
    (STATE / "journal.json").unlink()
    STATE.rmdir()


def verify_backend_peer(uid, label):
    # Native SO_PEERSEC includes the enforcing mode, unlike a bare profile name.
    if uid != 0 or label != f"{PROFILE} (enforce)":
        raise RuntimeError(f"Unauthenticated/unconfined backend peer: uid={uid}, label={label!r}")


def verify_pdf(data, *, firefox=False):
    if not firefox:
        if data != pdf_fixture():
            raise RuntimeError("This fixture accepts only the exact generated synthetic PDF")
        return
    # Firefox renders new PDF bytes. Inspect only in the already unprivileged
    # receiver; never run a PDF parser as root or write an arbitrary document.
    if os.getuid() == 0:
        raise RuntimeError("PDF parsing as root is forbidden")
    if not data.startswith(b"%PDF-") or len(data) > LIMIT:
        raise RuntimeError("Expected bounded Firefox PDF")
    text = run(["/usr/bin/pdftotext", "-f", "1", "-l", "1", "-", "-"], input=data).stdout.decode()
    info = run(["/usr/bin/pdfinfo", "-"], input=data).stdout.decode()
    if text.strip() != MARKER or not re.search(r"^Pages:\s+1\s*$", info, re.M):
        raise RuntimeError("Firefox fixture must contain exactly the one-page synthetic marker")


def receive(uid, ready_fd, result_fd, *, firefox=False):
    os.setgroups([])
    os.setgid(account(uid).pw_gid)
    os.setuid(uid)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.settimeout(120 if firefox else 30)
    server.bind(str(RUNTIME / "ingest.sock"))
    os.chmod(RUNTIME / "ingest.sock", 0o600)
    server.listen(4)
    os.write(ready_fd, b"ready")
    os.close(ready_fd)
    connection, _ = server.accept()
    connection.settimeout(5)
    _, peer_uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    label = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 256).rstrip(b"\0").decode()
    verify_backend_peer(peer_uid, label)
    header, _, flags, _ = connection.recvmsg(8)
    if flags & socket.MSG_TRUNC or len(header) != 8 or header[:4] != b"F3P1":
        raise RuntimeError("Invalid frame")
    size = struct.unpack("!I", header[4:])[0]
    if size < 5 or size > LIMIT:
        raise RuntimeError("Invalid PDF size")
    data = bytearray()
    while len(data) < size:
        packet, _, flags, _ = connection.recvmsg(min(65536, size - len(data)))
        if not packet or flags & socket.MSG_TRUNC:
            raise RuntimeError("Truncated PDF")
        data.extend(packet)
    verify_pdf(bytes(data), firefox=firefox)
    connection.send(b"ACCEPTED")
    connection.close()
    server.close()
    result = {"bytes": size, "sha256": digest(data), "peerUid": peer_uid, "apparmor": label,
              "ipSocketDenied": True, "credentialFileOpenDenied": True}
    os.write(result_fd, json.dumps(result).encode())


def allow_confined_root_peer(path, uid):
    # Root without DAC override still needs directory search and socket write.
    # Only this named UID gets access, not the owning group or other users.
    # Pin the inode before invoking ACL tools: the user owns the runtime path,
    # so following a substituted symlink as root would be unsafe.
    if path not in {RUNTIME, RUNTIME / "ingest.sock"}:
        raise RuntimeError("Unexpected ACL target")
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        directory = path == RUNTIME
        if info.st_uid != uid or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISSOCK(info.st_mode)):
            raise RuntimeError("Runtime ACL target identity changed")
        if stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
            raise RuntimeError("Runtime ACL permissions changed")
        permission = "--x" if directory else "rw-"
        target = f"/proc/self/fd/{fd}"
        run(["/usr/bin/setfacl", "--modify", f"u:0:{permission},m::{permission}", target], pass_fds=(fd,))
        actual = set(run(["/usr/bin/getfacl", "--omit-header", "--numeric", target], pass_fds=(fd,)).stdout.decode().split())
        expected = {"user::rwx" if directory else "user::rw-", f"user:0:{permission}",
                    "group::---", f"mask::{permission}", "other::---"}
        if actual != expected:
            raise RuntimeError("Unexpected effective runtime ACL")
    finally:
        os.close(fd)


def native(uid, *, firefox=False):
    user = account(uid)
    if Path("/.dockerenv").exists() or os.uname().machine != "x86_64":
        raise RuntimeError("Requires the authorized native Ubuntu x64 host")
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=ubuntu$', release, re.M) or not re.search(r'^VERSION_ID="(?:24.04|26.04)"$', release, re.M):
        raise RuntimeError("Only Ubuntu 24.04/26.04 is in scope")
    if any(path.exists() or path.is_symlink() for path in [STATE, RUNTIME, BACKEND, POLICY]):
        raise RuntimeError("Existing probe artifacts: inspect and use --cleanup, never overwrite")
    existing_jobs = jobs_snapshot()
    require_idle_jobs(existing_jobs)
    cups_config = CUPSD.read_bytes()
    verify_existing_policy(cups_config.decode())
    require_unused_queue()
    loaded = Path("/sys/kernel/security/apparmor/profiles").read_text()
    if "/usr/sbin/cupsd (enforce)" not in loaded or PROFILE in loaded:
        raise RuntimeError("Expected enforcing CUPS profile and unused probe name")
    if not re.search(r'^PeerCred\s+on\s*$', Path("/etc/cups/cups-files.conf").read_text(), re.M):
        raise RuntimeError("CUPS PeerCred is not explicitly enabled")
    with tempfile.TemporaryDirectory(prefix="fin3000-native-build-") as temporary:
        directory = Path(temporary)
        prepare(directory, uid)
        # Only traversal is granted for lp to read the synthetic fixture; the
        # staged source and compiled backend remain root-owned and unmodifiable.
        os.chmod(directory, 0o711)
        backend_bytes = (directory / "backend").read_bytes()
        STATE.mkdir(mode=0o700)
        journal = {"queue": QUEUE, "uid": uid, "files": [], "default": run(["/usr/bin/lpstat", "-d"]).stdout.decode(),
                   "existingJobs": existing_jobs, "cupsConfigSha256": digest(cups_config)}
        child = None
        result_read = None
        try:
            journal_write(journal)
            tracked_write(journal, BACKEND, backend_bytes, 0o700)
            tracked_write(journal, POLICY, apparmor_policy().encode())
            tracked_write(journal, LOCAL, apparmor_transition().encode(), append=True)
            run(["/usr/sbin/apparmor_parser", "--replace", "--skip-cache", POLICY])
            run(["/usr/sbin/apparmor_parser", "--replace", "--skip-cache", "/etc/apparmor.d/usr.sbin.cupsd"])
            run(["/usr/sbin/lpadmin", "-p", QUEUE, "-E", "-v", "fin3000nativeprobe:/local", "-P", directory / "probe.ppd",
                 "-D", "Fin3000 – NUR synthetischer Test, kein Upload", "-o", "printer-is-shared=false",
                 "-u", f"allow:{user.pw_name}", "-o", "printer-op-policy=authenticated", "-o", "printer-error-policy=abort-job"])
            negatives = negative_admission_tests(uid)
            RUNTIME.mkdir(mode=0o700)
            os.chown(RUNTIME, uid, user.pw_gid)
            ready_read, ready_write = os.pipe()
            result_read, result_write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(ready_read)
                os.close(result_read)
                try:
                    receive(uid, ready_write, result_write, firefox=firefox)
                    os._exit(0)
                except Exception as error:
                    os.write(result_write, json.dumps({"error": str(error)[:512]}).encode())
                    os._exit(1)
            os.close(ready_write)
            os.close(result_write)
            if not select.select([ready_read], [], [], 5)[0] or os.read(ready_read, 5) != b"ready":
                raise RuntimeError("Synthetic receiver failed to start")
            os.close(ready_read)
            allow_confined_root_peer(RUNTIME, uid)
            allow_confined_root_peer(RUNTIME / "ingest.sock", uid)
            if firefox:
                print(json.dumps({"status": "READY_FOR_FIREFOX", "queue": QUEUE, "timeoutSeconds": 120}), flush=True)
                submission = "external Firefox synthetic print; verified by the unprivileged orchestrator"
            else:
                submitted = run(["/usr/bin/lp", "-d", QUEUE, "-t", MARKER, directory / "probe.pdf"], uid=uid)
                submission = submitted.stdout.decode().strip()
            if not select.select([result_read], [], [], 125 if firefox else 25)[0]:
                raise RuntimeError("No synthetic PDF received from system CUPS")
            payload = os.read(result_read, 8192)
            if not payload:
                raise RuntimeError("Synthetic receiver rejected the transfer")
            evidence = json.loads(payload)
            if "error" in evidence:
                raise RuntimeError("Synthetic receiver: " + evidence["error"])
            return {"status": "PASS", "productReady": False, "gateStatus": "BLOCKED", "transport": evidence,
                    "submission": submission, "nativeGuiTested": False, "uploaded": False,
                    "negativeAdmission": negatives, "existingJobsUnchanged": True, "schedulerReloaded": False}
        finally:
            if child:
                try:
                    os.kill(child, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
            if result_read is not None:
                os.close(result_read)
            cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--run-synthetic", action="store_true")
    group.add_argument("--await-firefox-synthetic", action="store_true")
    group.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if args.check:
        if os.getuid() == 0:
            raise RuntimeError("Run --check as an ordinary user")
        with tempfile.TemporaryDirectory(prefix="fin3000-native-check-") as temporary:
            prepare(Path(temporary), os.getuid())
        print(json.dumps({"status": "PASS", "kind": "compile-and-policy-syntax-only", "hostChanged": False, "productReady": False}))
        return
    if os.getuid() != 0 or not re.fullmatch(r"[0-9]+", os.environ.get("PKEXEC_UID", "")):
        raise RuntimeError("Use pkexec /usr/bin/python3 -I scripts/linux-native-probe.py --run-synthetic (or --cleanup)")
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(InterruptedError("Probe interrupted")))
    if args.cleanup:
        cleanup()
        print(json.dumps({"status": "CLEANED", "productReady": False}))
    else:
        print(json.dumps(native(int(os.environ["PKEXEC_UID"]), firefox=args.await_firefox_synthetic)))


if __name__ == "__main__":
    main()

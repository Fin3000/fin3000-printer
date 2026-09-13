#!/usr/bin/python3
"""Desktop-UID CUPS ingress. Kernel peers + bounded pipes, no cloud or tokens."""
import hashlib
import json
import os
import pwd
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass

LIMIT = 20 * 1024 * 1024
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
PEER_LABEL = "fin3000-printer-backend (enforce)"


class IngressError(Exception):
    pass


@dataclass(frozen=True)
class Installation:
    uid: int
    username: str
    generation: str
    queue: str
    socket_path: str
    home_device: int
    home_inode: int


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IngressError("FRAME_INVALID")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError):
        raise IngressError("FRAME_INVALID") from None


def load_installation():
    uid = os.getuid()
    if uid < 1000 or uid > 60000:
        raise IngressError("DESKTOP_USER_REQUIRED")
    path = f"/etc/fin3000-printer/installations/{uid}.json"
    for candidate in ("/etc", "/etc/fin3000-printer", "/etc/fin3000-printer/installations", path):
        info = os.lstat(candidate)
        if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISREG(info.st_mode) if candidate == path else stat.S_ISDIR(info.st_mode)):
            raise IngressError("INSTALLATION_DRIFT")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096:
            raise IngressError("INSTALLATION_DRIFT")
    finally:
        os.close(descriptor)
    data = strict_json(raw)
    if not isinstance(data, dict) or set(data) != {"version", "uid", "username", "generation", "queue", "socketPath", "homeDevice", "homeInode"}:
        raise IngressError("INSTALLATION_DRIFT")
    user = pwd.getpwuid(uid)
    home = os.stat(user.pw_dir, follow_symlinks=False)
    if (type(data["version"]) is not int or data["version"] != 1 or type(data["uid"]) is not int or data["uid"] != uid or data["username"] != user.pw_name
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user.pw_name)
            or not isinstance(data["generation"], str) or not UUID.fullmatch(data["generation"])
            or data["queue"] != f"Fin3000-{uid}" or data["socketPath"] != f"/run/user/{uid}/fin3000-printer/ingest.sock"
            or not stat.S_ISDIR(home.st_mode) or home.st_uid != uid
            or type(data["homeDevice"]) is not int or type(data["homeInode"]) is not int
            or data["homeDevice"] != home.st_dev or data["homeInode"] != home.st_ino):
        raise IngressError("INSTALLATION_DRIFT")
    return Installation(uid, user.pw_name, data["generation"], data["queue"], data["socketPath"], home.st_dev, home.st_ino)


def verify_peer(connection):
    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    label = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERSEC, 256).rstrip(b"\0").decode("ascii", "strict")
    if uid != 0 or label != PEER_LABEL:
        raise IngressError("CUPS_PEER_DENIED")


def metadata(raw, installation):
    data = strict_json(raw)
    if (not isinstance(data, dict) or set(data) != {"version", "generation", "nativeJobUuid", "jobId", "title", "size", "sha256"}
            or data["version"] != 2 or data["generation"] != installation.generation
            or not isinstance(data["nativeJobUuid"], str) or not UUID.fullmatch(data["nativeJobUuid"])
            or type(data["jobId"]) is not int or not 1 <= data["jobId"] <= 2**31 - 1
            or type(data["size"]) is not int or not 5 <= data["size"] <= LIMIT
            or not isinstance(data["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", data["sha256"])
            or not isinstance(data["title"], str) or len(data["title"]) > 180
            or any(unicodedata.category(char).startswith("C") for char in data["title"])):
        raise IngressError("FRAME_INVALID")
    return data


def packet(connection, maximum):
    data, ancillary, flags, _ = connection.recvmsg(maximum)
    if not data or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise IngressError("FRAME_INVALID")
    return data


def read_pdf(connection, description):
    result = bytearray(description["size"])
    offset = 0
    deadline = time.monotonic() + 30
    while offset < len(result):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IngressError("HANDOFF_TIMEOUT")
        connection.settimeout(min(5, remaining))
        part = packet(connection, min(65536, len(result) - offset))
        result[offset:offset + len(part)] = part
        offset += len(part)
    if result[:5] != b"%PDF-" or hashlib.sha256(result).hexdigest() != description["sha256"]:
        raise IngressError("PDF_INVALID")
    return result


def validate_pdf(pdf):
    # Package-owned launcher enters the enforcing PDF-validator profile and
    # invokes the OS parser with only stdin; no paths/titles are passed to it.
    result = subprocess.run(["/usr/lib/fin3000-printer/bin/pdf-validator"], input=pdf,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=ENV, cwd="/", timeout=15, check=False)
    if result.returncode != 0:
        raise IngressError("PDF_INVALID")


def pipe_write(fd, value, deadline):
    view = memoryview(value)
    while view:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([], [fd], [], left)[1]:
            raise IngressError("HANDOFF_TIMEOUT")
        # Linux PIPE_BUF-sized writes cannot block halfway through a large
        # frame after select reports the otherwise single-writer pipe writable.
        written = os.write(fd, view[:4096])
        if written <= 0:
            raise IngressError("COORDINATOR_UNAVAILABLE")
        view = view[written:]


def pipe_read(fd, length, deadline):
    parts = bytearray()
    while len(parts) < length:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise IngressError("HANDOFF_TIMEOUT")
        part = os.read(fd, length - len(parts))
        if not part:
            raise IngressError("COORDINATOR_UNAVAILABLE")
        parts.extend(part)
    return parts


def handoff(input_fd, output_fd, description, pdf):
    wire = json.dumps({"type": "job", **description}, ensure_ascii=True, separators=(",", ":")).encode()
    if len(wire) > 4096:
        raise IngressError("FRAME_INVALID")
    deadline = time.monotonic() + 15
    pipe_write(output_fd, struct.pack("!I", len(wire)) + wire, deadline)
    pipe_write(output_fd, pdf, deadline)
    size = struct.unpack("!I", pipe_read(input_fd, 4, deadline))[0]
    if not 1 <= size <= 4096:
        raise IngressError("COORDINATOR_RESPONSE_INVALID")
    ack = strict_json(pipe_read(input_fd, size, deadline))
    if (not isinstance(ack, dict) or ack.get("nativeJobUuid") != description["nativeJobUuid"]
            or set(ack) - {"nativeJobUuid", "accepted", "operationId", "code"}):
        raise IngressError("COORDINATOR_RESPONSE_INVALID")
    if ack.get("accepted") is not True:
        code = ack.get("code")
        raise IngressError(code if code in {"QUEUE_FULL", "CONNECT_AND_REPRINT", "RECONCILE_REQUIRED", "DRAINING", "PDF_INVALID"} else "HANDOFF_REJECTED")
    if not isinstance(ack.get("operationId"), str) or not UUID.fullmatch(ack["operationId"]):
        raise IngressError("COORDINATOR_RESPONSE_INVALID")
    return ack["operationId"]


def allow_root(path, uid, directory):
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISSOCK(info.st_mode)):
            raise IngressError("RUNTIME_DRIFT")
        target, permission = f"/proc/self/fd/{fd}", "--x" if directory else "rw-"
        base = {"user::rwx" if directory else "user::rw-", "group::---", "other::---"}
        expected = base | {f"user:0:{permission}", f"mask::{permission}"}
        def acl():
            return set(subprocess.run(["/usr/bin/getfacl", "--omit-header", "--numeric", target], pass_fds=(fd,),
                                     capture_output=True, env=ENV, timeout=5, check=True).stdout.decode().split())
        if acl() not in (base, expected):
            raise IngressError("RUNTIME_DRIFT")
        subprocess.run(["/usr/bin/setfacl", "--modify", f"u:0:{permission},m::{permission}", target],
                       pass_fds=(fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV, timeout=5, check=True)
        if acl() != expected:
            raise IngressError("RUNTIME_DRIFT")
    finally:
        os.close(fd)


def private_channel(fd):
    info = os.fstat(fd)
    if info.st_uid != os.getuid():
        return False
    if stat.S_ISFIFO(info.st_mode):
        return True
    if not stat.S_ISSOCK(info.st_mode):
        return False
    # libuv's spawn stdio uses unnamed AF_UNIX stream socketpairs on Linux,
    # not FIFO pipes. Accept only the inherited connected parent endpoint.
    with socket.socket(fileno=os.dup(fd)) as endpoint:
        pid, uid, _ = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return (endpoint.family == socket.AF_UNIX and endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
                and endpoint.getpeername() in ("", b"") and uid == os.getuid() and pid == os.getppid())


def serve(installation):
    if not all(private_channel(fd) for fd in (0, 1, 3)):
        raise IngressError("PRIVATE_PIPES_REQUIRED")
    os.umask(0o077)
    runtime = os.path.dirname(installation.socket_path)
    if os.path.realpath(os.path.dirname(runtime)) != f"/run/user/{installation.uid}":
        raise IngressError("RUNTIME_DRIFT")
    os.makedirs(runtime, mode=0o700, exist_ok=True)
    if os.path.realpath(runtime) != runtime:
        raise IngressError("RUNTIME_DRIFT")
    allow_root(os.path.dirname(runtime), installation.uid, True)
    allow_root(runtime, installation.uid, True)
    if os.path.lexists(installation.socket_path):
        info = os.lstat(installation.socket_path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != installation.uid:
            raise IngressError("RUNTIME_DRIFT")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
            probe.settimeout(1)
            try:
                probe.connect(installation.socket_path)
            except ConnectionRefusedError:
                if os.lstat(installation.socket_path).st_ino != info.st_ino:
                    raise IngressError("RUNTIME_DRIFT")
                os.unlink(installation.socket_path)
            else:
                raise IngressError("INSTANCE_ALREADY_RUNNING")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(installation.socket_path)
    inode = os.lstat(installation.socket_path).st_ino
    os.chmod(installation.socket_path, 0o600)
    allow_root(installation.socket_path, installation.uid, False)
    server.listen(3)
    parent = os.getppid()
    try:
        pipe_write(3, json.dumps({"ready": True, "generation": installation.generation}, separators=(",", ":")).encode() + b"\n", time.monotonic() + 5)
        os.close(3)
        while os.getppid() == parent:
            ready, _, _ = select.select([server, 0], [], [], 1)
            if 0 in ready:
                break  # EOF or unsolicited parent command: stop, never orphan.
            if server not in ready:
                continue
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                pdf = None
                handing_off = False
                try:
                    verify_peer(connection)
                    description = metadata(packet(connection, 4096), installation)
                    pdf = read_pdf(connection, description)
                    validate_pdf(pdf)
                    handing_off = True
                    operation_id = handoff(0, 1, description, pdf)
                    connection.sendall(f"LOCAL_HANDOFF {operation_id}".encode())
                except (IngressError, OSError, UnicodeError, subprocess.SubprocessError) as error:
                    try:
                        connection.sendall(b"HANDOFF_REJECTED")
                    except OSError:
                        pass
                    if handing_off and str(error) not in {"QUEUE_FULL", "CONNECT_AND_REPRINT", "RECONCILE_REQUIRED", "DRAINING", "PDF_INVALID", "HANDOFF_REJECTED"}:
                        return  # A partial private pipe must never be reused.
                finally:
                    if pdf is not None:
                        pdf[:] = b"\0" * len(pdf)
    finally:
        server.close()
        try:
            if os.lstat(installation.socket_path).st_ino == inode:
                os.unlink(installation.socket_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    if os.environ.pop("FIN3000_CORE_GUARD", None) != "1":
        sys.exit(70)
    try:
        if len(sys.argv) != 1:
            raise IngressError("INVOCATION_INVALID")
        serve(load_installation())
    except (IngressError, OSError, UnicodeError, subprocess.SubprocessError):
        sys.exit(1)  # No paths, PDF metadata or unsanitized exceptions in journal.

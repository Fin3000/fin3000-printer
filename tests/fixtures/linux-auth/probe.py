#!/usr/bin/python3
"""Disposable G0 peer-credential experiment, NOT a production backend.

Run only through the dedicated networkless, read-only Docker fixture. Synthetic
IPP requests intentionally forge usernames to test authorization, not a new IPP
implementation. No host mounts, actual accounts, passwords, or cloud requests.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

QUEUE = "Fin3000SyntheticProbe"
OWNER = 2000
FOREIGN = 2001
MAX_BYTES = 1024 * 1024


def require_fixture():
    if not Path("/.dockerenv").exists() or os.environ.get("FIN3000_G0_CONTAINER") != "1":
        raise RuntimeError("This root/UID test may only run in its dedicated disposable container")


def become(uid):
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def fork_result(uid, fn):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            become(uid)
            result = {"result": fn()}
        except Exception as error:
            result = {"error": str(error)}
        os.write(write_fd, json.dumps(result).encode())
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    data = os.read(read_fd, 8192)
    os.close(read_fd)
    os.waitpid(pid, 0)
    result = json.loads(data)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def pdf_fixture():
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


def ipp_request(root, claimed, authorization):
    def attribute(tag, name, value):
        name, value = name.encode(), value.encode()
        return bytes([tag]) + struct.pack("!H", len(name)) + name + struct.pack("!H", len(value)) + value
    body = b"\x02\x00\x00\x02\x00\x00\x00\x01\x01"  # IPP/2.0 Print-Job
    for tag, name, value in [(0x47, "attributes-charset", "utf-8"), (0x48, "attributes-natural-language", "en"),
                             (0x45, "printer-uri", f"ipp://localhost/printers/{QUEUE}"),
                             (0x42, "requesting-user-name", claimed), (0x49, "document-format", "application/pdf")]:
        body += attribute(tag, name, value)
    body += b"\x03" + pdf_fixture()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(str(root / "state/cups.sock"))
    headers = {"Host": "localhost", "Content-Type": "application/ipp", "Content-Length": str(len(body)), "Connection": "close"}
    if authorization:
        headers["Authorization"] = authorization
    sock.sendall((f"POST /printers/{QUEUE} HTTP/1.1\r\n" + "".join(f"{key}: {value}\r\n" for key, value in headers.items()) + "\r\n").encode() + body)
    response = http.client.HTTPResponse(sock)
    response.begin()
    data = response.read(MAX_BYTES)
    status = {"http": response.status, "ipp": struct.unpack("!H", data[2:4])[0] if response.status == 200 and len(data) >= 8 else None}
    sock.close()
    return status


def agent(root, ready_fd):
    become(OWNER)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(root / "agent/ingest.sock"))
    # Intentionally reachable in this negative test. Rejection must come from
    # SO_PEERCRED, not merely directory permissions (product would use 0700).
    os.chmod(root / "agent/ingest.sock", 0o666)
    server.listen(4)
    os.write(ready_fd, b"ready")
    os.close(ready_fd)
    evidence = {"accepted": 0, "rejected": 0}
    while True:
        connection, _ = server.accept()
        connection.settimeout(3)
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            evidence["rejected"] += 1
            connection.send(b"DENIED")
        else:
            data, _, flags, _ = connection.recvmsg(MAX_BYTES)
            if flags & socket.MSG_TRUNC or data != pdf_fixture():
                connection.send(b"INVALID")
            else:
                evidence.update(accepted=evidence["accepted"] + 1, peerUid=uid, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                connection.send(b"ACCEPTED")
        connection.close()
        (root / "agent/evidence.json").write_text(json.dumps(evidence))


def backend():
    require_fixture()
    root = Path(os.environ["CUPS_SERVERROOT"]).parent
    if os.getuid() != 0 or not re.fullmatch(r"/tmp/fin3000-auth-probe-[a-z0-9_]+", str(root)):
        raise RuntimeError("Unexpected backend identity/path")
    if os.environ.get("AUTH_PASSWORD") or os.environ.get("DEVICE_URI") != "fin3000probe:/local":
        raise RuntimeError("Backend must not receive a password or credential-bearing URI")
    if len(sys.argv) == 7:
        path = Path(sys.argv[6])
        if path.parent != root / "spool" or not re.fullmatch(r"d[0-9]+-[0-9]+", path.name):
            raise RuntimeError("Unexpected CUPS fixture path")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
            data = source.read(MAX_BYTES + 1)
    elif len(sys.argv) == 6:
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
    else:
        raise RuntimeError("Unexpected backend invocation")
    if data != pdf_fixture():
        raise RuntimeError("Synthetic fixture only")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect(str(root / "agent/ingest.sock"))
        _, uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != OWNER:
            raise RuntimeError("Wrong agent peer")
        client.sendall(data)
        if client.recv(64) != b"ACCEPTED":
            raise RuntimeError("No custody acknowledgement")


def configure(root):
    for name in ["conf/ppd", "state", "spool", "cache", "tmp", "ssl", "bin/backend", "bin/filter", "bin/daemon", "data/mime", "www", "logs", "agent"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    # Traverse permission permits both test users to reach sockets but no lists.
    os.chmod(root, 0o711)
    os.chmod(root / "agent", 0o711)
    os.chown(root / "agent", OWNER, OWNER)
    dirs = {"ServerRoot": "conf", "StateDir": "state", "RequestRoot": "spool", "CacheDir": "cache", "TempDir": "tmp",
            "ServerKeychain": "ssl", "ServerBin": "bin", "DataDir": "data", "DocumentRoot": "www", "AccessLog": "logs/access",
            "ErrorLog": "logs/error", "PageLog": "logs/page", "Printcap": "printcap"}
    (root / "conf/cups-files.conf").write_text("".join(f"{key} {root / value}\n" for key, value in dirs.items()) +
        "User lp\nGroup lp\nSystemGroup root\nConfigFilePerm 0600\nLogFilePerm 0600\nCreateSelfSignedCerts No\nPeerCred on\nPassEnv FIN3000_G0_CONTAINER\n")
    (root / "conf/cupsd.conf").write_text(f"""Listen {root}/state/cups.sock
ServerName localhost
Browsing No
BrowseLocalProtocols none
DefaultShared No
WebInterface No
DefaultEncryption Never
LogLevel debug
MaxRequestSize 1024k
PreserveJobHistory Yes
PreserveJobFiles No
<Location />
Order deny,allow
Allow all
</Location>
<Location /admin>
Order allow,deny
Deny all
</Location>
<Policy fin3000-owner>
<Limit Print-Job Create-Job Send-Document>
AuthType Default
Require user probeowner
Order deny,allow
</Limit>
<Limit Get-Jobs Get-Job-Attributes Get-Printer-Attributes CUPS-Get-Printers>
Order deny,allow
Allow all
</Limit>
<Limit All>
Order allow,deny
Deny all
</Limit>
</Policy>
""")
    (root / "conf/printers.conf").write_text(f"""<Printer {QUEUE}>
Info Fin3000 SYNTHETIC ONLY
DeviceURI fin3000probe:/local
State Idle
Accepting Yes
Shared No
JobSheets none none
OpPolicy fin3000-owner
ErrorPolicy abort-job
</Printer>
""")
    # Private fixture only: use OS PDF pass-through filter, not a product driver.
    (root / f"conf/ppd/{QUEUE}.ppd").write_text('''*PPD-Adobe: "4.3"
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
    (root / "data/mime/mime.types").write_text("application/pdf pdf string(0,%PDF)\n")
    os.symlink("/usr/lib/cups/filter/gziptoany", root / "bin/filter/gziptoany")
    os.symlink("/usr/lib/cups/daemon/cups-exec", root / "bin/daemon/cups-exec")
    shutil.copyfile(__file__, root / "bin/backend/fin3000probe")
    os.chmod(root / "bin/backend/fin3000probe", 0o700)


def no_ip_listeners(pid):
    sockets = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        if link.startswith("socket:["):
            sockets.add(link[8:-1])
    for family in ["tcp", "tcp6", "udp", "udp6"]:
        for line in Path(f"/proc/{pid}/net/{family}").read_text().splitlines()[1:]:
            if line.split()[9] in sockets:
                raise RuntimeError("Unexpected IP socket")


def main():
    require_fixture()
    if os.getuid() != 0:
        raise RuntimeError("Container fixture requires its own root to spawn two test UIDs")
    root = Path(tempfile.mkdtemp(prefix="fin3000-auth-probe-"))
    cups = None
    agent_pid = None
    try:
        configure(root)
        env = {"PATH": "/usr/bin:/usr/sbin:/bin", "LANG": "C", "CUPS_SERVERROOT": str(root / "conf"),
               "FIN3000_G0_CONTAINER": "1"}
        args = ["/usr/sbin/cupsd", "-f", "-c", str(root / "conf/cupsd.conf"), "-s", str(root / "conf/cups-files.conf")]
        subprocess.run([args[0], "-t", *args[2:]], env=env, timeout=5, check=True, capture_output=True)
        read_fd, write_fd = os.pipe()
        agent_pid = os.fork()
        if agent_pid == 0:
            os.close(read_fd)
            try:
                agent(root, write_fd)
            finally:
                os._exit(1)
        os.close(write_fd)
        if os.read(read_fd, 16) != b"ready":
            raise RuntimeError("Agent did not start")
        os.close(read_fd)
        cups = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if (root / "state/cups.sock").exists():
                break
            if cups.poll() is not None:
                raise RuntimeError("CUPS fixture failed to start")
            time.sleep(0.1)
        # Ensure adversary reaches CUPS: filesystem permission must not fake PASS.
        os.chmod(root / "state", 0o711)
        os.chmod(root / "state/cups.sock", 0o666)
        no_ip_listeners(cups.pid)
        rejected = []
        for uid, claimed, auth in [(FOREIGN, "probeowner", "PeerCred probeowner"),
                                   (FOREIGN, "probeforeign", "PeerCred probeforeign"),
                                   (FOREIGN, "probeowner", None), (OWNER, "probeowner", None)]:
            result = fork_result(uid, lambda: ipp_request(root, claimed, auth))
            if result["http"] not in (401, 403):
                raise RuntimeError(f"Unauthenticated/foreign job was not denied: {result}")
            rejected.append(result)
        for uid in (OWNER, FOREIGN):
            def attempt_direct():
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                    client.settimeout(3)
                    client.connect(str(root / "agent/ingest.sock"))
                    return client.recv(64).decode()
            if fork_result(uid, attempt_direct) != "DENIED":
                raise RuntimeError("Non-CUPS peer was accepted by agent")
        accepted = fork_result(OWNER, lambda: ipp_request(root, "probeowner", "PeerCred probeowner"))
        if accepted["http"] != 200 or accepted["ipp"] not in (0, 1, 2):
            raise RuntimeError(f"Owner job was not accepted: {accepted}")
        evidence = {}
        for _ in range(70):
            try:
                evidence = json.loads((root / "agent/evidence.json").read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if evidence.get("accepted") == 1:
                break
            time.sleep(0.1)
        if evidence.get("accepted") != 1 or evidence.get("rejected") != 2:
            raise RuntimeError(f"Missing exact custody/denial evidence: {evidence}")
        no_ip_listeners(cups.pid)
        packages = subprocess.check_output(["/usr/bin/dpkg-query", "-W", "-f=${Package} ${Version}\n",
            "cups-daemon", "cups-core-drivers", "cups-filters", "python3"], timeout=3, text=True).splitlines()
        print(json.dumps({"probe": "linux-cups-peercred-container", "status": "PASS", "packages": packages, "ownerJob": accepted,
                          "unauthorizedSubmissions": rejected, "agent": evidence, "ipListeners": False,
                          "hostPrinterChanged": False, "uploaded": False, "productReady": False,
                          "gateStatus": "BLOCKED", "notProven": ["native-AppArmor-Polkit", "GNOME-Wayland-Snap", "production-adapter", "installer-signing"]}))
    except Exception:
        log = root / "logs/error"
        if log.exists():
            print("\n".join(log.read_text().splitlines()[-45:]), file=sys.stderr)
        raise
    finally:
        if cups:
            cups.terminate()
            try:
                cups.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cups.kill()
                cups.wait()
        if agent_pid:
            os.kill(agent_pid, signal.SIGTERM)
            os.waitpid(agent_pid, 0)
        shutil.rmtree(root)


if __name__ == "__main__":
    def deadline(_signum, _frame):
        raise TimeoutError("Synthetic test exceeded its 25-second deadline")
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(25)
    if Path(sys.argv[0]).name == "fin3000probe":
        backend()
    else:
        main()

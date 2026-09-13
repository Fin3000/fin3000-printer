#!/usr/bin/env python3
"""Explicit, unprivileged Ubuntu LTS desktop QA VM. Not a product installer.

The caller downloads the ISO and Canonical's signed checksums first. Preparation
verifies both before extracting or booting anything. No host directories/devices
are shared; QEMU, its disk and synthetic guest credentials stay in reports/.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
@dataclass(frozen=True)
class UbuntuRelease:
    version: str
    family: str
    sha256: str
    size: int

    @property
    def iso_name(self):
        return f"ubuntu-{self.version}-desktop-amd64.iso"

    @property
    def hostname(self):
        return f"fin3000-ubuntu{self.family}-qa"


# Reviewed official ISO releases, never caller-supplied hashes or download URLs.
UBUNTU24 = UbuntuRelease("24.04.4", "24", "3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e", 6655619072)
UBUNTU26 = UbuntuRelease("26.04.1", "26", "601e30fbf5d97759367c632e2c33630665039b7e2158fd068403da3ccf1bda1f", 6482409472)
RELEASES = {release.version: release for release in (UBUNTU24, UBUNTU26)}
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
GUEST_USER = "fin3000qa"


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def private_directory(value, release=UBUNTU24):
    path = Path(value).absolute()
    if path.is_symlink() or path.parent != REPORTS or not re.fullmatch(rf"ubuntu{release.family}-vm-[A-Za-z0-9_-]+", path.name):
        raise RuntimeError(f"Use an existing private reports/ubuntu{release.family}-vm-* directory")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("VM directory must belong to the current user and have mode 0700")
    if path.resolve() != path:
        raise RuntimeError("Symlinks are not allowed in the VM directory path")
    return path


def regular_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError(f"Expected own regular file: {path.name}")
    return info


def write_new(path, data):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(data)


@contextmanager
def locked(directory):
    descriptor = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def verify_iso(directory, release=UBUNTU24):
    iso = directory / release.iso_name
    if regular_file(iso).st_size != release.size:
        raise RuntimeError("Incomplete or unexpected ISO size")
    for name in ("SHA256SUMS", "SHA256SUMS.gpg"):
        regular_file(directory / name)
    run(["gpgv", "--keyring", KEYRING, str(directory / "SHA256SUMS.gpg"), str(directory / "SHA256SUMS")])
    expected_line = f"{release.sha256} *{release.iso_name}"
    if expected_line not in (directory / "SHA256SUMS").read_text().splitlines():
        raise RuntimeError("Signed checksum does not match the reviewed Ubuntu release")
    with iso.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != release.sha256:
        raise RuntimeError("ISO checksum mismatch; do not boot")


def cloud_config(public_key, password_hash, release=UBUNTU24):
    if not public_key.startswith("ssh-ed25519 ") or not password_hash.startswith("$6$"):
        raise ValueError("Expected a synthetic Ed25519 key and SHA-512 password hash")
    return {"autoinstall": {
        "version": 1,
        "locale": "en_US.UTF-8",
        "keyboard": {"layout": "us"},
        "identity": {"hostname": release.hostname, "username": GUEST_USER,
                     "realname": "Fin3000 disposable QA", "password": password_hash},
        "source": {"id": "ubuntu-desktop", "search_drivers": False},
        "drivers": {"install": False},
        "oem": {"install": False},
        "refresh-installer": {"update": False},
        # QEMU exposes exactly one writable disk; this never names a host device.
        "storage": {"layout": {"name": "direct"}},
        "ssh": {"install-server": True, "allow-pw": False, "authorized-keys": [public_key]},
        "packages": ["python3-cups", "gcc", "acl", "cups", "cups-filters", "apparmor-utils",
                     "poppler-utils", "libsecret-tools", "gjs", "dbus-x11"],
        "shutdown": "poweroff",
    }}


def validate_desktop_source(catalog):
    # Ubuntu 24 ships a flat list; Ubuntu 26 wraps the same source records in
    # its version-2 catalog. Neither format permits an arbitrary fallback ID.
    if isinstance(catalog, dict) and catalog.get("version") == 2:
        catalog = catalog.get("sources")
    if not isinstance(catalog, list) or not all(isinstance(item, dict) for item in catalog):
        raise RuntimeError("Unexpected verified ISO source catalog")
    desktop = [item for item in catalog if item.get("id") == "ubuntu-desktop"]
    if len(desktop) != 1 or desktop[0].get("variant") != "desktop":
        raise RuntimeError("The verified ISO does not offer exactly one reviewed ubuntu-desktop source")


def prepare(directory, release=UBUNTU24):
    for name in ("disk.qcow2", "id_ed25519", "id_ed25519.pub", "guest-password", "seed.iso",
                 "user-data", "meta-data", "vmlinuz", "initrd", "install-sources.yaml", "vm.json"):
        if (directory / name).exists() or (directory / name).is_symlink():
            raise RuntimeError(f"Preparation never overwrites existing state: {name}")
    if shutil.disk_usage(directory).free < 60 * 1024 ** 3:
        raise RuntimeError("Keep at least 60 GiB free before creating the 40 GiB sparse VM")
    verify_iso(directory, release)
    for source, target in (("/casper/vmlinuz", "vmlinuz"), ("/casper/initrd", "initrd"),
                           ("/casper/install-sources.yaml", "install-sources.yaml")):
        run(["xorriso", "-osirrox", "on", "-indev", str(directory / release.iso_name),
             "-extract", source, str(directory / target)], stdout=subprocess.DEVNULL)
    # Read the source IDs from this verified ISO, not from online examples.
    validate_desktop_source(yaml.safe_load((directory / "install-sources.yaml").read_text()))
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fin3000-disposable-vm",
         "-f", str(directory / "id_ed25519")])
    password = secrets.token_urlsafe(24)
    password_hash = run(["openssl", "passwd", "-6", "-stdin"], input=password + "\n",
                        text=True, capture_output=True).stdout.strip()
    write_new(directory / "guest-password", password + "\n")
    config = cloud_config((directory / "id_ed25519.pub").read_text().strip(), password_hash, release)
    write_new(directory / "user-data", "#cloud-config\n" + json.dumps(config, indent=2) + "\n")
    write_new(directory / "meta-data", json.dumps({"instance-id": directory.name,
                                                  "local-hostname": release.hostname}) + "\n")
    run(["xorriso", "-as", "mkisofs", "-output", str(directory / "seed.iso"), "-volid", "cidata",
         "-joliet", "-rock", str(directory / "user-data"), str(directory / "meta-data")],
        stdout=subprocess.DEVNULL)
    run(["qemu-img", "create", "-f", "qcow2", str(directory / "disk.qcow2"), "40G"])
    write_new(directory / "vm.json", json.dumps({"schema": 1, "isoSha256": release.sha256,
                                               "guestUser": GUEST_USER, "diskGiB": 40}, indent=2) + "\n")
    print(f"Prepared verified Ubuntu {release.version} desktop QA VM. No host filesystem sharing. Guest secrets are private.")


def qemu_command(directory, mode, port, release=UBUNTU24):
    if mode not in ("install", "boot") or not 1024 <= port <= 65535:
        raise ValueError("Expected install/boot and an unprivileged loopback SSH port")
    # cdroms are read-only. There is no -virtfs, host block disk, bridge or USB passthrough.
    args = ["qemu-system-x86_64", "-name", release.hostname, "-machine", "q35,accel=kvm",
            "-cpu", "host", "-smp", "4", "-m", "8192", "-device", "virtio-vga",
            "-drive", f"file={directory / 'disk.qcow2'},format=qcow2,if=virtio",
            "-device", "virtio-net-pci,netdev=qa",
            "-netdev", f"user,id=qa,restrict={'off' if mode == 'install' else 'on'},hostfwd=tcp:127.0.0.1:{port}-:22",
            # Resolved inside the validated private cwd; long worktree names
            # must not force public sockets or a symlink-based trust bypass.
            "-display", "none", "-vnc", "unix:vnc.sock",
            "-qmp", "unix:qmp.sock,server=on,wait=off",
            "-serial", f"file:{directory / (mode + '-console.log')}"]
    if mode == "install":
        args += ["-drive", f"file={directory / release.iso_name},format=raw,media=cdrom,readonly=on",
                 "-drive", f"file={directory / 'seed.iso'},format=raw,media=cdrom,readonly=on",
                 "-kernel", str(directory / "vmlinuz"), "-initrd", str(directory / "initrd"),
                 "-append", "boot=casper autoinstall ds=nocloud console=tty0 console=ttyS0,115200n8",
                 "-no-reboot"]
    return args


def start(directory, mode, port, release=UBUNTU24):
    expected = {"schema": 1, "isoSha256": release.sha256, "guestUser": GUEST_USER, "diskGiB": 40}
    regular_file(directory / "vm.json")
    if json.loads((directory / "vm.json").read_text()) != expected:
        raise RuntimeError("Unexpected VM manifest")
    for name in ("disk.qcow2", "id_ed25519", "guest-password"):
        regular_file(directory / name)
    info = json.loads(run(["qemu-img", "info", "--output=json", str(directory / "disk.qcow2")],
                          capture_output=True, text=True).stdout)
    format_data = info.get("format-specific", {}).get("data", {})
    if (info.get("format") != "qcow2" or "backing-filename" in info or "data-file" in format_data
            or info.get("virtual-size") != 40 * 1024 ** 3):
        raise RuntimeError("Only a standalone qcow2 image is allowed")
    if mode == "install":
        if (directory / "install-started").exists():
            raise RuntimeError("Installation already started; inspect retained state, never silently reinstall")
        verify_iso(directory, release)
        write_new(directory / "install-started", "Only the private 40 GiB QA disk is an install target.\n")
    elif not (directory / "install-started").is_file():
        raise RuntimeError("Installation has not started")
    print(f"Starting {mode}: guest SSH on 127.0.0.1:{port}; private Unix VNC/QMP; no host shares.", flush=True)
    # Stay attached: the caller can observe progress; locking prevents concurrent boots.
    run(qemu_command(directory, mode, port, release), cwd=directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "install", "boot"))
    parser.add_argument("--directory", required=True)
    parser.add_argument("--release", choices=tuple(RELEASES), default=UBUNTU24.version)
    parser.add_argument("--ssh-port", type=int, default=22424)
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error("Run as your ordinary user; this tool never needs root")
    os.umask(0o077)
    release = RELEASES[args.release]
    directory = private_directory(args.directory, release)
    with locked(directory):
        if args.mode == "prepare":
            prepare(directory, release)
        else:
            start(directory, args.mode, args.ssh_port, release)


if __name__ == "__main__":
    main()

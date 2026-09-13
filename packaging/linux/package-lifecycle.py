#!/usr/bin/python3 -I
"""Self-contained Debian hook; no user homes, tokens, networking or processes.

The builder embeds this exact source in each control script. It cannot import
code from the package being replaced. The persistent lease inode is never
deleted, including on purge. A failed exchange remains closed for repair.
"""
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import time

STATE = "/var/lib/fin3000-printer/lifecycle"
INVENTORY = "/usr/lib/fin3000-printer/package-files.json"
PROFILE = "/etc/apparmor.d/fin3000-printer"


def require(condition):
    if not condition:
        raise ValueError("PACKAGE_LIFECYCLE_UNSAFE")


def trusted(info, directory=False):
    require(info.st_uid == 0 and not info.st_mode & 0o022 and
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))


def directory(path, create=False):
    require(path.startswith("/") and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        trusted(os.fstat(parent), True)
        for part in PurePosixPath(path).parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                require(create)
                os.mkdir(part, 0o755, dir_fd=parent)
                os.fsync(parent)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                trusted(os.fstat(child), True)
            except BaseException:
                os.close(child); raise
            os.close(parent); parent = child
        return parent
    except BaseException:
        os.close(parent)
        raise


def regular(parent, name, *, writable=False, initial=None):
    require(name not in {"", ".", ".."} and "/" not in name)
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        require(initial is not None and writable)
        fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=parent)
        try:
            require(os.write(fd, initial) == len(initial)); os.fsync(fd); os.fsync(parent)
        except BaseException:
            os.close(fd); raise
    try:
        trusted(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd); raise


def set_ready(parent, value):
    fd = regular(parent, "ready", writable=True, initial=b"0\n")
    try:
        require(os.pwrite(fd, value, 0) == 2)
        os.ftruncate(fd, 2); os.fsync(fd); os.fsync(parent)
    finally:
        os.close(fd)


def quiesce(parent, timeout=210):
    # Close the admission gate BEFORE waiting: existing shared holders drain;
    # new shared holders immediately see 0 and exit without loading payload.
    set_ready(parent, b"0\n")
    fd = regular(parent, "lease", writable=True, initial=b"")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                require(time.monotonic() < deadline)
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except BaseException:
        os.close(fd); raise


def file_digest(path):
    parent = directory(str(PurePosixPath(path).parent))
    try:
        fd = regular(parent, PurePosixPath(path).name)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        require(os.fstat(stream.fileno()).st_size <= 256 * 1024 * 1024)
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_payload():
    parent = directory(str(PurePosixPath(INVENTORY).parent))
    try:
        fd = regular(parent, PurePosixPath(INVENTORY).name)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        require(0 < os.fstat(stream.fileno()).st_size <= 1024 * 1024)
        raw = stream.read(1024 * 1024 + 1)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result); result[key] = value
        return result
    files = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(files, dict) and 10 <= len(files) <= 1000)
    for path, digest in files.items():
        require(isinstance(path, str) and path.startswith(("/usr/", "/etc/apparmor.d/")) and
                isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest))
        require(file_digest(path) == digest)


def reload_profile():
    # This fixed, verified package profile must match the new backend before
    # reopening admission. No cupsd.conf edits, user-home reads or user code.
    file_digest("/usr/sbin/apparmor_parser")
    subprocess.run(["/usr/sbin/apparmor_parser", "--replace", PROFILE],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=30,
                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})


def run_hook(role, arguments):
    require(os.getuid() == os.geteuid() == 0 and sys.flags.isolated)
    require(role in {"preinst", "postinst", "prerm", "postrm"} and 1 <= len(arguments) <= 3)
    os.environ.clear(); os.environ.update({"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    os.umask(0o022)
    action = arguments[0]
    # Unpublished packages predating this contract cannot prove all readers
    # hold leases. Never pretend a live upgrade from such a build is safe.
    if role == "preinst" and action == "upgrade":
        probe = directory(STATE)
        try:
            fd = regular(probe, "lease"); os.close(fd)
        finally:
            os.close(probe)
    parent = directory(STATE, create=True)
    try:
        if role == "preinst" and action in {"install", "upgrade"} or role == "prerm" and action in {"remove", "upgrade", "deconfigure"}:
            fd = quiesce(parent); os.close(fd)
        elif role == "postinst" and action == "configure":
            fd = quiesce(parent)
            try:
                verify_payload()
                reload_profile()
                set_ready(parent, b"1\n")
            finally:
                os.close(fd)
        # Abort/uninstall never silently opens a possibly mixed payload, and
        # never removes another user's recovery/queue/keyring/autostart state.
    finally:
        os.close(parent)


# The builder appends only a fixed role and this fixed exception boundary.

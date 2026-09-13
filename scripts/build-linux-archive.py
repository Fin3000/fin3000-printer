#!/usr/bin/env python3
"""Stage a verified, immutable APT archive candidate. No signing or publication."""
import argparse
from datetime import datetime, timezone
from email.utils import format_datetime
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("archive_release_policy", ROOT / "scripts/verify-linux-release.py")
verify = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verify
spec.loader.exec_module(verify)


def put(root, relative, data):
    verify.require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "Unsafe archive path")
    target = root / relative
    parent = root
    for part in Path(relative).parent.parts:
        parent /= part
        parent.mkdir(mode=0o755, exist_ok=True)
        verify.require(parent.is_dir() and not parent.is_symlink(), "Unsafe archive directory")
        parent.chmod(0o755)
    with target.open("xb") as stream:
        stream.write(data)
    target.chmod(0o644)
    return target


def snapshot_artifact(source, target, artifact):
    # Signature/hash verification of the source alone cannot authorize later
    # changed bytes. Hash the exact snapshot that will be served by the archive.
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as original, target.open("xb") as copy:
        info = os.fstat(original.fileno())
        verify.require(stat.S_ISREG(info.st_mode) and info.st_size == artifact["size"], "Artifact changed")
        digest, total = hashlib.sha256(), 0
        while chunk := original.read(1024 * 1024):
            total += len(chunk)
            verify.require(total <= artifact["size"], "Artifact grew")
            digest.update(chunk); copy.write(chunk)
        verify.require(total == artifact["size"] and digest.hexdigest() == artifact["sha256"], "Artifact changed")
    target.chmod(0o644)


def package_record(path, artifact, name, version):
    result = subprocess.run(["/usr/bin/dpkg-deb", "--field", str(path)], capture_output=True,
                            timeout=30, check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    verify.require(0 < len(result.stdout) <= 65536, "Invalid package control size")
    control = result.stdout.decode("utf-8")
    fields = {}
    previous = None
    for line in control.rstrip("\n").split("\n"):
        if line.startswith((" ", "\t")):
            verify.require(previous is not None, "Unexpected package continuation")
            fields[previous] += "\n" + line
        else:
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)", line)
            verify.require(match is not None, "Invalid package control field")
            previous, value = match.groups()
            previous = previous.lower()
            verify.require(previous not in fields, "Duplicate package control field")
            fields[previous] = value
    verify.require(fields.get("package") == name and fields.get("version") == version
                   and fields.get("architecture") == "amd64", "Package identity disagrees with signed manifest")
    verify.require(not set(fields) & {"filename", "size", "sha256", "sha512", "md5sum"}, "Unexpected archive fields in package")
    return (control.rstrip("\n") + f"\nFilename: pool/main/{artifact['file']}\nSize: {artifact['size']}\n"
            f"SHA256: {artifact['sha256']}\n\n").encode()


def release_file(indexes, now, expires):
    stamp = lambda value: format_datetime(datetime.fromtimestamp(value, timezone.utc), usegmt=True)
    text = ("Origin: Fin3000\nLabel: Fin3000\nSuite: stable\nCodename: fin3000\n"
            f"Date: {stamp(now)}\nValid-Until: {stamp(expires)}\n"
            "Architectures: amd64\nComponents: main\nAcquire-By-Hash: yes\nSHA256:\n")
    for relative, data in sorted(indexes.items()):
        text += f" {hashlib.sha256(data).hexdigest()} {len(data)} {relative}\n"
    return text.encode()


def stage(bundle, output, certificate, *, policy=verify.PRODUCTION, now=None):
    now = int(time.time()) if now is None else now
    verify.require(os.getuid() != 0 and output.is_absolute()
                   and output.parent == ROOT / "reports" and output.parent.resolve() == output.parent
                   and re.fullmatch(r"linux-archive-build-[A-Za-z0-9_-]+", output.name)
                   and not output.exists() and not output.is_symlink(), "Use a new private reports/linux-archive-build-* directory")
    manifest = verify.verify_release(bundle, certificate, policy=policy, now=now)
    # Reverification of a complete private snapshot below binds metadata and
    # artifact bytes to one signature despite a source changing mid-copy.
    output.mkdir(mode=0o700)
    private_bundle = output / "verified-bundle"; private_bundle.mkdir(mode=0o700)
    for filename, maximum in (("release.json", 65536), ("release.json.asc", 16384)):
        _, _, content = verify.regular_file(bundle / filename, maximum, contents=True)
        put(private_bundle, filename, content)
    for artifact in manifest["artifacts"].values():
        snapshot_artifact(bundle / artifact["file"], private_bundle / artifact["file"], artifact)
    verified = verify.verify_release(private_bundle, certificate, policy=policy, now=now)
    verify.require(verified == manifest, "Release changed while staging")
    archive = output / "apt"; archive.mkdir(mode=0o755)
    pool = archive / "pool/main"; pool.mkdir(mode=0o755, parents=True)
    (archive / "pool").chmod(0o755); pool.chmod(0o755)
    records = []
    for kind, name in (("deb", "fin3000-printer"), ("setup", "fin3000-printer-setup")):
        artifact = manifest["artifacts"][kind]
        target = pool / artifact["file"]
        snapshot_artifact(private_bundle / artifact["file"], target, artifact)
        records.append(package_record(target, artifact, name, manifest["version"]))
    packages = b"".join(records)
    indexes = {"main/binary-amd64/Packages": packages,
               "main/binary-amd64/Packages.gz": gzip.compress(packages, mtime=0)}
    for relative, data in indexes.items():
        put(archive, f"dists/stable/{relative}", data)
        digest = hashlib.sha256(data).hexdigest()
        put(archive, f"dists/stable/main/binary-amd64/by-hash/SHA256/{digest}", data)
    expires = min(now + 7 * 86400, verify.timestamp(manifest["expiresAt"]))
    put(archive, "dists/stable/Release", release_file(indexes, now, expires))
    put(output, "archive-candidate.json", (json.dumps({"status": "UNSIGNED_NOT_PUBLISHABLE", "version": manifest["version"],
        "channel": policy.channel, "sourceCommit": manifest["sourceCommit"], "expiresAt": expires,
        "releaseSha256": hashlib.sha256((archive / "dists/stable/Release").read_bytes()).hexdigest()}, sort_keys=True) + "\n").encode())
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    archive = stage(args.bundle, args.directory, ROOT / "signing/linux-release-key.asc")
    print(f"Unsigned APT candidate: {archive}. No InRelease, installation, publication or release approval.")


if __name__ == "__main__":
    main()

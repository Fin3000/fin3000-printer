#!/usr/bin/env python3
"""Prepare a new private verified download generation; never sign or deploy."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publication_archive", ROOT / "scripts/build-linux-archive.py")
archive = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = archive
spec.loader.exec_module(archive)
verify = archive.verify
INDEX = "dists/stable/main/binary-amd64/"
INRELEASE = "dists/stable/InRelease"
PACKAGE = re.compile(r"pool/main/fin3000-printer(?:-setup)?_(0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))_amd64\.deb\Z")


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def source_file(root, relative, maximum):
    parts = relative.split("/")
    verify.require(all(part and part not in (".", "..") for part in parts), "Unsafe publication path")
    root = Path(root)
    verify.require(root.is_absolute() and root.resolve() == root, "Use a real absolute source directory")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            verify.require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "Invalid publication file")
            yield stream
    finally:
        os.close(directory)


def read_small(root, name, maximum):
    with source_file(root, name, maximum) as stream:
        raw = stream.read(maximum + 1)
    verify.require(len(raw) <= maximum, "Publication metadata grew")
    return raw


def copy_verified(root, relative, output, expected):
    """Bind the immutable output to the same FD that is sized and hashed."""
    target = output / relative
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with source_file(root, relative, expected["size"]) as source, target.open("xb") as destination:
        before = os.fstat(source.fileno())
        verify.require(before.st_size == expected["size"], "Publication file size changed")
        digest, total = hashlib.sha256(), 0
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            verify.require(total <= expected["size"], "Publication file grew")
            digest.update(chunk)
            destination.write(chunk)
        after = os.fstat(source.fileno())
        verify.require(total == expected["size"] and digest.hexdigest() == expected["sha256"], "Publication hash mismatch")
        verify.require((before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns),
                       "Publication file changed during copy")
        destination.flush()
        os.fsync(destination.fileno())
    target.chmod(0o644)


def metadata(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def signed_index(raw, certificate, policy, manifest, indexes, now):
    """Verify the actual clearsigner and compare its plaintext to our archive."""
    armor = raw.replace(b"\r\n", b"\n")
    verify.require(re.match(rb"\A-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA(?:256|384|512)\n\n", armor)
                   and armor.endswith(b"-----END PGP SIGNATURE-----\n")
                   and armor.count(b"-----BEGIN PGP SIGNED MESSAGE-----") == 1
                   and armor.count(b"-----BEGIN PGP SIGNATURE-----") == 1
                   and armor.count(b"-----END PGP SIGNATURE-----") == 1,
                   "Exactly one complete InRelease message required")
    _, _, public = verify.regular_file(certificate, 2 * 1024**2, contents=True)
    with tempfile.TemporaryDirectory(prefix="fin3000-apt-public-verify-") as temporary:
        temp = Path(temporary)
        (temp / "InRelease").write_bytes(raw)
        (temp / "certificate.asc").write_bytes(public)
        gpg = ["/usr/bin/gpg", "--no-options", "--homedir", temporary, "--batch",
               "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        listing = verify.command(gpg + ["--with-colons", "--import-options", "show-only", "--import", str(temp / "certificate.asc")])
        verify.require(listing.returncode == 0, "Cannot inspect APT certificate")
        verify.validate_certificate(listing.stdout.decode(), policy, now)
        converted = verify.command(gpg + ["--output", str(temp / "public.gpg"), "--dearmor", str(temp / "certificate.asc")])
        verify.require(converted.returncode == 0, "Cannot parse APT certificate")
        result = verify.command(["/usr/bin/gpgv", "--homedir", temporary, "--keyring", str(temp / "public.gpg"),
                                 "--status-fd", "1", "--output", str(temp / "Release"), str(temp / "InRelease")])
        verify.require(result.returncode == 0, "InRelease signature verification failed")
        plaintext = read_small(temp, "Release", 65536)
    dates = {}
    for line in plaintext.decode("ascii").splitlines():
        if line.startswith(("Date:", "Valid-Until:")):
            field, value = line.split(":", 1)
            verify.require(field not in dates, "Duplicate APT timestamp")
            parsed = parsedate_to_datetime(value.strip())
            verify.require(parsed.tzinfo is not None, "APT timestamp needs timezone")
            dates[field] = int(parsed.timestamp())
    verify.require(set(dates) == {"Date", "Valid-Until"}, "Missing APT validity")
    issued, expires = dates["Date"], dates["Valid-Until"]
    verify.require(issued <= now + 300 and now < expires <= verify.timestamp(manifest["expiresAt"])
                   and 0 < expires - issued <= 7 * 86400, "APT validity rejected")
    verify.validate_signature(result.stdout.decode(), policy, {"issuedAt": stamp(issued)}, now, signature_class="01")
    verify.require(plaintext == archive.release_file(indexes, issued, expires), "Signed APT metadata disagrees with bundle")
    return issued, expires


def retained_policy(name):
    if name.startswith(INDEX + "by-hash/SHA256/"):
        digest = name.removeprefix(INDEX + "by-hash/SHA256/")
        if re.fullmatch(r"[a-f0-9]{64}", digest):
            return 16 * 1024**2
    match = PACKAGE.fullmatch(name)
    if match and match[1] != "0.0.0":
        return verify.MAX_BOOTSTRAP if "fin3000-printer-setup_" in name else verify.MAX_PACKAGE
    return None


def retain_previous(previous, output, files):
    """Prior operator attestation is trusted provenance, not a fresh signature."""
    raw = read_small(previous, "apt/publication.json", 2 * 1024**2)
    value = json.loads(raw, object_pairs_hook=verify.unique_object)
    verify.require(isinstance(value, dict) and set(value) == {
        "schemaVersion", "releaseManifestSha256", "issuedAt", "expiresAt", "files"}, "Invalid previous publication")
    verify.require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                   and isinstance(value["files"], dict) and len(value["files"]) <= 4096, "Invalid previous file list")
    verify.require(isinstance(value["releaseManifestSha256"], str)
                   and re.fullmatch(r"[a-f0-9]{64}", value["releaseManifestSha256"]), "Invalid previous manifest hash")
    verify.timestamp(value["issuedAt"])
    verify.timestamp(value["expiresAt"])
    for name, item in value["files"].items():
        maximum = retained_policy(name)
        if maximum is None:
            verify.require(name in (INRELEASE, INDEX + "Packages", INDEX + "Packages.gz"), "Unexpected previous path")
            continue  # Mutable current metadata is always independently rebuilt.
        verify.require(isinstance(item, dict) and set(item) == {"size", "sha256"}
                       and type(item["size"]) is int and 0 < item["size"] <= maximum
                       and isinstance(item["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]),
                       "Invalid retained artifact")
        verify.require("/by-hash/" not in name or name.rsplit("/", 1)[-1] == item["sha256"], "Invalid retained content address")
        if name in files:
            verify.require(files[name] == item, "Immutable publication path collision")
        else:
            copy_verified(Path(previous) / "apt", name, output, item)
            files[name] = item
    verify.require(len(files) <= 4096, "Too many retained files; explicit retention review required")


def prepare(bundle, apt_source, output, certificate, *, previous=None, policy=verify.PRODUCTION, now=None):
    now = int(time.time()) if now is None else now
    output = Path(output)
    verify.require(os.getuid() != 0 and output.is_absolute() and output.parent == ROOT / "reports"
                   and output.parent.resolve() == output.parent
                   and re.fullmatch(r"linux-publication-[A-Za-z0-9_-]+", output.name)
                   and not output.exists() and not output.is_symlink(), "Use a new private reports/linux-publication-* directory")
    manifest = verify.verify_release(bundle, certificate, policy=policy, now=now)
    verify.require(manifest["version"] != "0.0.0", "Bootstrap version cannot be published")
    output.mkdir(mode=0o700)
    version = output / manifest["version"]
    version.mkdir(mode=0o755)
    for name, maximum in (("release.json", 65536), ("release.json.asc", 16384)):
        archive.put(version, name, read_small(bundle, name, maximum))
    for item in manifest["artifacts"].values():
        copy_verified(bundle, item["file"], version, item)
    verify.require(verify.verify_release(version, certificate, policy=policy, now=now) == manifest,
                   "Bundle changed during publication snapshot")
    release_bytes = read_small(version, "release.json", 65536)
    signature_bytes = read_small(version, "release.json.asc", 16384)
    manifest_hash = hashlib.sha256(release_bytes).hexdigest()
    apt = output / "apt"
    apt.mkdir(mode=0o755)
    files, records = {}, []
    for kind, package in (("deb", "fin3000-printer"), ("setup", "fin3000-printer-setup")):
        item = manifest["artifacts"][kind]
        name = "pool/main/" + item["file"]
        expected = {"size": item["size"], "sha256": item["sha256"]}
        copy_verified(apt_source, name, apt, expected)
        records.append(archive.package_record(apt / name, item, package, manifest["version"]))
        files[name] = expected
    packages = b"".join(records)
    indexes = {"main/binary-amd64/Packages": packages,
               "main/binary-amd64/Packages.gz": gzip.compress(packages, mtime=0)}
    for relative, raw in indexes.items():
        verify.require(0 < len(raw) <= 16 * 1024**2, "Index exceeds publication limit")
        item = metadata(raw)
        for name in ("dists/stable/" + relative, INDEX + "by-hash/SHA256/" + item["sha256"]):
            copy_verified(apt_source, name, apt, item)
            files[name] = item
    inrelease = read_small(apt_source, INRELEASE, 65536)
    issued, expires = signed_index(inrelease, certificate, policy, manifest, indexes, now)
    archive.put(apt, INRELEASE, inrelease)
    files[INRELEASE] = metadata(inrelease)
    if previous is not None:
        retain_previous(previous, apt, files)
    archive.put(version, "publication.json", (json.dumps({"schemaVersion": 1, "manifestSha256": manifest_hash,
                "signatureSha256": hashlib.sha256(signature_bytes).hexdigest()}, sort_keys=True) + "\n").encode())
    archive.put(apt, "publication.json", (json.dumps({"schemaVersion": 1, "releaseManifestSha256": manifest_hash,
                "issuedAt": stamp(issued), "expiresAt": stamp(expires), "files": files}, sort_keys=True) + "\n").encode())
    # This last marker is absent on every failed preparation. No existing mount,
    # active pointer, signature, keyring or repository is ever overwritten.
    archive.put(output, "active.json", (json.dumps({"version": manifest["version"]}) + "\n").encode())
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("archive", type=Path, help="Archive directory with independently signed InRelease")
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--previous", type=Path, help="Optional previous OWN operator-controlled generation, not a download")
    args = parser.parse_args()
    try:
        output = prepare(args.bundle, args.archive, args.directory, ROOT / "signing/linux-release-key.asc", previous=args.previous)
    except (verify.VerificationError, OSError, ValueError, KeyError, TypeError, IndexError,
            RecursionError, subprocess.SubprocessError):
        print("FAIL: publication preparation rejected. No live release changed.")
        return 1
    print(f"Prepared private verified generation: {output}")
    print("No signing, install, live activation, backend-readiness or user-acceptance claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

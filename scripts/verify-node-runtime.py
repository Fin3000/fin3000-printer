#!/usr/bin/env python3
"""Verify the pinned Node archive offline; never run, install or download it."""
import argparse
import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("node_release_common", ROOT / "scripts/verify-linux-release.py")
common = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = common
spec.loader.exec_module(common)
require = common.require


@dataclass(frozen=True)
class NodePolicy:
    version: str
    archive_sha256: str
    primary: str
    key_bits: int = 4096
    source_sha256: str = "bbe768df8d5815d7fa76124052985332452e0a4742d39f32027550d1aab8f6fb"
    supplement_sha256: str = "dfc40608aed9a48b3e8e00a0696ea904a1366299c5fea485ca7e14c9d4fad15f"


PINNED = NodePolicy("22.23.2", "d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307",
                    "CC68F5A3106FF448322E48ED27F5E38D5B0A215F")
CERTIFICATE = ROOT / "signing/node-release-key.asc"
SUPPLEMENT = ROOT / "signing/node-runtime-supplement.json"
SUPPLEMENT_SOURCE = "vendor-source/smartstring-1.0.1.crate"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_NOTICES = 16 * 1024 * 1024


@dataclass(frozen=True)
class RuntimeProvenance:
    name: str
    version: str
    archive: str
    archiveSha256: str
    archiveSize: int
    sha256: str
    licenseSha256: str
    checksumsSha256: str
    signatureSha256: str
    certificateSha256: str
    signer: str
    signedAt: int
    sourceArchive: str
    sourceArchiveSha256: str
    sourceArchiveSize: int
    sourceNoticesSha256: str
    sourceNoticeCount: int
    sourceSupplementSha256: str
    supplementalNoticeCount: int
    supplementalSourceSha256: str
    provenance: str = ("upstream-detached-signature-and-pinned-archive;"
                       "separately-reviewed-hash-pinned-supplement")


@dataclass(frozen=True)
class VerifiedRuntime:
    node: bytes
    license: bytes
    proof: RuntimeProvenance
    source_notices: bytes
    supplemental_source: bytes


@dataclass(frozen=True)
class VerifiedSupplement:
    notices: bytes
    count: int
    source: bytes
    source_sha256: str


def certificate_valid(listing, policy, now):
    """Node signs this release with the RSA primary, not our release subkey."""
    records = [line.split(":") for line in listing.splitlines()]
    public = [fields for fields in records if fields[0] == "pub"]
    require(len(public) == 1 and not any(row[0] in ("sec", "ssb") for row in records),
            "Exactly one public vendor certificate required")
    key = public[0]
    require(len(key) >= 12 and key[1] not in ("r", "e", "d", "i")
            and "D" not in key[11] and "s" in key[11], "Vendor signing key is not valid")
    require(key[2] == str(policy.key_bits) and key[3] == "1", "Wrong vendor key algorithm")
    created, expires = int(key[5]), int(key[6])
    require(created <= now and now < expires, "Vendor certificate expired or future-dated")
    index = records.index(key)
    require(index + 1 < len(records) and records[index + 1][0] == "fpr"
            and records[index + 1][9] == policy.primary, "Vendor primary is not pinned")
    return created


def signature_valid(status, policy, now, key_created):
    records = [line.removeprefix("[GNUPG:] ").split() for line in status.splitlines()
               if line.startswith("[GNUPG:] ")]
    bad = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY",
           "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED", "FAILURE", "ERROR", "NODATA"}
    require(not any(row[0] in bad for row in records), "Vendor signature policy rejected")
    signatures = [row for row in records if row[0] == "VALIDSIG"]
    require(len(signatures) == 1 and sum(row[0] == "NEWSIG" for row in records) == 1,
            "Exactly one vendor signature required")
    row = signatures[0]
    require(len(row) == 11 and row[1] == row[10] == policy.primary
            and row[7] == "1" and row[8] in ("8", "9", "10") and row[9] == "00",
            "Vendor signer or signature algorithm is not pinned")
    created, expires = int(row[3]), int(row[4])
    require(key_created <= created <= now and (expires == 0 or now < expires),
            "Vendor signature expired or future-dated")
    return created


def verify_signature(checksums, signature, certificate, policy, now):
    # All bytes are private snapshots. Never use the user's GPG configuration,
    # keyring, agent or a keyserver. No production private key is involved.
    with tempfile.TemporaryDirectory(prefix="fin3000-node-verify-") as temporary:
        root = Path(temporary)
        for name, content in (("checksums", checksums), ("signature", signature), ("public.asc", certificate)):
            (root / name).write_bytes(content)
        gpg = ["/usr/bin/gpg", "--no-options", "--homedir", temporary, "--batch",
               "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        listing = common.command(gpg + ["--with-colons", "--import-options", "show-only",
                                        "--import", str(root / "public.asc")])
        require(listing.returncode == 0, "Cannot inspect vendor certificate")
        created = certificate_valid(listing.stdout.decode("utf-8"), policy, now)
        conversion = common.command(gpg + ["--output", str(root / "public.gpg"), "--dearmor",
                                           str(root / "public.asc")])
        require(conversion.returncode == 0, "Cannot parse vendor certificate")
        verified = common.command(["/usr/bin/gpgv", "--homedir", temporary,
                                   "--keyring", str(root / "public.gpg"), "--status-fd", "1",
                                   str(root / "signature"), str(root / "checksums")])
        require(verified.returncode == 0, "Vendor detached signature rejected")
        return signature_valid(verified.stdout.decode("utf-8"), policy, now, created)


def checksum_matches(checksums, filename, digest):
    entries = {}
    lines = checksums.decode("ascii").splitlines()
    require(0 < len(lines) <= 128, "Invalid checksum entry count")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        require(match is not None, "Malformed vendor checksum entry")
        value, name = match.groups()
        require(name not in entries, "Duplicate vendor checksum entry")
        entries[name] = value
    require(entries.get(filename) == digest, "Archive is not bound by signed checksums")


def archive_payload(archive, prefix):
    """Read two exact regular members. Never extract archive paths or npm links."""
    wanted = {f"{prefix}/bin/node": 150 * 1024 * 1024, f"{prefix}/LICENSE": 4 * 1024 * 1024}
    found, names, expanded = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as bundle:
        for member in bundle:
            name, path = member.name.rstrip("/"), PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name
                    and path.parts and path.parts[0] == prefix and len(name) <= 512
                    and path.as_posix() == name, "Unsafe runtime archive path")
            require(name not in names, "Duplicate runtime archive member")
            names.add(name)
            expanded += member.size
            require(len(names) <= 50000 and 0 <= member.size and expanded <= 1024 * 1024 * 1024,
                    "Runtime archive expansion exceeds bounds")
            if name not in wanted:
                continue
            require(member.isreg() and 0 < member.size <= wanted[name], "Runtime payload must be a bounded regular member")
            with bundle.extractfile(member) as stream:
                data = stream.read(wanted[name] + 1)
            require(len(data) == member.size, "Truncated runtime payload")
            found[name] = data
    require(set(found) == set(wanted), "Runtime archive lacks binary or license")
    node, license_text = found[f"{prefix}/bin/node"], found[f"{prefix}/LICENSE"]
    require(node[:6] == b"\x7fELF\x02\x01" and node[18:20] == b"\x3e\x00", "Runtime is not Linux ELF64 x86-64")
    require("Node.js" in license_text.decode("utf-8") and b"MIT" in license_text, "Invalid vendor license text")
    return node, license_text


def source_notices(archive, prefix, license_text):
    """Preserve original notices from the authenticated source, without extraction.

    The collection deliberately includes build/test-only dependencies. It is
    not a declaration that every source component is linked into our runtime.
    Source paths and content hashes keep each original notice attributable.
    """
    selected, names, expanded, total = {}, set(), 0, 0
    required = {"LICENSE", "deps/v8/LICENSE", "deps/v8/LICENSE.fdlibm",
                "deps/nbytes/LICENSE", "deps/sqlite/sqlite3.h"}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as bundle:
        for member in bundle:
            name, path = member.name.rstrip("/"), PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name
                    and path.parts and path.parts[0] == prefix and len(name) <= 512
                    and path.as_posix() == name and name.isprintable(), "Unsafe source archive path")
            require(name not in names, "Duplicate source archive member")
            names.add(name)
            expanded += member.size
            require(len(names) <= 150000 and member.size >= 0 and expanded <= 1024 * 1024 * 1024,
                    "Source archive expansion exceeds bounds")
            relative = path.relative_to(prefix).as_posix()
            notice_name = re.fullmatch(r"(?:LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)(?:[._-].*)?",
                                       path.name, re.IGNORECASE)
            # Names alone also match vendor implementations such as
            # copying-phase.cc, license.js and copyright.pm. They are not
            # notice documents. Keep actual named licenses (LICENSE.fdlibm,
            # LICENSE.strongtalk, LICENSE-extra, etc.) byte-for-byte.
            if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
                                       ".js", ".mjs", ".cjs", ".ts", ".py", ".pm", ".sh", ".rs", ".go"}:
                notice_name = None
            if relative not in required and (not notice_name or member.isdir()):
                continue
            require(member.isreg() and 0 < member.size <= 2 * 1024 * 1024,
                    "Source notice must be a bounded regular member")
            with bundle.extractfile(member) as stream:
                raw = stream.read(2 * 1024 * 1024 + 1)
            require(len(raw) == member.size, "Truncated source notice")
            # SQLite declares its copyright status in the header, not a LICENSE
            # file. Preserve the exact leading notice, never the whole API/code.
            if relative == "deps/sqlite/sqlite3.h":
                lines = raw.splitlines(keepends=True)
                require(len(lines) >= 11 and b"The author disclaims copyright" in b"".join(lines[:11]),
                        "SQLite source notice changed")
                raw = b"".join(lines[:11])
            total += len(raw)
            require(len(selected) < 2048 and total <= MAX_NOTICES - 1024 * 1024,
                    "Source notice collection exceeds bounds")
            selected[relative] = raw
    require(required <= set(selected) and selected["LICENSE"] == license_text,
            "Source and binary license mismatch or required source notice missing")
    introduction = (
        "Original Node.js source notices; supplementary to NODE-LICENSE.\n"
        "Includes source/build/test dependencies NOT necessarily shipped in the runtime.\n"
        "This is not a complete SBOM, a Fin3000 license grant or release approval.\n"
        "SQLite sqlite3.h contains its exact first 11 lines only; other entries are whole files.\n"
    ).encode()
    parts = [introduction]
    for path, raw in sorted(selected.items()):
        parts.extend([f"\n===== {path} | SHA256 {hashlib.sha256(raw).hexdigest()} | {len(raw)} bytes =====\n".encode(),
                      raw, b"\n"])
    notices = b"".join(parts)
    require(len(notices) <= MAX_NOTICES, "Source notice collection exceeds bounds")
    return notices, len(selected)


def supplement_payload(raw, policy):
    """Parse only the reviewed hash-pinned supplement, never fetch or run it.

    These notices are NOT covered by Node's archive signature. Their separate
    pin/provenance binds the observed source attribution reviewed with this code.
    The original source archive remains opaque bytes in a fixed documentation path.
    """
    data = json.loads(raw, object_pairs_hook=common.unique_object)
    require(isinstance(data, dict) and type(data.get("schema")) is int and data["schema"] == 1
            and data.get("nodeVersion") == policy.version
            and data.get("nodeSourceSha256") == policy.source_sha256
            and data.get("status") == "RESOLVED_AND_OBSERVED_SUBSET_NOT_COMPLETE_SBOM_OR_RELEASE_APPROVAL",
            "Supplement does not match pinned Node source or attribution scope")
    require(isinstance(data.get("notices"), str) and type(data.get("noticeCount")) is int
            and 1 <= data["noticeCount"] <= 512, "Invalid supplemental notices")
    notices = data["notices"].encode("utf-8")
    require(0 < len(notices) <= 1024 * 1024
            and hashlib.sha256(notices).hexdigest() == data.get("noticesSha256"),
            "Supplemental notice bytes changed")
    # The bytes are pinned, but a metadata count is not independently verified
    # until the rendered original-notice boundaries agree with it.
    count = len(re.findall(rb"^===== [^\r\n]+ \(SHA256 [0-9a-f]{64}\) =====$", notices, re.MULTILINE))
    require(count == data["noticeCount"], "Supplemental notice count mismatch")
    item = data.get("originalSource")
    require(isinstance(item, dict) and item.get("file") == "smartstring-1.0.1.crate"
            and item.get("encoding") == "base64" and isinstance(item.get("data"), str)
            and 0 < len(item["data"]) <= 1024 * 1024, "Invalid supplemental source archive")
    source = base64.b64decode(item["data"], validate=True)
    digest = hashlib.sha256(source).hexdigest()
    require(source and digest == item.get("sha256"), "Supplemental source bytes changed")
    return VerifiedSupplement(notices, count, source, digest)


def verify_runtime(directory, *, certificate=CERTIFICATE, supplement=SUPPLEMENT, policy=PINNED, now=None):
    now = int(time.time()) if now is None else now
    directory = Path(directory)
    prefix = f"node-v{policy.version}-linux-x64"
    filename = prefix + ".tar.xz"
    _, sums_digest, sums = common.regular_file(directory / "SHASUMS256.txt", 65536, contents=True)
    _, sig_digest, sig = common.regular_file(directory / "SHASUMS256.txt.sig", 16384, contents=True)
    _, cert_digest, cert = common.regular_file(certificate, 256 * 1024, contents=True)
    signed_at = verify_signature(sums, sig, cert, policy, now)
    checksum_matches(sums, filename, policy.archive_sha256)
    size, digest, archive = common.regular_file(directory / filename, MAX_ARCHIVE, contents=True)
    require(digest == policy.archive_sha256, "Runtime archive digest is not pinned")
    source_name = f"node-v{policy.version}.tar.xz"
    checksum_matches(sums, source_name, policy.source_sha256)
    source_size, source_digest, source_archive = common.regular_file(directory / source_name, MAX_ARCHIVE, contents=True)
    require(source_digest == policy.source_sha256, "Source archive digest is not pinned")
    _, supplement_digest, supplement_raw = common.regular_file(supplement, 2 * 1024 * 1024, contents=True)
    require(supplement_digest == policy.supplement_sha256, "Supplement digest is not pinned")
    extra = supplement_payload(supplement_raw, policy)
    # Only authenticated, hash-pinned bytes reach the archive parser.
    node, license_text = archive_payload(archive, prefix)
    notices, count = source_notices(source_archive, f"node-v{policy.version}", license_text)
    notices += ("\nSupplementary embedded Rust notices (separately pinned, not Node-signed).\n"
                f"Original SmartString 1.0.1 source is installed beside this file at {SUPPLEMENT_SOURCE}.\n"
                "This observed subset is not a complete SBOM or release approval.\n").encode() + extra.notices
    require(len(notices) <= MAX_NOTICES, "Combined source notices exceed bounds")
    proof = RuntimeProvenance("node", policy.version, filename, digest, size,
                              hashlib.sha256(node).hexdigest(), hashlib.sha256(license_text).hexdigest(),
                              sums_digest, sig_digest, cert_digest, policy.primary, signed_at,
                              source_name, source_digest, source_size, hashlib.sha256(notices).hexdigest(), count,
                              supplement_digest, extra.count, extra.source_sha256)
    return VerifiedRuntime(node, license_text, proof, notices, extra.source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Local official archive plus SHASUMS256.txt and .sig")
    args = parser.parse_args()
    try:
        runtime = verify_runtime(args.directory)
    except (ValueError, OSError, KeyError, IndexError, TypeError, EOFError, binascii.Error, lzma.LZMAError, tarfile.TarError,
            common.subprocess.SubprocessError):
        print("FAIL: vendor runtime verification rejected; nothing was installed or executed.")
        return 1
    print(json.dumps(asdict(runtime.proof), indent=2))
    print("Verified build input only. No CVE clearance, complete SBOM or Fin3000 release approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

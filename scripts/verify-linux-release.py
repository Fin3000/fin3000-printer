#!/usr/bin/env python3
"""Offline bundle verification. Never installs, signs, downloads or uploads."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


class VerificationError(ValueError):
    """An artifact is not eligible for distribution."""


@dataclass(frozen=True)
class TrustPolicy:
    primary: str
    signer: str
    channel: str


PRODUCTION = TrustPolicy(
    "FDFF3DCD55DDAAECCDB048E14F91CA50AA992F61",
    "6C1594AE8A48B7D7649BEDA7DA6206688A5862E3", "production",
)
VERSION = re.compile(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MAX_PACKAGE = 1024 * 1024 * 1024
MAX_BOOTSTRAP = 4 * 1024 * 1024
MAX_SBOM = 16 * 1024 * 1024
MAX_VALIDITY = 31 * 24 * 60 * 60


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def regular_file(path, limit, *, contents=False):
    """Pin inode, reject symlinks/special files; stream large packages."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "Artifact must be a regular file")
        require(0 < before.st_size <= limit, "Artifact size outside limit")
        digest, data, total = hashlib.sha256(), bytearray(), 0
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            require(total <= limit, "Artifact grew beyond limit")
            digest.update(chunk)
            if contents:
                data.extend(chunk)
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and total == before.st_size, "Artifact changed during verification")
        return total, digest.hexdigest(), bytes(data)


def command(arguments):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False,
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    require(len(result.stdout) < 1024 * 1024, "Unexpected verifier output size")
    return result


def timestamp(value):
    require(isinstance(value, str) and
            re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
            "Timestamp must be UTC with second precision")
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp())


def validate_manifest(raw, policy, now):
    manifest = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(manifest, dict) and set(manifest) == {
        "schemaVersion", "product", "version", "channel", "platform", "architecture",
        "ubuntuVersions", "sourceCommit", "buildId", "minimumBackendVersion",
        "issuedAt", "expiresAt", "artifacts",
    }, "Unexpected manifest fields")
    require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2,
            "Unsupported manifest schema")
    require(manifest["product"] == "fin3000-printer", "Wrong product")
    require(manifest["channel"] == policy.channel, "Wrong release channel")
    require(manifest["platform"] == "linux" and manifest["architecture"] == "amd64",
            "Unsupported platform/architecture")
    require(manifest["ubuntuVersions"] == ["24.04", "26.04"], "Wrong support matrix")
    for field in ("version", "minimumBackendVersion"):
        require(isinstance(manifest[field], str) and VERSION.fullmatch(manifest[field]),
                "Invalid release/backend version")
    require(isinstance(manifest["sourceCommit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", manifest["sourceCommit"]), "Invalid source commit")
    require(isinstance(manifest["buildId"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", manifest["buildId"]),
            "Invalid build identity")
    issued, expires = timestamp(manifest["issuedAt"]), timestamp(manifest["expiresAt"])
    require(issued <= now + 300 and now < expires and 0 < expires - issued <= MAX_VALIDITY,
            "Release expired, future-dated or validity window too long")
    require(isinstance(manifest["artifacts"], dict)
            and set(manifest["artifacts"]) == {"deb", "setup", "sbom"}, "Missing package/setup/SBOM")
    for kind, limit in (("deb", MAX_PACKAGE), ("setup", MAX_BOOTSTRAP), ("sbom", MAX_SBOM)):
        artifact = manifest["artifacts"][kind]
        require(isinstance(artifact, dict) and set(artifact) == {"file", "size", "sha256"},
                "Unexpected artifact fields")
        expected = {"deb": f"fin3000-printer_{manifest['version']}_amd64.deb",
                    "setup": f"fin3000-printer-setup_{manifest['version']}_amd64.deb",
                    "sbom": f"fin3000-printer_{manifest['version']}.cdx.json"}[kind]
        require(artifact["file"] == expected, "Artifact filename does not match release")
        require(type(artifact["size"]) is int and 0 < artifact["size"] <= limit,
                "Invalid declared artifact size")
        require(isinstance(artifact["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]), "Invalid artifact digest")
    return manifest


def sbom_text(value, limit=512):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and value == value.strip() and not any(ord(char) < 32 for char in value))


def validate_sbom(raw, manifest):
    """Check our flat CycloneDX profile, not inventory truth or CVE clearance.

    A signed completeness declaration still needs an independent release audit.
    In particular, a binary-only scanner cannot establish Node's embedded deps.
    No URI, external reference or license URL is fetched by this validator.
    """
    bom = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(bom, dict) and bom.get("bomFormat") == "CycloneDX"
            and bom.get("specVersion") == "1.6" and type(bom.get("version")) is int
            and bom["version"] >= 1, "Expected CycloneDX 1.6 SBOM")
    metadata = bom.get("metadata")
    require(isinstance(metadata, dict) and isinstance(metadata.get("component"), dict),
            "SBOM root component required")
    root, components = metadata["component"], bom.get("components")
    require(isinstance(components, list) and 3 <= len(components) <= 512,
            "SBOM requires setup, runtime and embedded components")
    by_ref = {}
    for component in [root, *components]:
        require(isinstance(component, dict) and component.get("type") in
                ("application", "library", "framework", "data")
                and "components" not in component, "SBOM must use flat named components")
        reference = component.get("bom-ref")
        require(sbom_text(reference) and reference not in by_ref
                and sbom_text(component.get("name")) and sbom_text(component.get("version")),
                "SBOM component identity missing or duplicated")
        licenses = component.get("licenses")
        require(isinstance(licenses, list) and 1 <= len(licenses) <= 64,
                "SBOM component requires license declarations")
        for declaration in licenses:
            require(isinstance(declaration, dict) and len(declaration) == 1,
                    "Invalid SBOM license declaration")
            if "expression" in declaration:
                label = declaration["expression"]
            else:
                license_value = declaration.get("license")
                require(isinstance(license_value, dict)
                        and ("id" in license_value) != ("name" in license_value),
                        "SBOM license needs one identifier or name")
                label = license_value.get("id", license_value.get("name"))
            require(sbom_text(label, 4096)
                    and label.upper() not in ("NOASSERTION", "NONE", "UNKNOWN", "UNLICENSED"),
                    "Unresolved SBOM license declaration")
        by_ref[reference] = component
    require(root["name"] == manifest["product"] and root["type"] == "application",
            "SBOM product does not match release")
    setup = [component for component in components if component["name"] == "fin3000-printer-setup"]
    runtime = [component for component in components if component["name"] == "node"]
    require(len(setup) == len(runtime) == 1 and runtime[0]["type"] == "application",
            "SBOM must identify exactly one setup package and Node runtime")
    for component, kind in ((root, "deb"), (setup[0], "setup")):
        require(component["type"] == "application" and component["version"] == manifest["version"]
                and component.get("hashes") == [{"alg": "SHA-256", "content": manifest["artifacts"][kind]["sha256"]}],
                "SBOM package identity or hash does not match release")
    properties = metadata.get("properties")
    require(isinstance(properties, list) and len(properties) <= 128, "SBOM build properties missing")
    indexed = {}
    for prop in properties:
        require(isinstance(prop, dict) and set(prop) == {"name", "value"}
                and sbom_text(prop["name"]) and prop["name"] not in indexed
                and sbom_text(prop["value"], 4096), "Invalid or duplicate SBOM build property")
        indexed[prop["name"]] = prop["value"]
    require(indexed.get("fin3000:source-commit") == manifest["sourceCommit"]
            and indexed.get("fin3000:build-id") == manifest["buildId"],
            "SBOM source/build does not match release")
    dependencies = bom.get("dependencies")
    require(isinstance(dependencies, list) and len(dependencies) == len(by_ref),
            "SBOM dependency inventory missing")
    graph = {}
    for dependency in dependencies:
        require(isinstance(dependency, dict) and set(dependency) == {"ref", "dependsOn"},
                "Invalid SBOM dependency entry")
        reference, targets = dependency["ref"], dependency["dependsOn"]
        require(sbom_text(reference) and reference in by_ref and reference not in graph
                and isinstance(targets, list) and len(targets) <= len(by_ref)
                and all(sbom_text(target) and target in by_ref and target != reference for target in targets)
                and len(targets) == len(set(targets)), "Invalid or duplicate SBOM dependency reference")
        graph[reference] = targets
    pending, seen = [root["bom-ref"]], set()
    while pending:
        reference = pending.pop()
        if reference not in seen:
            seen.add(reference)
            pending.extend(graph[reference])
    require(seen == by_ref.keys() and graph[runtime[0]["bom-ref"]]
            and all(by_ref[ref]["type"] in ("library", "framework", "data")
                    for ref in graph[runtime[0]["bom-ref"]]),
            "SBOM has unreachable components or omits embedded runtime dependencies")
    require(bom.get("compositions") == [{"aggregate": "complete", "assemblies": [root["bom-ref"]]}],
            "SBOM completeness declaration missing; manual audit still required")


def validate_certificate(colons, policy, now):
    keys, current = [], None
    for line in colons.splitlines():
        fields = line.split(":")
        if fields[0] in ("pub", "sub"):
            require(len(fields) >= 12, "Malformed certificate record")
            current = {"type": fields[0], "validity": fields[1], "created": int(fields[5] or "0"),
                       "expires": int(fields[6] or "0"), "caps": fields[11]}
            keys.append(current)
        elif fields[0] == "fpr" and current is not None:
            require("fingerprint" not in current, "Ambiguous certificate fingerprint")
            current["fingerprint"] = fields[9]
    primaries = [key for key in keys if key["type"] == "pub"]
    require(len(primaries) == 1 and primaries[0].get("fingerprint") == policy.primary,
            "Certificate primary identity is not pinned")
    signers = [key for key in keys if key["type"] == "sub"
               and key.get("fingerprint") == policy.signer]
    require(len(signers) == 1, "Pinned signing subkey is missing")
    for key in (primaries[0], signers[0]):
        require(key["validity"] not in ("r", "e", "d", "i") and "D" not in key["caps"],
                "Certificate revoked, expired, disabled or invalid")
        require(key["created"] <= now + 300 and now < key["expires"],
                "Certificate outside its validity window")
    require("s" in signers[0]["caps"], "Subkey is not a signing key")


def validate_signature(status, policy, manifest, now, *, signature_class="00"):
    require(signature_class in ("00", "01"), "Unsupported expected signature class")
    records = [line.removeprefix("[GNUPG:] ").split()
               for line in status.splitlines() if line.startswith("[GNUPG:] ")]
    bad = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY",
           "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED", "FAILURE", "ERROR", "NODATA"}
    require(not any(record[0] in bad for record in records), "Signature policy rejected")
    signatures = [record for record in records if record[0] == "VALIDSIG"]
    require(len(signatures) == 1 and sum(record[0] == "NEWSIG" for record in records) == 1,
            "Exactly one valid detached signature required")
    signature = signatures[0]
    require(len(signature) == 11 and signature[1] == policy.signer
            and signature[10] == policy.primary, "Actual signer is not pinned")
    require(signature[7] == "22" and signature[8] in ("8", "9", "10")
            and signature[9] == signature_class, "Unsupported signature algorithm/class")
    created, expires = int(signature[3]), int(signature[4])
    require(timestamp(manifest["issuedAt"]) - 300 <= created <= now + 300,
            "Signature timestamp does not match release")
    require(expires == 0 or now < expires, "Signature expired")


def verify_release(directory, certificate, *, policy=PRODUCTION, now=None):
    now = int(time.time()) if now is None else now
    directory = Path(directory)
    _, _, raw = regular_file(directory / "release.json", 65536, contents=True)
    manifest = validate_manifest(raw, policy, now)
    _, _, signature = regular_file(directory / "release.json.asc", 16384, contents=True)
    _, _, public = regular_file(certificate, 2 * 1024 * 1024, contents=True)
    # Snapshots bind the signature to the exact inspected bytes. The isolated
    # public-only home does not use user configuration, trustdb or key retrieval.
    with tempfile.TemporaryDirectory(prefix="fin3000-release-verify-") as temporary:
        temp = Path(temporary)
        (temp / "release.json").write_bytes(raw)
        (temp / "signature.asc").write_bytes(signature)
        (temp / "certificate.asc").write_bytes(public)
        gpg = ["/usr/bin/gpg", "--no-options", "--homedir", temporary, "--batch",
               "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        listing = command(gpg + ["--with-colons", "--import-options", "show-only",
                                 "--import", str(temp / "certificate.asc")])
        require(listing.returncode == 0, "Cannot inspect certificate")
        validate_certificate(listing.stdout.decode("utf-8"), policy, now)
        conversion = command(gpg + ["--output", str(temp / "public.gpg"), "--dearmor",
                                    str(temp / "certificate.asc")])
        require(conversion.returncode == 0, "Cannot parse certificate")
        verified = command(["/usr/bin/gpgv", "--homedir", temporary,
                            "--keyring", str(temp / "public.gpg"), "--status-fd", "1",
                            str(temp / "signature.asc"), str(temp / "release.json")])
        require(verified.returncode == 0, "Detached signature verification failed")
        validate_signature(verified.stdout.decode("utf-8"), policy, manifest, now)
    for kind, limit in (("deb", MAX_PACKAGE), ("setup", MAX_BOOTSTRAP), ("sbom", MAX_SBOM)):
        expected = manifest["artifacts"][kind]
        size, digest, raw = regular_file(directory / expected["file"], limit, contents=kind == "sbom")
        require(size == expected["size"] and digest == expected["sha256"],
                f"{kind} artifact size or digest mismatch")
        if kind == "sbom":
            validate_sbom(raw, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Local release bundle directory")
    arguments = parser.parse_args()
    certificate = Path(__file__).resolve().parent.parent / "signing/linux-release-key.asc"
    try:
        manifest = verify_release(arguments.directory, certificate)
    except (VerificationError, OSError, ValueError, KeyError, IndexError, TypeError, RecursionError,
            subprocess.SubprocessError):
        print("FAIL: release verification rejected; nothing was installed.")
        return 1
    print(f"PASS: Fin3000 Printer {manifest['version']} — signature and artifact hashes verified.")
    print("Verification only: no installation, backend readiness or user acceptance implied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

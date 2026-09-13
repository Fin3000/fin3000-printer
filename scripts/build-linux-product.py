#!/usr/bin/env python3
"""Build an unsigned, UNRELEASED product candidate from committed public inputs.

This is not the QA builder and cannot convert or install a QA package. The
production profile must be reviewed and committed separately; no default receipt
key, storage origin or minimum backend is invented. No network, signing, host
installation or publication. Release qualification is a separate mandatory step.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "fin3000-printer"
PROFILE = "packaging/linux/production-profile.json"
LANGUAGES = "bg cs da de el en es et fi fr ga hi hr hu it lt lv nl no pl pt ro sk sv tr uk".split()
spec = importlib.util.spec_from_file_location("product_build_primitives", ROOT / "scripts/build-linux-qa.py")
build = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build
spec.loader.exec_module(build)
verify = build.vendor.common
require = verify.require


@dataclass(frozen=True)
class ReceiptKey:
    key_id: str
    public_pem: str


@dataclass(frozen=True)
class ProductionProfile:
    quarantine_origins: tuple[str, ...]
    receipt_keys: tuple[ReceiptKey, ...]
    minimum_backend_commit: str
    minimum_backend_version: str

    def config(self):
        return {"environment": "production", "apiOrigin": "https://api.fin3000.com",
                "appOrigin": "https://app.fin3000.com", "clientId": "fin3000-system-print",
                "audience": "fin3000-printer:production", "quarantineOrigins": list(self.quarantine_origins),
                "receiptKeys": {key.key_id: key.public_pem for key in self.receipt_keys}}


@dataclass(frozen=True)
class BuildInputs:
    directory: Path
    node_release: Path
    image: str


def quarantine_origin(value):
    require(isinstance(value, str) and len(value) <= 253, "Invalid quarantine origin")
    url = urlsplit(value)
    host = url.hostname or ""
    require(url.scheme == "https" and value == f"https://{host}" and "." in host
            and re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", host)
            and not host.endswith((".test", ".invalid", ".localhost", ".local", ".example", ".example.com", ".example.net", ".example.org"))
            and host not in ("example.com", "example.net", "example.org", "api.fin3000.com", "app.fin3000.com")
            and re.fullmatch(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})", host.rsplit(".", 1)[-1])
            and all(label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
                    for label in host.split(".")), "Quarantine must be an explicit canonical production HTTPS origin")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return value
    raise verify.VerificationError("Quarantine origin must not be an IP literal")


def validate_profile(raw):
    value = json.loads(raw, object_pairs_hook=verify.unique_object)
    require(isinstance(value, dict) and set(value) == {
        "schemaVersion", "environment", "apiOrigin", "appOrigin", "clientId", "audience",
        "quarantineOrigins", "receiptKeys", "minimumBackendCommit", "minimumBackendVersion",
    }, "Production profile fields are missing or unknown")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1,
            "Unsupported production profile schema")
    for name, fixed in (("environment", "production"), ("apiOrigin", "https://api.fin3000.com"),
                        ("appOrigin", "https://app.fin3000.com"), ("clientId", "fin3000-system-print"),
                        ("audience", "fin3000-printer:production")):
        require(value[name] == fixed, "Production identity cannot be overridden")
    minimum = value["minimumBackendCommit"]
    require(isinstance(minimum, str) and re.fullmatch(r"[0-9a-f]{40}", minimum) and minimum != "0" * 40,
            "Exact minimum backend commit required")
    version = value["minimumBackendVersion"]
    require(isinstance(version, str) and verify.VERSION.fullmatch(version) and version != "0.0.0",
            "Explicit minimum backend release version required")
    origins = value["quarantineOrigins"]
    require(isinstance(origins, list) and 1 <= len(origins) <= 4, "Invalid quarantine origin list")
    origins = tuple(quarantine_origin(origin) for origin in origins)
    require(len(set(origins)) == len(origins), "Duplicate quarantine origin")
    receipts = value["receiptKeys"]
    require(isinstance(receipts, dict) and 1 <= len(receipts) <= 4, "Receipt key pins are required")
    keys, unique_der = [], set()
    for key_id, pem in sorted(receipts.items()):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id)
                and not key_id.lower().startswith(("qa-", "test-", "example-")), "Invalid product receipt key ID")
        require(isinstance(pem, str) and len(pem) <= 4096
                and re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n", pem),
                "Only a public Ed25519 receipt key is permitted")
        der = build.command(["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"],
                            input=pem.encode(), capture_output=True).stdout
        require(len(der) == 44 and der[:12].hex() == "302a300506032b6570032100"
                and der not in unique_der, "Receipt pins must be distinct Ed25519 public keys")
        unique_der.add(der)
        keys.append(ReceiptKey(key_id, pem))
    return ProductionProfile(origins, tuple(keys), minimum, version)


def render(relative, original):
    # Product artifacts also have a compiled-in environment boundary: changing
    # a JSON file cannot turn an installed production binary into a QA client.
    if relative == "core/config.ts":
        anchor = "if (!['production', 'qa'].includes(input.environment) ||"
        require(original.count(anchor) == 1, "Production build environment guard source drift")
        return original.replace(anchor, "if (input.environment !== 'production' ||")
    return original


def committed_source(commit, relative, limit=1024 * 1024):
    _, _, raw = verify.regular_file(ROOT / relative, limit, contents=True)
    tracked = build.command(["git", "cat-file", "blob", f"{commit}:{relative}"], cwd=ROOT,
                            capture_output=True).stdout
    require(raw == tracked, "Product input is not byte-identical to the committed source")
    return raw


def check_catalogs(sources):
    catalogs = {Path(path).stem: json.loads(raw, object_pairs_hook=verify.unique_object)
                for path, raw in sources.items() if path.startswith("platforms/linux/locales/")}
    require(sorted(catalogs) == LANGUAGES, "All 26 native language catalogs are required")
    source = catalogs["de"]
    require(isinstance(source, dict) and source, "German source catalog is invalid")
    for catalog in catalogs.values():
        require(isinstance(catalog, dict) and catalog.keys() == source.keys(), "Native language keys differ")
        for key, text in catalog.items():
            require(isinstance(text, str) and text.strip() and isinstance(source[key], str)
                    and sorted(re.findall(r"\{\w+\}", text)) == sorted(re.findall(r"\{\w+\}", source[key])),
                    "Native language text or placeholders are invalid")


def stage(inputs):
    directory = inputs.directory
    require(os.getuid() != 0 and directory.is_absolute() and directory.parent == ROOT / "reports"
            and directory.parent.resolve() == directory.parent
            and re.fullmatch(r"linux-product-build-[A-Za-z0-9_-]+", directory.name)
            and not directory.exists() and not directory.is_symlink(),
            "Use a new private reports/linux-product-build-* directory as an ordinary user")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", inputs.image), "Immutable local builder image required")
    dirty = build.command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                          capture_output=True).stdout
    require(not dirty, "Commit the complete product worktree before packaging")
    commit = build.command(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Exact source commit required")
    epoch = int(build.command(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT, capture_output=True).stdout)
    profile_raw = committed_source(commit, PROFILE, 65536)
    profile = validate_profile(profile_raw)
    package_json = committed_source(commit, "package.json", 65536)
    version = json.loads(package_json, object_pairs_hook=verify.unique_object)["version"]
    require(isinstance(version, str) and verify.VERSION.fullmatch(version), "Invalid committed product version")
    # Authenticate the runtime before parsing its archive or creating output.
    runtime = build.vendor.verify_runtime(inputs.node_release)
    paths = [path.relative_to(ROOT).as_posix() for path in build.source_files()]
    assets = {"fin3000.ppd": f"usr/lib/{PACKAGE}/platforms/linux/fin3000.ppd",
              "com.fin3000.Printer.desktop": "usr/share/applications/com.fin3000.Printer.desktop",
              "com.fin3000.printer.setup.policy": "usr/share/polkit-1/actions/com.fin3000.printer.setup.policy",
              "fin3000-printer.service": f"usr/lib/systemd/user/{PACKAGE}.service"}
    native = ("cups-backend.c", "pdf-validator.c", "launcher.c", "package-gate.h", "no-core.c")
    sources = {relative: committed_source(commit, relative) for relative in paths}
    check_catalogs(sources)
    for name in (*assets, *native):
        relative = f"platforms/linux/{name}"
        sources[relative] = committed_source(commit, relative)
    for relative in ("scripts/build-linux-product.py", "scripts/build-linux-qa.py", "scripts/verify-node-runtime.py",
                     "scripts/verify-linux-release.py", "packaging/linux/Dockerfile.build", "signing/node-release-key.asc",
                     "signing/node-runtime-supplement.json",
                     "packaging/linux/package-lifecycle.py", *build.PROJECT_DOCUMENTS):
        # Match the runtime verifier's bounded supplemental-license input. Its
        # full original notices can exceed the default 1 MiB source-file cap.
        limit = 2 * 1024 * 1024 if relative == "signing/node-runtime-supplement.json" else 1024 * 1024
        sources[relative] = committed_source(commit, relative, limit)
    require(runtime.proof.certificateSha256 == hashlib.sha256(sources["signing/node-release-key.asc"]).hexdigest(),
            "Runtime verification certificate differs from committed build input")
    require(runtime.proof.sourceSupplementSha256 == hashlib.sha256(sources["signing/node-runtime-supplement.json"]).hexdigest(),
            "Runtime source supplement differs from committed build input")
    sources[PROFILE], sources["package.json"] = profile_raw, package_json
    # Validate the compiler guard before writing any package paths.
    render("core/config.ts", sources["core/config.ts"].decode())
    directory.mkdir(mode=0o700)
    tree = directory / "root"; tree.mkdir(mode=0o755)
    owned = f"usr/lib/{PACKAGE}"
    for relative, installed_name in build.PROJECT_DOCUMENTS.items():
        build.put(tree, f"usr/share/doc/{PACKAGE}/{installed_name}", sources[relative])
    for relative in paths:
        build.put(tree, f"{owned}/{relative}", render(relative, sources[relative].decode()).encode(),
                  0o755 if relative == "platforms/linux/setup.py" else 0o644)
    for name in native:
        build.put(directory, f"compile/{name}", sources[f"platforms/linux/{name}"])
    for name, destination in assets.items():
        build.put(tree, destination, sources[f"platforms/linux/{name}"])
    profiles = runpy.run_path(tree / owned / "platforms/linux/apparmor.py")
    build.put(tree, f"etc/apparmor.d/{PACKAGE}",
              (profiles["backend_profile"]() + profiles["validator_profile"]()).encode())
    build.put(tree, f"{owned}/package.json", (json.dumps({"type": "module", "private": True, "version": version}) + "\n").encode())
    build.put(tree, f"{owned}/build-config.json", (json.dumps(profile.config(), sort_keys=True) + "\n").encode())
    build.put(tree, f"{owned}/runtime/bin/node", runtime.node, 0o755)
    build.put(tree, f"usr/share/doc/{PACKAGE}/NODE-LICENSE", runtime.license)
    build.put(tree, f"usr/share/doc/{PACKAGE}/NODE-SOURCE-NOTICES", runtime.source_notices)
    build.put(tree, f"usr/share/doc/{PACKAGE}/{build.vendor.SUPPLEMENT_SOURCE}", runtime.supplemental_source)
    build.put(tree, f"usr/share/doc/{PACKAGE}/runtime-provenance.json", (json.dumps(asdict(runtime.proof), sort_keys=True) + "\n").encode())
    build.put(tree, f"usr/share/doc/{PACKAGE}/README", (
        "Fin3000 Drucker\n\n"
        "Open Fin3000 Drucker from the application menu to set up the printer and connect your account.\n"
        "Print to An Fin3000 senden (Cloud-Upload), then confirm the upload in the app.\n"
        "Only explicitly confirmed PDF print copies are sent to your Fin3000 invoice inbox.\n"
        "If receipt is unclear, check the operation status before printing again.\n"
        "Setup, updates, removal and help: https://fin3000.com/tools/fin3000-drucker/\n"
    ).encode())
    for relative, mode in ((f"etc/{PACKAGE}/installations", 0o755), (f"var/lib/{PACKAGE}/setup", 0o700),
                           ("usr/lib/cups/backend", 0o755), (f"{owned}/bin", 0o755), ("usr/bin", 0o755)):
        build.package_directory(tree, relative, mode)
    build.stage_hooks(tree, sources["packaging/linux/package-lifecycle.py"])
    control = (f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: amd64\nPre-Depends: python3\n"
               "Maintainer: Fin3000 <mail@fin3000.com>\nSection: utils\nPriority: optional\n"
               f"Depends: {build.DEPENDENCIES}\n"
               "Description: Send confirmed PDF print copies to Fin3000\n"
               " Adds a system printer and an app for account connection, explicit upload\n"
               " confirmation and receipt status in the Fin3000 invoice inbox.\n")
    build.put(tree, "DEBIAN/control", control.encode())
    digests = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    inventory = {"status": "UNRELEASED", "package": PACKAGE, "version": version, "buildProfile": "production",
                 "sourceCommit": commit, "sourceFiles": digests, "sourceDateEpoch": epoch,
                 "sourceDigest": hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest(),
                 "profileSha256": hashlib.sha256(profile_raw).hexdigest(),
                 "minimumBackendCommit": profile.minimum_backend_commit,
                 "minimumBackendVersion": profile.minimum_backend_version,
                 "backendReadinessVerified": False, "protocolVersion": 2, "stateSchemaVersion": 1,
                 "platform": "linux", "architecture": "amd64", "ubuntuVersions": ["24.04", "26.04"],
                 "languages": LANGUAGES, "runtime": asdict(runtime.proof), "builderImage": inputs.image,
                 "releaseGates": "OPEN"}
    encoded = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    build.put(tree, f"{owned}/build-manifest.json", encoded)
    build.put(directory, "build-inputs.json", encoded)
    return directory, tree, inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--node-release", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        directory, tree, inventory = stage(BuildInputs(**vars(args)))
        artifact = build.compile_package(directory, tree, inventory, package=PACKAGE)
    except FileNotFoundError as error:
        if error.filename == str(ROOT / PROFILE):
            print(f"FAIL: committed {PROFILE} is missing; no product artifact was created.")
        else:
            print("FAIL: required local build input is missing; no product candidate was completed.")
        return 1
    except (OSError, ValueError, KeyError, TypeError, build.subprocess.SubprocessError):
        print("FAIL: product candidate was not completed; check committed public profile, clean source and verified inputs.")
        return 1
    print(f"UNRELEASED unsigned product candidate; do not distribute or install: {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

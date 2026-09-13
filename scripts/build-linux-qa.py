#!/usr/bin/env python3
"""Build an OFFLINE, unsigned, isolated QA DEB. Not a release/installer publisher.

Source and a supplied public receipt key enter an owned private staging tree.
No signing keys, user credentials, root, network or host installation. Embedded
maintainer scripts execute only when the DEB is installed in QA. Native compilation uses an explicit immutable Ubuntu 24
builder image; the resulting libc baseline also runs on Ubuntu 26.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "fin3000-printer-qa"
spec = importlib.util.spec_from_file_location("qa_node_runtime", ROOT / "scripts/verify-node-runtime.py")
vendor = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = vendor
spec.loader.exec_module(vendor)
AUTH_DEPENDENCIES = "polkitd, pkexec"
PROJECT_DOCUMENTS = {"LICENSE": "copyright", "NOTICE": "NOTICE", "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md"}
DEPENDENCIES = ("libc6 (>= 2.39), libcups2t64, libjson-c5, libssl3t64, gjs (>= 1.80), "
                "gir1.2-gtk-4.0, gir1.2-secret-1, python3, python3-cups, "
                f"cups, cups-filters, apparmor, apparmor-utils, acl, {AUTH_DEPENDENCIES}, "
                "poppler-utils, gnome-keyring, systemd")
REPLACEMENTS = {
    "fin3000-printer.service": "fin3000-printer-qa.service",
    "/usr/lib/fin3000-printer": "/usr/lib/fin3000-printer-qa",
    "/usr/bin/fin3000-printer": "/usr/bin/fin3000-printer-qa",
    "/var/lib/fin3000-printer": "/var/lib/fin3000-printer-qa",
    "/etc/fin3000-printer": "/etc/fin3000-printer-qa",
    "/etc/apparmor.d/fin3000-printer": "/etc/apparmor.d/fin3000-printer-qa",
    "/usr/lib/cups/backend/fin3000": "/usr/lib/cups/backend/fin3000qa",
    "fin3000-printer-backend": "fin3000-printer-qa-backend",
    "fin3000-printer-pdf-validator": "fin3000-printer-qa-pdf-validator",
    "/fin3000-printer/ingest.sock": "/fin3000-printer-qa/ingest.sock",
    '"fin3000-printer", "installations"': '"fin3000-printer-qa", "installations"',
    '"fin3000-printer", "lifecycle"': '"fin3000-printer-qa", "lifecycle"',
    "fin3000:/": "fin3000qa:/",
    "Fin3000-": "Fin3000QA-",
    "com.fin3000.Printer": "com.fin3000.PrinterQA",
    "com.fin3000.printer.setup": "com.fin3000.printer.qa.setup",
    "Fin3000 Printer": "Fin3000 Printer QA (NOT_FOR_PRODUCTION)",
    "const QA_BUILD = false;": "const QA_BUILD = true;",
}
REPLACEMENT_PATTERN = re.compile("|".join(re.escape(value) for value in sorted(REPLACEMENTS, key=len, reverse=True)))


@dataclass(frozen=True)
class BuildInputs:
    directory: Path
    node_release: Path
    image: str
    api_origin: str
    app_origin: str
    quarantine_origin: str
    receipt_public_key: Path
    backend_worktree_base_commit: str
    qa_revision: int = 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def qa_version(revision):
    # Explicit QA-only ordering for real in-place upgrade tests. Never take an
    # arbitrary Debian/product version, infer one from a directory or bump the
    # product release. The same input still gives a reproducible artifact name.
    require(type(revision) is int and 1 <= revision <= 999999,
            "QA revision must be an integer between 1 and 999999")
    return f"0.0.0~qa{revision}"


def local_origin(value):
    url = urlsplit(value)
    require(url.scheme in ("http", "https") and url.hostname == "127.0.0.1" and not url.username
            and not url.password and url.port is not None and 1024 <= url.port <= 65535
            and value == f"{url.scheme}://127.0.0.1:{url.port}", "QA endpoints must be explicit isolated loopback origins")
    return value


def render(relative, text):
    # Namespace installed desktop paths/queues, not the shared wire protocol.
    # Rewriting "Fin3000-" in core/http.ts changes the v2 dispatch header and
    # sends a native token to the Chrome v1 permission boundary instead.
    rendered = text if relative.startswith("core/") else REPLACEMENT_PATTERN.sub(lambda match: REPLACEMENTS[match.group()], text)
    if relative == "platforms/linux/fin3000.ppd":
        # PPD ModelName forbids parentheses; ShortNickName is <=31 bytes.
        rendered = rendered.replace("Fin3000 Printer QA (NOT_FOR_PRODUCTION)", "Fin3000 Printer QA")
    if relative == "core/config.ts":
        anchor = "if (!['production', 'qa'].includes(input.environment) ||"
        require(rendered.count(anchor) == 1, "QA build environment guard source drift")
        rendered = rendered.replace(anchor, "if (input.environment !== 'qa' ||")
    if relative == "platforms/linux/launcher.c":
        # The disposable VM can trust a local fixture CA through its normal
        # root-managed store. Never inherit NODE_OPTIONS, trust arbitrary env
        # paths or turn off TLS verification; production rendering is separate.
        anchor = '"--experimental-strip-types",'
        require(rendered.count(anchor) == 1, "QA runtime trust anchor source drift")
        rendered = rendered.replace(anchor, '"--use-system-ca", ' + anchor)
    return rendered


def read_regular(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "Expected a bounded regular build input")
        value = source.read(maximum + 1)
        require(len(value) == info.st_size, "Build input changed")
        return value


def package_directory(root, relative, mode=0o755):
    require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "Unsafe package path")
    # The artifact container is private; only descendants are package paths.
    if not Path(relative).parts:
        return root
    path = root
    for part in Path(relative).parts:
        path = path / part
        path.mkdir(mode=0o755, exist_ok=True)
        require(path.is_dir() and not path.is_symlink(), "Unexpected package path")
        path.chmod(0o755)
    path.chmod(mode)
    return path


def put(root, relative, value, mode=0o644):
    path = root / relative
    require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "Unsafe package path")
    package_directory(root, Path(relative).parent)
    with path.open("xb") as output:
        output.write(value)
    path.chmod(mode)
    return path


def command(arguments, **kwargs):
    kwargs.setdefault("env", {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
    return subprocess.run(arguments, check=True, timeout=180, **kwargs)


def local_docker():
    context = json.loads(command(["docker", "context", "inspect", "default"], capture_output=True).stdout)
    require(isinstance(context, list) and len(context) == 1
            and context[0].get("Endpoints", {}).get("docker", {}).get("Host") == "unix:///var/run/docker.sock",
            "Build requires the local default Docker socket")
    return ["docker", "--context", "default"]


def source_files():
    files = sorted([*ROOT.glob("core/*.ts"), *ROOT.glob("platforms/linux/*.ts"),
                    *ROOT.glob("platforms/linux/*.js"), *ROOT.glob("platforms/linux/*.py"),
                    *ROOT.glob("platforms/linux/locales/*.json")])
    require(files and all(path.is_file() and not path.is_symlink() for path in files), "Invalid source graph")
    return files


def stage(inputs):
    version = qa_version(inputs.qa_revision)
    directory = inputs.directory.absolute()
    require(os.getuid() != 0 and directory.parent.resolve() == (ROOT / "reports").resolve()
            and directory.parent == ROOT / "reports" and re.fullmatch(r"linux-qa-build-[a-zA-Z0-9_-]+", directory.name),
            "Build only as an ordinary user in a new reports/linux-qa-build-* directory")
    require(not directory.exists() and not directory.is_symlink(), "Never overwrite build artifacts")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", inputs.image), "Builder must be an immutable local image ID")
    require(re.fullmatch(r"[0-9a-f]{40}", inputs.backend_worktree_base_commit), "Exact backend worktree base commit required")
    for origin in (inputs.api_origin, inputs.app_origin, inputs.quarantine_origin):
        local_origin(origin)
    runtime = vendor.verify_runtime(inputs.node_release)
    key = read_regular(inputs.receipt_public_key, 4096)
    require(b"PRIVATE" not in key and re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n", key),
            "Only a public receipt key enters the package")
    # OpenSSL, not a custom key parser. Ed25519 SPKI has a fixed 12-byte prefix.
    der = command(["/usr/bin/openssl", "pkey", "-pubin", "-outform", "DER"], input=key, capture_output=True).stdout
    require(len(der) == 44 and der[:12].hex() == "302a300506032b6570032100", "Receipt key must be Ed25519")
    commit = command(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True).stdout.strip()
    epoch = int(command(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True, capture_output=True).stdout.strip())
    directory.mkdir(mode=0o700)
    tree = directory / "root"; tree.mkdir(mode=0o755)
    package_root = f"usr/lib/{PACKAGE}"
    source_digests = {}
    for relative, installed_name in PROJECT_DOCUMENTS.items():
        original = read_regular(ROOT / relative, 1024 * 1024)
        source_digests[relative] = hashlib.sha256(original).hexdigest()
        put(tree, f"usr/share/doc/{PACKAGE}/{installed_name}", original)
    for path in source_files():
        relative = path.relative_to(ROOT).as_posix()
        original = read_regular(path, 1024 * 1024)
        source_digests[relative] = hashlib.sha256(original).hexdigest()
        content = render(relative, original.decode()).encode()
        put(tree, f"{package_root}/{relative}", content, 0o755 if path.name == "setup.py" else 0o644)
    for name in ("cups-backend.c", "pdf-validator.c", "launcher.c", "package-gate.h", "no-core.c"):
        relative = f"platforms/linux/{name}"
        original = read_regular(ROOT / relative, 1024 * 1024)
        source_digests[relative] = hashlib.sha256(original).hexdigest()
        put(directory, f"compile/{name}", render(relative, original.decode()).encode())
    for name, destination in (
        ("fin3000.ppd", f"{package_root}/platforms/linux/fin3000.ppd"),
        ("com.fin3000.Printer.desktop", "usr/share/applications/com.fin3000.PrinterQA.desktop"),
        ("com.fin3000.printer.setup.policy", "usr/share/polkit-1/actions/com.fin3000.printer.qa.setup.policy"),
        ("fin3000-printer.service", f"usr/lib/systemd/user/{PACKAGE}.service"),
    ):
        relative = f"platforms/linux/{name}"
        original = read_regular(ROOT / relative, 1024 * 1024)
        source_digests[relative] = hashlib.sha256(original).hexdigest()
        put(tree, destination, render(relative, original.decode()).encode())
    profiles = runpy.run_path(tree / package_root / "platforms/linux/apparmor.py")
    put(tree, f"etc/apparmor.d/{PACKAGE}", (profiles["backend_profile"]() + profiles["validator_profile"]()).encode())
    put(tree, f"{package_root}/package.json", b'{"type":"module","private":true}\n')
    config = {"environment": "qa", "apiOrigin": inputs.api_origin, "appOrigin": inputs.app_origin,
              "quarantineOrigins": [inputs.quarantine_origin], "clientId": "fin3000-system-print-qa",
              "audience": "fin3000-printer:qa", "receiptKeys": {"qa-ephemeral": key.decode()}}
    put(tree, f"{package_root}/build-config.json", (json.dumps(config, sort_keys=True) + "\n").encode())
    put(tree, f"{package_root}/runtime/bin/node", runtime.node, 0o755)
    put(tree, f"usr/share/doc/{PACKAGE}/NODE-LICENSE", runtime.license)
    put(tree, f"usr/share/doc/{PACKAGE}/NODE-SOURCE-NOTICES", runtime.source_notices)
    put(tree, f"usr/share/doc/{PACKAGE}/{vendor.SUPPLEMENT_SOURCE}", runtime.supplemental_source)
    source_digests["signing/node-runtime-supplement.json"] = runtime.proof.sourceSupplementSha256
    put(tree, f"usr/share/doc/{PACKAGE}/runtime-provenance.json",
        (json.dumps(asdict(runtime.proof), indent=2) + "\n").encode())
    put(tree, f"usr/share/doc/{PACKAGE}/README", b"NOT_FOR_PRODUCTION\nUnsigned local native QA only. No release, APT bootstrap, update or uninstall approval.\n")
    for relative, mode in ((f"etc/{PACKAGE}/installations", 0o755), (f"var/lib/{PACKAGE}/setup", 0o700),
                           ("usr/lib/cups/backend", 0o755), (f"{package_root}/bin", 0o755), ("usr/bin", 0o755)):
        package_directory(tree, relative, mode)
    hooks = read_regular(ROOT / "packaging/linux/package-lifecycle.py", 65536)
    source_digests["packaging/linux/package-lifecycle.py"] = hashlib.sha256(hooks).hexdigest()
    stage_hooks(tree, render("packaging/linux/package-lifecycle.py", hooks.decode()).encode())
    control = (f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: amd64\nMaintainer: Fin3000 <mail@fin3000.com>\nPre-Depends: python3\n"
               f"Depends: {DEPENDENCIES}\nSection: utils\nPriority: optional\n"
               "Description: Fin3000 native printer - ISOLATED QA ONLY\n NOT_FOR_PRODUCTION. No public distribution or lifecycle release approval.\n")
    put(tree, "DEBIAN/control", control.encode())
    inventory = {"status": "NOT_FOR_PRODUCTION", "sourceCommit": commit, "sourceFiles": source_digests,
                 "sourceDigest": hashlib.sha256(json.dumps(source_digests, sort_keys=True).encode()).hexdigest(),
                 "backendWorktreeBaseCommit": inputs.backend_worktree_base_commit,
                 "minimumBackendCommit": None, "protocolVersion": 2, "stateSchemaVersion": 1,
                 "runtime": asdict(runtime.proof),
                 "builderImage": inputs.image, "languages": sorted(path.stem for path in ROOT.glob("platforms/linux/locales/*.json")),
                 "releaseGates": "OPEN", "package": PACKAGE, "version": version, "sourceDateEpoch": epoch}
    put(tree, f"{package_root}/build-manifest.json", (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode())
    put(directory, "build-inputs.json", (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode())
    return directory, tree, inventory


def stage_hooks(tree, source):
    for role in ("preinst", "postinst", "prerm", "postrm"):
        trailer = (f"\nif __name__ == '__main__':\n    try:\n        run_hook('{role}', sys.argv[1:])\n"
                   "    except Exception:\n        print('Fin3000: package exchange paused; complete or repair the package installation.', file=sys.stderr)\n        sys.exit(1)\n")
        put(tree, f"DEBIAN/{role}", source + trailer.encode(), 0o755)


def payload_inventory(tree, package):
    files = {}
    for path in sorted(tree.rglob("*")):
        relative = path.relative_to(tree).as_posix()
        if relative.startswith("DEBIAN/") or path.is_dir():
            continue
        require(not path.is_symlink() and path.is_file(), "Unsafe payload entry")
        with path.open("rb") as stream:
            files[f"/{relative}"] = hashlib.file_digest(stream, "sha256").hexdigest()
    put(tree, f"usr/lib/{package}/package-files.json", (json.dumps(files, sort_keys=True) + "\n").encode())


def set_installed_size(tree):
    """Debian Policy 5.6.20: per-file KiB rounding, excluding DEBIAN metadata.

    Called only on our private staged payload after native compilation. Package
    symlinks and special files remain forbidden by the existing build boundary.
    This estimate is not compressed download size or dependency disk usage.
    """
    require(tree.is_dir() and not tree.is_symlink(), "Expected private package root")
    size = 0
    for path in tree.rglob("*"):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "Unexpected special file or symlink in package")
        if path.relative_to(tree).parts[0] != "DEBIAN":
            size += (info.st_size + 1023) // 1024 if stat.S_ISREG(info.st_mode) else 1
    control = tree / "DEBIAN/control"
    raw = read_regular(control, 65536)
    anchor = b"\nArchitecture: amd64\n"
    require(raw.count(anchor) == 1 and b"Installed-Size:" not in raw and size > 0,
            "Installed size needs a fresh control file and nonempty payload")
    updated = raw.replace(anchor, anchor + f"Installed-Size: {size}\n".encode())
    fd = os.open(control, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "wb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Expected regular control file")
        stream.write(updated)
        stream.truncate()
    return size


def runtime_component_evidence(directory, tree, inventory, container):
    """Collect runtime facts in the existing offline build sandbox, not a SBOM.

    ABI numbers and build flags are retained separately from dependencies. This
    self-report omits some embedded source fragments and never grants licenses
    or asserts complete composition. Reconcile it with authenticated sources.
    """
    package = inventory["package"]
    require(package in (PACKAGE, "fin3000-printer"), "Unknown runtime package")
    binary = f"usr/lib/{package}/runtime/bin/node"
    runtime = inventory["runtime"]
    for relative, expected, limit in (
        (binary, runtime["sha256"], 150 * 1024 * 1024),
        (f"usr/share/doc/{package}/NODE-LICENSE", runtime["licenseSha256"], 4 * 1024 * 1024),
        (f"usr/share/doc/{package}/NODE-SOURCE-NOTICES", runtime["sourceNoticesSha256"], vendor.MAX_NOTICES),
        (f"usr/share/doc/{package}/{vendor.SUPPLEMENT_SOURCE}", runtime["supplementalSourceSha256"], 1024 * 1024),
    ):
        raw = read_regular(tree / relative, limit)
        require(hashlib.sha256(raw).hexdigest() == expected,
                "Staged runtime or license differs from authenticated input")
    expression = "process.stdout.write(JSON.stringify({platform:process.platform,arch:process.arch,versions:process.versions,variables:process.config.variables}))"
    raw = command([*container, f"/build/root/{binary}", "--input-type=commonjs",
                   "--eval", expression], capture_output=True).stdout
    require(0 < len(raw) <= 128 * 1024, "Runtime component report exceeds bounds")
    facts = json.loads(raw, object_pairs_hook=vendor.common.unique_object)
    require(isinstance(facts, dict) and set(facts) == {"platform", "arch", "versions", "variables"}
            and facts["platform"] == "linux" and facts["arch"] == "x64"
            and isinstance(facts["versions"], dict) and isinstance(facts["variables"], dict),
            "Unexpected runtime component report")
    versions = facts["versions"]
    require(versions.get("node") == runtime["version"] and len(versions) <= 128
            and all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
                    and isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9.+_-]{1,128}", value)
                    for name, value in versions.items()), "Runtime version evidence is invalid")
    report = {"schemaVersion": 1, "status": "INVENTORY_EVIDENCE_NOT_COMPLETE_SBOM",
              "sourceCommit": inventory["sourceCommit"], "builderImage": inventory["builderImage"],
              "runtimeProvenance": runtime, "runtimeFacts": facts}
    # Build-side evidence only. Does not change installed runtime configuration.
    put(directory, "runtime-components.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())


def compile_package(directory, tree, inventory, *, package=PACKAGE):
    # Two fixed namespaces share compilation, never a CLI-selected package or
    # an in-place conversion of an existing QA artifact into a product release.
    require(package in (PACKAGE, "fin3000-printer") and inventory["package"] == package,
            "Unknown or inconsistent native package identity")
    status = "NOT_FOR_PRODUCTION" if package == PACKAGE else "UNRELEASED"
    require(inventory["status"] == status, "Compilation cannot grant release approval")
    backend = "fin3000qa" if package == PACKAGE else "fin3000"
    # No full-repo/home/credential mount. One already-staged, own artifact tree.
    container = [*local_docker(), "run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--user", f"{os.getuid()}:{os.getgid()}",
                 "--mount", f"type=bind,source={directory},target=/build", "--workdir", "/build",
                 inventory["builderImage"]]
    flags = ["/usr/bin/gcc", "-std=c11", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,-z,relro,-z,now"]
    for source, destination, libs, mode in (
        ("cups-backend.c", f"usr/lib/cups/backend/{backend}", ["-lcups", "-ljson-c", "-lcrypto"], 0o700),
        ("pdf-validator.c", f"usr/lib/{package}/bin/pdf-validator", [], 0o755),
        ("launcher.c", f"usr/bin/{package}", [], 0o755),
        ("no-core.c", f"usr/lib/{package}/bin/no-core.so", ["-shared", "-fPIC"], 0o644),
    ):
        command([*container, *flags, f"compile/{source}", *libs, "-o", f"root/{destination}"])
        (tree / destination).chmod(mode)
    # Capture exact package versions without treating them as a complete SBOM.
    toolchain = command([*container, "/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n"], capture_output=True).stdout
    put(directory, "build-toolchain.tsv", toolchain)
    runtime_component_evidence(directory, tree, inventory, container)
    payload_inventory(tree, package)
    set_installed_size(tree)
    for path in sorted(tree.rglob("*"), reverse=True):
        require(not path.is_symlink(), "Unexpected package symlink")
        os.utime(path, (inventory["sourceDateEpoch"], inventory["sourceDateEpoch"]))
    os.utime(tree, (inventory["sourceDateEpoch"], inventory["sourceDateEpoch"]))
    filename = f"{package}_{inventory['version']}_amd64.deb"
    command([*container, "/usr/bin/env", f"SOURCE_DATE_EPOCH={inventory['sourceDateEpoch']}",
             "/usr/bin/dpkg-deb", "--build", "--root-owner-group", "-Zxz", "root", filename])
    artifact = directory / filename
    with artifact.open("rb") as package:
        digest = hashlib.file_digest(package, "sha256").hexdigest()
    put(directory, "artifact.json", (json.dumps({"status": status, "file": filename,
         "sha256": digest, "size": artifact.stat().st_size, "signed": False}, indent=2) + "\n").encode())
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--node-release", type=Path, required=True,
                        help="Official pinned Node archive, checksums and detached signature directory")
    parser.add_argument("--image", required=True)
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--app-origin", required=True)
    parser.add_argument("--quarantine-origin", required=True)
    parser.add_argument("--receipt-public-key", type=Path, required=True)
    parser.add_argument("--backend-worktree-base-commit", required=True)
    parser.add_argument("--qa-revision", type=int, default=1,
                        help="Isolated package revision (1–999999) for native in-place upgrade tests; never a product version")
    args = parser.parse_args()
    directory, tree, inventory = stage(BuildInputs(**vars(args)))
    artifact = compile_package(directory, tree, inventory)
    print(f"Unsigned isolated QA artifact, NOT_FOR_PRODUCTION: {artifact}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build a local, UNRELEASED bootstrap candidate. No signing/install/publication.

Only the public release certificate is used. A separately reviewed release must
bind this package, the printer, SBOM and APT archive before any distribution.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/linux/bootstrap"
PACKAGE = "fin3000-printer-setup"


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


build = module("bootstrap_build_primitives", "build-linux-qa.py")
verify = module("bootstrap_certificate_policy", "verify-linux-release.py")


def committed_source(commit, relative, limit=1024 * 1024):
    raw = build.read_regular(ROOT / relative, limit)
    tracked = build.command(["git", "cat-file", "blob", f"{commit}:{relative}"], cwd=ROOT,
                            capture_output=True).stdout
    build.require(raw == tracked, "Bootstrap input is not byte-identical to the committed source")
    return raw


def archive_keyring(public):
    with tempfile.TemporaryDirectory(prefix="fin3000-bootstrap-public-") as temporary:
        # Isolated, public-only keyring. No operator configuration, private
        # key, passphrase, trustdb, network key discovery or signing operation.
        arguments = ["/usr/bin/gpg", "--no-options", "--homedir", temporary, "--batch", "--no-auto-key-retrieve"]
        subprocess.run([*arguments, "--import"], input=public, check=True, capture_output=True, timeout=30)
        records = subprocess.run([*arguments, "--with-colons", "--fixed-list-mode", "--list-keys"],
                                 check=True, capture_output=True, timeout=30).stdout.decode()
        verify.validate_certificate(records, verify.PRODUCTION, int(time.time()))
        return subprocess.run([*arguments, "--export", verify.PRODUCTION.primary],
                              check=True, capture_output=True, timeout=30).stdout


def stage(directory, image):
    build.require(os.getuid() != 0 and directory.is_absolute()
                  and directory.parent == ROOT / "reports"
                  and directory.parent.resolve() == directory.parent
                  and re.fullmatch(r"linux-bootstrap-build-[A-Za-z0-9_-]+", directory.name)
                  and not directory.exists() and not directory.is_symlink(),
                  "Use a new private reports/linux-bootstrap-build-* directory as an ordinary user")
    build.require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "Immutable local builder image required")
    dirty = build.command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                          capture_output=True).stdout
    build.require(not dirty, "Commit the complete bootstrap worktree before packaging")
    commit = build.command(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.decode().strip()
    build.require(re.fullmatch(r"[0-9a-f]{40}", commit), "Exact source commit required")
    epoch = int(build.command(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT, capture_output=True).stdout)
    catalogs = build.command(["git", "ls-tree", "-r", "--name-only", commit, "--", "platforms/linux/locales"],
                             cwd=ROOT, capture_output=True).stdout.decode().splitlines()
    build.require(catalogs and all(re.fullmatch(r"platforms/linux/locales/[a-z]{2}\.json", path)
                                  for path in catalogs), "Invalid committed language catalog paths")
    paths = [*build.PROJECT_DOCUMENTS, "package.json", "signing/linux-release-key.asc",
             "scripts/build-linux-bootstrap.py", "scripts/build-linux-qa.py", "scripts/verify-node-runtime.py",
             "scripts/verify-linux-release.py", "packaging/linux/Dockerfile.build", "platforms/linux/i18n.js",
             *catalogs, *(f"packaging/linux/bootstrap/{name}" for name in
                          ("install.py", "app.js", "fin3000-printer.sources", "fin3000-printer.pref",
                           "com.fin3000.PrinterSetup.desktop", "com.fin3000.printer.install.policy"))]
    # Snapshot every source before writing package paths or exporting the public
    # certificate. Later edits cannot change the bytes attributed to this commit.
    sources = {relative: committed_source(commit, relative) for relative in paths}
    version = json.loads(sources["package.json"], object_pairs_hook=verify.unique_object)["version"]
    build.require(isinstance(version, str) and verify.VERSION.fullmatch(version), "Invalid source version")
    key = archive_keyring(sources["signing/linux-release-key.asc"])
    build.require(key, "Empty archive certificate")
    directory.mkdir(mode=0o700)
    tree = directory / "root"; tree.mkdir(mode=0o755)
    owned = f"usr/lib/{PACKAGE}"
    inputs = {relative: hashlib.sha256(raw).hexdigest() for relative, raw in sources.items()}

    def copy(source, destination, mode=0o644):
        raw = sources[source.relative_to(ROOT).as_posix()]
        return build.put(tree, destination, raw, mode)

    for relative, installed_name in build.PROJECT_DOCUMENTS.items():
        copy(ROOT / relative, f"usr/share/doc/{PACKAGE}/{installed_name}")
    for name in ("install.py", "app.js", "fin3000-printer.sources", "fin3000-printer.pref"):
        copy(SOURCE / name, f"{owned}/{name}", 0o755 if name == "install.py" else 0o644)
    copy(ROOT / "platforms/linux/i18n.js", f"{owned}/i18n.js")
    for relative in catalogs:
        copy(ROOT / relative, f"{owned}/locales/{Path(relative).name}")
    copy(SOURCE / "com.fin3000.PrinterSetup.desktop", "usr/share/applications/com.fin3000.PrinterSetup.desktop")
    copy(SOURCE / "com.fin3000.printer.install.policy", "usr/share/polkit-1/actions/com.fin3000.printer.install.policy")
    copy(SOURCE / "fin3000-printer.sources", "etc/apt/sources.list.d/fin3000-printer.sources")
    copy(SOURCE / "fin3000-printer.pref", "etc/apt/preferences.d/fin3000-printer.pref")
    build.put(tree, "usr/share/keyrings/fin3000-printer-archive-keyring.gpg", key)
    build.put(tree, f"{owned}/archive-keyring.sha256", (hashlib.sha256(key).hexdigest() + "\n").encode())
    build.put(tree, f"usr/share/doc/{PACKAGE}/README", (
        "Fin3000 Drucker Setup\n\n"
        "Open Fin3000 Drucker Setup from the application menu to install or update the printer.\n"
        "Ubuntu asks for administrator authentication when installing packages.\n"
        "The initial setup download relies on HTTPS from fin3000.com. Subsequent printer\n"
        "installation and updates use the signed Fin3000 APT repository.\n"
        "Setup and help: https://fin3000.com/tools/fin3000-drucker/\n"
    ).encode())
    build.put(tree, "DEBIAN/conffiles", b"/etc/apt/sources.list.d/fin3000-printer.sources\n/etc/apt/preferences.d/fin3000-printer.pref\n")
    control = (f"Package: {PACKAGE}\nVersion: {version}\nArchitecture: amd64\n"
               "Maintainer: Fin3000 <mail@fin3000.com>\nSection: utils\nPriority: optional\n"
               f"Depends: apt (>= 2.8), ca-certificates, python3, python3-apt, gjs (>= 1.80), gir1.2-gtk-4.0, {build.AUTH_DEPENDENCIES}\n"
               "Description: Graphical setup and updates for Fin3000 Drucker\n"
               " Installs the Fin3000 printer through its signed APT repository.\n"
               " Includes the archive verification key and graphical setup assistant.\n")
    build.put(tree, "DEBIAN/control", control.encode())
    inventory = {"status": "UNRELEASED", "package": PACKAGE, "version": version, "sourceCommit": commit,
                 "sourceFiles": inputs, "builderImage": image, "sourceDateEpoch": epoch,
                 "archivePrimary": verify.PRODUCTION.primary, "archiveSigner": verify.PRODUCTION.signer,
                 "keyringSha256": hashlib.sha256(key).hexdigest(),
                 "releaseGates": "OPEN", "initialTrust": "HTTPS_WEB_PKI_NOT_DETACHED_SIGNATURE"}
    build.put(tree, f"usr/share/doc/{PACKAGE}/build-manifest.json", (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())
    build.put(directory, "build-inputs.json", (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())
    return tree, inventory


def compile_package(directory, tree, inventory):
    build.set_installed_size(tree)
    for path in sorted(tree.rglob("*"), reverse=True):
        build.require(not path.is_symlink(), "Unexpected package symlink")
        os.utime(path, (inventory["sourceDateEpoch"], inventory["sourceDateEpoch"]))
    os.utime(tree, (inventory["sourceDateEpoch"], inventory["sourceDateEpoch"]))
    filename = f"{PACKAGE}_{inventory['version']}_amd64.deb"
    build.command([*build.local_docker(), "run", "--rm", "--pull=never", "--network", "none", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--read-only",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--mount", f"type=bind,source={directory},target=/build", "--workdir", "/build",
                   inventory["builderImage"], "/usr/bin/env", f"SOURCE_DATE_EPOCH={inventory['sourceDateEpoch']}",
                   "/usr/bin/dpkg-deb", "--build", "--root-owner-group", "-Zxz", "root", filename])
    artifact = directory / filename
    size, digest, _ = verify.regular_file(artifact, 4 * 1024 * 1024)
    build.put(directory, "artifact.json", (json.dumps({"file": filename, "size": size, "sha256": digest,
              "signed": False, "status": "UNRELEASED"}, sort_keys=True, indent=2) + "\n").encode())
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    tree, inventory = stage(args.directory, args.image)
    artifact = compile_package(args.directory, tree, inventory)
    print(f"UNRELEASED local packaging candidate; do not distribute or install: {artifact}")


if __name__ == "__main__":
    main()

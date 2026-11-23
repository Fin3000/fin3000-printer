#!/usr/bin/env python3
"""Build an Apple Silicon installer on macOS from the pinned runtime and this checkout."""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "platforms/macos"
spec = importlib.util.spec_from_file_location("node_runtime", ROOT / "scripts/verify-node-runtime.py")
vendor = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = vendor
spec.loader.exec_module(vendor)
ARCHIVE = f"node-v{vendor.PINNED.version}-darwin-arm64.tar.xz"
DIGEST = "d0c68c321161bb2c6483efea9a343010dea8e5e7f60d73c6a7eba140016d662f"


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def put(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    path.chmod(mode)


def install_runtime(archive_path, resources):
    if archive_path.name != ARCHIVE:
        raise ValueError("Wrong Node archive name.")
    _, digest, archive = vendor.common.regular_file(archive_path, vendor.MAX_ARCHIVE, contents=True)
    if digest != DIGEST:
        raise ValueError("Wrong Node archive SHA-256.")
    node, license_text = vendor.archive_payload(archive, ARCHIVE.removesuffix(".tar.xz"), platform="darwin-arm64")
    material = vendor.verify_source_material(archive_path.parent, license_text)
    licenses = resources / "licenses"
    put(resources / "node", node, 0o755)
    put(licenses / "NODE-LICENSE", license_text)
    put(licenses / "NODE-SOURCE-NOTICES", material.notices)
    put(licenses / vendor.SUPPLEMENT_SOURCE, material.supplement.source)


def build(args):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Build on an Apple Silicon Mac.")
    qa = args.profile == "qa"
    if not qa and (
        args.config or args.qa_ca or not re.fullmatch(r"[A-Z0-9]{10}", args.team or "")
    ):
        raise ValueError(
            "Production requires the approved Team ID and the checked-in public configuration."
        )
    if not qa and not args.installer_identity:
        raise ValueError("Developer ID Installer certificate required.")
    if not qa and not args.app_identity:
        raise ValueError("Developer ID Application certificate required.")
    if qa and (
        not args.config or args.team or args.app_identity or args.installer_identity
    ):
        raise ValueError(
            "Use a separate loopback configuration and ad-hoc identities for QA."
        )
    config = json.loads(
        (
            args.config if qa else ROOT / "packaging/linux/production-profile.json"
        ).read_text()
    )
    if config["environment"] != args.profile or config["clientId"] != (
        "fin3000-system-print-qa" if qa else "fin3000-system-print"
    ):
        raise ValueError("Configuration profile mismatch.")
    if qa and not all(
        re.fullmatch(r"https?://127\.0\.0\.1:[1-9]\d{0,4}", origin)
        for origin in [
            config["appOrigin"],
            config["apiOrigin"],
            *config["quarantineOrigins"],
        ]
    ):
        raise ValueError("QA is confined to loopback.")
    version = json.loads((ROOT / "package.json").read_text())["version"]
    vendor = "Fin3000QA" if qa else "Fin3000"
    service = "com.fin3000.printer" + (".qa" if qa else "")
    name = "Fin3000 Drucker" + (" QA" if qa else "")
    display = "An Fin3000 senden (Cloud-Upload)" + (" · QA" if qa else "")
    output = args.output.resolve()
    if output.exists() or not output.parent.is_dir():
        raise ValueError("Use a new output directory under an existing parent.")
    with tempfile.TemporaryDirectory(prefix="mac-print-build-", dir=output.parent) as temp:
        work = Path(temp)
        payload = work / "root"
        app = payload / "Applications" / (name + ".app")
        contents = app / "Contents"
        res = contents / "Resources"
        binary = contents / "MacOS/Fin3000"
        native = payload / "Library/Printers" / vendor
        for d in [res, binary.parent, native / "users"]:
            d.mkdir(parents=True)
            d.chmod(0o755)
        node = res / "node"
        install_runtime(args.archive, res)
        for f in ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"]:
            shutil.copyfile(ROOT / f, res / "licenses" / f)
        run(
            node,
            ROOT / "node_modules/typescript/bin/tsc",
            "-p",
            ROOT / "tsconfig.json",
            "--noEmit",
            "false",
            "--rewriteRelativeImportExtensions",
            "true",
            "--outDir",
            res,
        )
        shutil.rmtree(res / "platforms/linux")
        put(res / "package.json", '{"type":"module"}\n')
        put(res / "config.json", json.dumps(config))
        if args.qa_ca:
            shutil.copyfile(args.qa_ca, res / "qa-ca.crt")
        shutil.copytree(ROOT / "platforms/linux/locales", res / "locales")
        put(
            contents / "Info.plist",
            plistlib.dumps(
                {
                    "CFBundleName": name,
                    "CFBundleDisplayName": name,
                    "CFBundlePackageType": "APPL",
                    "CFBundleIdentifier": service,
                    "CFBundleExecutable": "Fin3000",
                    "CFBundleVersion": version,
                    "CFBundleShortVersionString": version,
                    "LSMinimumSystemVersion": "26.0",
                    "LSUIElement": True,
                    "NSHighResolutionCapable": True,
                }
            ),
        )
        flags = [
            "xcrun",
            "clang",
            "-arch",
            "arm64",
            "-mmacosx-version-min=26.0",
            "-fobjc-arc",
            "-fblocks",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wno-unused-parameter",
            "-Wno-deprecated-declarations",
            "-Wno-incompatible-pointer-types",
        ]
        if qa:
            flags.append("-DFIN3000_QA")
        common = [
            MAC / "native.m",
            "-framework",
            "Foundation",
            "-framework",
            "Security",
            "-framework",
            "CoreGraphics",
            "-lcups",
        ]
        run(*flags, MAC / "App.m", *common, "-framework", "AppKit", "-o", binary)
        run(*flags, MAC / "filter.m", *common, "-o", native / "pdf-filter")
        run(*flags, MAC / "relay.m", *common, "-o", native / "relay")
        ppd = (ROOT / "platforms/linux/fin3000.ppd").read_text()
        assert ppd.count("0 gziptoany") == 1
        put(
            native / "Fin3000.ppd",
            ppd.replace("0 gziptoany", f"0 /Library/Printers/{vendor}/pdf-filter"),
        )
        setup = (
            (MAC / "setup.sh")
            .read_text()
            .replace("@VENDOR@", vendor)
            .replace("@SERVICE@", service)
            .replace("@DISPLAY@", display)
        )
        put(native / "setup.sh", setup, 0o755)
        scripts = work / "scripts"
        # macOS clears /var/tmp at its discretion. Recreate the trusted parent at install.
        parent = "/private/var/tmp/" + service
        put(
            scripts / "postinstall",
            f"""#!/bin/sh
set -eu
p='{parent}'
if [ -e "$p" ] || [ -L "$p" ]; then
  [ -d "$p" ] && [ ! -L "$p" ] && [ "$(/usr/bin/stat -f %u:%Lp "$p")" = '0:755' ] || exit 1
else
  /bin/mkdir -m 0755 "$p"
fi
""",
            0o755,
        )
        plist = work / "node-entitlements.plist"
        put(plist, plistlib.dumps({"com.apple.security.cs.allow-jit": True}))
        sign = [
            "/usr/bin/codesign",
            "--force",
            "--options",
            "runtime",
            "--timestamp=none" if qa else "--timestamp",
            "--sign",
            "-" if qa else args.app_identity,
        ]
        run(*sign, "--entitlements", plist, node)
        run(*sign, "--identifier", service + ".filter", native / "pdf-filter")
        run(*sign, "--identifier", service + ".relay", native / "relay")
        run(*sign, app)
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)
        run("/usr/bin/codesign", "--verify", "--strict", native / "pdf-filter")
        if not qa:
            for obj in [app, node, native / "pdf-filter", native / "relay"]:
                signature = run(
                    "/usr/bin/codesign",
                    "-dv",
                    "--verbose=4",
                    obj,
                    capture_output=True,
                    text=True,
                ).stderr
                if (
                    ("TeamIdentifier=" + args.team + "\n") not in signature
                    or "Authority=Developer ID Application:" not in signature
                ):
                    raise ValueError("Unexpected Developer ID Application identity")
        spec = work / "components.plist"
        put(
            spec,
            plistlib.dumps(
                [
                    {
                        "RootRelativeBundlePath": "Applications/" + name + ".app",
                        "BundleIsRelocatable": False,
                        "BundleIsVersionChecked": True,
                        "BundleHasStrictIdentifier": True,
                        "BundleOverwriteAction": "upgrade",
                    }
                ]
            ),
        )
        pkgid = service + ".installer"
        part = work / "payload.pkg"
        run(
            "/usr/bin/pkgbuild",
            "--root",
            payload,
            "--ownership",
            "recommended",
            "--component-plist",
            spec,
            "--identifier",
            pkgid,
            "--version",
            version,
            "--install-location",
            "/",
            "--scripts",
            scripts,
            part,
        )
        dist = ET.Element("installer-gui-script", {"minSpecVersion": "2"})
        ET.SubElement(dist, "title").text = name
        ET.SubElement(
            dist,
            "options",
            {
                "hostArchitectures": "arm64",
                "customize": "never",
                "require-scripts": "false",
            },
        )
        oscheck = ET.SubElement(
            ET.SubElement(dist, "volume-check"), "allowed-os-versions"
        )
        ET.SubElement(oscheck, "os-version", {"min": "26.0", "before": "27.0"})
        ET.SubElement(
            ET.SubElement(dist, "choices-outline"), "line", {"choice": "product"}
        )
        ET.SubElement(
            ET.SubElement(dist, "choice", {"id": "product", "visible": "false"}),
            "pkg-ref",
            {"id": pkgid},
        )
        ET.SubElement(
            dist, "pkg-ref", {"id": pkgid, "version": version}
        ).text = "#payload.pkg"
        xml = work / "Distribution.xml"
        ET.ElementTree(dist).write(xml, encoding="UTF-8", xml_declaration=True)
        target = output / f"fin3000-printer{'-qa' if qa else ''}_{version}_arm64.pkg"
        run(
            "/usr/bin/productbuild",
            "--distribution",
            xml,
            "--package-path",
            work,
            *([] if qa else ["--sign", args.installer_identity, "--timestamp"]),
            work / target.name,
        )
        output.mkdir()
        (work / target.name).rename(target)
    print(target)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", required=True, choices=["qa", "production"])
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--archive", required=True, type=Path)
    p.add_argument("--config", type=Path)
    p.add_argument("--qa-ca", type=Path)
    p.add_argument("--team")
    p.add_argument("--app-identity")
    p.add_argument("--installer-identity")
    build(p.parse_args())

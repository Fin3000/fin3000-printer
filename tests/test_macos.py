"""Exercise Mac runtime packaging and the native state adapter."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mac_builder", ROOT / "scripts/build-macos.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

spec = importlib.util.spec_from_file_location("mac_signer", ROOT / "scripts/macos_installer_fingerprint.py")
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


class MacInstallerSignatureTests(unittest.TestCase):
    team = "A123456789"
    octets = [f"{value:02X}" for value in range(32)]

    def report(self, leaf):
        return (
            "   Certificate Chain:\n"
            f"    1. Developer ID Installer: Example GmbH ({self.team})\n"
            f"       Expires: 2027-12-22 19:39:44 +0000\n{leaf}"
            "    2. Developer ID Certification Authority\n"
            "       SHA256 Fingerprint:\n           " + " FF" * 32 + "\n"
        )

    def test_leaf_fingerprint_spans_two_lines(self):
        leaf = "       SHA256 Fingerprint:\n           " + " ".join(self.octets[:22]) + " \n"
        leaf += "           " + " ".join(self.octets[22:]) + "\n       " + "-" * 72 + "\n"
        self.assertEqual(signer.installer_fingerprint(self.report(leaf), self.team), bytes(range(32)).hex())

    def test_issuer_cannot_supply_a_missing_or_invalid_leaf_fingerprint(self):
        for leaf in ["", "11 " * 31, "11 " * 31 + "ZZ", "11 " * 33]:
            with self.subTest(leaf=leaf), self.assertRaisesRegex(ValueError, "fingerprint"):
                signer.installer_fingerprint(self.report("       SHA256 Fingerprint:\n" + leaf + "\n"), self.team)

    def test_first_certificate_must_be_an_installer_from_the_requested_team(self):
        report = self.report("       SHA256 Fingerprint:\n" + "11 " * 32 + "\n")
        for actual in [report.replace(self.team, "B123456789"), report.replace("ID Installer:", "ID Application:")]:
            with self.subTest(actual=actual), self.assertRaisesRegex(ValueError, "first certificate"):
                signer.installer_fingerprint(actual, self.team)


class MacRuntimeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="fin3000-mac-runtime-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.archive = root / builder.ARCHIVE
        self.resources = root / "Resources"
        self.node = bytes.fromhex("cf fa ed fe 0c 00 00 01") + b"SYNTHETIC"
        self.license = b"Node.js MIT synthetic license"
        with tarfile.open(self.archive, "w:xz") as bundle:
            for path, content in [("bin/node", self.node), ("LICENSE", self.license)]:
                member = tarfile.TarInfo(builder.ARCHIVE.removesuffix(".tar.xz") + "/" + path)
                member.size = len(content)
                bundle.addfile(member, io.BytesIO(content))
        digest = patch.object(builder, "DIGEST", hashlib.sha256(self.archive.read_bytes()).hexdigest())
        digest.start()
        self.addCleanup(digest.stop)

    def test_runtime_includes_verified_notices_and_unchanged_source(self):
        source = b"synthetic corresponding source"
        supplement = builder.vendor.VerifiedSupplement(b"extra", 1, source, hashlib.sha256(source).hexdigest())
        material = builder.vendor.VerifiedSourceMaterial(b"combined notices", 5, 100, supplement)
        with patch.object(builder.vendor, "verify_source_material", return_value=material) as verify:
            builder.install_runtime(self.archive, self.resources)
        verify.assert_called_once_with(self.archive.parent, self.license)
        licenses = self.resources / "licenses"
        self.assertEqual((licenses / "NODE-LICENSE").read_bytes(), self.license)
        self.assertEqual((licenses / "NODE-SOURCE-NOTICES").read_bytes(), material.notices)
        self.assertEqual((licenses / "vendor-source/smartstring-1.0.1.crate").read_bytes(), source)
        self.assertEqual((self.resources / "node").read_bytes(), self.node)
        self.assertEqual((self.resources / "node").stat().st_mode & 0o777, 0o755)

    def test_tampered_source_prevents_installing_runtime(self):
        (self.archive.parent / f"node-v{builder.vendor.PINNED.version}.tar.xz").write_bytes(b"wrong source")
        with self.assertRaisesRegex(ValueError, "Source archive digest"):
            builder.install_runtime(self.archive, self.resources)
        self.assertFalse(self.resources.exists())


@unittest.skipUnless(
    platform.system() == "Darwin", "Requires macOS and Xcode Command Line Tools"
)
class MacStateTests(unittest.TestCase):
    def test_durable_state_roundtrip_and_file_ownership(self):
        with tempfile.TemporaryDirectory(prefix="fin3000-mac-test-") as directory:
            where = Path(directory)
            (where / "state.m").write_text("""
#import "native.h"
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 2) return 1;
        int dir = open(argv[1], O_RDONLY|O_DIRECTORY);
        NSError *err = nil;
        if (dir < 0 || F3LoadState(dir, &err) || err) return 2;
        NSData *first = [@"first" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *second = [@"second" dataUsingEncoding:NSUTF8StringEncoding];
        if (!F3SaveState(dir, first) || ![F3LoadState(dir, &err) isEqual:first]) return 3;
        if (!F3SaveState(dir, second) || ![F3LoadState(dir, &err) isEqual:second]) return 4;
        if (renameat(dir, "state.json", dir, "private") || symlinkat("private", dir, "state.json")) return 5;
        if (F3LoadState(dir, &err) || err == nil) return 6;
        close(dir); return 0;
    }
}
""")
            binary = where / "state-test"
            subprocess.run(
                [
                    "xcrun",
                    "clang",
                    "-fobjc-arc",
                    "-Wno-deprecated-declarations",
                    "-I",
                    ROOT / "platforms/macos",
                    where / "state.m",
                    ROOT / "platforms/macos/native.m",
                    "-framework",
                    "Foundation",
                    "-framework",
                    "Security",
                    "-lcups",
                    "-o",
                    binary,
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run([binary, where], check=True)
            self.assertEqual(os.stat(where / "private").st_mode & 0o777, 0o600)

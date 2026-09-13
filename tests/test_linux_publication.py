"""Publication generation with real disposable signatures, never live writes."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


publication = load("linux_publication", "scripts/prepare-linux-publication.py")
fixtures = load("publication_archive_fixtures", "tests/test_linux_archive.py")


class PublicationTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.ArchiveTests.setUpClass.__func__)
    run_gpg = classmethod(fixtures.ArchiveTests.run_gpg.__func__)
    add_artifact = fixtures.ArchiveTests.add_artifact
    sign_manifest = fixtures.ArchiveTests.sign_manifest
    sign_index = fixtures.ArchiveTests.sign_index
    apt_update = fixtures.ArchiveTests.apt_update

    def setUp(self):
        fixtures.ArchiveTests.setUp(self)
        self.source = fixtures.archive.stage(self.bundle, self.output, self.certificate, policy=self.policy, now=self.now)
        self.sign_index(self.source)
        self.destination = self.root / "reports/linux-publication-synthetic"
        root_patch = patch.object(publication, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def prepare(self, **kwargs):
        return publication.prepare(self.bundle, self.source, self.destination, self.certificate,
                                   policy=self.policy, now=self.now, **kwargs)

    def test_complete_generation_binds_bundle_and_all_public_files(self):
        output = self.prepare()
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((output / "active.json").read_text()), {"version": "0.1.0"})
        marker = json.loads((output / "apt/publication.json").read_text())
        bundle_marker = json.loads((output / "0.1.0/publication.json").read_text())
        self.assertEqual(marker["releaseManifestSha256"], bundle_marker["manifestSha256"])
        self.assertEqual(marker["issuedAt"], self.manifest["issuedAt"])
        self.assertEqual(marker["expiresAt"], self.manifest["expiresAt"])
        self.assertEqual(len(marker["files"]), 7)
        for name, expected in marker["files"].items():
            body = (output / "apt" / name).read_bytes()
            self.assertEqual(publication.metadata(body), expected)
        self.assertFalse((output / "apt/dists/stable/Release").exists())
        result = self.apt_update(output / "apt")
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode()[-2500:])
        self.assertEqual((self.root / "isolated-apt/state/status").read_bytes(), b"")

    def test_never_overwrites_existing_generation(self):
        self.prepare()
        before = (self.destination / "active.json").read_bytes()
        with self.assertRaises(publication.verify.VerificationError):
            self.prepare()
        self.assertEqual((self.destination / "active.json").read_bytes(), before)

    def test_tampered_bundle_and_archive_never_get_active_marker(self):
        paths = [self.bundle / "release.json", self.source / publication.INRELEASE,
                 self.source / (publication.INDEX + "Packages"),
                 self.source / (publication.INDEX + "Packages.gz"),
                 self.source / "pool/main/fin3000-printer_0.1.0_amd64.deb"]
        original_destination = self.destination
        for index, path in enumerate(paths):
            with self.subTest(path=path.name):
                self.destination = original_destination.with_name(f"linux-publication-tampered-{index}")
                original = path.read_bytes()
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                try:
                    with self.assertRaises((publication.verify.VerificationError, ValueError)):
                        self.prepare()
                    self.assertFalse((self.destination / "active.json").exists())
                finally:
                    path.write_bytes(original)

    def test_unsigned_release_file_is_not_an_authority(self):
        (self.source / "dists/stable/Release").write_text("UNTRUSTED SIDECAR")
        self.prepare()
        self.assertTrue((self.destination / "active.json").exists())

    def test_valid_signature_over_different_archive_contract_is_rejected(self):
        release = self.source / "dists/stable/Release"
        release.write_bytes(release.read_bytes().replace(b"Origin: Fin3000", b"Origin: Different"))
        self.sign_index(self.source)
        with self.assertRaisesRegex(publication.verify.VerificationError, "metadata disagrees"):
            self.prepare()
        self.assertFalse((self.destination / "active.json").exists())

    def test_inrelease_requires_single_complete_message(self):
        target = self.source / publication.INRELEASE
        original = target.read_bytes()
        for index, value in enumerate((original + original, b"PREFIX\n" + original, original + b"TRAILER\n")):
            with self.subTest(index=index):
                self.destination = self.root / f"reports/linux-publication-messages-{index}"
                target.write_bytes(value)
                with self.assertRaisesRegex(publication.verify.VerificationError, "complete InRelease"):
                    self.prepare()
                self.assertFalse((self.destination / "active.json").exists())

    def test_previous_immutable_files_are_retained_not_old_stable_metadata(self):
        previous = self.prepare()
        marker_path = previous / "apt/publication.json"
        marker = json.loads(marker_path.read_text())
        old_index = b"SYNTHETIC PREVIOUS INDEX"
        old = {"pool/main/fin3000-printer_0.0.9_amd64.deb": b"SYNTHETIC OLD PACKAGE",
               publication.INDEX + "by-hash/SHA256/" + hashlib.sha256(old_index).hexdigest(): old_index}
        for name, body in old.items():
            (previous / "apt" / name).write_bytes(body)
            marker["files"][name] = publication.metadata(body)
        marker_path.write_text(json.dumps(marker))
        (previous / "apt" / publication.INRELEASE).write_bytes(b"STALE CURRENT INDEX MUST NOT BE USED")
        self.destination = self.root / "reports/linux-publication-successor"
        output = self.prepare(previous=previous)
        for name, body in old.items():
            self.assertEqual((output / "apt" / name).read_bytes(), body)
        self.assertEqual((output / "apt" / publication.INRELEASE).read_bytes(), (self.source / publication.INRELEASE).read_bytes())

    def test_immutable_path_collision_is_rejected(self):
        previous = self.prepare()
        marker = previous / "apt/publication.json"
        value = json.loads(marker.read_text())
        value["files"]["pool/main/fin3000-printer_0.1.0_amd64.deb"]["sha256"] = "f" * 64
        marker.write_text(json.dumps(value))
        self.destination = self.root / "reports/linux-publication-conflict"
        with self.assertRaisesRegex(publication.verify.VerificationError, "collision"):
            self.prepare(previous=previous)
        self.assertFalse((self.destination / "active.json").exists())

    def test_symlink_archive_component_is_rejected(self):
        original = self.source / "dists"
        original.rename(self.source / "real-dists")
        original.symlink_to(self.source / "real-dists")
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.destination / "active.json").exists())

    def test_signed_expired_or_future_index_is_rejected(self):
        packages = (self.source / (publication.INDEX + "Packages")).read_bytes()
        compressed = (self.source / (publication.INDEX + "Packages.gz")).read_bytes()
        indexes = {"main/binary-amd64/Packages": packages, "main/binary-amd64/Packages.gz": compressed}
        for number, (issued, expires) in enumerate(((self.now - 7200, self.now - 3600),
                                                   (self.now + 600, self.now + 1800))):
            with self.subTest(issued=issued):
                self.destination = self.root / f"reports/linux-publication-date-{number}"
                (self.source / "dists/stable/Release").write_bytes(publication.archive.release_file(indexes, issued, expires))
                self.sign_index(self.source)
                with self.assertRaisesRegex(publication.verify.VerificationError, "validity rejected"):
                    self.prepare()
                self.assertFalse((self.destination / "active.json").exists())

    def test_retained_bytes_are_rehashed_and_symlinks_rejected(self):
        previous = self.prepare()
        name = "pool/main/fin3000-printer_0.0.9_amd64.deb"
        marker_path = previous / "apt/publication.json"
        marker = json.loads(marker_path.read_text())
        marker["files"][name] = publication.metadata(b"OLD FIXTURE")
        marker_path.write_text(json.dumps(marker))
        path = previous / "apt" / name
        path.write_bytes(b"BAD FIXTURE")
        self.destination = self.root / "reports/linux-publication-old-tampered"
        with self.assertRaisesRegex(publication.verify.VerificationError, "hash mismatch"):
            self.prepare(previous=previous)
        self.assertFalse((self.destination / "active.json").exists())
        path.unlink()
        path.symlink_to(previous / "apt/pool/main/fin3000-printer_0.1.0_amd64.deb")
        self.destination = self.root / "reports/linux-publication-old-symlink"
        with self.assertRaises(OSError):
            self.prepare(previous=previous)
        self.assertFalse((self.destination / "active.json").exists())

    def test_previous_duplicate_fields_and_content_address_mismatch_are_rejected(self):
        previous = self.prepare()
        marker_path = previous / "apt/publication.json"
        marker = json.loads(marker_path.read_text())
        marker_path.write_text('{"schemaVersion":1,' + json.dumps(marker)[1:])
        self.destination = self.root / "reports/linux-publication-duplicate"
        with self.assertRaises(publication.verify.VerificationError):
            self.prepare(previous=previous)
        self.assertFalse((self.destination / "active.json").exists())
        marker["files"][publication.INDEX + "by-hash/SHA256/" + "f" * 64] = publication.metadata(b"INDEX")
        marker_path.write_text(json.dumps(marker))
        self.destination = self.root / "reports/linux-publication-address"
        with self.assertRaisesRegex(publication.verify.VerificationError, "content address"):
            self.prepare(previous=previous)
        self.assertFalse((self.destination / "active.json").exists())

    def test_cli_has_no_trust_clock_or_qa_override(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/prepare-linux-publication.py"), "--help"],
                                capture_output=True, check=True, timeout=10)
        for flag in (b"--policy", b"--signer", b"--certificate", b"--now", b"--qa", b"--url"):
            self.assertNotIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()

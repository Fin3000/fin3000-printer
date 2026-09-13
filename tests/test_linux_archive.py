"""Real signed disposable APT archive; no host configuration or installation."""
from datetime import datetime, timezone
from email.utils import format_datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


archive = load("linux_archive_builder", ROOT / "scripts/build-linux-archive.py")
release_test = load("archive_synthetic_keys", ROOT / "tests/test_linux_release.py")


class ArchiveTests(unittest.TestCase):
    # Reuse only the disposable signing identity fixture, not its test cases.
    setUpClass = classmethod(release_test.ReleaseTest.setUpClass.__func__)
    run_gpg = classmethod(release_test.ReleaseTest.run_gpg.__func__)

    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="fin3000-apt-qa-")
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name)
        self.bundle = self.root / "bundle"; self.bundle.mkdir()
        (self.root / "reports").mkdir()
        self.output = self.root / "reports/linux-archive-build-synthetic"
        self.certificate = self.root / "synthetic.asc"; self.certificate.write_bytes(self.public)
        self.now = int(time.time())
        stamp = lambda value: datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.manifest = {"schemaVersion": 2, "product": "fin3000-printer", "version": "0.1.0",
            "channel": "qa", "platform": "linux", "architecture": "amd64", "ubuntuVersions": ["24.04", "26.04"],
            "sourceCommit": "1" * 40, "buildId": "SYNTHETIC_ONLY", "minimumBackendVersion": "0.1.0",
            "issuedAt": stamp(self.now), "expiresAt": stamp(self.now + 3600), "artifacts": {}}
        for kind, package in (("deb", "fin3000-printer"), ("setup", "fin3000-printer-setup")):
            tree = self.root / package
            (tree / "DEBIAN").mkdir(parents=True)
            (tree / "DEBIAN/control").write_text(f"Package: {package}\nVersion: 0.1.0\nArchitecture: amd64\n"
                "Maintainer: SYNTHETIC ONLY <qa@example.invalid>\nDescription: SYNTHETIC APT TEST ONLY\n")
            filename = f"{package}_0.1.0_amd64.deb"
            subprocess.run(["/usr/bin/dpkg-deb", "--build", "--root-owner-group", "-Zgzip", str(tree), str(self.bundle / filename)],
                           check=True, capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.add_artifact(kind, filename)
        filename = "fin3000-printer_0.1.0.cdx.json"
        (self.bundle / filename).write_text(json.dumps(release_test.synthetic_sbom(self.manifest)))
        self.add_artifact("sbom", filename)
        self.sign_manifest()
        self.patch = patch.object(archive, "ROOT", self.root); self.patch.start()
        self.addCleanup(self.patch.stop)

    def add_artifact(self, kind, filename):
        value = (self.bundle / filename).read_bytes()
        self.manifest["artifacts"][kind] = {"file": filename, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}

    def sign_manifest(self):
        (self.bundle / "release.json").write_text(json.dumps(self.manifest))
        self.run_gpg(["--yes", "--local-user", self.signer + "!", "--digest-algo", "SHA256", "--armor", "--detach-sign",
                      str(self.bundle / "release.json")])

    def stage(self):
        return archive.stage(self.bundle, self.output, self.certificate, policy=self.policy, now=self.now)

    def sign_index(self, target):
        self.run_gpg(["--yes", "--local-user", self.signer + "!", "--digest-algo", "SHA256", "--output",
                      str(target / "dists/stable/InRelease"), "--clearsign", str(target / "dists/stable/Release")])

    def apt_update(self, target, *, signer=None):
        state = self.root / "isolated-apt"
        for name in ("etc", "state/lists/partial", "cache/archives/partial", "log"):
            (state / name).mkdir(parents=True, exist_ok=True)
        (state / "state/status").write_text("")
        (state / "etc/source.sources").write_text(f"Types: deb\nURIs: {target.as_uri()}\nSuites: stable\n"
            f"Components: main\nArchitectures: amd64\nSigned-By: {self.certificate} {signer or self.signer}!\n"
            "Check-Valid-Until: yes\nCheck-Date: yes\nInRelease-Path: InRelease\nBy-Hash: force\n")
        configuration = state / "apt.conf"
        configuration.write_text(f'''Dir "{state}";
Dir::Etc "{state}/etc";
Dir::Etc::main "-";
Dir::Etc::parts "-";
Dir::Etc::sourcelist "{state}/etc/source.sources";
Dir::Etc::sourceparts "-";
Dir::Etc::trusted "-";
Dir::Etc::trustedparts "-";
Dir::Etc::preferences "-";
Dir::Etc::preferencesparts "-";
Dir::State "{state}/state";
Dir::State::status "{state}/state/status";
Dir::Cache "{state}/cache";
Dir::Log "{state}/log";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Sandbox::User "{os.getuid()}";
Acquire::Languages "none";
APT::Update::Error-Mode "any";
''')
        return subprocess.run(["/usr/bin/apt-get", "update"], check=False, capture_output=True, timeout=30,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(configuration)})

    def test_signed_bundle_stages_exact_two_packages_and_content_addressed_indexes(self):
        target = self.stage()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertFalse((target / "dists/stable/InRelease").exists())
        raw = (target / "dists/stable/main/binary-amd64/Packages").read_bytes()
        self.assertEqual(raw.count(b"\nFilename: pool/main/"), 2)
        self.assertIn(b"Package: fin3000-printer-setup\n", raw)
        by_hash = target / "dists/stable/main/binary-amd64/by-hash/SHA256" / hashlib.sha256(raw).hexdigest()
        self.assertEqual(by_hash.read_bytes(), raw)
        self.assertIn(b"Acquire-By-Hash: yes", (target / "dists/stable/Release").read_bytes())
        with self.assertRaises(archive.verify.VerificationError):
            self.stage()

    def test_actual_apt_accepts_correct_synthetic_subkey_and_indexes_without_install(self):
        target = self.stage(); self.sign_index(target)
        result = self.apt_update(target)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode()[-4000:])
        self.assertTrue(list((self.root / "isolated-apt/state/lists").glob("*Packages*")))
        self.assertEqual((self.root / "isolated-apt/state/status").read_bytes(), b"")

    def test_actual_apt_rejects_wrong_signer(self):
        target = self.stage(); self.sign_index(target)
        result = self.apt_update(target, signer="A" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"signature", result.stderr.lower())

    def test_actual_apt_rejects_expired_release_even_with_correct_signature(self):
        target = self.stage()
        path = target / "dists/stable/Release"
        raw = path.read_text()
        lines = raw.splitlines()
        for number, line in enumerate(lines):
            if line.startswith(("Date:", "Valid-Until:")):
                field = line.split(":", 1)[0]
                epoch = self.now - (86400 if field == "Valid-Until" else 2 * 86400)
                lines[number] = f"{field}: {format_datetime(datetime.fromtimestamp(epoch, timezone.utc), usegmt=True)}"
        path.write_text("\n".join(lines) + "\n")
        self.sign_index(target)
        result = self.apt_update(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"expired", result.stderr.lower())

    def test_actual_apt_rejects_unsigned_and_tampered_index(self):
        target = self.stage()
        result = self.apt_update(target)
        self.assertNotEqual(result.returncode, 0)
        self.sign_index(target)
        path = target / "dists/stable/InRelease"
        path.write_bytes(path.read_bytes().replace(b"Origin: Fin3000", b"Origin: Attacker"))
        result = self.apt_update(target)
        self.assertNotEqual(result.returncode, 0)

    def test_actual_apt_rejects_modified_packages_after_valid_index_signature(self):
        target = self.stage(); self.sign_index(target)
        indexes = target / "dists/stable/main/binary-amd64"
        for path in indexes.rglob("*"):
            if path.is_file():
                path.write_bytes(b"X" * path.stat().st_size)
        result = self.apt_update(target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Hash Sum mismatch", result.stdout + result.stderr)

    def test_signed_hash_does_not_allow_package_name_to_disagree_with_manifest(self):
        source = self.bundle / "fin3000-printer-setup_0.1.0_amd64.deb"
        target = self.bundle / "fin3000-printer_0.1.0_amd64.deb"
        target.write_bytes(source.read_bytes())
        self.add_artifact("deb", target.name)
        sbom = self.bundle / self.manifest["artifacts"]["sbom"]["file"]
        sbom.write_text(json.dumps(release_test.synthetic_sbom(self.manifest)))
        self.add_artifact("sbom", sbom.name)
        self.sign_manifest()
        with self.assertRaisesRegex(archive.verify.VerificationError, "identity disagrees"):
            self.stage()

    def test_modified_source_after_initial_verification_never_gets_trusted(self):
        original = archive.snapshot_artifact
        mutated = False

        def mutate(source, target, artifact):
            nonlocal mutated
            if not mutated:
                source.write_bytes(b"MUTATED"); mutated = True
            original(source, target, artifact)

        with patch.object(archive, "snapshot_artifact", side_effect=mutate), \
                self.assertRaisesRegex(archive.verify.VerificationError, "Artifact changed"):
            self.stage()
        self.assertFalse((self.output / "apt").exists())

    def test_cli_has_no_qa_signer_clock_or_url_override(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/build-linux-archive.py"), "--help"],
                                capture_output=True, check=True, timeout=10)
        for flag in (b"--policy", b"--signer", b"--now", b"--url", b"--qa"):
            self.assertNotIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main()

"""Real signatures with disposable synthetic identities, never production secrets."""

from datetime import datetime, timezone
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


SPEC = importlib.util.spec_from_file_location(
    "linux_release", Path(__file__).resolve().parents[1] / "scripts/verify-linux-release.py")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


def synthetic_sbom(manifest):
    """Structurally realistic only; not a product inventory or license grant."""
    def component(name, reference, version, kind="application", artifact=None):
        result = {"type": kind, "bom-ref": reference, "name": name, "version": version,
                  "licenses": [{"license": {"name": "SYNTHETIC ONLY - NOT FOR DISTRIBUTION"}}]}
        if artifact:
            result["hashes"] = [{"alg": "SHA-256", "content": manifest["artifacts"][artifact]["sha256"]}]
        return result

    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": component("fin3000-printer", "printer", manifest["version"], artifact="deb"),
                         "properties": [{"name": "fin3000:source-commit", "value": manifest["sourceCommit"]},
                                        {"name": "fin3000:build-id", "value": manifest["buildId"]}]},
            "components": [component("fin3000-printer-setup", "setup", manifest["version"], artifact="setup"),
                           component("node", "runtime", "22.23.2"),
                           component("synthetic-dependency", "dependency", "1.0", "library")],
            "dependencies": [{"ref": "printer", "dependsOn": ["setup", "runtime"]},
                             {"ref": "setup", "dependsOn": []},
                             {"ref": "runtime", "dependsOn": ["dependency"]},
                             {"ref": "dependency", "dependsOn": []}],
            "compositions": [{"aggregate": "complete", "assemblies": ["printer"]}]}


class ReleaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="fin3000-synthetic-release-key-")
        cls.addClassCleanup(cls.keys.cleanup)
        cls.addClassCleanup(subprocess.run, ["/usr/bin/gpgconf", "--homedir", cls.keys.name,
                            "--kill", "gpg-agent"], check=True, timeout=10, capture_output=True)
        cls.gpg = ["/usr/bin/gpg", "--no-options", "--homedir", cls.keys.name,
                   "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        cls.run_gpg(["--quick-generate-key", "SYNTHETIC TEST ONLY", "ed25519", "cert", "1d"])
        listing = cls.run_gpg(["--with-colons", "--list-keys"]).stdout.decode()
        cls.primary = next(line.split(":")[9] for line in listing.splitlines()
                           if line.startswith("fpr:"))
        cls.run_gpg(["--quick-add-key", cls.primary, "ed25519", "sign", "1d"])
        listing = cls.run_gpg(["--with-colons", "--list-keys"]).stdout.decode()
        cls.signer = [line.split(":")[9] for line in listing.splitlines()
                      if line.startswith("fpr:")][-1]
        cls.policy = release.TrustPolicy(cls.primary, cls.signer, "qa")
        cls.public = cls.run_gpg(["--armor", "--export", cls.primary]).stdout

    @classmethod
    def run_gpg(cls, args):
        return subprocess.run(cls.gpg + args, capture_output=True, timeout=30, check=True,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def setUp(self):
        self.bundle = tempfile.TemporaryDirectory(prefix="fin3000-synthetic-bundle-")
        self.addCleanup(self.bundle.cleanup)
        self.directory = Path(self.bundle.name)
        self.certificate = self.directory / "test-certificate.asc"
        self.certificate.write_bytes(self.public)
        self.now = int(time.time())
        self.manifest = {
            "schemaVersion": 2, "product": "fin3000-printer", "version": "0.1.0",
            "channel": "qa", "platform": "linux", "architecture": "amd64",
            "ubuntuVersions": ["24.04", "26.04"], "sourceCommit": "1" * 40,
            "buildId": "synthetic-only", "minimumBackendVersion": "0.1.0",
            "issuedAt": self.stamp(self.now), "expiresAt": self.stamp(self.now + 3600),
            "artifacts": {},
        }
        for kind, filename in (("deb", "fin3000-printer_0.1.0_amd64.deb"),
                               ("setup", "fin3000-printer-setup_0.1.0_amd64.deb"),
                               ("sbom", "fin3000-printer_0.1.0.cdx.json")):
            content = f"SYNTHETIC {kind}: NOT INSTALLABLE".encode()
            if kind == "sbom":
                content = json.dumps(synthetic_sbom(self.manifest)).encode()
            (self.directory / filename).write_bytes(content)
            self.manifest["artifacts"][kind] = {
                "file": filename, "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        self.sign()

    @staticmethod
    def stamp(epoch):
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self):
        (self.directory / "release.json").write_text(json.dumps(self.manifest))
        self.run_gpg(["--yes", "--local-user", self.signer + "!", "--digest-algo", "SHA256",
                      "--armor", "--detach-sign", str(self.directory / "release.json")])

    def verify(self):
        return release.verify_release(self.directory, self.certificate,
                                      policy=self.policy, now=self.now)

    def test_valid_signature_and_exact_artifacts(self):
        self.assertEqual(self.verify()["version"], "0.1.0")

    def replace_sbom(self, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        artifact = self.manifest["artifacts"]["sbom"]
        (self.directory / artifact["file"]).write_bytes(raw)
        artifact.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        self.sign()

    def test_signed_placeholder_is_not_a_release_sbom(self):
        for raw in (b"SYNTHETIC SBOM", b"{}", b"[]", b"null",
                    b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}'):
            with self.subTest(raw=raw):
                self.replace_sbom(raw)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_sbom_is_bound_to_both_packages_and_source_build(self):
        for change in (
            lambda b: b.update(specVersion="1.5"),
            lambda b: b.update(version=True),
            lambda b: b["metadata"]["component"].update(name="other-product"),
            lambda b: b["metadata"]["component"].update(version="0.2.0"),
            lambda b: b["metadata"]["component"]["hashes"][0].update(content="0" * 64),
            lambda b: b["components"][0]["hashes"][0].update(content="0" * 64),
            lambda b: b["metadata"]["properties"][0].update(value="2" * 40),
            lambda b: b["metadata"]["properties"][1].update(value="other-build"),
            lambda b: b["metadata"]["properties"].append(b["metadata"]["properties"][0]),
        ):
            value = synthetic_sbom(self.manifest)
            change(value)
            self.replace_sbom(value)
            with self.assertRaises(release.VerificationError):
                self.verify()

    def test_incomplete_license_and_dependency_inventory_rejected(self):
        for change in (
            lambda b: b.update(components=[]),
            lambda b: b["components"][1].update(name="something-not-node"),
            lambda b: b["components"][1].update(licenses=[]),
            lambda b: b["components"][1].update(licenses=[{"license": {"id": "NOASSERTION"}}]),
            lambda b: b["components"][1].update(version=""),
            lambda b: b["components"].append(b["components"][0]),
            lambda b: b["dependencies"][0].update(dependsOn=["runtime"]),
            lambda b: b["dependencies"][2].update(dependsOn=[]),
            lambda b: b["dependencies"][2].update(dependsOn=["missing"]),
            lambda b: b["dependencies"][2].update(dependsOn=["dependency", "dependency"]),
            lambda b: b["dependencies"].pop(),
            lambda b: b["compositions"][0].update(aggregate="incomplete"),
            lambda b: b["compositions"][0].update(assemblies=["missing"]),
        ):
            value = synthetic_sbom(self.manifest)
            change(value)
            self.replace_sbom(value)
            with self.assertRaises(release.VerificationError):
                self.verify()

    def test_sbom_bounds_and_malformed_values_fail_closed(self):
        cases = [
            ("metadata", None), ("components", "not-a-list"), ("components", [None] * 3),
            ("components", [{}] * 513), ("dependencies", None), ("compositions", []),
        ]
        for field, value in cases:
            with self.subTest(field=field, value_type=type(value).__name__):
                bom = synthetic_sbom(self.manifest)
                bom[field] = value
                with self.assertRaises(release.VerificationError):
                    release.validate_sbom(json.dumps(bom), self.manifest)
        for field, value in (("bom-ref", []), ("version", None), ("name", "x\n"),
                             ("name", "x" * 513), ("licenses", [None]),
                             ("licenses", [{"license": {"id": "MIT", "name": "ambiguous"}}])):
            with self.subTest(field=field):
                bom = synthetic_sbom(self.manifest)
                bom["components"][1][field] = value
                with self.assertRaises(release.VerificationError):
                    release.validate_sbom(json.dumps(bom), self.manifest)

    def test_sbom_urls_are_data_not_fetch_instructions(self):
        bom = synthetic_sbom(self.manifest)
        bom["components"][1]["externalReferences"] = [{"type": "website", "url": "https://never-fetch.invalid"}]
        with patch.object(release, "command", side_effect=AssertionError("SBOM must not execute commands")):
            release.validate_sbom(json.dumps(bom), self.manifest)

    def test_qa_identity_cannot_authorize_production(self):
        self.manifest["channel"] = "production"
        self.sign()
        with self.assertRaisesRegex(release.VerificationError, "identity is not pinned"):
            release.verify_release(self.directory, self.certificate, now=self.now)

    def test_tampered_signed_manifest(self):
        self.manifest["buildId"] = "tampered"
        (self.directory / "release.json").write_text(json.dumps(self.manifest))
        with self.assertRaises(release.VerificationError):
            self.verify()

    def test_invalid_detached_signature_and_missing_artifact(self):
        signature = self.directory / 'release.json.asc'
        original = signature.read_bytes()
        signature.write_bytes(b'not a signature')
        with self.assertRaises(release.VerificationError):
            self.verify()
        signature.write_bytes(original)
        (self.directory / self.manifest['artifacts']['deb']['file']).unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_second_real_signature_is_not_accepted(self):
        signature = self.directory / 'release.json.asc'
        signature.write_bytes(signature.read_bytes() * 2)
        with self.assertRaises(release.VerificationError):
            self.verify()

    def test_subprocess_discards_untrusted_stderr_and_has_no_ambient_environment(self):
        result = subprocess.CompletedProcess([], 0, b'ok', None)
        with patch.object(release.subprocess, 'run', return_value=result) as run:
            self.assertIs(release.command(['/usr/bin/gpg', '--version']), result)
        self.assertIs(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

    def test_production_public_certificate_matches_hardcoded_policy(self):
        # Public bytes only; do not access or unlock the production private home.
        certificate = Path(SPEC.origin).parent.parent / 'signing/linux-release-key.asc'
        result = self.run_gpg(['--with-colons', '--import-options', 'show-only',
                               '--import', str(certificate)])
        release.validate_certificate(result.stdout.decode(), release.PRODUCTION, self.now)

    def test_corrupted_package_and_sbom(self):
        for kind in ("deb", "setup", "sbom"):
            with self.subTest(kind=kind):
                path = self.directory / self.manifest["artifacts"][kind]["file"]
                original = path.read_bytes()
                path.write_bytes(original.replace(b"SYNTHETIC", b"TAMPERED!"))
                with self.assertRaises(release.VerificationError):
                    self.verify()
                path.write_bytes(original)

    def test_manifest_schema_rejections(self):
        cases = (("schemaVersion", True), ("schemaVersion", 1), ("channel", "production"),
                 ("architecture", "arm64"), ("version", "0.1.0\n"),
                 ("version", "00.1.0"), ("minimumBackendVersion", "anything"),
                 ("sourceCommit", "main"), ("ubuntuVersions", ["24.04"]),
                 ("buildId", "../build"), ("issuedAt", self.stamp(self.now + 900)),
                 ("expiresAt", self.stamp(self.now)),
                 ("expiresAt", self.stamp(self.now + release.MAX_VALIDITY + 1)))
        for field, value in cases:
            with self.subTest(field=field):
                data = dict(self.manifest, **{field: value})
                with self.assertRaises(release.VerificationError):
                    release.validate_manifest(json.dumps(data), self.policy, self.now)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(release.VerificationError):
            release.validate_manifest('{"schemaVersion":1,"schemaVersion":1}',
                                      self.policy, self.now)

    def test_path_traversal_and_oversize_rejected(self):
        for field, value in (("file", "../outside.deb"), ("size", True),
                             ("size", release.MAX_PACKAGE + 1), ("sha256", "abc")):
            with self.subTest(field=field):
                data = json.loads(json.dumps(self.manifest))
                data["artifacts"]["deb"][field] = value
                with self.assertRaises(release.VerificationError):
                    release.validate_manifest(json.dumps(data), self.policy, self.now)

    def test_symlink_and_fifo_rejected_without_blocking(self):
        target = self.directory / "special"
        target.symlink_to(self.certificate)
        with self.assertRaises(OSError):
            release.regular_file(target, 65536)
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(release.VerificationError):
            release.regular_file(target, 65536)

    def test_expired_public_key_rejected(self):
        listing = self.run_gpg(["--with-colons", "--list-keys"]).stdout.decode()
        with self.assertRaises(release.VerificationError):
            release.validate_certificate(listing, self.policy, self.now + 2 * 86400)

    def test_revoked_key_status_rejected(self):
        listing = self.run_gpg(["--with-colons", "--list-keys"]).stdout.decode()
        with self.assertRaises(release.VerificationError):
            release.validate_certificate(listing.replace("pub:u:", "pub:r:"),
                                         self.policy, self.now)

    def test_actual_signer_and_status_are_required(self):
        valid = (f"[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {self.signer} 2026-09-09 "
                 f"{self.now} 0 4 0 22 8 00 {self.primary}\n")
        release.validate_signature(valid, self.policy, self.manifest, self.now)
        for invalid in (valid.replace(self.signer, "A" * 40),
                        valid.replace(self.primary, "B" * 40), valid + valid,
                        valid.replace("22 8 00", "22 2 00"),
                        valid + "[GNUPG:] REVKEYSIG ABC synthetic\n"):
            with self.subTest(status=invalid):
                with self.assertRaises(release.VerificationError):
                    release.validate_signature(invalid, self.policy, self.manifest, self.now)

    def test_cli_never_installs_or_accepts_qa_override(self):
        result = subprocess.run([sys.executable, "-I", str(SPEC.origin), self.bundle.name],
                                check=False, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"nothing was installed", result.stdout)


if __name__ == "__main__":
    unittest.main()

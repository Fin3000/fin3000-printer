"""Project license metadata and actual package staging, without network or install."""
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


qa = load("project_license_qa", "build-linux-qa.py")
bootstrap = load("project_license_bootstrap", "build-linux-bootstrap.py")


class ProjectLicenseTests(unittest.TestCase):
    def test_full_standard_license_and_matching_npm_metadata(self):
        license_bytes = (ROOT / "LICENSE").read_bytes()
        # Apache's complete, unmodified 2.0 text, including its example appendix.
        self.assertEqual(hashlib.sha256(license_bytes).hexdigest(),
                         "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30")
        metadata = json.loads((ROOT / "package.json").read_bytes())
        locked = json.loads((ROOT / "package-lock.json").read_bytes())
        self.assertEqual(metadata["license"], "Apache-2.0")
        self.assertEqual(locked["packages"][""]["license"], "Apache-2.0")
        self.assertTrue(metadata["private"], "Open source must not enable accidental npm publication")
        self.assertEqual(metadata["version"], locked["version"])
        self.assertEqual(metadata["version"], locked["packages"][""]["version"])

    def fixture(self, root):
        # Copy source inputs only. Never copy local reports, node_modules, .git,
        # environment files or operator credentials into the test fixture.
        for name in ("core", "platforms", "packaging"):
            shutil.copytree(ROOT / name, root / name,
                            ignore=shutil.ignore_patterns("__pycache__", "production-profile.json"))
        for relative in (*qa.PROJECT_DOCUMENTS, "package.json"):
            shutil.copyfile(ROOT / relative, root / relative)
        (root / "reports").mkdir()

    def assert_documents(self, tree, package, inventory):
        self.assertEqual(qa.PROJECT_DOCUMENTS,
                         {"LICENSE": "copyright", "NOTICE": "NOTICE", "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md"})
        for relative, installed_name in qa.PROJECT_DOCUMENTS.items():
            original = (ROOT / relative).read_bytes()
            installed = tree / f"usr/share/doc/{package}/{installed_name}"
            self.assertEqual(installed.read_bytes(), original)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o644)
            self.assertEqual(inventory["sourceFiles"][relative], hashlib.sha256(original).hexdigest())
        self.assertEqual(inventory["releaseGates"], "OPEN")

    def test_qa_stages_license_and_preserves_upstream_license_and_source(self):
        proof = qa.vendor.RuntimeProvenance("node", "22.23.2", "fixture.tar.xz", "1" * 64, 42,
            "2" * 64, "3" * 64, "4" * 64, "5" * 64, "6" * 64, "7" * 40, 1780000000,
            "synthetic-source.tar.xz", "8" * 64, 64, "9" * 64, 5, "a" * 64,
            1, hashlib.sha256(b"synthetic original source").hexdigest())
        runtime = qa.vendor.VerifiedRuntime(b"synthetic runtime", b"distinct upstream license", proof,
                                           b"upstream notices", b"synthetic original source")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            public_key = root / "receipt-public.pem"
            public_key.write_bytes(b"-----BEGIN PUBLIC KEY-----\nQUFB\n-----END PUBLIC KEY-----\n")

            def command(arguments, **kwargs):
                if arguments[:2] == ["git", "rev-parse"]:
                    return subprocess.CompletedProcess(arguments, 0, "b" * 40 + "\n")
                if arguments[:2] == ["git", "show"]:
                    return subprocess.CompletedProcess(arguments, 0, "1780000000\n")
                if arguments[:2] == ["/usr/bin/openssl", "pkey"]:
                    return subprocess.CompletedProcess(arguments, 0, bytes.fromhex("302a300506032b6570032100") + b"s" * 32)
                self.fail(f"Unexpected subprocess: {arguments[0]}")

            with patch.object(qa, "ROOT", root), patch.object(qa, "command", side_effect=command), \
                    patch.object(qa.vendor, "verify_runtime", return_value=runtime):
                _, tree, inventory = qa.stage(qa.BuildInputs(root / "reports/linux-qa-build-license", root,
                    "sha256:" + "1" * 64, "http://127.0.0.1:19001", "http://127.0.0.1:19002",
                    "http://127.0.0.1:19003", public_key, "2" * 40))
            self.assert_documents(tree, qa.PACKAGE, inventory)
            self.assertEqual(inventory["status"], "NOT_FOR_PRODUCTION")
            self.assertEqual(inventory["runtime"], asdict(proof))
            self.assertEqual((tree / f"usr/share/doc/{qa.PACKAGE}/NODE-LICENSE").read_bytes(), runtime.license)
            self.assertEqual((tree / f"usr/share/doc/{qa.PACKAGE}/NODE-SOURCE-NOTICES").read_bytes(), runtime.source_notices)
            self.assertEqual((tree / f"usr/share/doc/{qa.PACKAGE}/{qa.vendor.SUPPLEMENT_SOURCE}").read_bytes(), runtime.supplemental_source)

    def test_bootstrap_stages_original_documents_and_binds_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            for relative in ("signing/linux-release-key.asc", "scripts/build-linux-bootstrap.py",
                             "scripts/build-linux-qa.py", "scripts/verify-node-runtime.py", "scripts/verify-linux-release.py"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

            def git(*arguments):
                return subprocess.run(["git", *arguments], cwd=root, env=env, check=True,
                                      capture_output=True, timeout=10).stdout

            git("init", "-b", "feature/synthetic-bootstrap-license-test")
            git("add", ".")
            git("-c", "user.name=License QA", "-c", "user.email=license-qa@example.invalid",
                "commit", "-m", "synthetic public source fixture")
            commit = git("rev-parse", "HEAD").decode().strip()
            with ExitStack() as stack:
                stack.enter_context(patch.object(bootstrap, "ROOT", root))
                stack.enter_context(patch.object(bootstrap, "SOURCE", root / "packaging/linux/bootstrap"))
                stack.enter_context(patch.object(bootstrap, "archive_keyring", return_value=b"synthetic public keyring"))
                tree, inventory = bootstrap.stage(root / "reports/linux-bootstrap-build-license", "sha256:" + "1" * 64)
            self.assert_documents(tree, bootstrap.PACKAGE, inventory)
            self.assertEqual(inventory["sourceCommit"], commit)
            for relative, digest in inventory["sourceFiles"].items():
                self.assertEqual(digest, hashlib.sha256(git("cat-file", "blob", f"{commit}:{relative}")).hexdigest())
            self.assertEqual(inventory["status"], "UNRELEASED")
            self.assertNotIn("UNRELEASED", (tree / "DEBIAN/control").read_text())
            self.assertTrue((tree / f"usr/share/doc/{bootstrap.PACKAGE}/README").is_file())
            self.assertFalse((tree / f"usr/share/doc/{bootstrap.PACKAGE}/NODE-LICENSE").exists())

    def test_missing_or_symlinked_license_input_is_not_silently_omitted(self):
        for kind in ("missing", "symlink", "empty"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "LICENSE"
                if kind == "symlink":
                    target.symlink_to(ROOT / "LICENSE")
                elif kind == "empty":
                    target.touch()
                with self.assertRaises((OSError, ValueError)):
                    qa.read_regular(target, 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

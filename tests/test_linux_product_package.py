"""Product packaging tests with synthetic public pins; no install/signing/network."""
from contextlib import ExitStack
import copy
from dataclasses import asdict
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("linux_product_package", ROOT / "scripts/build-linux-product.py")
product = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = product
spec.loader.exec_module(product)
build = product.build


def profile(pem):
    return {"schemaVersion": 1, "environment": "production", "apiOrigin": "https://api.fin3000.com",
            "appOrigin": "https://app.fin3000.com", "clientId": "fin3000-system-print",
            "audience": "fin3000-printer:production", "quarantineOrigins": ["https://storage.fin3000.com"],
            "receiptKeys": {"rotation-1": pem}, "minimumBackendCommit": "1" * 40,
            "minimumBackendVersion": "0.9.0"}


class ProductPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Disposable key exists only in test-process memory; never use any
        # host keyring, operator key, production credential or remote service.
        generated = subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519"],
                                   capture_output=True, check=True, timeout=10).stdout
        cls.pem = subprocess.run(["/usr/bin/openssl", "pkey", "-pubout"], input=generated,
                                 capture_output=True, check=True, timeout=10).stdout.decode()

    def validate(self, value):
        return product.validate_profile(json.dumps(value))

    def test_committed_production_profile_preserves_fixed_identity_and_public_key(self):
        result = self.validate(profile(self.pem))
        self.assertEqual(result.minimum_backend_commit, "1" * 40)
        self.assertEqual(result.minimum_backend_version, "0.9.0")
        config = result.config()
        self.assertEqual(config["environment"], "production")
        self.assertEqual(config["receiptKeys"], {"rotation-1": self.pem})
        self.assertEqual(config["quarantineOrigins"], ["https://storage.fin3000.com"])
        config["receiptKeys"]["rotation-1"] = "changed"
        self.assertEqual(result.config()["receiptKeys"]["rotation-1"], self.pem)

    def test_unknown_missing_duplicate_and_non_object_profile_fields_fail(self):
        original = profile(self.pem)
        cases = [None, [], {**original, "secret": "not-permitted"}, {**original, "schemaVersion": True},
                 {**original, "schemaVersion": 2}]
        cases += [{key: value for key, value in original.items() if key != missing} for missing in original]
        for value in cases:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.validate(value)
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            product.validate_profile('{"schemaVersion":1,"schemaVersion":1}')

    def test_every_production_identity_rejects_qa_and_arbitrary_overrides(self):
        for field, values in {"environment": ["qa", None], "apiOrigin": ["https://foreign.invalid", "http://127.0.0.1:19000"],
                              "appOrigin": ["https://app.fin3000.com/", "https://app.fin3000.test"],
                              "clientId": ["fin3000-system-print-qa", "fin3000-browser-print"],
                              "audience": ["fin3000-printer:qa", "browser-print"]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.validate({**profile(self.pem), field: value})

    def test_minimum_backend_is_explicit_not_unborn_or_syntax_placeholder(self):
        for field, values in {"minimumBackendCommit": [None, "main", "0" * 40, "a" * 39, True],
                              "minimumBackendVersion": [None, "0.0.0", "0.1", "1.0.0", "0.01.2", True]}.items():
            for value in values:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.validate({**profile(self.pem), field: value})

    def test_quarantine_only_exact_https_dns_origins_no_qa_aliases_or_credentials(self):
        for value in (None, "http://storage.fin3000.com", "https://storage.fin3000.com/",
                      "https://storage.fin3000.com:443", "https://storage.fin3000.com:9443",
                      "https://storage.fin3000.com?q=x", "https://storage.fin3000.com#x",
                      "https://user:password@storage.fin3000.com", "https://STORAGE.fin3000.com",
                      "https://127.0.0.1", "https://127.1", "https://127.0.0.0x1", "https://[::1]", "https://localhost", "https://host.test",
                      "https://host.invalid", "https://example.com", "https://api.fin3000.com",
                      "https://storage.example.com",
                      "https://app.fin3000.com", "https://storage..fin3000.com", "https://-host.fin3000.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                product.quarantine_origin(value)
        for origins in ([], ["https://storage.fin3000.com"] * 2, ["https://a.fin3000.com"] * 5, None, "https://storage.fin3000.com"):
            with self.subTest(origins=origins), self.assertRaises(ValueError):
                self.validate({**profile(self.pem), "quarantineOrigins": origins})

    def test_receipt_key_ids_are_bounded_and_duplicate_public_keys_are_rejected(self):
        for keys in ({}, [], {"qa-ephemeral": self.pem}, {"test-1": self.pem}, {"": self.pem},
                     {"x" * 65: self.pem}, {"line\nbreak": self.pem}, {"rotation-1": self.pem, "rotation-2": self.pem}):
            with self.subTest(ids=list(keys)), self.assertRaises(ValueError):
                self.validate({**profile(self.pem), "receiptKeys": keys})

    def test_private_malformed_and_wrong_algorithm_receipt_keys_are_never_packaged(self):
        for pem in (None, "", "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
                    self.pem + "extra", "x" * 4097, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"):
            with self.subTest(pem_type=type(pem).__name__), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.validate({**profile(self.pem), "receiptKeys": {"rotation-1": pem}})
        rsa = subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                             capture_output=True, check=True, timeout=10).stdout
        public = subprocess.run(["/usr/bin/openssl", "pkey", "-pubout"], input=rsa,
                                capture_output=True, check=True, timeout=10).stdout.decode()
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            self.validate({**profile(self.pem), "receiptKeys": {"rotation-1": public}})

    def test_production_environment_guard_cannot_be_converted_by_qa_config(self):
        original = (ROOT / "core/config.ts").read_text()
        rendered = product.render("core/config.ts", original)
        self.assertIn("if (input.environment !== 'production' ||", rendered)
        self.assertNotIn("if (!['production', 'qa'].includes", rendered)
        self.assertEqual((ROOT / "core/config.ts").read_text(), original)
        with self.assertRaisesRegex(ValueError, "source drift"):
            product.render("core/config.ts", "different guard")
        app = (ROOT / "platforms/linux/app.js").read_text()
        self.assertEqual(product.render("platforms/linux/app.js", app), app)
        self.assertIn("const QA_BUILD = false;", app)

    def test_all_26_committed_catalogs_and_each_placeholder_are_mandatory(self):
        sources = {p.relative_to(ROOT).as_posix(): p.read_bytes() for p in (ROOT / "platforms/linux/locales").glob("*.json")}
        product.check_catalogs(sources)
        modified = copy.copy(sources); del modified["platforms/linux/locales/hi.json"]
        with self.assertRaises(ValueError):
            product.check_catalogs(modified)
        for replacement in ({}, {"title": "Incomplete"}, {**json.loads(sources["platforms/linux/locales/ga.json"]), "ready": "Missing variable"},
                            {**json.loads(sources["platforms/linux/locales/ga.json"]), "ready": "   "}):
            modified = {**sources, "platforms/linux/locales/ga.json": json.dumps(replacement).encode()}
            with self.assertRaises(ValueError):
                product.check_catalogs(modified)

    def test_actual_rendered_typescript_rejects_cross_environment_config_in_both_directions(self):
        script = """
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
const product = await import(pathToFileURL(process.argv[1]).href);
const qa = await import(pathToFileURL(process.argv[2]).href);
const common = {receiptKeys: {'public-fixture': 'nonempty'}, quarantineOrigins: ['https://storage.fin3000.com']};
const production = {...common, environment: 'production', apiOrigin: 'https://api.fin3000.com',
  appOrigin: 'https://app.fin3000.com', clientId: 'fin3000-system-print', audience: 'fin3000-printer:production'};
const isolated = {...common, environment: 'qa', apiOrigin: 'http://127.0.0.1:19000', appOrigin: 'http://127.0.0.1:19001',
  quarantineOrigins: ['http://127.0.0.1:19002'], clientId: 'fin3000-system-print-qa', audience: 'fin3000-printer:qa'};
assert.equal(product.validateBuildConfig(production).environment, 'production');
assert.equal(qa.validateBuildConfig(isolated).environment, 'qa');
assert.throws(() => product.validateBuildConfig(isolated), {code: 'BUILD_CONFIG_INVALID'});
assert.throws(() => qa.validateBuildConfig(production), {code: 'BUILD_CONFIG_INVALID'});
console.log('PASS: actual product/QA module boundaries; no HTTP or native adapter invoked');
"""
        with tempfile.TemporaryDirectory(prefix="fin3000-config-boundary-") as temporary:
            root = Path(temporary)
            source = (ROOT / "core/config.ts").read_text()
            (root / "product.ts").write_text(product.render("core/config.ts", source))
            (root / "qa.ts").write_text(build.render("core/config.ts", source))
            (root / "protocol.ts").write_bytes((ROOT / "core/protocol.ts").read_bytes())
            # Match the packaged GTK launcher, including explicit type stripping.
            # Use the same developer Node selected for npm/core tests, not a
            # distro build that can omit TypeScript entirely. Still clear all
            # inherited NODE_OPTIONS and other process injection variables.
            node = shutil.which("node")
            self.assertIsNotNone(node, "Native core tests require Node with TypeScript support")
            result = build.command([node, "--experimental-strip-types", "--input-type=module", "-e", script,
                                    str(root / "product.ts"), str(root / "qa.ts")], capture_output=True)
            self.assertIn(b"PASS: actual product/QA module boundaries", result.stdout)

    def test_missing_committed_profile_prevents_runtime_access_and_any_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "reports").mkdir()
            output = root / "reports/linux-product-build-missing-profile"
            responses = [subprocess.CompletedProcess([], 0, b""), subprocess.CompletedProcess([], 0, b"a" * 40 + b"\n"),
                         subprocess.CompletedProcess([], 0, b"1780000000\n")]
            with patch.object(product, "ROOT", root), patch.object(build, "command", side_effect=responses), \
                    patch.object(build.vendor, "verify_runtime") as runtime, self.assertRaises(FileNotFoundError):
                product.stage(product.BuildInputs(output, root, "sha256:" + "1" * 64))
            runtime.assert_not_called(); self.assertFalse(output.exists())

    def test_foreign_existing_or_qa_artifact_path_rejected_before_reading_profile(self):
        for path in (Path("relative"), Path("/etc/apt"), ROOT / "reports",
                     ROOT / "reports/linux-qa-build-not-product", ROOT / "reports/../linux-product-build-wrong"):
            with self.subTest(path=path), patch.object(product, "committed_source") as read, self.assertRaises(ValueError):
                product.stage(product.BuildInputs(path, ROOT, "sha256:" + "1" * 64))
            read.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "reports").mkdir()
            directory = root / "reports/linux-product-build-existing"; directory.mkdir()
            with patch.object(product, "ROOT", root), patch.object(product, "committed_source") as read, self.assertRaises(ValueError):
                product.stage(product.BuildInputs(directory, root, "sha256:" + "1" * 64))
            read.assert_not_called()

    def test_dirty_product_worktree_fails_before_runtime_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "reports").mkdir()
            output = root / "reports/linux-product-build-dirty"
            dirty = subprocess.CompletedProcess([], 0, b" M core/config.ts\n")
            with patch.object(product, "ROOT", root), patch.object(build, "command", return_value=dirty), \
                    patch.object(build.vendor, "verify_runtime") as runtime, self.assertRaisesRegex(ValueError, "Commit"):
                product.stage(product.BuildInputs(output, root, "sha256:" + "1" * 64))
            runtime.assert_not_called(); self.assertFalse(output.exists())

    def test_committed_source_compares_real_git_blob_and_rejects_modified_or_untracked_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

            def git(*arguments):
                return subprocess.run(["git", *arguments], cwd=root, env=env, check=True,
                                      capture_output=True, timeout=10).stdout

            git("init", "-b", "feature/synthetic-package-test")
            (root / "public.json").write_bytes(b"public build input\n")
            git("add", "public.json")
            git("-c", "user.name=Package QA", "-c", "user.email=package-qa@example.invalid", "commit", "-m", "synthetic fixture")
            commit = git("rev-parse", "HEAD").decode().strip()
            with patch.object(product, "ROOT", root):
                self.assertEqual(product.committed_source(commit, "public.json"), b"public build input\n")
                (root / "public.json").write_bytes(b"modified build input\n")
                with self.assertRaisesRegex(ValueError, "byte-identical"):
                    product.committed_source(commit, "public.json")
                (root / "untracked.json").write_bytes(b"untracked\n")
                with self.assertRaises(subprocess.CalledProcessError):
                    product.committed_source(commit, "untracked.json")

    def test_product_payload_preserves_production_namespace_and_binds_provenance(self):
        self.assertEqual(product.PROFILE, "packaging/linux/production-profile.json")
        profile_bytes = json.dumps(profile(self.pem)).encode()
        source_paths = build.source_files()
        proof = build.vendor.RuntimeProvenance("node", "22.23.2", "fixture.tar.xz", "1" * 64, 42,
            "2" * 64, "3" * 64, "4" * 64, "5" * 64,
            hashlib.sha256((ROOT / "signing/node-release-key.asc").read_bytes()).hexdigest(), "7" * 40, 1780000000,
            "synthetic-source.tar.xz", "8" * 64, 64, "9" * 64, 5,
            hashlib.sha256((ROOT / "signing/node-runtime-supplement.json").read_bytes()).hexdigest(),
            1, hashlib.sha256(b"synthetic original source").hexdigest())
        runtime = build.vendor.VerifiedRuntime(b"synthetic verified binary", b"synthetic full license", proof,
                                              b"synthetic source notices", b"synthetic original source")
        actual_command = build.command

        def git_or_openssl(arguments, **kwargs):
            if arguments[:2] == ["git", "status"]:
                return subprocess.CompletedProcess(arguments, 0, b"")
            if arguments[:2] == ["git", "rev-parse"]:
                return subprocess.CompletedProcess(arguments, 0, b"a" * 40 + b"\n")
            if arguments[:2] == ["git", "show"]:
                return subprocess.CompletedProcess(arguments, 0, b"1780000000\n")
            return actual_command(arguments, **kwargs)

        def read_fixture(commit, relative, limit=1024 * 1024):
            self.assertEqual(commit, "a" * 40)
            raw = profile_bytes if relative == product.PROFILE else (ROOT / relative).read_bytes()
            self.assertLessEqual(len(raw), limit, f"Real input exceeds its declared limit: {relative}")
            if relative == "signing/node-runtime-supplement.json":
                self.assertEqual(limit, 2 * 1024 * 1024)
            return raw

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "reports").mkdir()
            # source_files() only supplies the graph; the source-read port above
            # supplies current checked fixture bytes without copying credentials.
            paths = [root / path.relative_to(ROOT) for path in source_paths]
            with ExitStack() as stack:
                stack.enter_context(patch.object(product, "ROOT", root))
                stack.enter_context(patch.object(build, "command", side_effect=git_or_openssl))
                stack.enter_context(patch.object(product, "committed_source", side_effect=read_fixture))
                stack.enter_context(patch.object(build, "source_files", return_value=paths))
                stack.enter_context(patch.object(build.vendor, "verify_runtime", return_value=runtime))
                directory, tree, inventory = product.stage(product.BuildInputs(root / "reports/linux-product-build-synthetic", root, "sha256:" + "b" * 64))
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(inventory["status"], "UNRELEASED")
            self.assertFalse(inventory["backendReadinessVerified"])
            self.assertEqual(inventory["releaseGates"], "OPEN")
            self.assertEqual(inventory["minimumBackendCommit"], "1" * 40)
            self.assertEqual(inventory["profileSha256"], hashlib.sha256(profile_bytes).hexdigest())
            self.assertEqual(inventory["runtime"], asdict(proof))
            for relative, installed_name in build.PROJECT_DOCUMENTS.items():
                raw = (ROOT / relative).read_bytes()
                self.assertEqual((tree / f"usr/share/doc/fin3000-printer/{installed_name}").read_bytes(), raw)
                self.assertEqual(inventory["sourceFiles"][relative], hashlib.sha256(raw).hexdigest())
            owned = tree / "usr/lib/fin3000-printer"
            config = json.loads((owned / "build-config.json").read_bytes())
            self.assertEqual(config, self.validate(profile(self.pem)).config())
            self.assertIn("input.environment !== 'production'", (owned / "core/config.ts").read_text())
            self.assertEqual((owned / "runtime/bin/node").read_bytes(), runtime.node)
            self.assertEqual((tree / "usr/share/doc/fin3000-printer/NODE-LICENSE").read_bytes(), runtime.license)
            self.assertEqual((tree / "usr/share/doc/fin3000-printer/NODE-SOURCE-NOTICES").read_bytes(), runtime.source_notices)
            self.assertEqual((tree / f"usr/share/doc/fin3000-printer/{build.vendor.SUPPLEMENT_SOURCE}").read_bytes(), runtime.supplemental_source)
            self.assertEqual(inventory["sourceFiles"]["signing/node-runtime-supplement.json"], proof.sourceSupplementSha256)
            self.assertEqual(sorted(p.stem for p in (owned / "platforms/linux/locales").glob("*.json")), product.LANGUAGES)
            self.assertTrue((tree / "usr/share/applications/com.fin3000.Printer.desktop").is_file())
            self.assertTrue((tree / "usr/lib/systemd/user/fin3000-printer.service").is_file())
            self.assertFalse((tree / "etc/apt").exists())
            self.assertEqual(sorted(p.name for p in (tree / "DEBIAN").iterdir()), ["control", "postinst", "postrm", "preinst", "prerm"])
            self.assertIn("Pre-Depends: python3", (tree / "DEBIAN/control").read_text())
            self.assertNotIn("UNRELEASED", (tree / "DEBIAN/control").read_text())
            packaged_readme = (tree / "usr/share/doc/fin3000-printer/README").read_text()
            self.assertIn("there is no second send button", packaged_readme)
            self.assertNotIn("confirm the upload in the app", packaged_readme)
            control = (tree / "DEBIAN/control").read_text()
            self.assertIn("automatic upload", control)
            self.assertNotIn("explicit upload", control)
            self.assertIn('"packaging/linux/package-lifecycle.py"', json.dumps(inventory["sourceFiles"]))
            self.assertIn("/usr/lib/cups/backend/fin3000", (tree / "etc/apparmor.d/fin3000-printer").read_text())
            self.assertNotIn("fin3000-printer-qa", "\n".join(str(p) for p in tree.rglob("*")))
            self.assertEqual((owned / "build-manifest.json").read_bytes(), (directory / "build-inputs.json").read_bytes())

    def test_no_profile_host_key_or_signing_overrides_in_cli(self):
        result = subprocess.run([sys.executable, "-B", "-I", str(ROOT / "scripts/build-linux-product.py"), "--help"],
                                capture_output=True, check=True, timeout=10)
        for option in ("--environment", "--profile", "--api-origin", "--receipt-public-key", "--minimum-backend-commit", "--sign", "--install"):
            self.assertNotIn(option, result.stdout.decode())
        self.assertIn("--node-release", result.stdout.decode())


if __name__ == "__main__":
    unittest.main()

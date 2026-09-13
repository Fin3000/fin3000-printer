"""QA package boundary tests. No Docker, host install, signing or live account."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("linux_qa_package", ROOT / "scripts/build-linux-qa.py")
build = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build
spec.loader.exec_module(build)


class PackageTests(unittest.TestCase):
    def test_qa_revisions_have_real_debian_order_without_becoming_product_versions(self):
        previous = None
        for revision in (1, 2, 9, 10, 999999):
            version = build.qa_version(revision)
            self.assertEqual(version, f"0.0.0~qa{revision}")
            subprocess.run(["/usr/bin/dpkg", "--compare-versions", version, "lt", "0.0.0"], check=True)
            if previous:
                subprocess.run(["/usr/bin/dpkg", "--compare-versions", previous, "lt", version], check=True)
            previous = version

    def test_invalid_revision_fails_before_reading_inputs_or_creating_artifacts(self):
        for revision in (None, True, False, 0, -1, 1000000, 1.5, "2", "0.1.0", "1\nVersion: 1.0.0"):
            with self.subTest(revision=revision), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = root / "reports/linux-qa-build-invalid"
                inputs = build.BuildInputs(directory, root, "sha256:" + "1" * 64,
                                           "http://127.0.0.1:19001", "http://127.0.0.1:19002",
                                           "http://127.0.0.1:19003", root / "unused", "2" * 40, revision)
                with patch.object(build.vendor, "verify_runtime") as verify, \
                        self.assertRaisesRegex(ValueError, "QA revision"):
                    build.stage(inputs)
                verify.assert_not_called()
                self.assertFalse(directory.exists())

    def test_installed_size_counts_payload_per_file_not_build_or_control_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "root"
            tree.mkdir()
            build.put(tree, "DEBIAN/control", b"Package: fin3000-printer-qa\nArchitecture: amd64\n")
            build.put(tree, "DEBIAN/conffiles", b"x" * 10000)
            build.put(tree, "usr/bin/one", b"x" * 1025)
            build.put(tree, "usr/bin/two", b"x")
            build.put(tree, "usr/bin/empty", b"")
            build.package_directory(tree, "var/lib/empty")
            # Five payload directories + 2 KiB + 1 KiB + empty file (0).
            self.assertEqual(build.set_installed_size(tree), 8)
            self.assertIn(b"Installed-Size: 8\n", (tree / "DEBIAN/control").read_bytes())
            with self.assertRaises(ValueError):
                build.set_installed_size(tree)

    def test_installed_size_rejects_symlink_and_special_payload_without_changing_control(self):
        for kind in ("link", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                tree = Path(temporary) / "root"
                tree.mkdir()
                control = b"Package: fin3000-printer-qa\nArchitecture: amd64\n"
                build.put(tree, "DEBIAN/control", control)
                target = tree / "outside"
                if kind == "link":
                    target.symlink_to("/etc")
                else:
                    os.mkfifo(target)
                with self.assertRaises(ValueError):
                    build.set_installed_size(tree)
                self.assertEqual((tree / "DEBIAN/control").read_bytes(), control)

    def test_auth_dependencies_exist_on_both_ubuntu_lts_families(self):
        # policykit-1 was transitional in 24.04 and is absent in 26.04.
        self.assertEqual(build.AUTH_DEPENDENCIES, "polkitd, pkexec")
        dependencies = build.DEPENDENCIES.split(", ")
        self.assertIn("polkitd", dependencies)
        self.assertIn("pkexec", dependencies)
        self.assertIn("gjs (>= 1.80)", dependencies)
        self.assertNotIn("policykit-1", dependencies)

    def test_shared_compiler_refuses_unknown_identity_or_release_approval_before_docker(self):
        for package, declared, status in (("other", "other", "UNRELEASED"),
                                         ("fin3000-printer", "fin3000-printer-qa", "UNRELEASED"),
                                         ("fin3000-printer", "fin3000-printer", "RELEASED"),
                                         ("fin3000-printer-qa", "fin3000-printer-qa", "UNRELEASED")):
            with self.subTest(package=package, status=status), patch.object(build, "local_docker") as docker:
                with self.assertRaises(ValueError):
                    build.compile_package(ROOT, ROOT, {"package": declared, "status": status}, package=package)
                docker.assert_not_called()

    def test_shared_compiler_uses_only_fixed_qa_or_product_destinations_and_preserves_status(self):
        for package, backend, status in (("fin3000-printer-qa", "fin3000qa", "NOT_FOR_PRODUCTION"),
                                          ("fin3000-printer", "fin3000", "UNRELEASED")):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); tree = directory / "root"; tree.mkdir()
                inventory = {"package": package, "status": status, "builderImage": "sha256:" + "a" * 64,
                             "sourceDateEpoch": 1780000000, "version": "0.0.0"}
                build.put(tree, "DEBIAN/control", f"Package: {package}\nArchitecture: amd64\n".encode())
                for relative in (f"usr/lib/cups/backend/{backend}", f"usr/lib/{package}/bin/pdf-validator", f"usr/bin/{package}", f"usr/lib/{package}/bin/no-core.so"):
                    build.put(tree, relative, b"synthetic compiler output")
                artifact = directory / f"{package}_0.0.0_amd64.deb"
                artifact.write_bytes(b"synthetic package output")
                result = subprocess.CompletedProcess([], 0, b"compiler\tfixture\n")
                with patch.object(build, "local_docker", return_value=["docker", "--context", "default"]), \
                        patch.object(build, "command", return_value=result) as command, \
                        patch.object(build, "runtime_component_evidence") as evidence:
                    self.assertEqual(build.compile_package(directory, tree, inventory, package=package), artifact)
                evidence.assert_called_once()
                self.assertEqual(evidence.call_args.args[:3], (directory, tree, inventory))
                sandbox = evidence.call_args.args[3]
                self.assertIn("--read-only", sandbox)
                self.assertEqual(sandbox[sandbox.index("--network") + 1], "none")
                commands = [call.args[0] for call in command.call_args_list]
                self.assertEqual(len(commands), 6)
                for invocation in commands:
                    self.assertIn("--network", invocation)
                    self.assertEqual(invocation[invocation.index("--network") + 1], "none")
                    self.assertIn("--read-only", invocation)
                    self.assertIn("--pull=never", invocation)
                    self.assertNotIn("--privileged", invocation)
                self.assertEqual(commands[0][-1], f"root/usr/lib/cups/backend/{backend}")
                self.assertEqual(commands[1][-1], f"root/usr/lib/{package}/bin/pdf-validator")
                self.assertEqual(commands[2][-1], f"root/usr/bin/{package}")
                self.assertEqual(commands[3][-1], f"root/usr/lib/{package}/bin/no-core.so")
                self.assertIn("-shared", commands[3])
                self.assertIn("-fPIC", commands[3])
                self.assertEqual((tree / f"usr/lib/{package}/bin/no-core.so").stat().st_mode & 0o777, 0o644)
                self.assertEqual(commands[-1][-1], artifact.name)
                metadata = json.loads((directory / "artifact.json").read_text())
                self.assertEqual(metadata["status"], status)
                self.assertFalse(metadata["signed"])
                self.assertEqual((tree / f"usr/lib/cups/backend/{backend}").stat().st_mode & 0o777, 0o700)
                self.assertRegex((tree / "DEBIAN/control").read_text(), r"Installed-Size: [1-9][0-9]*\n")

    def test_unverified_runtime_rejected_before_creating_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "reports").mkdir()
            directory = root / "reports/linux-qa-build-rejected"
            inputs = build.BuildInputs(directory, root, "sha256:" + "1" * 64,
                                       "http://127.0.0.1:19001", "http://127.0.0.1:19002",
                                       "http://127.0.0.1:19003", root / "unused-public-key", "2" * 40)
            with patch.object(build, "ROOT", root), patch.object(build.vendor, "verify_runtime",
                    side_effect=ValueError("Untrusted runtime")), self.assertRaisesRegex(ValueError, "Untrusted runtime"):
                build.stage(inputs)
            self.assertFalse(directory.exists())

    def test_runtime_evidence_is_bound_and_does_not_claim_complete_licenses_or_sbom(self):
        for package in ("fin3000-printer-qa", "fin3000-printer"):
            with self.subTest(package=package), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); tree = directory / "root"
                tree.mkdir()
                node = b"synthetic non-executable binary"
                license_text = b"synthetic license evidence"
                build.put(tree, f"usr/lib/{package}/runtime/bin/node", node)
                build.put(tree, f"usr/share/doc/{package}/NODE-LICENSE", license_text)
                build.put(tree, f"usr/share/doc/{package}/NODE-SOURCE-NOTICES", b"notices")
                build.put(tree, f"usr/share/doc/{package}/{build.vendor.SUPPLEMENT_SOURCE}", b"source")
                inventory = {"package": package, "sourceCommit": "a" * 40, "builderImage": "sha256:" + "b" * 64,
                             "runtime": {"version": "22.23.2", "sha256": hashlib.sha256(node).hexdigest(),
                                         "licenseSha256": hashlib.sha256(license_text).hexdigest(),
                                         "sourceNoticesSha256": hashlib.sha256(b"notices").hexdigest(),
                                         "supplementalSourceSha256": hashlib.sha256(b"source").hexdigest()}}
                facts = {"platform": "linux", "arch": "x64", "versions": {"node": "22.23.2", "modules": "127", "sqlite": "3.51.3"},
                         "variables": {"node_shared_sqlite": False}}
                with patch.object(build, "command", return_value=subprocess.CompletedProcess([], 0, json.dumps(facts).encode())) as command:
                    build.runtime_component_evidence(directory, tree, inventory, ["synthetic-offline-sandbox"])
                invocation = command.call_args.args[0]
                self.assertEqual(invocation[:3], ["synthetic-offline-sandbox", f"/build/root/usr/lib/{package}/runtime/bin/node", "--input-type=commonjs"])
                report = json.loads((directory / "runtime-components.json").read_text())
                self.assertEqual(report["runtimeProvenance"], inventory["runtime"])
                self.assertEqual(report["runtimeFacts"], facts)
                self.assertEqual(report["status"], "INVENTORY_EVIDENCE_NOT_COMPLETE_SBOM")
                self.assertNotIn("compositions", report)
                self.assertNotIn("licenses", report)

    def test_runtime_evidence_rejects_changed_inputs_before_execution(self):
        for altered in ("binary", "license", "notices", "source"):
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); tree = directory / "root"
                tree.mkdir()
                build.put(tree, "usr/lib/fin3000-printer-qa/runtime/bin/node", b"altered" if altered == "binary" else b"node")
                build.put(tree, "usr/share/doc/fin3000-printer-qa/NODE-LICENSE", b"altered" if altered == "license" else b"license")
                build.put(tree, "usr/share/doc/fin3000-printer-qa/NODE-SOURCE-NOTICES", b"altered" if altered == "notices" else b"notices")
                build.put(tree, f"usr/share/doc/fin3000-printer-qa/{build.vendor.SUPPLEMENT_SOURCE}", b"altered" if altered == "source" else b"source")
                inventory = {"package": "fin3000-printer-qa", "runtime": {"sha256": hashlib.sha256(b"node").hexdigest(),
                             "licenseSha256": hashlib.sha256(b"license").hexdigest(),
                             "sourceNoticesSha256": hashlib.sha256(b"notices").hexdigest(),
                             "supplementalSourceSha256": hashlib.sha256(b"source").hexdigest()}}
                with patch.object(build, "command") as command, self.assertRaisesRegex(ValueError, "authenticated input"):
                    build.runtime_component_evidence(directory, tree, inventory, [])
                command.assert_not_called()
                self.assertFalse((directory / "runtime-components.json").exists())

    def test_runtime_evidence_rejects_wrong_architecture_version_or_duplicate_keys(self):
        valid = {"platform": "linux", "arch": "x64", "versions": {"node": "22.23.2"}, "variables": {}}
        invalid = [json.dumps({**valid, "arch": "arm64"}).encode(), json.dumps({**valid, "versions": {"node": "99.0.0"}}).encode(),
                   b'{"platform":"linux","platform":"linux","arch":"x64","versions":{"node":"22.23.2"},"variables":{}}', b"x" * (128 * 1024 + 1)]
        for raw in invalid:
            with self.subTest(raw=raw[:100]), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); tree = directory / "root"
                tree.mkdir()
                build.put(tree, "usr/lib/fin3000-printer-qa/runtime/bin/node", b"node")
                build.put(tree, "usr/share/doc/fin3000-printer-qa/NODE-LICENSE", b"license")
                build.put(tree, "usr/share/doc/fin3000-printer-qa/NODE-SOURCE-NOTICES", b"notices")
                build.put(tree, f"usr/share/doc/fin3000-printer-qa/{build.vendor.SUPPLEMENT_SOURCE}", b"source")
                inventory = {"package": "fin3000-printer-qa", "runtime": {"version": "22.23.2", "sha256": hashlib.sha256(b"node").hexdigest(),
                             "licenseSha256": hashlib.sha256(b"license").hexdigest(),
                             "sourceNoticesSha256": hashlib.sha256(b"notices").hexdigest(),
                             "supplementalSourceSha256": hashlib.sha256(b"source").hexdigest()}}
                with patch.object(build, "command", return_value=subprocess.CompletedProcess([], 0, raw)), self.assertRaises(ValueError):
                    build.runtime_component_evidence(directory, tree, inventory, [])
                self.assertFalse((directory / "runtime-components.json").exists())

    def test_runtime_binary_and_full_license_come_from_same_verified_archive(self):
        source = (ROOT / "scripts/build-linux-qa.py").read_text()
        self.assertIn("vendor.verify_runtime(inputs.node_release)", source)
        self.assertIn('runtime.node, 0o755', source)
        self.assertIn('NODE-LICENSE", runtime.license', source)
        self.assertIn('"runtime": asdict(runtime.proof)', source)
        self.assertNotIn('"--node-license"', source)
        self.assertNotIn('local-QA-only', source)

    def test_autostart_waits_for_gnome_display_and_is_scoped_to_graphical_session(self):
        text = (ROOT / "platforms/linux/fin3000-printer.service").read_text()
        self.assertIn("After=graphical-session-pre.target gnome-session-initialized.target", text)
        self.assertIn("PartOf=graphical-session.target", text)
        self.assertIn("WantedBy=graphical-session.target", text)
        self.assertIn("ExecStart=/usr/bin/fin3000-printer --background", text)
        self.assertNotIn("WantedBy=default.target", text)
        rendered = build.render("platforms/linux/fin3000-printer.service", text)
        self.assertIn("ExecStart=/usr/bin/fin3000-printer-qa --background", rendered)

    def test_build_commands_drop_ambient_remote_docker_and_require_local_default(self):
        valid = subprocess.CompletedProcess([], 0, b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]')
        with patch.object(build.subprocess, "run", return_value=valid) as run:
            self.assertEqual(build.local_docker(), ["docker", "--context", "default"])
            self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
        for data in (b'[]', b'[{"Endpoints":{"docker":{"Host":"tcp://foreign.invalid:2376"}}}]'):
            with patch.object(build.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, data)), self.assertRaises(ValueError):
                build.local_docker()

    def test_qa_endpoints_cannot_name_any_production_service_or_alias(self):
        self.assertEqual(build.local_origin("http://127.0.0.1:19000"), "http://127.0.0.1:19000")
        self.assertEqual(build.local_origin("https://127.0.0.1:19002"), "https://127.0.0.1:19002")
        for url in ("https://api.fin3000.com", "https://api.fin3000.test", "http://localhost:19000",
                    "http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:19000/",
                    "http://u:p@127.0.0.1:19000", "http://127.0.0.1:19000?prod=1",
                    "http://127.0.0.1:19000#x", "http://127.0.0.1:019000"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                build.local_origin(url)

    def test_packaged_build_cannot_select_production_even_with_changed_config(self):
        source = build.render("core/config.ts", (ROOT / "core/config.ts").read_text())
        self.assertIn("if (input.environment !== 'qa' ||", source)
        with self.assertRaisesRegex(ValueError, "source drift"):
            build.render("core/config.ts", "changed guard")
        app = build.render("platforms/linux/app.js", (ROOT / "platforms/linux/app.js").read_text())
        self.assertIn("const QA_BUILD = true;", app)
        self.assertIn("QA_BUILD ? isolatedQa : production", app)
        self.assertIn("com.fin3000.PrinterQA", app)
        self.assertIn("['/usr/bin/fin3000-printer-qa', '--runtime']", app)
        launcher = build.render("platforms/linux/launcher.c", (ROOT / "platforms/linux/launcher.c").read_text())
        self.assertIn('"--use-system-ca", "--experimental-strip-types"', launcher)
        self.assertNotIn("--use-system-ca", (ROOT / "platforms/linux/launcher.c").read_text())
        self.assertNotIn("NODE_TLS_REJECT_UNAUTHORIZED", app)
        with self.assertRaisesRegex(ValueError, "source drift"):
            build.render("platforms/linux/launcher.c", "changed runtime")
        gate = build.render("platforms/linux/package-gate.h", (ROOT / "platforms/linux/package-gate.h").read_text())
        self.assertIn('"fin3000-printer-qa", "lifecycle"', gate)

    def test_hooks_are_self_contained_and_payload_inventory_covers_compiled_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            source = (ROOT / "packaging/linux/package-lifecycle.py").read_bytes()
            build.stage_hooks(tree, source)
            for role in ("preinst", "postinst", "prerm", "postrm"):
                hook = tree / "DEBIAN" / role
                self.assertEqual(hook.stat().st_mode & 0o777, 0o755)
                self.assertTrue(hook.read_bytes().startswith(source))
                compile(hook.read_text(), role, "exec")
                self.assertIn(f"run_hook('{role}', sys.argv[1:])", hook.read_text())
            build.put(tree, "usr/bin/fin3000-printer", b"compiled launcher", 0o755)
            build.put(tree, "usr/lib/fin3000-printer/runtime/bin/node", b"verified runtime", 0o755)
            build.payload_inventory(tree, "fin3000-printer")
            files = json.loads((tree / "usr/lib/fin3000-printer/package-files.json").read_text())
            self.assertEqual(files, {"/usr/bin/fin3000-printer": hashlib.sha256(b"compiled launcher").hexdigest(),
                                     "/usr/lib/fin3000-printer/runtime/bin/node": hashlib.sha256(b"verified runtime").hexdigest()})

    def test_qa_core_preserves_real_wire_protocol_including_native_dispatch_header(self):
        for path in sorted((ROOT / "core").glob("*.ts")):
            if path.name == "config.ts":
                continue  # Its existing environment guard is intentionally QA-only.
            original = path.read_text()
            self.assertEqual(build.render(path.relative_to(ROOT).as_posix(), original), original, path.name)
        http = build.render("core/http.ts", (ROOT / "core/http.ts").read_text())
        self.assertIn("'X-Fin3000-Print-Protocol': '2'", http)
        self.assertNotIn("X-Fin3000QA-Print-Protocol", http)

    def test_runtime_activates_validated_build_identity_before_auth_and_ingress(self):
        source = (ROOT / "platforms/linux/runtime.ts").read_text()
        for rendered in (source, build.render("platforms/linux/runtime.ts", source)):
            self.assertIn("const manifestPath = `${ROOT}/build-manifest.json`;", rendered)
            self.assertIn("await assertRootOwned(manifestPath);", rendered)
            self.assertIn("stateReleaseFromManifest(JSON.parse(await readFile(manifestPath, 'utf8')), config.environment)", rendered)
            self.assertIn("? '-qa' : ''}`), release);", rendered)
            self.assertLess(rendered.index("await assertRootOwned(manifestPath)"), rendered.index("const release ="))
            self.assertLess(rendered.index("const release ="), rendered.index("await LinuxStateStore.acquire("))
            self.assertLess(rendered.index("await LinuxStateStore.acquire("), rendered.index("new NativeOAuth("))
            self.assertLess(rendered.index("await LinuxStateStore.acquire("), rendered.index("await desktop.start()"))
            announced = "emit({ type: 'release', version: release.version, sourceCommit: release.sourceCommit });"
            self.assertIn(announced, rendered)
            self.assertLess(rendered.index("await LinuxStateStore.acquire("), rendered.index(announced))
            self.assertLess(rendered.index(announced), rendered.index("new NativeHttp("))
        self.assertIn("view.setRelease(message)", (ROOT / "platforms/linux/app.js").read_text())

    def test_every_native_identity_is_separate_and_no_double_suffix(self):
        for path in (ROOT / "platforms/linux").glob("*"):
            if not path.is_file() or path.suffix not in (".ts", ".js", ".py", ".c", ".desktop", ".service", ".policy"):
                continue
            original = path.read_text()
            rendered = build.render(path.relative_to(ROOT).as_posix(), original)
            for value in ("/usr/lib/fin3000-printer/", "/usr/bin/fin3000-printer ",
                          "/etc/fin3000-printer/", "/var/lib/fin3000-printer/", "fin3000:/",
                          "fin3000-printer-backend", "fin3000-printer-pdf-validator", "/fin3000-printer/ingest.sock"):
                self.assertNotIn(value, rendered, str(path))
            self.assertNotIn("fin3000-printer-qa-qa", rendered)
            self.assertEqual(path.read_text(), original)  # source/Chrome never rewritten
        backend = build.render("platforms/linux/cups-backend.c", (ROOT / "platforms/linux/cups-backend.c").read_text())
        self.assertIn('"fin3000-printer-qa", "installations"', backend)
        self.assertIn('"Fin3000QA-%u"', backend)
        self.assertIn('"fin3000qa:/%u/%s"', backend)

        process = build.render("platforms/linux/process.ts", (ROOT / "platforms/linux/process.ts").read_text())
        self.assertIn("const AUTOSTART_UNIT = 'fin3000-printer-qa.service';", process)
        self.assertNotIn("'fin3000-printer.service'", process)

    def test_actual_qa_profiles_parse_and_target_only_qa_helpers(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "apparmor.py"
            source.write_text(build.render("platforms/linux/apparmor.py", (ROOT / "platforms/linux/apparmor.py").read_text()))
            profiles = runpy.run_path(source)
            text = profiles["backend_profile"]() + profiles["validator_profile"]()
            subprocess.run(["/usr/sbin/apparmor_parser", "-Q", "-T"], input=text.encode(), check=True, capture_output=True, timeout=10)
            self.assertIn("profile fin3000-printer-qa-backend /usr/lib/cups/backend/fin3000qa", text)
            self.assertIn("/run/user/[0-9]*/fin3000-printer-qa/ingest.sock", text)
            self.assertIn("deny network inet", text)

    def test_rendered_qa_ppd_still_passes_cups_model_name_and_length_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "qa.ppd"
            path.write_text(build.render("platforms/linux/fin3000.ppd", (ROOT / "platforms/linux/fin3000.ppd").read_text()))
            subprocess.run(["/usr/bin/cupstestppd", "-q", str(path)], check=True, capture_output=True, timeout=10)

    def test_package_input_does_not_follow_symlinks_or_accept_empty_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "input"; regular.write_bytes(b"test")
            self.assertEqual(build.read_regular(regular, 4), b"test")
            with self.assertRaises(ValueError):
                build.read_regular(regular, 3)
            regular.write_bytes(b"")
            with self.assertRaises(ValueError):
                build.read_regular(regular, 4)
            alias = root / "alias"; alias.symlink_to(regular)
            with self.assertRaises(OSError):
                build.read_regular(alias, 4)

    def test_staging_never_overwrites_or_escapes_its_artifact_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = build.put(root, "safe/file", b"first", 0o600)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                build.put(root, "safe/file", b"second")
            for path in ("../foreign", "/etc/foreign", "safe/../../foreign"):
                with self.assertRaises(ValueError):
                    build.put(root, path, b"bad")
            self.assertEqual(target.read_bytes(), b"first")

    def test_all_package_ancestors_are_non_group_writable_despite_builder_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = os.umask(0o002)
            try:
                build.put(root, "usr/lib/fin3000-printer-qa/nested/file", b"test")
            finally:
                os.umask(original)
            for path in root.rglob("*"):
                if path.is_dir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o755, str(path))

    def test_artifact_directory_stays_private_when_writing_top_level_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            build.put(root, "build-inputs.json", b"{}")
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_qa_manifest_does_not_claim_uncommitted_backend_is_a_release_minimum(self):
        source = (ROOT / "scripts/build-linux-qa.py").read_text()
        self.assertIn('"backendWorktreeBaseCommit": inputs.backend_worktree_base_commit', source)
        self.assertIn('"minimumBackendCommit": None', source)
        self.assertNotIn('"--minimum-backend-commit"', source)

    def test_builder_has_no_global_signing_install_or_production_override(self):
        source = (ROOT / "scripts/build-linux-qa.py").read_text()
        self.assertNotIn('"--environment"', source)
        self.assertIn('"--network", "none"', source)
        self.assertIn('"--cap-drop", "ALL"', source)
        self.assertIn('"--root-owner-group"', source)
        for command in ('"apt-get"', '"dpkg", "-i"', '"gpg"', '"sudo"', '"--privileged"'):
            self.assertNotIn(command, source)
        self.assertEqual(build.PACKAGE, "fin3000-printer-qa")
        self.assertEqual(build.qa_version(1), "0.0.0~qa1")
        self.assertNotEqual(build.qa_version(1), json.loads((ROOT / "package.json").read_text())["version"])


if __name__ == "__main__":
    unittest.main()

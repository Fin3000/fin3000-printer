"""Bootstrap policy tests. Never invoke live APT, root, installation or signing."""
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/linux/bootstrap"
PREPARED_ARCHIVES = Path("/synthetic-apt-archives")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helper = load("bootstrap_installer", SOURCE / "install.py")
builder = load("bootstrap_builder", ROOT / "scripts/build-linux-bootstrap.py")


class ComparableCandidate(SimpleNamespace):
    def __lt__(self, other):
        return tuple(map(int, self.version.split("."))) < tuple(map(int, other.version.split(".")))


def candidate(**overrides):
    value = SimpleNamespace(version="0.1.0", architecture="amd64", downloadable=True,
        sha256="a" * 64, size=4096,
        uris=["https://fin3000.com/tools/apt/pool/main/fin3000-printer_0.1.0_amd64.deb"],
        origins=[SimpleNamespace(site="fin3000.com", trusted=True, origin="Fin3000",
                                 label="Fin3000", archive="stable", component="main")])
    for key, replacement in overrides.items():
        setattr(value, key, replacement)
    return value


@contextmanager
def configuration(change=None):
    files = {
        helper.SOURCES: (SOURCE / "fin3000-printer.sources").read_bytes(),
        helper.PREFERENCES: (SOURCE / "fin3000-printer.pref").read_bytes(),
        helper.PACKAGE / "fin3000-printer.sources": (SOURCE / "fin3000-printer.sources").read_bytes(),
        helper.PACKAGE / "fin3000-printer.pref": (SOURCE / "fin3000-printer.pref").read_bytes(),
        helper.KEYRING: b"synthetic public certificate",
        helper.PACKAGE / "archive-keyring.sha256": hashlib.sha256(b"synthetic public certificate").hexdigest().encode(),
        Path("/var/lib/fin3000-printer/lifecycle/ready"): b"1\n",
    }
    if change:
        path, replacement = change
        files[path] = replacement
    def read(path, *args):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]
    @contextmanager
    def prepared(record):
        helper.cached_bytes(record)
        yield PREPARED_ARCHIVES
    with patch.object(helper, "read_trusted", side_effect=read), \
            patch.object(helper, "prepared_archives", side_effect=prepared), \
            patch.object(helper, "collect_cache"):
        yield


class BootstrapTests(unittest.TestCase):
    def test_cache_failure_precedes_acquisition_or_package_mutation(self):
        with configuration(), patch.object(helper, 'collect_cache',
                side_effect=helper.InstallError('INSTALL_CACHE_UNSAFE')) as collect, \
                patch.object(helper, 'run_apt') as apt, patch.object(helper, 'save_journal') as save:
            with self.assertRaisesRegex(helper.InstallError, 'INSTALL_CACHE_UNSAFE'):
                helper.install()
            collect.assert_called_once_with(helper.InstallJournal())
            apt.assert_not_called(); save.assert_not_called()

    def test_bootstrap_adds_installed_size_before_packing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); tree = directory / "root"; tree.mkdir()
            builder.build.put(tree, "DEBIAN/control", b"Package: fin3000-printer-setup\nArchitecture: amd64\n")
            builder.build.put(tree, "usr/bin/synthetic-setup", b"x" * 1025)
            artifact = directory / "fin3000-printer-setup_0.0.0_amd64.deb"
            artifact.write_bytes(b"synthetic package only")

            def pack(*args, **kwargs):
                self.assertIn(b"Installed-Size: 4\n", (tree / "DEBIAN/control").read_bytes())
                return subprocess.CompletedProcess([], 0)

            inventory = {"version": "0.0.0", "sourceDateEpoch": 1780000000, "builderImage": "sha256:" + "a" * 64}
            with patch.object(builder.build, "local_docker", return_value=["docker"]), \
                    patch.object(builder.build, "command", side_effect=pack):
                self.assertEqual(builder.compile_package(directory, tree, inventory), artifact)

    def test_bootstrap_uses_the_same_nontransitional_polkit_dependencies(self):
        self.assertEqual(builder.build.AUTH_DEPENDENCIES, "polkitd, pkexec")
        source = (ROOT / "scripts/build-linux-bootstrap.py").read_text()
        self.assertIn("{build.AUTH_DEPENDENCIES}\\n", source)
        self.assertNotIn(", policykit-1", source)
        self.assertIn("gjs (>= 1.80)", source)

    def test_source_is_https_exact_signer_scoped_keyring_and_expiry_checked(self):
        values = dict(line.split(": ", 1) for line in (SOURCE / "fin3000-printer.sources").read_text().splitlines())
        self.assertEqual(values["URIs"], "https://fin3000.com/tools/apt/")
        self.assertEqual(values["Signed-By"], f"{helper.KEYRING} {builder.verify.PRODUCTION.signer}!")
        self.assertEqual(values["Architectures"], "amd64")
        self.assertEqual(values["Check-Date"], "yes")
        self.assertEqual(values["Check-Valid-Until"], "yes")
        self.assertEqual(values["Valid-Until-Max"], "604800")
        self.assertEqual(values["InRelease-Path"], "InRelease")
        self.assertEqual(values["By-Hash"], "force")
        self.assertNotIn("Trusted", values)

    def test_archive_cannot_supply_unrelated_os_packages(self):
        rules = (SOURCE / "fin3000-printer.pref").read_text().split("\n\n")
        self.assertIn("Package: fin3000-printer fin3000-printer-setup", rules[0])
        self.assertIn("o=Fin3000,l=Fin3000,a=stable,n=fin3000,c=main", rules[0])
        self.assertIn("Pin-Priority: 500", rules[0])
        self.assertIn('Pin: origin "fin3000.com"', rules[1])
        self.assertIn("Pin-Priority: -1", rules[1])

    def test_helper_polkit_requires_active_admin_for_exact_script(self):
        policy = ET.parse(SOURCE / "com.fin3000.printer.install.policy").getroot()
        action = policy.find("action")
        self.assertEqual(action.attrib["id"], "com.fin3000.printer.install")
        self.assertEqual(action.findtext("defaults/allow_any"), "no")
        self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
        self.assertEqual(action.findtext("defaults/allow_active"), "auth_admin")
        self.assertEqual(action.findtext("annotate"), "/usr/lib/fin3000-printer-setup/install.py")

    def test_source_changes_and_disable_never_reenable_or_call_apt(self):
        for path, content in ((helper.SOURCES, b"Enabled: no\n"), (helper.SOURCES, b""),
                              (helper.KEYRING, b"other key"), (helper.PREFERENCES, b"Pin-Priority: 1001")):
            with self.subTest(path=path), configuration((path, content)), patch.object(helper, "run_apt") as run:
                with self.assertRaisesRegex(helper.InstallError, "INSTALL_SOURCE_CHANGED"):
                    helper.install()
                run.assert_not_called()
        with configuration():
            helper.check_configuration()

    def test_candidate_requires_exact_download_identity_and_supported_version(self):
        self.assertEqual(helper.candidate_version(candidate()), "0.1.0")
        for value in (None, candidate(version="0.1.0;id"), candidate(architecture="arm64"),
                      candidate(downloadable=False), candidate(uris=[]), candidate(uris=["http://fin3000.com/file"]),
                      candidate(uris=["https://foreign.invalid/file"]), candidate(origins=[])):
            with self.subTest(value=value), self.assertRaises(helper.InstallError):
                helper.candidate_version(value)

    def test_origin_requires_all_remote_origins_trusted_and_no_ambiguous_duplicate(self):
        for field, value in (("trusted", False), ("site", "foreign.invalid"), ("origin", "Ubuntu"),
                             ("label", "other"), ("archive", "testing"), ("component", "universe")):
            package = candidate(); setattr(package.origins[0], field, value)
            with self.subTest(field=field), self.assertRaisesRegex(helper.InstallError, "INSTALL_WRONG_ORIGIN"):
                helper.candidate_version(package)
        package = candidate(); package.origins.append(SimpleNamespace(site="foreign.invalid", trusted=False))
        with self.assertRaises(helper.InstallError):
            helper.candidate_version(package)

    def test_update_failure_prevents_any_install_or_cache_fallback(self):
        with configuration(), patch.object(helper, "run_apt", side_effect=helper.InstallError("INSTALL_UPDATE_FAILED")), \
                patch.object(helper.apt, "Cache") as cache:
            with self.assertRaisesRegex(helper.InstallError, "INSTALL_UPDATE_FAILED"):
                helper.install()
            cache.assert_not_called()

    def test_update_only_own_source_then_install_exact_version_and_recheck_state(self):
        cache = Mock()
        cache.__contains__ = Mock(return_value=True)
        values = [SimpleNamespace(candidate=candidate(), is_installed=False),
                  SimpleNamespace(is_installed=True, installed=SimpleNamespace(version="0.1.0")),
                  SimpleNamespace(is_installed=True, installed=SimpleNamespace(version="0.1.0"))]
        cache.__getitem__ = Mock(side_effect=values)
        retained = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        with configuration(), patch.object(helper.apt, "Cache", return_value=cache), patch.object(helper, "run_apt") as run, \
                patch.object(helper, "retain_candidate", return_value=retained), \
                patch.object(helper, "cached_bytes"), patch.object(helper, "save_journal") as save, \
                patch.object(helper, "installed_status", return_value=("install ok installed", retained.version)):
            helper.install()
            first, second = run.call_args_list
            self.assertIn(f"Dir::Etc::sourcelist={helper.SOURCES}", first.args[0])
            self.assertIn("Dir::Etc::sourceparts=-", first.args[0])
            self.assertIn("APT::Update::Error-Mode=any", first.args[0])
            self.assertEqual(second.args[0], [*helper.apt_preflight_options(), "-o", f"Dir::Cache::archives={PREPARED_ARCHIVES}", "--yes", "--no-remove", "--no-install-recommends", "--reinstall", "install",
                                             str(PREPARED_ARCHIVES / retained.apt_filename)])
            self.assertTrue(second.kwargs["installing"])
            cache.open.assert_not_called()
            self.assertEqual(save.call_args_list[0].args[0], helper.InstallJournal(pending=retained))
            self.assertEqual(save.call_args_list[1].args[0], helper.InstallJournal(current=retained))

    def test_missing_pending_original_blocks_network_and_cannot_be_overwritten(self):
        retained = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        with configuration(), patch.object(helper, "load_journal", return_value=helper.InstallJournal(pending=retained)), \
                patch.object(helper, "run_apt") as run, patch.object(helper, "save_journal") as save:
            with self.assertRaises(FileNotFoundError):
                helper.install()
            run.assert_not_called(); save.assert_not_called()

    def test_installed_version_without_matching_backup_is_not_updated(self):
        cache = Mock()
        cache.__contains__ = Mock(return_value=True)
        selected = ComparableCandidate(**vars(candidate()))
        cache.__getitem__ = Mock(return_value=SimpleNamespace(candidate=selected, is_installed=True,
                                                             installed=SimpleNamespace(version="0.0.9")))
        with configuration(), patch.object(helper.apt, "Cache", return_value=cache), patch.object(helper, "run_apt") as run, \
                patch.object(helper, "retain_candidate") as retain, patch.object(helper, "save_journal") as save:
            with self.assertRaisesRegex(helper.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                helper.install()
            self.assertEqual(run.call_count, 1)
            retain.assert_not_called(); save.assert_not_called()

    def test_failed_install_keeps_previous_bytes_and_pending_record(self):
        old = helper.CachedPackage("0.0.9", "b" * 64, 2048)
        new = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        cache = Mock(); cache.__contains__ = Mock(return_value=True)
        selected = ComparableCandidate(**vars(candidate()))
        cache.__getitem__ = Mock(return_value=SimpleNamespace(candidate=selected, is_installed=True,
                                                             installed=SimpleNamespace(version=old.version)))
        events = []
        def apt(arguments, **kwargs):
            if kwargs.get("installing"):
                self.assertEqual(events, [helper.InstallJournal(old, None, new)])
                raise helper.InstallError("INSTALL_PACKAGE_FAILED")
        with configuration(), patch.object(helper, "load_journal", return_value=helper.InstallJournal(current=old)), \
                patch.object(helper.apt, "Cache", return_value=cache), patch.object(helper, "run_apt", side_effect=apt), \
                patch.object(helper, "retain_candidate", return_value=new), patch.object(helper, "cached_bytes") as read, \
                patch.object(helper, "save_journal", side_effect=events.append), \
                patch.object(helper, "restore_previous", side_effect=helper.InstallError("INSTALL_RECOVERY_REQUIRED")) as restore:
            with self.assertRaisesRegex(helper.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                helper.install()
            self.assertEqual(events, [helper.InstallJournal(old, None, new)])
            self.assertEqual([call.args[0] for call in read.call_args_list], [old, new])
            restore.assert_called_once_with(events[0])

    def test_interrupted_update_restores_before_any_network_lookup(self):
        journal = helper.InstallJournal(current=helper.CachedPackage("0.0.9", "b" * 64, 2048),
                                        pending=helper.CachedPackage("0.1.0", "a" * 64, 4096))
        with configuration(), patch.object(helper, "load_journal", return_value=journal), \
                patch.object(helper, "restore_previous", return_value="INSTALL_RESTORED") as restore, \
                patch.object(helper, "run_apt") as apt, patch.object(helper, 'collect_cache') as collect:
            self.assertEqual(helper.install(), "INSTALL_RESTORED")
            restore.assert_called_once_with(journal); apt.assert_not_called()
            collect.assert_not_called()

    def test_first_install_retry_uses_original_and_only_promotes_after_configured(self):
        record = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        journal = helper.InstallJournal(pending=record)
        for status in (None, ("install ok half-configured", record.version), ("install ok installed", record.version)):
            with self.subTest(status=status), configuration(), patch.object(helper, "load_journal", return_value=journal), \
                    patch.object(helper, "cached_bytes"), patch.object(helper, "installed_status",
                        side_effect=[status, ("install ok installed", record.version)]), \
                    patch.object(helper, "run_apt") as run, patch.object(helper, "save_journal") as save, \
                    patch.object(helper, "retain_candidate") as retain, patch.object(helper.apt, "Cache") as cache:
                self.assertEqual(helper.install(), "INSTALL_COMPLETE")
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0], [*helper.apt_preflight_options(), "-o", f"Dir::Cache::archives={PREPARED_ARCHIVES}", "--yes", "--no-remove", "--no-install-recommends",
                                                       *(["--reinstall"] if status == ("install ok installed", record.version) else []),
                                                       "install", str(PREPARED_ARCHIVES / record.apt_filename)])
                save.assert_called_once_with(helper.InstallJournal(current=record))
                retain.assert_not_called(); cache.assert_not_called()

    def test_first_install_retry_failure_preserves_pending_and_avoids_rollback(self):
        journal = helper.InstallJournal(pending=helper.CachedPackage("0.1.0", "a" * 64, 4096))
        with configuration(), patch.object(helper, "load_journal", return_value=journal), patch.object(helper, "cached_bytes"), \
                patch.object(helper, "installed_status", return_value=None), \
                patch.object(helper, "run_apt", side_effect=helper.InstallError("INSTALL_PACKAGE_FAILED")), \
                patch.object(helper, "save_journal") as save, patch.object(helper, "restore_previous") as restore:
            with self.assertRaisesRegex(helper.InstallError, "INSTALL_PACKAGE_FAILED"):
                helper.install()
            save.assert_not_called(); restore.assert_not_called()

    def test_first_install_retry_rejects_another_version_and_explicit_removal(self):
        journal = helper.InstallJournal(pending=helper.CachedPackage("0.1.0", "a" * 64, 4096))
        for status in (("install ok installed", "0.2.0"), ("install ok installed", "0.0.9"),
                       ("deinstall ok config-files", "0.1.0")):
            with self.subTest(status=status), configuration(), patch.object(helper, "load_journal", return_value=journal), \
                    patch.object(helper, "cached_bytes"), patch.object(helper, "installed_status", return_value=status), \
                    patch.object(helper, "run_apt") as run, patch.object(helper, "save_journal") as save:
                with self.assertRaisesRegex(helper.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                    helper.install()
                run.assert_not_called(); save.assert_not_called()

    def test_package_query_allows_only_real_missing_result_not_database_errors(self):
        for code, output, allowed in ((1, b"", True), (2, b"", False), (1, b"partial", False)):
            with self.subTest(code=code, output=output), patch.object(helper.subprocess, "run",
                    return_value=SimpleNamespace(returncode=code, stdout=output)):
                if allowed:
                    self.assertIsNone(helper.installed_status(missing_ok=True))
                else:
                    with self.assertRaises(helper.InstallError):
                        helper.installed_status(missing_ok=True)

    def test_success_requires_configured_package_and_open_gate(self):
        record = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        for status, ready in ((("install ok half-configured", record.version), b"1\n"),
                              (("install ok installed", record.version), b"0\n")):
            with self.subTest(status=status, ready=ready), configuration((helper.READY, ready)), \
                    patch.object(helper, "cached_bytes"), patch.object(helper, "installed_status", return_value=status), \
                    patch.object(helper, "run_apt"):
                with self.assertRaisesRegex(helper.InstallError, "INSTALL_PACKAGE_FAILED"):
                    helper.install_cached(record)

    def test_restore_only_fixed_cached_package_and_checks_activation_before_clearing_journal(self):
        old = helper.CachedPackage("0.0.9", "b" * 64, 2048)
        new = helper.CachedPackage("0.1.0", "a" * 64, 4096)
        journal = helper.InstallJournal(current=old, pending=new)
        with configuration(), patch.object(helper, "cached_bytes"), \
                patch.object(helper, "dpkg_frontend_lock", return_value=nullcontext()), \
                patch.object(helper, "installed_status", side_effect=[("install ok half-configured", new.version),
                                                                      ("install ok installed", old.version)]), \
                patch.object(helper.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(helper, "save_journal") as save:
            self.assertEqual(helper.restore_previous(journal), "INSTALL_RESTORED")
            self.assertEqual(run.call_args.args[0], ["/usr/bin/dpkg", "--force-confold", "--install", str(helper.STORE / old.filename)])
            self.assertEqual(run.call_args.kwargs["env"], helper.ENV | {"DPKG_FRONTEND_LOCKED": "true"})
            self.assertIsNone(run.call_args.kwargs["timeout"])
            save.assert_called_once_with(helper.InstallJournal(current=old))

    def test_restore_does_not_undo_other_admin_version_or_removal(self):
        journal = helper.InstallJournal(current=helper.CachedPackage("0.0.9", "b" * 64, 2048),
                                        pending=helper.CachedPackage("0.1.0", "a" * 64, 4096))
        for status in (("install ok installed", "0.2.0"), ("deinstall ok config-files", "0.1.0")):
            with self.subTest(status=status), configuration(), patch.object(helper, "cached_bytes"), \
                    patch.object(helper, "dpkg_frontend_lock", return_value=nullcontext()), \
                    patch.object(helper, "installed_status", return_value=status), \
                    patch.object(helper.subprocess, "run") as run, patch.object(helper, "save_journal") as save:
                with self.assertRaisesRegex(helper.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                    helper.restore_previous(journal)
                run.assert_not_called(); save.assert_not_called()

    def test_installer_does_not_kill_dpkg_and_ignores_inherited_environment(self):
        with patch.object(helper.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            helper.run_apt(["install", "fin3000-printer=0.1.0"], installing=True)
            call = run.call_args
            self.assertIsNone(call.kwargs["timeout"])
            self.assertEqual(call.kwargs["env"], helper.ENV)
            self.assertIn("APT::Get::AllowUnauthenticated=false", call.args[0])
            self.assertIn("Acquire::https::Verify-Peer=true", call.args[0])
            self.assertEqual(call.kwargs["stdout"], subprocess.DEVNULL)

    def test_root_action_has_no_url_package_or_command_override(self):
        with patch.object(helper.os, "getuid", return_value=0), patch.object(helper.os, "geteuid", return_value=0), \
                patch.object(helper.sys, "argv", ["install.py", "--whatever"]), patch.object(helper, "install") as install, \
                patch("builtins.print") as output:
            self.assertEqual(helper.main(), 1)
            output.assert_called_once_with("INSTALL_NOT_AUTHORIZED", flush=True)
            install.assert_not_called()

    def test_apt_preflight_is_fixed_read_only_and_requires_apt_context(self):
        self.assertEqual(helper.apt_preflight_options(), [
            '-o', 'DPkg::Pre-Install-Pkgs::=/usr/lib/fin3000-printer-setup/install.py --apt-preflight',
            '-o', 'DPkg::Tools::Options::/usr/lib/fin3000-printer-setup/install.py::Version=1',
            '-o', 'DPkg::Tools::Options::/usr/lib/fin3000-printer-setup/install.py::InfoFD=0'])
        with patch.dict(helper.os.environ, {}, clear=True), patch.object(helper, 'check_configuration') as check:
            with self.assertRaisesRegex(helper.InstallError, 'INSTALL_NOT_AUTHORIZED'):
                helper.verify_apt_transaction()
            check.assert_not_called()
        with patch.object(helper.os, 'getuid', return_value=0), patch.object(helper.os, 'geteuid', return_value=0), \
                patch.object(helper.sys, 'argv', ['install.py', '--apt-preflight']), \
                patch.object(helper, 'verify_apt_transaction') as guard, patch.object(helper, 'install') as install:
            self.assertEqual(helper.main(), 0)
            guard.assert_called_once_with(); install.assert_not_called()

    def test_apt_preflight_rejects_changed_admin_state_and_substituted_packages(self):
        content = b'authenticated synthetic bytes'
        pending = helper.CachedPackage('0.3.0', hashlib.sha256(content).hexdigest(), len(content))
        old = helper.CachedPackage('0.1.0', 'a' * 64, 3)
        path = helper.APT_ARCHIVES / '.fin3000-fixture' / pending.apt_filename
        journal = helper.InstallJournal(current=old, pending=pending)
        with patch.dict(helper.os.environ, {'DPKG_FRONTEND_LOCKED': 'true', 'APT_HOOK_INFO_FD': '0'}, clear=True), \
                patch.object(helper, 'check_configuration'), patch.object(helper, 'load_journal', return_value=journal), \
                patch.object(helper, 'cached_bytes'), patch.object(helper, 'read_trusted', return_value=content) as read, \
                patch.object(helper, 'installed_status', return_value=('install ok installed', '0.1.0')) as status:
            for payload, valid in ((str(path).encode() + b'\n', True), (b'', False),
                                   (b'/etc/passwd\n', False), (b'\x00', False),
                                   ((str(path) + '\n' + str(path) + '\n').encode(), False)):
                with self.subTest(payload=payload), patch.object(helper.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(payload))):
                    if valid:
                        helper.verify_apt_transaction()
                    else:
                        with self.assertRaises(helper.InstallError):
                            helper.verify_apt_transaction()
            for changed in (None, ('install ok installed', '0.2.0'), ('deinstall ok config-files', '0.1.0')):
                status.return_value = changed
                with self.subTest(status=changed), self.assertRaisesRegex(helper.InstallError, 'INSTALL_RECOVERY_REQUIRED'):
                    helper.verify_apt_transaction()
            status.return_value = ('install ok installed', '0.1.0')
            read.return_value = b'substituted bytes'
            with patch.object(helper.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(str(path).encode() + b'\n'))):
                with self.assertRaisesRegex(helper.InstallError, 'INSTALL_PACKAGE_FAILED'):
                    helper.verify_apt_transaction()

    def test_public_keyring_export_uses_only_pinned_public_identity(self):
        data = builder.archive_keyring((ROOT / "signing/linux-release-key.asc").read_bytes())
        self.assertGreater(len(data), 100)
        self.assertNotIn(b"PRIVATE KEY", data)

    def test_dirty_bootstrap_worktree_fails_before_source_key_or_output(self):
        for status in (b" M packaging/linux/bootstrap/install.py\n", b"?? new-public-input.json\n"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / "reports").mkdir()
                output = root / "reports/linux-bootstrap-build-dirty"
                with patch.object(builder, "ROOT", root), patch.object(builder.build, "command",
                        return_value=subprocess.CompletedProcess([], 0, status)), \
                        patch.object(builder, "committed_source") as read, \
                        patch.object(builder, "archive_keyring") as key:
                    with self.assertRaisesRegex(ValueError, "Commit"):
                        builder.stage(output, "sha256:" + "a" * 64)
                    read.assert_not_called(); key.assert_not_called()
                    self.assertFalse(output.exists())

    def test_source_binding_checks_actual_git_blob_after_the_clean_worktree_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}

            def git(*arguments):
                return subprocess.run(["git", *arguments], cwd=root, env=env, check=True,
                                      capture_output=True, timeout=10).stdout

            git("init", "-b", "feature/synthetic-bootstrap-test")
            source = root / "public.json"
            source.write_bytes(b"committed public input\n")
            git("add", "public.json")
            git("-c", "user.name=Bootstrap QA", "-c", "user.email=bootstrap-qa@example.invalid",
                "commit", "-m", "synthetic fixture")
            commit = git("rev-parse", "HEAD").decode().strip()
            self.assertEqual(git("status", "--porcelain", "--untracked-files=all"), b"")
            with patch.object(builder, "ROOT", root):
                self.assertEqual(builder.committed_source(commit, "public.json"), b"committed public input\n")
                source.write_bytes(b"changed after clean check\n")
                with self.assertRaisesRegex(ValueError, "byte-identical"):
                    builder.committed_source(commit, "public.json")
                (root / "untracked.json").write_bytes(b"untracked input\n")
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.committed_source(commit, "untracked.json")
                source.unlink()
                source.symlink_to(root / "untracked.json")
                with self.assertRaises(OSError):
                    builder.committed_source(commit, "public.json")

    def test_builder_refuses_existing_or_foreign_destination_before_any_key_access(self):
        for path in (Path("/etc/apt"), ROOT / "reports", Path("relative"), ROOT / "reports/../wrong"):
            with self.subTest(path=path), patch.object(builder, "archive_keyring") as key:
                with self.assertRaises(ValueError):
                    builder.stage(path, "sha256:" + "a" * 64)
                key.assert_not_called()

    def test_trust_texts_and_same_catalog_tree(self):
        de = json.loads((ROOT / "platforms/linux/locales/de.json").read_text())
        en = json.loads((ROOT / "platforms/linux/locales/en.json").read_text())
        self.assertEqual(de.keys(), en.keys())
        self.assertIn("nicht automatisch", de["installerTrust"])
        self.assertIn("does not automatically", en["installerTrust"])
        self.assertIn("--force-confold", " ".join(helper.OPTIONS))

    def test_gui_does_not_force_exit_or_auto_install_and_launches_printer_as_user(self):
        source = (SOURCE / "app.js").read_text()
        self.assertIn("install.connect('clicked'", source)
        self.assertIn("if (busy)", source)
        self.assertNotIn("force_exit", source)
        self.assertIn("['/usr/bin/fin3000-printer']", source)
        self.assertIn("['INSTALL_COMPLETE', 'INSTALL_RESTORED'].includes(code)", source)
        self.assertIn("child.get_successful() && ready", source)
        self.assertIn("!ok && ready ? 'INSTALL_PACKAGE_FAILED'", source)


if __name__ == "__main__":
    unittest.main()

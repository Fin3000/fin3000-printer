"""Real root filesystem/flock and dpkg-deb checks, in a disposable container.

Mount only this file and bootstrap/install.py read-only. Root state and /tmp
must be private tmpfs. APT acquisition is replaced with a synthetic DEB copy;
the package-owned APT preflight is covered by the separate full HTTPS fixture.
real dpkg installs/restores synthetic packages only. These tests do NOT claim
signed APT acquisition, an installed native printer or native rollback coverage.
"""
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/linux/bootstrap/install.py"


class InstallerCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or not Path('/.dockerenv').is_file() or os.environ.get('FIN3000_INSTALLER_CACHE_CONTAINER') != '1':
            raise RuntimeError('Run only in the explicitly isolated cache container; never host root')
        # No dependency on a host distro binding and no accidental APT calls.
        sys.modules['apt'] = ModuleType('apt')
        spec = importlib.util.spec_from_file_location('bootstrap_cache', SOURCE)
        cls.helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.helper
        spec.loader.exec_module(cls.helper)

    def setUp(self):
        preflight = patch.object(self.helper, 'apt_preflight_options', return_value=[])
        preflight.start(); self.addCleanup(preflight.stop)
        self.helper.APT_ARCHIVES.mkdir(mode=0o755, exist_ok=True)
        parent = Path('/var/lib/fin3000-printer')
        self.temporary = tempfile.TemporaryDirectory(prefix='cache-', dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.store = Path(self.temporary.name) / 'installer'
        self.store_patch = patch.object(self.helper, 'STORE', self.store)
        self.store_patch.start(); self.addCleanup(self.store_patch.stop)

    def record(self, value=b'original synthetic bytes', version='0.1.0'):
        return self.helper.CachedPackage(version, hashlib.sha256(value).hexdigest(), len(value))

    def test_persistent_lock_inode_excludes_another_process(self):
        with self.helper.installer_lock():
            path = self.store / 'lease'
            inode = path.stat().st_ino
            child = subprocess.run(['/usr/bin/python3', '-I', '-c',
                'import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDWR); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)', str(path)],
                capture_output=True, timeout=5)
            self.assertNotEqual(child.returncode, 0)
            self.assertIn(b'BlockingIOError', child.stderr)
        with self.helper.installer_lock():
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o700)

    def test_new_shared_ancestors_remain_traversable_with_private_process_umask(self):
        target = self.store / 'shared' / 'installer'
        previous = os.umask(0o077)
        try:
            with patch.object(self.helper, 'STORE', target), self.helper.installer_lock():
                self.assertEqual(stat.S_IMODE((self.store / 'shared').stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((target / 'lease').stat().st_mode), 0o600)
        finally:
            os.umask(previous)

    def test_public_apt_staging_exposes_only_original_deb_and_cleans_up_on_error(self):
        record = self.record()
        sentinel = self.helper.APT_ARCHIVES / 'synthetic-outside-stage'
        sentinel.write_bytes(b'preserve outside temporary directory')
        self.addCleanup(sentinel.unlink)
        with self.helper.installer_lock():
            self.helper.atomic_store(record.filename, b'original synthetic bytes')
            self.helper.save_journal(self.helper.InstallJournal(pending=record))
            for fail in (False, True):
                directory = None
                try:
                    with self.helper.prepared_archives(record) as directory:
                        target = directory / record.apt_filename
                        self.assertEqual(list(directory.iterdir()), [target])
                        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
                        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
                        reader = ['/usr/bin/python3', '-I', '-c',
                                  'from pathlib import Path; import sys; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())']
                        public = subprocess.run([*reader, str(target)], user='_apt', group='nogroup', extra_groups=[],
                                                capture_output=True, timeout=5)
                        self.assertEqual(public.returncode, 0, public.stderr)
                        self.assertEqual(public.stdout, b'original synthetic bytes')
                        private = subprocess.run([*reader, str(self.store / 'journal.json')], user='_apt',
                                                 group='nogroup', extra_groups=[], capture_output=True, timeout=5)
                        self.assertNotEqual(private.returncode, 0)
                        self.assertIn(b'PermissionError', private.stderr)
                        (directory / 'escape').symlink_to(sentinel)
                        if fail:
                            raise RuntimeError('synthetic interrupted APT call')
                except RuntimeError:
                    self.assertTrue(fail)
                self.assertIsNotNone(directory)
                self.assertFalse(directory.exists())
                self.assertEqual(sentinel.read_bytes(), b'preserve outside temporary directory')
                self.assertEqual(self.helper.cached_bytes(record), b'original synthetic bytes')

    def test_unsafe_apt_archives_parent_is_not_repaired_or_used(self):
        original_mode = stat.S_IMODE(self.helper.APT_ARCHIVES.stat().st_mode)
        with self.helper.installer_lock():
            record = self.record()
            self.helper.atomic_store(record.filename, b'original synthetic bytes')
            try:
                self.helper.APT_ARCHIVES.chmod(0o777)
                with self.assertRaises(self.helper.InstallError):
                    with self.helper.prepared_archives(record):
                        self.fail('unsafe archive admitted')
                self.assertEqual(list(self.helper.APT_ARCHIVES.glob('.fin3000-*')), [])
                self.assertEqual(stat.S_IMODE(self.helper.APT_ARCHIVES.stat().st_mode), 0o777)
            finally:
                self.helper.APT_ARCHIVES.chmod(original_mode)

    def test_journal_roundtrip_and_both_original_packages_are_retained(self):
        old, new = self.record(), self.record(b'next synthetic bytes', '0.2.0')
        with self.helper.installer_lock():
            self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal())
            self.helper.atomic_store(old.filename, b'original synthetic bytes')
            self.helper.atomic_store(new.filename, b'next synthetic bytes')
            journal = self.helper.InstallJournal(current=old, pending=new)
            self.helper.save_journal(journal)
            self.assertEqual(self.helper.load_journal(), journal)
            self.assertEqual(self.helper.cached_bytes(old), b'original synthetic bytes')
            self.assertEqual(self.helper.cached_bytes(new), b'next synthetic bytes')
            self.assertEqual(stat.S_IMODE((self.store / 'journal.json').stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((self.store / old.filename).stat().st_mode), 0o600)

    def test_write_error_before_replace_keeps_previous_complete_record(self):
        with self.helper.installer_lock():
            old = self.helper.InstallJournal(current=self.record())
            self.helper.save_journal(old)
            before = (self.store / 'journal.json').read_bytes()
            with patch.object(self.helper.os, 'replace', side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError):
                    self.helper.save_journal(self.helper.InstallJournal(current=old.current, pending=self.record(b'new')))
            self.assertEqual((self.store / 'journal.json').read_bytes(), before)
            self.assertEqual(self.helper.load_journal(), old)
            self.assertEqual(list(self.store.glob('.writing-*')), [])

    def test_cache_collection_keeps_all_recovery_references_and_stable_lock(self):
        with self.helper.installer_lock():
            records = []
            for index in range(8):
                data = f'synthetic original {index}'.encode()
                record = self.record(data, f'0.{index}.0')
                self.helper.atomic_store(record.filename, data)
                records.append(record)
            journal = self.helper.InstallJournal(records[-2], records[-3], records[-1])
            self.helper.save_journal(journal)
            lease = (self.store / 'lease').stat().st_ino
            sentinel = self.store / 'administrator-note'
            sentinel.write_bytes(b'not a managed package')
            self.helper.collect_cache(journal)
            self.assertEqual({p.name for p in self.store.glob('*.deb')},
                             {r.filename for r in records[-3:]})
            self.assertEqual(self.helper.load_journal(), journal)
            self.assertEqual((self.store / 'lease').stat().st_ino, lease)
            self.assertEqual(sentinel.read_bytes(), b'not a managed package')
            self.helper.collect_cache(journal)
            for record in records[-3:]:
                self.assertEqual(len(self.helper.cached_bytes(record)), record.size)

    def test_collection_validates_recovery_before_removing_any_old_package(self):
        with self.helper.installer_lock():
            old = self.record(b'old original')
            current = self.record(b'current original', '0.2.0')
            self.helper.atomic_store(old.filename, b'old original')
            journal = self.helper.InstallJournal(current=current)
            self.helper.save_journal(journal)
            for invalid in (None, b'corrupt original'):
                if invalid is not None:
                    self.helper.atomic_store(current.filename, invalid)
                with self.assertRaises((OSError, self.helper.InstallError)):
                    self.helper.collect_cache(journal)
                self.assertEqual(self.helper.cached_bytes(old), b'old original')

    def test_collection_never_follows_links_or_removes_unrecognized_files(self):
        with self.helper.installer_lock():
            outside = self.store.parent / 'outside'
            outside.write_bytes(b'keep outside')
            paths = [self.store / (str(index) * 64 + '.deb') for index in range(1, 7)]
            paths[0].symlink_to(outside)
            paths[1].mkdir()
            os.mkfifo(paths[2])
            paths[3].write_bytes(b'content does not match the filename'); paths[3].chmod(0o600)
            paths[4].write_bytes(b'not private'); paths[4].chmod(0o666)
            os.link(outside, paths[5])
            temporary = self.store / '.writing-interrupted'
            temporary.write_bytes(b'unknown interrupted write')
            self.helper.collect_cache(self.helper.InstallJournal())
            self.assertTrue(all(os.path.lexists(path) for path in paths))
            self.assertEqual(outside.read_bytes(), b'keep outside')
            self.assertEqual(temporary.read_bytes(), b'unknown interrupted write')

    def test_bad_unused_previous_does_not_block_collection_or_next_update(self):
        class Selected(SimpleNamespace):
            def __lt__(self, other):
                return False
        with self.helper.installer_lock():
            previous = self.record(b'previous original', '0.1.0')
            current = self.record(b'current original', '0.2.0')
            next_record = self.record(b'next original', '0.3.0')
            stale = self.record(b'obsolete original', '0.0.1')
            self.helper.atomic_store(current.filename, b'current original')
            selected = Selected(version=next_record.version)
            def retain(_candidate):
                self.helper.atomic_store(next_record.filename, b'next original')
                return next_record
            cache = {'fin3000-printer': SimpleNamespace(candidate=selected, is_installed=True,
                      installed=SimpleNamespace(version=current.version))}
            for invalid in (None, b'corrupt previous'):
                with self.subTest(previous=invalid):
                    self.helper.atomic_store(stale.filename, b'obsolete original')
                    if invalid is not None:
                        self.helper.atomic_store(previous.filename, invalid)
                    self.helper.save_journal(self.helper.InstallJournal(current, previous))
                    with patch.object(self.helper, 'check_configuration'), \
                            patch.object(self.helper, 'run_apt'), \
                            patch.object(self.helper.apt, 'Cache', return_value=cache, create=True), \
                            patch.object(self.helper, 'candidate_version', return_value=next_record.version), \
                            patch.object(self.helper, 'retain_candidate', side_effect=retain), \
                            patch.object(self.helper, 'install_cached') as install:
                        self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
                    install.assert_called_once_with(next_record)
                    self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(next_record, current))
                    self.assertFalse((self.store / stale.filename).exists())
                    self.assertEqual(self.helper.cached_bytes(current), b'current original')
                    if invalid is not None:
                        self.assertEqual((self.store / previous.filename).read_bytes(), invalid)

    def test_obsolete_package_io_error_skips_cleanup_but_not_other_candidates(self):
        with self.helper.installer_lock():
            bad = self.record(b'unreadable old file')
            good = self.record(b'reclaimable old file')
            for record, data in ((bad, b'unreadable old file'), (good, b'reclaimable old file')):
                self.helper.atomic_store(record.filename, data)
            original_open = self.helper.os.open
            def failing_open(path, *args, **kwargs):
                if path == bad.filename:
                    raise OSError('synthetic obsolete-file I/O failure')
                return original_open(path, *args, **kwargs)
            with patch.object(self.helper.os, 'open', side_effect=failing_open):
                self.helper.collect_cache(self.helper.InstallJournal())
            self.assertEqual(self.helper.cached_bytes(bad), b'unreadable old file')
            self.assertFalse((self.store / good.filename).exists())

    def test_collection_rejects_a_stale_journal_snapshot_without_deleting(self):
        with self.helper.installer_lock():
            current = self.record(b'current original')
            self.helper.atomic_store(current.filename, b'current original')
            journal = self.helper.InstallJournal(current=current)
            self.helper.save_journal(journal)
            with self.assertRaises(self.helper.InstallError):
                self.helper.collect_cache(self.helper.InstallJournal())
            self.assertEqual(self.helper.load_journal(), journal)
            self.assertEqual(self.helper.cached_bytes(current), b'current original')

    def test_collection_after_terminal_transition_reclaims_abandoned_candidate(self):
        with self.helper.installer_lock():
            current = self.record(b'current original')
            pending = self.record(b'failed candidate', '0.2.0')
            self.helper.atomic_store(current.filename, b'current original')
            self.helper.atomic_store(pending.filename, b'failed candidate')
            journal = self.helper.InstallJournal(current=current, pending=pending)
            self.helper.save_journal(journal)
            self.helper.collect_cache(journal)
            self.assertEqual(self.helper.cached_bytes(pending), b'failed candidate')
            terminal = self.helper.InstallJournal(current=current)
            self.helper.save_journal(terminal)
            self.helper.collect_cache(terminal)
            self.assertFalse((self.store / pending.filename).exists())
            self.assertEqual(self.helper.cached_bytes(current), b'current original')

    def test_duplicate_unknown_truncated_and_invalid_records_are_rejected(self):
        descriptor = asdict(self.record())
        valid = {'schema': 1, 'current': descriptor, 'previous': None, 'pending': None}
        invalid = [b'{', b'{"schema":1,"schema":1,"current":null,"previous":null,"pending":null}',
                   json.dumps(valid | {'schema': True}).encode(), json.dumps(valid | {'extra': 1}).encode(),
                   json.dumps(valid | {'current': descriptor | {'size': True}}).encode(),
                   json.dumps(valid | {'current': descriptor | {'version': '../evil'}}).encode(),
                   json.dumps(valid | {'current': descriptor | {'sha256': 'bad'}}).encode(),
                   json.dumps(valid | {'current': None, 'previous': descriptor}).encode()]
        with self.helper.installer_lock():
            for raw in invalid:
                with self.subTest(raw=raw):
                    self.helper.atomic_store('journal.json', raw)
                    with self.assertRaises(self.helper.InstallError):
                        self.helper.load_journal()

    def test_cached_corruption_size_and_permissions_are_rejected(self):
        record = self.record()
        with self.helper.installer_lock():
            for raw in (b'wrong', b'x' * record.size):
                self.helper.atomic_store(record.filename, raw)
                with self.assertRaises(self.helper.InstallError):
                    self.helper.cached_bytes(record)
            self.helper.atomic_store(record.filename, b'original synthetic bytes')
            path = self.store / record.filename
            path.chmod(0o666)
            with self.assertRaises(self.helper.InstallError):
                self.helper.cached_bytes(record)
            path.chmod(0o600)
            os.link(path, self.store / 'synthetic-hardlink')
            with self.assertRaises(self.helper.InstallError):
                self.helper.cached_bytes(record)

    def test_symlink_fifo_and_writable_lock_are_not_followed(self):
        with self.helper.installer_lock():
            pass
        lease = self.store / 'lease'
        for kind in ('symlink', 'fifo', 'writable', 'hardlink'):
            lease.unlink()
            if kind == 'symlink':
                lease.symlink_to('/dev/null')
            elif kind == 'fifo':
                os.mkfifo(lease, 0o600)
            else:
                lease.write_bytes(b''); lease.chmod(0o666 if kind == 'writable' else 0o600)
                if kind == 'hardlink':
                    os.link(lease, self.store / 'linked-lease')
            with self.subTest(kind=kind), self.assertRaises((OSError, self.helper.InstallError)):
                with self.helper.installer_lock():
                    self.fail('unsafe lock admitted')

    def test_symlink_or_writable_directory_does_not_get_repaired(self):
        self.store.symlink_to('/tmp', target_is_directory=True)
        with self.assertRaises(OSError):
            with self.helper.installer_lock():
                self.fail('symlink admitted')
        self.store.unlink(); self.store.mkdir(mode=0o777); self.store.chmod(0o777)
        with self.assertRaises(self.helper.InstallError):
            with self.helper.installer_lock():
                self.fail('writable directory admitted')
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o777)

    def test_real_deb_identity_and_signed_index_digest_are_both_required(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-deb-') as temporary:
            directory = Path(temporary); tree = directory / 'tree'
            (tree / 'DEBIAN').mkdir(parents=True)
            (tree / 'DEBIAN/control').write_text('Package: fin3000-printer\nVersion: 0.1.0\nArchitecture: amd64\nMaintainer: QA <qa@example.invalid>\nDescription: Synthetic cache fixture only\n')
            artifact = directory / 'synthetic.deb'
            subprocess.run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(tree), str(artifact)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
            raw = artifact.read_bytes()
            candidate = SimpleNamespace(version='0.1.0', sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
            def download(arguments, *, directory):
                self.assertEqual(arguments, ['-o', 'APT::Sandbox::User=_apt', 'download', 'fin3000-printer=0.1.0'])
                self.assertEqual(Path(directory).stat().st_uid, pwd.getpwnam('_apt').pw_uid)
                self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
                self.assertEqual(Path(directory).parent, self.helper.APT_ARCHIVES)
                (Path(directory) / 'fin3000-printer_0.1.0_amd64.deb').write_bytes(raw)
            with self.helper.installer_lock(), patch.object(self.helper, 'candidate_version', return_value='0.1.0'), \
                    patch.object(self.helper, 'run_apt', side_effect=download):
                retained = self.helper.retain_candidate(candidate)
                self.assertEqual(self.helper.cached_bytes(retained), raw)
                candidate.sha256 = '0' * 64
                with self.assertRaises(self.helper.InstallError):
                    self.helper.retain_candidate(candidate)
                # Same authenticated bytes but conflicting declared package identity.
                candidate.sha256 = hashlib.sha256(raw).hexdigest()
                with patch.object(self.helper.subprocess, 'run', return_value=SimpleNamespace(returncode=0,
                                        stdout=b'other-package\t0.1.0\tamd64\n')):
                    with self.assertRaises(self.helper.InstallError):
                        self.helper.retain_candidate(candidate)
                self.assertEqual(list(self.store.glob('.download-*')), [])
                self.assertEqual(list(self.helper.APT_ARCHIVES.glob('.fin3000-*')), [])
                with patch.object(self.helper, 'run_apt', side_effect=self.helper.InstallError('INSTALL_UPDATE_FAILED')):
                    with self.assertRaises(self.helper.InstallError):
                        self.helper.retain_candidate(candidate)
                self.assertEqual(list(self.helper.APT_ARCHIVES.glob('.fin3000-*')), [])

    def test_real_apt_initial_failure_is_retried_from_the_same_original(self):
        # Real APT/dpkg, no sources/network/signing fixture. Only local synthetic
        # package repair is claimed; initial authenticated acquisition is separate.
        marker = Path('/var/lib/fin3000-printer/synthetic-initial-failure')
        marker.write_bytes(b'fail until the synthetic environment recovers')
        ready = Path('/var/lib/fin3000-printer/lifecycle/ready')
        ready.parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='synthetic-first-install-') as temporary:
            tree = Path(temporary) / 'tree'; (tree / 'DEBIAN').mkdir(parents=True)
            (tree / 'DEBIAN/control').write_text('Package: fin3000-printer\nVersion: 0.0.8\nArchitecture: amd64\nMaintainer: QA <qa@example.invalid>\nDescription: Synthetic first-install retry only\n')
            script = tree / 'DEBIAN/postinst'
            script.write_text('#!/bin/sh\nset -eu\nif test -e /var/lib/fin3000-printer/synthetic-initial-failure; then\n  printf "0\\n" > /var/lib/fin3000-printer/lifecycle/ready\n  exit 1\nfi\nprintf "1\\n" > /var/lib/fin3000-printer/lifecycle/ready\n')
            script.chmod(0o755)
            artifact = Path(temporary) / 'fin3000-printer_0.0.8_amd64.deb'
            subprocess.run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(tree), str(artifact)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
            raw = artifact.read_bytes(); record = self.record(raw, '0.0.8')
            command = subprocess.run
            apt_results = []
            def observe(arguments, **kwargs):
                if arguments[0] == '/usr/bin/apt-get':
                    kwargs['stdout'] = subprocess.PIPE; kwargs['stderr'] = subprocess.PIPE
                    result = command(arguments, **kwargs); apt_results.append(result)
                    return result
                return command(arguments, **kwargs)
            with self.helper.installer_lock(), patch.object(self.helper, 'check_configuration'), \
                    patch.object(self.helper.subprocess, 'run', side_effect=observe):
                self.helper.atomic_store(record.filename, raw)
                journal = self.helper.InstallJournal(pending=record)
                self.helper.save_journal(journal)
                self.assertIsNone(self.helper.installed_status(missing_ok=True))
                with self.assertRaisesRegex(self.helper.InstallError, 'INSTALL_PACKAGE_FAILED'):
                    self.helper.install()
                self.assertEqual(self.helper.load_journal(), journal)
                self.assertEqual(self.helper.installed_status(missing_ok=True), ('install ok half-configured', '0.0.8'),
                                 (apt_results[-1].stdout + apt_results[-1].stderr).decode()[-2500:])
                marker.unlink()  # Exact disposable failure marker, not package/user data.
                try:
                    result = self.helper.install()
                except self.helper.InstallError:
                    self.fail((apt_results[-1].stdout + apt_results[-1].stderr).decode()[-2500:])
                self.assertEqual(result, 'INSTALL_COMPLETE')
                self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.0.8'))
                self.assertEqual(ready.read_bytes(), b'1\n')
                self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(current=record))
                self.assertEqual(self.helper.cached_bytes(record), raw)
                # Interrupted promotion can leave the package configured but
                # its activation closed. A no-op APT install cannot repair it:
                # the same trusted original must run its configuration again.
                self.helper.save_journal(journal)
                ready.write_bytes(b'0\n')
                self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
                self.assertEqual(ready.read_bytes(), b'1\n')
                self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(current=record))

    def test_real_dpkg_failure_restores_previous_offline_and_keeps_unrelated_files(self):
        # These writable paths exist only as this test container's tmpfs.
        # Nothing is installed on the host, and no actual printer is created.
        fixture = Path('/usr/share/fin3000-printer-cache-fixture')
        sentinel = fixture / 'unrelated-synthetic-file'
        sentinel.write_bytes(b'preserve unrelated synthetic file')
        ready = Path('/var/lib/fin3000-printer/lifecycle/ready')
        ready.parent.mkdir(exist_ok=True)
        artifacts = []
        with tempfile.TemporaryDirectory(prefix='synthetic-install-') as temporary:
            for version, fail in [('0.1.0', False), ('0.2.0', True)]:
                tree = Path(temporary) / version
                (tree / 'DEBIAN').mkdir(parents=True)
                (tree / 'DEBIAN/control').write_text(f'Package: fin3000-printer\nVersion: {version}\nArchitecture: amd64\nMaintainer: QA <qa@example.invalid>\nDescription: Synthetic offline rollback only\n')
                payload = tree / 'usr/share/fin3000-printer-cache-fixture/version'
                payload.parent.mkdir(parents=True); payload.write_text(version)
                script = tree / 'DEBIAN/postinst'
                script.write_text('#!/bin/sh\nset -eu\nprintf "' + ('0' if fail else '1') + '\\n" > /var/lib/fin3000-printer/lifecycle/ready\n' + ('exit 1\n' if fail else ''))
                script.chmod(0o755)
                artifact = Path(temporary) / f'fin3000-printer_{version}_amd64.deb'
                subprocess.run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(tree), str(artifact)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
                artifacts.append(artifact)
            with self.helper.installer_lock():
                old, new = [self.record(path.read_bytes(), version) for path, version in zip(artifacts, ['0.1.0', '0.2.0'])]
                for record, path in zip((old, new), artifacts):
                    self.helper.atomic_store(record.filename, path.read_bytes())
                installed = subprocess.run(['/usr/bin/dpkg', '--install', str(artifacts[0])],
                                           env=self.helper.ENV, capture_output=True, timeout=30)
                self.assertEqual(installed.returncode, 0, installed.stderr.decode())
                journal = self.helper.InstallJournal(current=old, pending=new)
                self.helper.save_journal(journal)
                failed = subprocess.run(['/usr/bin/dpkg', '--install', str(artifacts[1])],
                                        env=self.helper.ENV, capture_output=True, timeout=30)
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(self.helper.installed_status(), ('install ok half-configured', '0.2.0'))
                self.assertEqual(ready.read_bytes(), b'0\n')
                # Only repo trust configuration is replaced for this synthetic
                # fixture. Real dpkg locks, DB, scripts and bytes are exercised.
                with patch.object(self.helper, 'check_configuration'), patch.object(self.helper, 'run_apt', side_effect=AssertionError('network/APT forbidden')):
                    self.assertEqual(self.helper.install(), 'INSTALL_RESTORED')
                self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.1.0'))
                self.assertEqual((fixture / 'version').read_text(), '0.1.0')
                self.assertEqual(ready.read_bytes(), b'1\n')
                self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(current=old))
                self.assertEqual(self.helper.cached_bytes(old), artifacts[0].read_bytes())
                self.assertEqual(sentinel.read_bytes(), b'preserve unrelated synthetic file')


if __name__ == '__main__':
    unittest.main()

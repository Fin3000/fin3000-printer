"""Actual root trust + kernel flock in a disposable, networkless container.

NOT a host-root test. Mount only this file, the hook, launcher and gate header
read-only under /src, with /tmp and /var/lib/fin3000-printer private tmpfs.
No desktop, CUPS scheduler, account, signing key or network is involved.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class LifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or not Path('/.dockerenv').is_file() or os.environ.get('FIN3000_LIFECYCLE_CONTAINER') != '1':
            raise RuntimeError('Run only in the explicitly isolated lifecycle container; never host root')
        cls.product = runpy.run_path(ROOT / 'packaging/linux/package-lifecycle.py')
        cls.globals = cls.product['quiesce'].__globals__
        cls.temporary = tempfile.TemporaryDirectory(prefix='fin3000-lifecycle-')
        cls.addClassCleanup(cls.temporary.cleanup)
        output = Path(cls.temporary.name)
        harness = '#define _GNU_SOURCE\n#include "package-gate.h"\n#include <stdio.h>\nint main(void) { int fd=package_lease(); if(fd<0)return 75; puts("held"); fflush(stdout); char c; return read(0,&c,1)<0; }\n'
        (output / 'test.c').write_text(harness)
        cls.executable = output / 'lease'
        flags = ['/usr/bin/gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-Wformat=2', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=3']
        subprocess.run([*flags, '-I', str(ROOT / 'platforms/linux'), str(output / 'test.c'), '-o', str(cls.executable)], check=True, timeout=20)
        # Also compile the actual executable, with no execution/root stubs.
        cls.launcher = output / 'launcher'
        subprocess.run([*flags, str(ROOT / 'platforms/linux/launcher.c'), '-o', str(cls.launcher)], check=True, timeout=20)

    def setUp(self):
        self.parent = self.product['directory'](self.product['STATE'], create=True)
        self.addCleanup(os.close, self.parent)
        fd = self.product['quiesce'](self.parent, timeout=0)
        os.close(fd)
        self.product['set_ready'](self.parent, b'1\n')

    def lease_process(self):
        process = subprocess.Popen([str(self.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.close_process, process)
        self.assertEqual(process.stdout.readline(), b'held\n')
        return process

    @staticmethod
    def close_process(process):
        if not process.stdin.closed:
            process.stdin.close()
        process.wait(timeout=3)
        process.stdout.close(); process.stderr.close()

    def ready(self):
        return Path(self.product['STATE'], 'ready').read_bytes()

    def test_multiple_actual_c_readers_block_writer_and_new_admission(self):
        first, second = self.lease_process(), self.lease_process()
        before = Path(self.product['STATE'], 'lease').stat().st_ino
        with self.assertRaises(ValueError):
            self.product['quiesce'](self.parent, timeout=0.02)
        self.assertEqual(self.ready(), b'0\n')
        denied = subprocess.run([str(self.executable)], input=b'', capture_output=True, timeout=2)
        self.assertEqual(denied.returncode, 75)
        self.close_process(first)
        with self.assertRaises(ValueError):
            self.product['quiesce'](self.parent, timeout=0)
        self.close_process(second)
        fd = self.product['quiesce'](self.parent, timeout=0)
        os.close(fd)
        self.assertEqual(Path(self.product['STATE'], 'lease').stat().st_ino, before)

    def test_writer_also_blocks_reader_even_if_ready_file_is_one(self):
        fd = self.product['quiesce'](self.parent, timeout=0)
        try:
            self.product['set_ready'](self.parent, b'1\n')
            result = subprocess.run([str(self.executable)], input=b'', capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 75)
        finally:
            os.close(fd)
        self.lease_process()

    def test_all_invalid_readiness_values_fail_closed(self):
        path = Path(self.product['STATE'], 'ready')
        for value in (b'', b'0\n', b'1', b'1\nextra', b'2\n'):
            with self.subTest(value=value):
                path.write_bytes(value)
                result = subprocess.run([str(self.executable)], input=b'', capture_output=True, timeout=2)
                self.assertEqual(result.returncode, 75)

    def test_symlink_fifo_writable_and_nonroot_files_are_rejected(self):
        # Only disposable entries; the stable lease is never removed.
        base = Path(self.product['STATE'])
        for kind in ('link', 'fifo', 'writable', 'nonroot', 'hardlink'):
            path = base / f'synthetic-{kind}'
            if kind == 'link': path.symlink_to('ready')
            elif kind == 'fifo': os.mkfifo(path)
            elif kind == 'hardlink': os.link(base / 'ready', path)
            else:
                path.write_bytes(b'1\n')
                if kind == 'writable': path.chmod(0o666)
                else: os.chown(path, 1000, 1000)
            try:
                with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                    self.product['regular'](self.parent, path.name)
            finally:
                path.unlink()

    def test_hook_keeps_gate_closed_on_verification_failure_and_abort(self):
        for role, action in (('postinst', 'abort-upgrade'), ('postrm', 'purge')):
            fd = self.product['quiesce'](self.parent, timeout=0); os.close(fd)
            inode = Path(self.product['STATE'], 'lease').stat().st_ino
            self.product['run_hook'](role, [action])
            self.assertEqual(self.ready(), b'0\n')
            self.assertEqual(Path(self.product['STATE'], 'lease').stat().st_ino, inode)
        with patch.dict(self.globals, verify_payload=lambda: (_ for _ in ()).throw(ValueError('bad payload'))), self.assertRaises(ValueError):
            self.product['run_hook']('postinst', ['configure'])
        self.assertEqual(self.ready(), b'0\n')
        with patch.dict(self.globals, verify_payload=lambda: None, reload_profile=lambda: (_ for _ in ()).throw(ValueError('profile failure'))), self.assertRaises(ValueError):
            self.product['run_hook']('postinst', ['configure'])
        self.assertEqual(self.ready(), b'0\n')
        with patch.dict(self.globals, verify_payload=lambda: None, reload_profile=lambda: None):
            self.product['run_hook']('postinst', ['configure'])
        self.assertEqual(self.ready(), b'1\n')

    def test_installed_file_integrity_checks_real_bytes_not_only_manifest(self):
        base = Path(self.product['STATE'])
        # Only the fixed inventory path and absolute entry namespace are fixture
        # inputs. Actual O_NOFOLLOW/root ownership/hash implementation is used.
        manifest = base / 'synthetic-inventory.json'
        files = {}
        for index in range(10):
            path = base / f'synthetic-file-{index}'
            path.write_bytes(b'synthetic payload')
            files[f'/usr/fixture/{index}'] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(files))
        digest = self.product['file_digest']
        with patch.dict(self.globals, INVENTORY=str(manifest), file_digest=lambda path: digest(str(base / f'synthetic-file-{Path(path).name}'))):
            self.product['verify_payload']()
            (base / 'synthetic-file-7').write_bytes(b'corrupt')
            with self.assertRaises(ValueError): self.product['verify_payload']()

    def test_root_launcher_does_not_offer_arbitrary_command_or_desktop(self):
        for args in ([], ['--runtime'], ['--ingress'], ['--secrets'], ['--setup', 'shell'], ['--setup', 'configure', 'extra']):
            result = subprocess.run([str(self.launcher), *args], capture_output=True, timeout=2,
                                    env={'PATH': '/usr/bin:/bin', 'PKEXEC_UID': '1000'})
            self.assertEqual(result.returncode, 1)
        self.product['set_ready'](self.parent, b'0\n')
        result = subprocess.run([str(self.launcher), '--setup', 'configure'], capture_output=True, timeout=2,
                                env={'PATH': '/usr/bin:/bin', 'PKEXEC_UID': '1000'})
        self.assertEqual(result.returncode, 75)


if __name__ == '__main__':
    unittest.main()

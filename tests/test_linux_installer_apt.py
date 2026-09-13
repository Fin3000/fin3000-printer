"""Full installer with real HTTPS/APT/dpkg, ONLY in a disposable container.

Run network-none with fin3000.com mapped to container loopback, private tmpfs
for package/trust state and individually mounted sources. Never host root.
Synthetic TLS/OpenPGP keys and tiny synthetic DEBs, no production credentials,
actual native printer, queue, account, signing identity or public publication.
"""
import gzip
import hashlib
import http.server
import importlib.util
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class InstallerAptTests(unittest.TestCase):
    offline_first_install = False
    failed_first_install = False
    race = None

    @classmethod
    def setUpClass(cls):
        if (os.getuid() != 0 or not Path('/.dockerenv').is_file()
                or os.environ.get('FIN3000_INSTALLER_APT_CONTAINER') != '1'
                or any(name != 'lo' for _index, name in socket.if_nameindex())
                or socket.gethostbyname('fin3000.com') != '127.0.0.1'):
            raise RuntimeError('Requires the isolated network-none installer container; never host root')
        # These are root-mutating integration tests, unlike the read-only
        # signature/index tests. Refuse a container with non-disposable targets.
        mounts = Path('/proc/mounts').read_text().splitlines()
        for target in ('/var/lib/dpkg', '/var/lib/apt', '/var/cache/apt', '/var/log',
                       '/var/lib/fin3000-printer', '/usr/lib/fin3000-printer-setup',
                       '/usr/share/fin3000-printer-cache-fixture', '/usr/share/keyrings',
                       '/etc/apt/sources.list.d', '/etc/apt/preferences.d', '/etc/ssl/certs'):
            if not any(line.split()[1:3] == [target, 'tmpfs'] for line in mounts):
                raise RuntimeError('Missing private tmpfs: ' + target)
        cls.helper = load('real_apt_installer', ROOT / 'packaging/linux/bootstrap/install.py')
        cls.archive = load('real_apt_archive', ROOT / 'scripts/build-linux-archive.py')
        fixture = load('real_apt_signing_fixture', ROOT / 'tests/test_linux_release.py')
        cls.run_gpg = classmethod(fixture.ReleaseTest.run_gpg.__func__)
        fixture.ReleaseTest.setUpClass.__func__(cls)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fin3000-https-installer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0
        self.helper.APT_ARCHIVES.mkdir(mode=0o755, exist_ok=True)
        self.requests = []
        self.apt_output = []
        self.peer_uids = []
        self.served = None
        self.offline = False
        # Represent shared OS-directory ownership in the private dpkg database.
        # Without this base package, removing the sole synthetic package also
        # tries to remove read-only system ancestors/the fixture mount itself.
        base = self.root / 'base'
        (base / 'DEBIAN').mkdir(parents=True)
        (base / 'DEBIAN/control').write_text('Package: fin3000-fixture-base\nVersion: 1.0\n'
            'Architecture: all\nMaintainer: QA <qa@example.invalid>\n'
            'Description: SYNTHETIC shared-directory owner, not a printer\n')
        marker = base / 'usr/share/fin3000-printer-cache-fixture/base-marker'
        marker.parent.mkdir(parents=True)
        marker.write_text('Unrelated synthetic OS package must survive\n')
        base_deb = self.root / 'base.deb'
        subprocess.run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(base), str(base_deb)],
                       check=True, capture_output=True, timeout=20)
        subprocess.run(['/usr/bin/dpkg', '--install', str(base_deb)], check=True, capture_output=True, timeout=20)
        command = subprocess.run

        def observe_apt(arguments, **kwargs):
            # Preserve the real command, environment, exit and effects. Capture
            # only discarded output so an integration failure is diagnosable.
            if arguments[0] != '/usr/bin/apt-get':
                try:
                    return command(arguments, **kwargs)
                except subprocess.CalledProcessError as error:
                    if arguments[0] in ('/usr/bin/dpkg-deb', '/usr/bin/dpkg'):
                        print('Synthetic DEB diagnostic:', (error.stderr or b'').decode()[-2000:], flush=True)
                    raise
            kwargs['stdout'] = subprocess.PIPE
            kwargs['stderr'] = subprocess.PIPE
            result = command(arguments, **kwargs)
            self.apt_output.append(result.stdout + result.stderr)
            if result.returncode or b'unsandboxed as root' in result.stderr:
                print('Synthetic APT diagnostic:', (result.stdout + result.stderr).decode()[-2000:], flush=True)
            return result

        observer = patch.object(self.helper.subprocess, 'run', side_effect=observe_apt)
        observer.start()
        self.addCleanup(observer.stop)
        key, certificate = self.root / 'tls.key', self.root / 'tls.crt'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1',
                        '-subj', '/CN=SYNTHETIC INSTALLER TEST ONLY',
                        '-addext', 'subjectAltName=DNS:fin3000.com',
                        '-addext', 'basicConstraints=critical,CA:TRUE'],
                       check=True, capture_output=True, timeout=30)
        Path('/etc/ssl/certs/ca-certificates.crt').write_bytes(certificate.read_bytes())
        fixture = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(fixture.root), **kwargs)

            def do_GET(self):
                fixture.requests.append(self.path)
                # Observe the actual downloader's kernel socket owner while
                # this loopback request is alive, not just the absence of a
                # warning or the requested APT configuration.
                endpoint = f'0100007F:{self.client_address[1]:04X}'
                peers = [row.split() for row in Path('/proc/net/tcp').read_text().splitlines()[1:]]
                fixture.peer_uids.append((self.path, [int(row[7]) for row in peers
                    if row[1] == endpoint and row[2] == '0100007F:01BB']))
                if fixture.offline:
                    self.send_error(503, 'Synthetic offline repository')
                    return
                # Fixture releases change several times within one second;
                # mtime's second-resolution validator must not serve stale 304s.
                if 'If-Modified-Since' in self.headers:
                    del self.headers['If-Modified-Since']
                prefix = '/tools/apt/'
                if not self.path.startswith(prefix) or fixture.served is None:
                    self.send_error(404)
                    return
                self.path = '/' + fixture.served.name + '/' + self.path[len(prefix):]
                super().do_GET()

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        keyring = self.run_gpg(['--export', self.primary]).stdout
        packaged_hook = self.helper.PACKAGE / 'install.py'
        packaged_hook.write_bytes((ROOT / 'packaging/linux/bootstrap/install.py').read_bytes())
        packaged_hook.chmod(0o755)
        self.helper.KEYRING.write_bytes(keyring)
        public_hash = self.helper.PACKAGE / 'archive-keyring.sha256'
        public_hash.write_text(hashlib.sha256(keyring).hexdigest() + '\n')
        source = (ROOT / 'packaging/linux/bootstrap/fin3000-printer.sources').read_text()
        source = source.replace('6C1594AE8A48B7D7649BEDA7DA6206688A5862E3!', self.signer + '!')
        preferences = (ROOT / 'packaging/linux/bootstrap/fin3000-printer.pref').read_bytes()
        for location in (self.helper.SOURCES, self.helper.PACKAGE / 'fin3000-printer.sources'):
            location.write_text(source)
        for location in (self.helper.PREFERENCES, self.helper.PACKAGE / 'fin3000-printer.pref'):
            location.write_bytes(preferences)
        # The real root entrypoint selects this mask. Keep it through package
        # acquisition and installation; fixture public-source files are already
        # in their package-delivered modes above.
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def publish_synthetic(self, version, *, fail=False, expired=False, tampered=False, invalid_signature=False,
                          changed_release=False, fail_once=False):
        """Private loopback fixture; reuse the actual archive index constructors."""
        self.sequence += 1
        repo = self.root / f'repo-{self.sequence}'
        repo.mkdir()
        tree = self.root / f'package-{self.sequence}'
        (tree / 'DEBIAN').mkdir(parents=True)
        (tree / 'DEBIAN/control').write_text(f'Package: fin3000-printer\nVersion: {version}\n'
            'Architecture: amd64\nMaintainer: QA <qa@example.invalid>\n'
            'Description: SYNTHETIC INSTALLER ONLY\n')
        hook = tree / 'DEBIAN/postinst'
        hook.write_text('#!/bin/sh\nset -eu\nmkdir -p /var/lib/fin3000-printer/lifecycle\n'
            + ('if ! test -f /var/lib/fin3000-printer/synthetic-first-failed; then\n'
               'touch /var/lib/fin3000-printer/synthetic-first-failed\n'
               'printf "0\\n" > /var/lib/fin3000-printer/lifecycle/ready\nexit 1\nfi\n' if fail_once else '')
            + ('touch /var/lib/fin3000-printer/synthetic-changed-release-ran\n' if changed_release else '')
            + ("printf '0\\n' > /var/lib/fin3000-printer/lifecycle/ready\nexit 1\n" if fail else
               "printf '1\\n' > /var/lib/fin3000-printer/lifecycle/ready\n"))
        hook.chmod(0o755)
        payload = tree / 'usr/share/fin3000-printer-cache-fixture/version'
        payload.parent.mkdir(parents=True)
        payload.write_text(version + '\n')
        # The package builder, unlike the installer, must set the distribution
        # modes explicitly. Keep the installer's umask 077 in effect throughout.
        for directory in (tree, tree / 'DEBIAN', tree / 'usr', tree / 'usr/share', payload.parent):
            directory.chmod(0o755)
        (tree / 'DEBIAN/control').chmod(0o644)
        payload.chmod(0o644)
        pool = repo / 'pool/main'
        pool.mkdir(parents=True)
        package = pool / f'fin3000-printer_{version}_amd64.deb'
        subprocess.run(['/usr/bin/dpkg-deb', '--build', '--root-owner-group', str(tree), str(package)],
                       check=True, capture_output=True, timeout=20)
        raw = package.read_bytes()
        record = {'file': package.name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        packages = self.archive.package_record(package, record, 'fin3000-printer', version)
        indexes = {'main/binary-amd64/Packages': packages,
                   'main/binary-amd64/Packages.gz': gzip.compress(packages, mtime=0)}
        for name, data in indexes.items():
            self.archive.put(repo, 'dists/stable/' + name, data)
            digest = hashlib.sha256(data).hexdigest()
            self.archive.put(repo, 'dists/stable/main/binary-amd64/by-hash/SHA256/' + digest, data)
        now = int(time.time())
        release = self.archive.release_file(indexes, now - 172800 if expired else now,
                                            now - 86400 if expired else now + 3600)
        self.archive.put(repo, 'dists/stable/Release', release)
        self.run_gpg(['--yes', '--local-user', self.signer + '!', '--digest-algo', 'SHA256',
                      '--output', str(repo / 'dists/stable/InRelease'), '--clearsign',
                      str(repo / 'dists/stable/Release')])
        if tampered:
            package.write_bytes(b'X' * len(raw))
        if invalid_signature:
            signed = repo / 'dists/stable/InRelease'
            signed.write_bytes(signed.read_bytes().replace(b'Origin: Fin3000', b'Origin: Attacker'))
        self.served = repo
        return self.helper.CachedPackage(version, record['sha256'], record['size'])

    def test_signed_https_install_update_failure_offline_restore_and_invalid_release(self):
        # Everything below calls the real unmodified installer, python-apt,
        # authenticated APT acquisition and actual dpkg. The observer captures
        # output only; no command, environment, outcome or behavior is stubbed.
        if self.race:
            return self.run_race_before_apt_install()
        with self.helper.installer_lock():
            original = self.publish_synthetic('0.1.0', fail_once=self.failed_first_install)
            if self.failed_first_install:
                with self.assertRaises(self.helper.InstallError):
                    self.helper.install()
                self.assertEqual(self.helper.installed_status(), ('install ok half-configured', '0.1.0'))
                self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(pending=original))
            if self.offline_first_install:
                # Acquisition finished, then the process/connection was lost
                # before package mutation. Preserve exactly that pending state.
                self.helper.run_apt(['-o', f'Dir::Etc::sourcelist={self.helper.SOURCES}',
                    '-o', 'Dir::Etc::sourceparts=-', '-o', 'APT::Get::List-Cleanup=0',
                    '-o', 'APT::Update::Error-Mode=any', 'update'])
                candidate = self.helper.apt.Cache()['fin3000-printer'].candidate
                self.assertEqual(self.helper.retain_candidate(candidate), original)
                self.helper.save_journal(self.helper.InstallJournal(pending=original))
                self.offline = True
                self.requests.clear()
            self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
            self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(current=original))
            self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.1.0'))
            if self.offline_first_install:
                self.assertEqual(self.requests, [])
                self.offline = False
            else:
                self.assertTrue(any('/pool/main/' in path for path in self.requests))
            original_bytes = self.helper.cached_bytes(original)
            self.assertFalse(any(b'unsandboxed as root' in output for output in self.apt_output),
                             'APT acquisition fell back to privileged root download')

            self.publish_synthetic('0.2.0', fail=True)
            # The new repository does not contain 0.1.0: recovery must use the
            # retained authenticated original, never a server-side old release.
            self.requests.clear()
            self.assertEqual(self.helper.install(), 'INSTALL_RESTORED')
            self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.1.0'))
            self.assertEqual(self.helper.load_journal(), self.helper.InstallJournal(current=original))
            self.assertFalse(any('0.1.0' in path for path in self.requests))
            self.assertEqual(self.helper.cached_bytes(original), original_bytes)

            latest = self.publish_synthetic('0.3.0')
            self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
            expected = self.helper.InstallJournal(current=latest, previous=original)
            self.assertEqual(self.helper.load_journal(), expected)
            self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
            self.assertEqual(self.helper.load_journal(), expected)

            for options in ({'expired': True}, {'tampered': True}, {'invalid_signature': True}):
                with self.subTest(options=options):
                    self.publish_synthetic('0.4.0', **options)
                    with self.assertRaises(self.helper.InstallError):
                        self.helper.install()
                    self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.3.0'))
                    self.assertEqual(self.helper.load_journal(), expected)
            self.publish_synthetic('0.4.0')
            # Trust failure at TLS, even though the repository's OpenPGP
            # signature would be valid. This is a private container CA bundle.
            Path('/etc/ssl/certs/ca-certificates.crt').write_bytes(b'')
            self.requests.clear()
            with self.assertRaises(self.helper.InstallError):
                self.helper.install()
            self.assertEqual(self.requests, [])
            self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.3.0'))
            self.assertEqual(self.helper.load_journal(), expected)
            self.helper.SOURCES.write_text(self.helper.SOURCES.read_text().replace('Enabled: yes', 'Enabled: no'))
            self.requests.clear()
            with self.assertRaisesRegex(self.helper.InstallError, 'INSTALL_SOURCE_CHANGED'):
                self.helper.install()
            self.assertEqual(self.requests, [])
            self.assertEqual(self.helper.load_journal(), expected)
            self.assertTrue(any('/pool/main/' in path for path, _uids in self.peer_uids))
            self.assertTrue(all(uids == [pwd.getpwnam('_apt').pw_uid] for _path, uids in self.peer_uids),
                            self.peer_uids)
            self.assertFalse(any(b'unsandboxed as root' in output for output in self.apt_output))

    def run_race_before_apt_install(self):
        with self.helper.installer_lock():
            original = self.publish_synthetic('0.1.0')
            self.assertEqual(self.helper.install(), 'INSTALL_COMPLETE')
            self.publish_synthetic('0.3.0')
            install_cached = self.helper.install_cached
            expected_status = None

            def intervene(record, **kwargs):
                nonlocal expected_status
                # Mutate through real package tools at the identified boundary:
                # after our candidate was retained, before APT owns its locks.
                if self.race == 'remove':
                    subprocess.run(['/usr/bin/dpkg', '--remove', 'fin3000-printer'],
                                   check=True, capture_output=True, timeout=20)
                elif self.race == 'upgrade':
                    self.publish_synthetic('0.2.0')
                    subprocess.run(['/usr/bin/dpkg', '--install',
                                    str(self.served / 'pool/main/fin3000-printer_0.2.0_amd64.deb')],
                                   check=True, capture_output=True, timeout=20)
                elif self.race == 'index':
                    self.publish_synthetic('0.3.0', changed_release=True)
                    self.helper.run_apt(['-o', f'Dir::Etc::sourcelist={self.helper.SOURCES}',
                        '-o', 'Dir::Etc::sourceparts=-', '-o', 'APT::Get::List-Cleanup=0',
                        '-o', 'APT::Update::Error-Mode=any', 'update'])
                else:
                    self.fail('unknown synthetic race')
                expected_status = self.helper.installed_status(missing_ok=True)
                self.apt_output.clear()
                return install_cached(record, **kwargs)

            with patch.object(self.helper, 'install_cached', side_effect=intervene):
                try:
                    result = self.helper.install()
                except self.helper.InstallError:
                    result = 'REJECTED'
            self.assertFalse(Path('/var/lib/fin3000-printer/synthetic-changed-release-ran').exists())
            if self.race == 'index' and result == 'INSTALL_COMPLETE':
                # APT can retain the explicit local original despite a changed
                # index. That is valid only if it never executes the replacement.
                self.assertEqual(self.helper.installed_status(), ('install ok installed', '0.3.0'))
                self.assertEqual(self.helper.load_journal().current.version, '0.3.0')
            else:
                self.assertEqual(self.helper.installed_status(missing_ok=True), expected_status)
                self.assertIn(result, ('REJECTED', 'INSTALL_RESTORED'))
                self.assertFalse(any(b'Unpacking fin3000-printer (0.3.0)' in output for output in self.apt_output))
            self.assertEqual(Path('/usr/share/fin3000-printer-cache-fixture/base-marker').read_text(),
                             'Unrelated synthetic OS package must survive\n')
            self.assertEqual(self.helper.cached_bytes(original), (self.helper.STORE / original.filename).read_bytes())


if __name__ == '__main__':
    if '--failed-first-install' in sys.argv:
        sys.argv.remove('--failed-first-install')
        InstallerAptTests.failed_first_install = True
    for option in ('remove', 'upgrade', 'index'):
        flag = '--race-' + option
        if flag in sys.argv:
            if InstallerAptTests.race is not None:
                raise RuntimeError('Select one race per disposable container')
            sys.argv.remove(flag)
            InstallerAptTests.race = option
    if '--offline-first-install' in sys.argv:
        sys.argv.remove('--offline-first-install')
        InstallerAptTests.offline_first_install = True
    if sum((InstallerAptTests.failed_first_install, InstallerAptTests.offline_first_install,
            InstallerAptTests.race is not None)) > 1:
        raise RuntimeError('Select one scenario per disposable container')
    unittest.main()

"""No VMs, downloads, keys, listeners or package installations in these tests."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("vm_probe", Path(__file__).resolve().parents[1] / "scripts/linux-vm-probe.py")
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


class VMProbeTests(unittest.TestCase):
    def test_both_verified_desktop_catalog_formats(self):
        sources = [{"id": "ubuntu-desktop-minimal", "variant": "desktop"},
                   {"id": "ubuntu-desktop", "variant": "desktop"}]
        probe.validate_desktop_source(sources)
        probe.validate_desktop_source({"version": 2, "sources": sources, "kernel": {}})

    def test_catalog_never_guesses_another_source_or_version(self):
        desktop = {"id": "ubuntu-desktop", "variant": "desktop"}
        for catalog in (None, [], [None], {"sources": [desktop]},
                        {"version": 3, "sources": [desktop]},
                        {"version": 2, "sources": "invalid"}, [desktop, desktop],
                        [{"id": "ubuntu-desktop", "variant": "server"}],
                        [{"id": "ubuntu-desktop-minimal", "variant": "desktop"}]):
            with self.subTest(catalog=catalog), self.assertRaises(RuntimeError):
                probe.validate_desktop_source(catalog)

    def test_only_private_owned_report_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "ubuntu24-vm-test"
            directory.mkdir(mode=0o700)
            with patch.object(probe, "REPORTS", root):
                self.assertEqual(probe.private_directory(directory), directory)
                with self.assertRaises(RuntimeError):
                    probe.private_directory(root)
                directory.chmod(0o755)
                with self.assertRaises(RuntimeError):
                    probe.private_directory(directory)
                directory.chmod(0o700)
                alias = root / "ubuntu24-vm-alias"
                alias.symlink_to(directory)
                with self.assertRaises(RuntimeError):
                    probe.private_directory(alias)
                with self.assertRaises(RuntimeError):
                    probe.private_directory(root / "ubuntu24-vm-injected,file=elsewhere")

    def test_no_host_shares_or_devices_and_loopback_only(self):
        directory = Path("/private/vm")
        for mode in ("install", "boot"):
            command = probe.qemu_command(directory, mode, 22424)
            for forbidden in ("-virtfs", "-fsdev", "-usbdevice", "-chardev", "-daemonize", "-enable-kvm"):
                self.assertNotIn(forbidden, command)
            self.assertIn("q35,accel=kvm", command)
            self.assertIn("user,id=qa,restrict=" + ("off" if mode == "install" else "on") +
                          ",hostfwd=tcp:127.0.0.1:22424-:22", command)
            self.assertIn("unix:vnc.sock", command)
            self.assertIn("unix:qmp.sock,server=on,wait=off", command)
            for value in command:
                self.assertNotIn("/dev/", value)

    def test_runtime_does_not_attach_installer_or_seed_secrets(self):
        command = probe.qemu_command(Path("/private/vm"), "boot", 22424)
        self.assertEqual(command.count("-drive"), 1)
        self.assertNotIn("-kernel", command)
        self.assertNotIn("autoinstall", " ".join(command))

    def test_installation_cdroms_are_read_only(self):
        command = probe.qemu_command(Path("/private/vm"), "install", 22424)
        drives = [command[index + 1] for index, value in enumerate(command) if value == "-drive"]
        self.assertEqual(len(drives), 3)
        self.assertTrue(all("media=cdrom,readonly=on" in item for item in drives[1:]))

    def test_invalid_port_and_mode_rejected(self):
        for port in (0, 22, 65536):
            with self.assertRaises(ValueError):
                probe.qemu_command(Path("/private/vm"), "boot", port)
        with self.assertRaises(ValueError):
            probe.qemu_command(Path("/private/vm"), "erase", 22424)

    def test_disposable_identity_ssh_and_install_defaults(self):
        config = probe.cloud_config("ssh-ed25519 synthetic", "$6$synthetic")["autoinstall"]
        self.assertEqual(config["source"]["id"], "ubuntu-desktop")
        self.assertFalse(config["ssh"]["allow-pw"])
        self.assertTrue(config["ssh"]["install-server"])
        self.assertFalse(config["drivers"]["install"])
        self.assertFalse(config["oem"]["install"])
        self.assertEqual(config["shutdown"], "poweroff")
        self.assertNotIn("late-commands", config)
        self.assertNotIn("early-commands", config)
        self.assertNotIn("sudo", json.dumps(config))

    def test_existing_state_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keep"
            path.write_text("original")
            with self.assertRaises(FileExistsError):
                probe.write_new(path, "replacement")
            self.assertEqual(path.read_text(), "original")
            (Path(tmp) / "disk.qcow2").write_bytes(b"existing")
            with patch.object(probe, "verify_iso") as verify, self.assertRaisesRegex(RuntimeError, "never overwrites"):
                probe.prepare(Path(tmp))
            verify.assert_not_called()

    def test_bad_iso_rejected_before_signature_or_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / probe.UBUNTU24.iso_name).write_bytes(b"not an ISO")
            with patch.object(probe, "run") as run, self.assertRaisesRegex(RuntimeError, "ISO size"):
                probe.verify_iso(Path(tmp))
            run.assert_not_called()

    def test_release_directory_and_manifest_cannot_cross_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "ubuntu26-vm-test"
            directory.mkdir(mode=0o700)
            with patch.object(probe, "REPORTS", root):
                self.assertEqual(probe.private_directory(directory, probe.UBUNTU26), directory)
                with self.assertRaises(RuntimeError):
                    probe.private_directory(directory, probe.UBUNTU24)
            (directory / "vm.json").write_text(json.dumps({
                "schema": 1, "isoSha256": probe.UBUNTU24.sha256,
                "guestUser": probe.GUEST_USER, "diskGiB": 40,
            }))
            with patch.object(probe, "run") as run, self.assertRaisesRegex(RuntimeError, "manifest"):
                probe.start(directory, "boot", 22426, probe.UBUNTU26)
            run.assert_not_called()

    def test_ubuntu26_keeps_exact_iso_identity_and_isolation(self):
        release = probe.UBUNTU26
        self.assertEqual(release.iso_name, "ubuntu-26.04.1-desktop-amd64.iso")
        self.assertEqual(release.size, 6482409472)
        command = probe.qemu_command(Path("/private/vm"), "install", 22426, release)
        self.assertIn(release.hostname, command)
        self.assertIn("file=/private/vm/ubuntu-26.04.1-desktop-amd64.iso,format=raw,media=cdrom,readonly=on", command)
        boot = probe.qemu_command(Path("/private/vm"), "boot", 22426, release)
        self.assertIn("user,id=qa,restrict=on,hostfwd=tcp:127.0.0.1:22426-:22", boot)
        self.assertEqual(boot.count("-drive"), 1)
        config = probe.cloud_config("ssh-ed25519 synthetic", "$6$synthetic", release)
        self.assertEqual(config["autoinstall"]["identity"]["hostname"], release.hostname)

    def test_ubuntu26_incomplete_iso_is_rejected_before_any_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / probe.UBUNTU26.iso_name).write_bytes(b"not an ISO")
            with patch.object(probe, "run") as run, self.assertRaisesRegex(RuntimeError, "ISO size"):
                probe.verify_iso(Path(tmp), probe.UBUNTU26)
            run.assert_not_called()

    def test_concurrent_vm_use_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, probe.locked(Path(tmp)):
            with self.assertRaises(BlockingIOError), probe.locked(Path(tmp)):
                self.fail("Concurrent lock acquired")


if __name__ == "__main__":
    unittest.main()

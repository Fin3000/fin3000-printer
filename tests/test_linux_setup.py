"""Actual setup state machine with memory ports: never invokes root/Polkit/CUPS."""
import copy
import hashlib
from pathlib import Path
import runpy
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
product = runpy.run_path(ROOT / "platforms/linux/setup.py")


def mapping():
    return product["installation"](1000, SimpleNamespace(pw_uid=1000, pw_name="synthetic"),
                                   SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_dev=1, st_ino=2), str(uuid4()))


def attributes(value):
    return {"device-uri": product["uri"](value), "printer-op-policy": "authenticated", "printer-error-policy": "abort-job",
            "printer-is-shared": False, "requesting-user-name-allowed": [value["username"]]}


class MemorySystem:
    def __init__(self):
        self.saved = None
        self.current = None
        self.printer = None
        self.policy = b"# administrator-owned comment\n"
        self.events = []
        self.fail_at = None
        self.pending = False

    def event(self, name):
        self.events.append(name)
        if self.fail_at == name:
            raise product["SetupError"]("SYNTHETIC_INTERRUPTION")

    def read_journal(self):
        return copy.deepcopy(self.saved)

    def journal(self, value):
        self.saved = copy.deepcopy(value)
        self.event("journal_" + value["phase"])

    def mapping(self):
        return copy.deepcopy(self.current)

    def put_mapping(self, value):
        self.current = copy.deepcopy(value)
        self.event("mapping")

    def remove_mapping(self, value):
        self.current = None
        self.event("remove_mapping")

    def policies(self, value, *, remove=False):
        self.policy = product["policy_change"](self.policy, value, remove=remove)
        self.event("policy_remove" if remove else "policy")

    def queue(self, value):
        return copy.deepcopy(self.printer)

    def add_queue(self, value):
        assert self.printer is None
        self.printer = attributes(value)
        self.event("queue")

    def remove_queue(self, value):
        if self.printer is not None:
            product["verify_queue"](self.printer, value)
            product["require"](not self.pending, "PRINT_JOBS_PENDING")
        self.printer = None
        self.event("remove_queue")


class SetupTests(unittest.TestCase):
    def test_ubuntu24_loginctl_requires_separate_property_options(self):
        def command(args):
            if args[1] == "show-user":
                return b"14\n"
            if "--property=Active,Remote,Type,Class,User" in args:
                return b""  # Actual Ubuntu 24 loginctl silently returns no properties.
            self.assertEqual(args[3:], ["--property=Active", "--property=Remote", "--property=Type", "--property=Class", "--property=User"])
            return b"User=1000\nRemote=no\nType=wayland\nClass=user\nActive=yes\n"
        with patch.dict(product["active_desktop"].__globals__, run=command):
            product["active_desktop"](1000)

    def test_expired_session_does_not_hide_live_desktop_but_invalid_evidence_never_authorizes(self):
        def command(args):
            if args[1] == "show-user":
                return b"gone 14\n"
            if args[2] == "gone":
                raise product["SetupError"]("SYSTEM_COMMAND_FAILED")
            return b"User=1000\nRemote=no\nType=wayland\nClass=user\nActive=yes\n"
        with patch.dict(product["active_desktop"].__globals__, run=command):
            product["active_desktop"](1000)
        for invalid in (b"User=2000\nRemote=no\nType=wayland\nClass=user\nActive=yes\n",
                        b"User=1000\nRemote=yes\nType=wayland\nClass=user\nActive=yes\n",
                        b"User=1000\nRemote=no\nType=x11\nClass=user\nActive=yes\n", b""):
            with patch.dict(product["active_desktop"].__globals__, run=lambda args: b"14\n" if args[1] == "show-user" else invalid):
                with self.assertRaises(product["SetupError"]):
                    product["active_desktop"](1000)

    def test_installation_binds_exact_uid_username_home_inode_and_new_generation(self):
        value = mapping()
        self.assertEqual(value["queue"], "Fin3000-1000")
        self.assertEqual(value["socketPath"], "/run/user/1000/fin3000-printer/ingest.sock")
        self.assertEqual(value["homeInode"], 2)
        self.assertEqual(product["decode"](product["canonical"](value)), value)
        for uid, name, home_uid, mode in ((0, "root", 0, stat.S_IFDIR), (1000, "bad/../path", 1000, stat.S_IFDIR),
                                          (1000, "synthetic", 1001, stat.S_IFDIR), (1000, "synthetic", 1000, stat.S_IFLNK)):
            with self.subTest(uid=uid, name=name), self.assertRaises(product["SetupError"]):
                product["installation"](uid, SimpleNamespace(pw_uid=uid, pw_name=name),
                    SimpleNamespace(st_mode=mode, st_uid=home_uid, st_dev=1, st_ino=2), str(uuid4()))

    def test_journal_precedes_mutations_and_reopen_keeps_generation(self):
        system, value = MemorySystem(), mapping()
        product["configure"](system, value)
        self.assertEqual(system.events, ["journal_preparing", "mapping", "policy", "queue", "journal_ready"])
        reopened = product["configure"](system, mapping())
        self.assertEqual(reopened, value)
        self.assertEqual(system.events.count("queue"), 1)
        self.assertEqual(system.policy.count(product["marker"](value)), 1)

    def test_every_installation_crash_point_resumes_without_duplicate_queue(self):
        for phase in ("journal_preparing", "mapping", "policy", "queue", "journal_ready"):
            with self.subTest(phase=phase):
                system, value = MemorySystem(), mapping()
                system.fail_at = phase
                with self.assertRaises(product["SetupError"]):
                    product["configure"](system, value)
                system.fail_at = None
                self.assertEqual(product["configure"](system, mapping()), value)
                self.assertEqual(system.saved["phase"], "ready")
                self.assertEqual(system.events.count("queue"), 1)

    def test_foreign_queue_or_mapping_is_never_overwritten(self):
        for foreign in ("queue", "mapping"):
            system, value = MemorySystem(), mapping()
            if foreign == "queue":
                system.printer = attributes(mapping())
            else:
                system.current = mapping()
            before = copy.deepcopy(vars(system))
            with self.subTest(foreign=foreign), self.assertRaises(product["SetupError"]):
                product["configure"](system, value)
            self.assertEqual(vars(system), before)

    def test_queue_policy_acl_device_or_sharing_drift_fails_closed(self):
        value = mapping()
        for key, changed in (("device-uri", "file:/tmp/foreign"), ("printer-op-policy", "default"),
                             ("printer-error-policy", "retry-job"), ("printer-is-shared", True),
                             ("requesting-user-name-allowed", ["all"])):
            with self.subTest(key=key), self.assertRaises(product["SetupError"]):
                product["verify_queue"]({**attributes(value), key: changed}, value)

    def test_journal_shape_duplicate_keys_and_uid_reuse_are_rejected(self):
        value = mapping()
        good = {"version": 1, "phase": "ready", "mapping": value}
        for malformed in ([], {**good, "path": "/etc/passwd"}, {**good, "phase": "other"},
                          {**good, "mapping": {**value, "homeInode": 999}},
                          {**good, "mapping": {**value, "uid": 1001}}):
            system = MemorySystem()
            system.saved = malformed
            with self.subTest(malformed=malformed), self.assertRaises(product["SetupError"]):
                product["configure"](system, value)
            self.assertEqual(system.events, [])
        with self.assertRaises(product["SetupError"]):
            product["decode"](b'{"uid":1000,"uid":1001}')

    def test_own_policy_block_roundtrip_preserves_other_users_and_admin_bytes(self):
        first, second = mapping(), {**mapping(), "uid": 1001}
        original = b"# unchanged\n/other/profile r,\n"
        one = product["policy_change"](original, first)
        two = product["policy_change"](one, second)
        self.assertEqual(product["policy_change"](two, first), two)
        self.assertEqual(product["policy_change"](two, first, remove=True), product["policy_change"](original, second))
        self.assertEqual(product["policy_change"](one, first, remove=True), original)
        for drift in (one + product["marker"](first), one.replace(b"Px ->", b"ux #"), b"# no final newline"):
            with self.subTest(drift=drift), self.assertRaises(product["SetupError"]):
                product["policy_change"](drift, first)

    def test_remove_keeps_recovery_tombstone_and_reinstall_has_new_generation(self):
        system, value = MemorySystem(), mapping()
        original = system.policy
        product["configure"](system, value)
        product["remove"](system, mapping())
        self.assertIsNone(system.printer)
        self.assertIsNone(system.current)
        self.assertEqual(system.policy, original)
        self.assertEqual(system.saved["phase"], "removed")
        new = product["configure"](system, mapping())
        self.assertNotEqual(new["generation"], value["generation"])

    def test_removal_never_deletes_pending_jobs_and_can_resume(self):
        system, value = MemorySystem(), mapping()
        product["configure"](system, value)
        system.pending = True
        with self.assertRaisesRegex(product["SetupError"], "PRINT_JOBS_PENDING"):
            product["remove"](system, mapping())
        self.assertEqual(system.current, value)
        self.assertEqual(system.saved["phase"], "removing")
        with self.assertRaisesRegex(product["SetupError"], "REMOVAL_INCOMPLETE"):
            product["configure"](system, mapping())
        system.pending = False
        product["remove"](system, mapping())
        self.assertEqual(system.saved["phase"], "removed")

    def test_real_cups_port_requests_job_id_or_pycups_silently_omits_jobs(self):
        value = mapping()
        connection = MagicMock()
        connection.getPrinterAttributes.return_value = attributes(value)
        def jobs(**options):
            if "job-id" not in options["requested_attributes"]:
                return {}  # pycups cannot key its result without requested job-id.
            return {17: {"job-id": 17, "job-printer-uri": "ipp://localhost/printers/" + value["queue"]}}
        connection.getJobs.side_effect = jobs
        system = object.__new__(product["System"])
        system.connection = connection
        system.cups = product["cups"]
        with patch.dict(product["run"].__globals__, run=MagicMock()) as globals_:
            with self.assertRaisesRegex(product["SetupError"], "PRINT_JOBS_PENDING"):
                system.remove_queue(value)
            globals_["run"].assert_not_called()
        connection.rejectJobs.assert_called_once_with(value["queue"], reason="Fin3000 removal in progress")

    def test_all_removal_crash_points_resume_without_removing_other_policy(self):
        for phase in ("journal_removing", "remove_queue", "policy_remove", "remove_mapping", "journal_removed"):
            system, value = MemorySystem(), mapping()
            product["configure"](system, value)
            original = b"# administrator-owned comment\n"
            system.fail_at = phase
            with self.subTest(phase=phase), self.assertRaises(product["SetupError"]):
                product["remove"](system, mapping())
            system.fail_at = None
            product["remove"](system, mapping())
            self.assertEqual(system.saved["phase"], "removed")
            self.assertEqual(system.policy, original)

    def test_policy_contract_rejects_unreviewed_authenticated_configuration(self):
        fake = b"<Policy authenticated>synthetic</Policy>"
        parent = product["INCLUDE"].encode()
        with self.assertRaises(product["SetupError"]):
            product["policy_contract"](fake, parent)
        globals_ = product["policy_contract"].__globals__
        with patch.dict(globals_, POLICY_DIGEST=hashlib.sha256(fake).hexdigest()):
            product["policy_contract"](fake, parent)
            for config, layout in ((fake + fake, parent), (fake, parent + parent), (fake, b"no include")):
                with self.assertRaises(product["SetupError"]):
                    product["policy_contract"](config, layout)

    def test_polkit_is_active_admin_only_without_keep_or_gui_root(self):
        policy = ET.parse(ROOT / "platforms/linux/com.fin3000.printer.setup.policy").getroot()
        action = policy.find("action")
        self.assertEqual(action.findtext("defaults/allow_active"), "auth_admin")
        self.assertEqual(action.findtext("defaults/allow_inactive"), "no")
        self.assertEqual(action.findtext("defaults/allow_any"), "no")
        self.assertEqual({item.attrib["key"]: item.text for item in action.findall("annotate")}, {
            "org.freedesktop.policykit.exec.path": "/usr/bin/fin3000-printer",
            "org.freedesktop.policykit.exec.argv1": "--setup"})
        self.assertNotIn("allow_gui", ET.tostring(policy).decode())
        renderer = runpy.run_path(ROOT / "platforms/linux/apparmor.py")
        self.assertEqual(product["TRANSITION"], renderer["cups_transition"]())

    def test_actual_helper_without_polkit_denies_before_any_mutation(self):
        result = subprocess.run(["/usr/bin/python3", "-B", "-I", str(ROOT / "platforms/linux/setup.py"), "configure"],
                                capture_output=True, check=False, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(product["decode"](result.stdout), {"ok": False, "code": "POLKIT_REQUIRED"})
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()

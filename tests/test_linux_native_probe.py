"""Nonprivileged contract tests. No queue, service, profile or keyring changes."""
import importlib.util
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("native_probe", Path(__file__).resolve().parents[1] / "scripts/linux-native-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class NativeProbeTests(unittest.TestCase):
    def test_clean_desktop_without_printers_is_allowed(self):
        with patch.object(probe, "queue_attributes", return_value=None), patch.object(probe, "run") as run:
            probe.require_unused_queue()
            run.assert_not_called()

    def test_existing_queue_and_ipp_errors_are_not_treated_as_clean_desktop(self):
        for attributes in [{}, {"printer-op-policy": "default"}]:
            with patch.object(probe, "queue_attributes", return_value=attributes):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    probe.require_unused_queue()
        with patch.object(probe, "queue_attributes", side_effect=probe.cups.IPPError(probe.cups.IPP_FORBIDDEN, "synthetic")):
            with self.assertRaises(probe.cups.IPPError):
                probe.require_unused_queue()

    def test_exact_pdf_mode_remains_byte_bound(self):
        probe.verify_pdf(probe.pdf_fixture())
        with self.assertRaises(RuntimeError):
            probe.verify_pdf(probe.pdf_fixture() + b"extra")

    def test_firefox_pdf_requires_exact_marker_and_one_page(self):
        valid = SimpleNamespace(stdout=(probe.MARKER + "\n\f").encode())
        one_page = SimpleNamespace(stdout=b"Pages: 1\n")
        with patch.object(probe, "run", side_effect=[valid, one_page]):
            probe.verify_pdf(b"%PDF-synthetic", firefox=True)
        for outputs in [[SimpleNamespace(stdout=b"other document"), one_page],
                        [valid, SimpleNamespace(stdout=b"Pages: 2\n")]]:
            with patch.object(probe, "run", side_effect=outputs), self.assertRaises(RuntimeError):
                probe.verify_pdf(b"%PDF-synthetic", firefox=True)
        with patch.object(probe, "run") as run, self.assertRaises(RuntimeError):
            probe.verify_pdf(b"not a PDF", firefox=True)
        run.assert_not_called()

    def test_firefox_pdf_parser_cannot_run_as_root(self):
        with patch.object(probe.os, "getuid", return_value=0), patch.object(probe, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "as root is forbidden"):
                probe.verify_pdf(b"%PDF-synthetic", firefox=True)
            run.assert_not_called()

    def test_only_exact_reviewed_policy_and_authentication_are_reused(self):
        block = "<Policy authenticated>\nsynthetic reviewed fixture\n</Policy>"
        with patch.object(probe, "AUTHENTICATED_POLICY_SHA256", probe.digest(block.encode())):
            probe.verify_existing_policy("DefaultAuthType Basic\n" + block)
            for config in [block, "DefaultAuthType None\n" + block,
                           "DefaultAuthType Basic\n" + block * 2,
                           "DefaultAuthType Basic\n" + block.replace("reviewed", "changed")]:
                with self.assertRaises(RuntimeError):
                    probe.verify_existing_policy(config)

    def test_stopped_jobs_are_not_confused_with_running_jobs(self):
        probe.require_idle_jobs({})
        probe.require_idle_jobs({"164": {"job-state": 6}})
        probe.require_idle_jobs({"164": {"job-state": 4, "job-hold-until": "indefinite"}})
        for job in [{}, {"job-state": 3}, {"job-state": 5}, {"job-state": 4},
                    {"job-state": 4, "job-hold-until": "evening"}, {"job-state": 99}]:
            with self.subTest(job=job), self.assertRaisesRegex(RuntimeError, "wait for idle"):
                probe.require_idle_jobs({"164": job})

    def test_job_snapshot_only_reads_lifecycle_metadata_and_excludes_test_queue(self):
        old = {"job-state": 6, "job-printer-uri": "ipp://localhost/printers/Existing"}
        own = {"job-state": 5, "job-printer-uri": "ipp://localhost/printers/" + probe.QUEUE}
        with patch.object(probe, "connection") as connection:
            connection.return_value.getJobs.return_value = {164: old, 200: own}
            self.assertEqual(probe.jobs_snapshot(), {"164": old})
            connection.return_value.getJobs.assert_called_once_with(
                which_jobs="not-completed", requested_attributes=probe.JOB_FIELDS)
            self.assertNotIn("job-name", probe.JOB_FIELDS)
            self.assertNotIn("job-originating-user-name", probe.JOB_FIELDS)
            self.assertIn("job-id", probe.JOB_FIELDS)

    def test_admission_side_effect_check_requests_job_ids(self):
        with patch.object(probe, "connection") as connection:
            connection.return_value.getJobs.return_value = {
                164: {"job-printer-uri": "ipp://localhost/printers/Existing"},
                200: {"job-printer-uri": "ipp://localhost/printers/" + probe.QUEUE}}
            self.assertEqual(probe.own_job_ids(), [200])
            connection.return_value.getJobs.assert_called_once_with(
                which_jobs="all", requested_attributes=["job-id", "job-printer-uri"])

    def test_cups_configuration_is_not_a_write_target(self):
        with patch.object(probe, "regular_snapshot") as snapshot:
            with self.assertRaisesRegex(RuntimeError, "Unexpected write target"):
                probe.tracked_write({"files": []}, probe.CUPSD, b"changed")
            snapshot.assert_not_called()

    def test_only_live_ipp_not_found_counts_as_an_absent_queue(self):
        with patch.object(probe, "connection") as connection:
            connection.return_value.getPrinterAttributes.side_effect = probe.cups.IPPError(probe.cups.IPP_NOT_FOUND, "synthetic")
            self.assertIsNone(probe.queue_attributes())
            connection.return_value.getPrinterAttributes.side_effect = probe.cups.IPPError(probe.cups.IPP_FORBIDDEN, "synthetic")
            with self.assertRaises(probe.cups.IPPError):
                probe.queue_attributes()

    def test_cleanup_deletes_only_verified_live_queue_and_checks_absence(self):
        own = {"device-uri": "fin3000nativeprobe:/local", "printer-op-policy": "authenticated",
               "printer-is-shared": False, "requesting-user-name-allowed": ["synthetic_owner"]}
        with patch.object(probe, "account") as account, patch.object(probe, "run") as run, \
             patch.object(probe, "queue_attributes", side_effect=[own, None]):
            account.return_value.pw_name = "synthetic_owner"
            probe.remove_test_queue(1000)
            run.assert_called_once_with(["/usr/sbin/lpadmin", "-x", probe.QUEUE])

    def test_cleanup_refuses_changed_queue_or_failed_deletion(self):
        own = {"device-uri": "fin3000nativeprobe:/local", "printer-op-policy": "authenticated",
               "printer-is-shared": False, "requesting-user-name-allowed": ["synthetic_owner"]}
        for key, value in [("device-uri", "ipp://elsewhere"), ("printer-op-policy", "default"),
                           ("printer-is-shared", True), ("requesting-user-name-allowed", ["another_user"])]:
            with patch.object(probe, "account") as account, patch.object(probe, "run") as run, \
                 patch.object(probe, "queue_attributes", return_value={**own, key: value}):
                account.return_value.pw_name = "synthetic_owner"
                with self.assertRaisesRegex(RuntimeError, "not removed"):
                    probe.remove_test_queue(1000)
                run.assert_not_called()
        with patch.object(probe, "account") as account, patch.object(probe, "run"), \
             patch.object(probe, "queue_attributes", return_value=own):
            account.return_value.pw_name = "synthetic_owner"
            with self.assertRaisesRegex(RuntimeError, "journal retained"):
                probe.remove_test_queue(1000)

    @unittest.skipIf(os.getuid() == 0, "This contract exercises user-owned socket ACLs without elevation")
    def test_named_root_acl_on_disposable_user_socket_without_group_access(self):
        with tempfile.TemporaryDirectory(prefix="fin3000-native-acl-test-") as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir(mode=0o700)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server, \
                 patch.object(probe, "RUNTIME", runtime):
                path = runtime / "ingest.sock"
                server.bind(str(path))
                path.chmod(0o600)
                probe.allow_confined_root_peer(runtime, os.getuid())
                probe.allow_confined_root_peer(path, os.getuid())
                self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o710)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o660)
                # Group-class mode bits are the ACL mask, NOT owning-group access.
                acl = probe.run(["/usr/bin/getfacl", "--omit-header", "--numeric", path]).stdout.decode()
                self.assertIn("group::---", acl)
                self.assertIn("user:0:rw-", acl)

    def test_acl_never_follows_a_substituted_socket_symlink(self):
        with tempfile.TemporaryDirectory(prefix="fin3000-native-acl-test-") as temporary:
            runtime = Path(temporary)
            path = runtime / "ingest.sock"
            path.symlink_to("/etc/shadow")
            with patch.object(probe, "RUNTIME", runtime), patch.object(probe, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    probe.allow_confined_root_peer(path, os.getuid())
                run.assert_not_called()

    def test_backend_profile_has_no_unconfined_fallback_or_network(self):
        text = probe.apparmor_policy()
        self.assertNotIn("complain", text)
        self.assertNotIn("capability,", text)
        self.assertNotIn("file,", text)
        self.assertNotIn(" ux", text)
        self.assertIn("deny network inet,", text)
        self.assertIn("deny /etc/shadow r,", text)
        self.assertIn("/dev/null rw,", text)
        self.assertIn("Px -> fin3000-native-probe", probe.apparmor_transition())

    def test_native_peer_requires_root_and_exact_enforcing_label(self):
        probe.verify_backend_peer(0, "fin3000-native-probe (enforce)")
        for uid, label in [(1000, "fin3000-native-probe (enforce)"), (0, "unconfined"),
                           (0, "fin3000-native-probe"), (0, "fin3000-native-probe (complain)"),
                           (0, "other-profile (enforce)")]:
            with self.subTest(uid=uid, label=label), self.assertRaisesRegex(RuntimeError, "backend peer"):
                probe.verify_backend_peer(uid, label)

    def test_recovery_rejects_arbitrary_paths_before_access(self):
        with patch.object(probe, "regular_snapshot") as snapshot:
            for path in ["/etc/shadow", "/", "/home/synthetic-user", "/etc/cups/printers.conf", str(probe.CUPSD)]:
                with self.assertRaisesRegex(RuntimeError, "unexpected target"):
                    probe.restore_entry({"path": path})
            snapshot.assert_not_called()

    def test_recovery_never_overwrites_later_admin_changes(self):
        entry = {"path": str(probe.LOCAL), "before": {"hex": b"original".hex(), "mode": 0o640, "gid": 7},
                 "sha256": probe.digest(b"our configuration")}
        with patch.object(probe, "regular_snapshot", return_value={"hex": b"later admin change".hex(), "mode": 0o640, "gid": 7}), \
             patch.object(probe, "atomic_write") as write:
            with self.assertRaisesRegex(RuntimeError, "not overwritten"):
                probe.restore_entry(entry)
            write.assert_not_called()

    def test_recovery_preserves_original_bytes_mode_group(self):
        entry = {"path": str(probe.LOCAL), "before": {"hex": b"original\x00bytes".hex(), "mode": 0o640, "gid": 7},
                 "sha256": probe.digest(b"our configuration")}
        with patch.object(probe, "regular_snapshot", return_value={"hex": b"our configuration".hex(), "mode": 0o644, "gid": 7}), \
             patch.object(probe, "atomic_write") as write:
            probe.restore_entry(entry)
            write.assert_called_once_with(probe.LOCAL, b"original\x00bytes", 0o640, 7)

    def test_synthetic_pdf_reuses_known_fixture(self):
        pdf = probe.pdf_fixture()
        self.assertEqual(len(pdf), 614)
        self.assertEqual(probe.digest(pdf), "ae8a8c7b234ce6e6631a95585aead900fe8ff392abd0d084eeb6125d9a42325f")

    def test_source_matches_reviewed_digest(self):
        self.assertEqual(probe.digest(probe.backend_source()), probe.BACKEND_SOURCE_SHA256)

    def test_append_uses_same_snapshot_for_content_and_recovery(self):
        before = {"hex": b"admin configuration\n".hex(), "mode": 0o640, "gid": 7}
        journal = {"files": []}
        with patch.object(probe, "regular_snapshot", return_value=before), \
             patch.object(probe, "journal_write"), patch.object(probe, "atomic_write") as write:
            probe.tracked_write(journal, probe.LOCAL, b"our policy", append=True)
            write.assert_called_once_with(probe.LOCAL, b"admin configuration\nour policy", 0o640, 7)
            self.assertEqual(journal["files"][0]["before"], before)

    def test_append_refuses_drift_before_write(self):
        before = {"hex": b"original".hex(), "mode": 0o644, "gid": 0}
        changed = {**before, "hex": b"admin edit".hex()}
        with patch.object(probe, "regular_snapshot", side_effect=[before, changed]), \
             patch.object(probe, "journal_write"), patch.object(probe, "atomic_write") as write:
            with self.assertRaisesRegex(RuntimeError, "changed during preparation"):
                probe.tracked_write({"files": []}, probe.LOCAL, b"policy", append=True)
            write.assert_not_called()

    def test_new_probe_target_cannot_overwrite_existing_file(self):
        before = {"hex": b"existing backend".hex(), "mode": 0o700, "gid": 0}
        with patch.object(probe, "regular_snapshot", return_value=before), \
             patch.object(probe, "atomic_write") as write:
            with self.assertRaisesRegex(RuntimeError, "appeared during preparation"):
                probe.tracked_write({"files": []}, probe.BACKEND, b"binary")
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()

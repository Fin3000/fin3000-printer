"""Compile real product C with hardening; no host install, queue or root execution."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="fin3000-backend-contract-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.output = Path(cls.temporary.name)
        headers = Path(os.environ.get("FIN3000_NATIVE_INCLUDE", "/usr/include"))
        if not (headers / "cups/cups.h").is_file() or not (headers / "json-c/json.h").is_file():
            raise RuntimeError("Build requires Ubuntu libcups2-dev and libjson-c-dev headers, or explicit FIN3000_NATIVE_INCLUDE sysroot")
        flags = ["/usr/bin/gcc", "-std=c11", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wl,-z,relro,-z,now", "-I", str(headers)]
        for name, source, libs in (
            ("backend", "platforms/linux/cups-backend.c", ["-Wl,-l:libcups.so.2", "-Wl,-l:libjson-c.so.5", "-lcrypto"]),
            ("contract", "tests/fixtures/linux-backend-contract.c", ["-Wl,-l:libcups.so.2", "-Wl,-l:libjson-c.so.5", "-lcrypto"]),
            ("validator", "platforms/linux/pdf-validator.c", []),
        ):
            subprocess.run([*flags, str(ROOT / source), *libs, "-o", str(cls.output / name)], check=True, capture_output=True, timeout=30)

    def test_real_helpers_pass_strict_identity_title_and_path_contract(self):
        subprocess.run([str(self.output / "contract")], check=True, timeout=5)

    def test_backend_discovery_has_no_output_and_nonroot_job_invocation_is_rejected(self):
        result = subprocess.run([str(self.output / "backend")], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        result = subprocess.run([str(self.output / "backend"), "1", "synthetic", "PRIVATE TITLE", "1", ""], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"PRIVATE TITLE", result.stderr)
        self.assertIn(b"INVOCATION_DENIED", result.stderr)

    def test_validator_requires_enforcing_profile_before_reading_or_parsing(self):
        result = subprocess.run([str(self.output / "validator")], input=b"%PDF-synthetic", capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout + result.stderr, b"")

    def test_both_actual_profiles_compile_without_loading_any_kernel_policy(self):
        profiles = runpy.run_path(ROOT / "platforms/linux/apparmor.py")
        source = profiles["backend_profile"]() + profiles["validator_profile"]()
        subprocess.run(["/usr/sbin/apparmor_parser", "-Q", "-T"], input=source.encode(), check=True, capture_output=True, timeout=10)
        self.assertNotIn("abstractions/base", source)
        self.assertIn("deny network inet", source)
        self.assertIn("deny network,", profiles["validator_profile"]())
        self.assertNotIn("capability", source)
        self.assertIn("/usr/lib/fin3000-printer/bin/no-core.so mr,", profiles["validator_profile"]())
        self.assertNotIn("/usr/lib/fin3000-printer/**", profiles["validator_profile"]())
        self.assertIn("/usr/lib/cups/backend/fin3000 Px -> fin3000-printer-backend", profiles["cups_transition"]())

    def test_root_mapping_directory_walk_and_os_locale_are_explicitly_permitted(self):
        profiles = runpy.run_path(ROOT / "platforms/linux/apparmor.py")
        source = profiles["backend_profile"]()
        for rule in ("  / r,", "  /etc/ r,", "/etc/locale.alias r,", "/etc/gnutls/config r,",
                     "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules* r,"):
            self.assertIn(rule, source)
        self.assertNotIn("/etc/** r,", source)
        self.assertIn("deny /home/** rwklmx,", source)

    def test_product_ppd_passes_the_real_cups_validator(self):
        subprocess.run(["/usr/bin/cupstestppd", "-q", str(ROOT / "platforms/linux/fin3000.ppd")],
                       check=True, capture_output=True, timeout=10)


if __name__ == "__main__":
    unittest.main()

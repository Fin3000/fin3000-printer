"""Offline vendor-boundary tests using an ephemeral RSA identity, never prod keys."""
from dataclasses import replace
import base64
import hashlib
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "node_runtime_test", Path(__file__).resolve().parents[1] / "scripts/verify-node-runtime.py")
vendor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vendor
SPEC.loader.exec_module(vendor)


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="fin3000-test-vendor-key-")
        cls.addClassCleanup(cls.keys.cleanup)
        cls.addClassCleanup(subprocess.run, ["/usr/bin/gpgconf", "--homedir", cls.keys.name,
                            "--kill", "gpg-agent"], check=True, capture_output=True, timeout=10)
        cls.gpg = ["/usr/bin/gpg", "--no-options", "--homedir", cls.keys.name, "--batch",
                   "--pinentry-mode", "loopback", "--passphrase", ""]
        cls.run_gpg(["--quick-generate-key", "SYNTHETIC VENDOR TEST ONLY", "rsa2048", "sign", "1d"])
        cls.listing = cls.run_gpg(["--with-colons", "--list-keys"]).stdout.decode()
        cls.primary = next(row.split(":")[9] for row in cls.listing.splitlines() if row.startswith("fpr:"))
        cls.public = cls.run_gpg(["--armor", "--export", cls.primary]).stdout

    @classmethod
    def run_gpg(cls, arguments):
        return subprocess.run(cls.gpg + arguments, check=True, capture_output=True, timeout=30,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def setUp(self):
        self.bundle = tempfile.TemporaryDirectory(prefix="fin3000-test-vendor-bundle-")
        self.addCleanup(self.bundle.cleanup)
        self.root = Path(self.bundle.name)
        self.prefix = "node-v22.23.2-linux-x64"
        self.node = b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00" + b"NOT EXECUTABLE"
        self.license = b"Node.js MIT license\nSYNTHETIC THIRD PARTY LICENSES\n"
        self.certificate = self.root / "test.asc"
        self.certificate.write_bytes(self.public)
        self.archive = self.make_archive()
        self.digest = hashlib.sha256(self.archive).hexdigest()
        self.source = self.make_source()
        self.source_digest = hashlib.sha256(self.source).hexdigest()
        self.supplement = self.root / "supplement.json"
        synthetic_notice = "\n===== synthetic/LICENSE (SHA256 " + "0" * 64 + ") =====\nSYNTHETIC SUPPLEMENT\n"
        self.supplement_data = {"schema": 1, "nodeVersion": "22.23.2", "nodeSourceSha256": self.source_digest,
            "status": "RESOLVED_AND_OBSERVED_SUBSET_NOT_COMPLETE_SBOM_OR_RELEASE_APPROVAL",
            "notices": synthetic_notice, "noticeCount": 1,
            "noticesSha256": hashlib.sha256(synthetic_notice.encode()).hexdigest(),
            "originalSource": {"file": "smartstring-1.0.1.crate", "encoding": "base64",
                "data": base64.b64encode(b"SYNTHETIC SOURCE ONLY").decode(),
                "sha256": hashlib.sha256(b"SYNTHETIC SOURCE ONLY").hexdigest()}}
        self.supplement.write_text(json.dumps(self.supplement_data))
        self.policy = vendor.NodePolicy("22.23.2", self.digest, self.primary, 2048, self.source_digest,
                                       hashlib.sha256(self.supplement.read_bytes()).hexdigest())
        (self.root / (self.prefix + ".tar.xz")).write_bytes(self.archive)
        (self.root / "node-v22.23.2.tar.xz").write_bytes(self.source)
        self.sign_checksums((f"{self.digest}  {self.prefix}.tar.xz\n"
                             f"{self.source_digest}  node-v22.23.2.tar.xz\n").encode())

    def make_archive(self, *, extra=(), node_type=tarfile.REGTYPE, license=True, node=None):
        entries = [(self.prefix + "/bin/node", self.node if node is None else node, node_type)]
        if license:
            entries.append((self.prefix + "/LICENSE", self.license, tarfile.REGTYPE))
        entries.extend(extra)
        return self.tar_bytes(entries)

    def make_source(self, *, extra=(), omit=(), root_license=None, sqlite=None):
        paths = {"LICENSE": self.license if root_license is None else root_license,
                 "deps/v8/LICENSE": b"SYNTHETIC V8 NOTICE\n",
                 "deps/v8/LICENSE.fdlibm": b"SYNTHETIC FDLIBM NOTICE\n",
                 "deps/nbytes/LICENSE": b"SYNTHETIC NBYTES NOTICE\n",
                 "deps/sqlite/sqlite3.h": sqlite if sqlite is not None else
                     b"/*\n** The author disclaims copyright\n" + b"** synthetic\n" * 9 + b"DO NOT COPY API CODE\n"}
        entries = [("node-v22.23.2/" + path, data, tarfile.REGTYPE)
                   for path, data in paths.items() if path not in omit]
        return self.tar_bytes([*entries, *extra])

    @staticmethod
    def tar_bytes(entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
            for name, data, kind in entries:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = len(data) if kind == tarfile.REGTYPE else 0
                entry.linkname = "/outside" if kind != tarfile.REGTYPE else ""
                archive.addfile(entry, io.BytesIO(data))
        return buffer.getvalue()

    def sign_checksums(self, data):
        path = self.root / "SHASUMS256.txt"
        path.write_bytes(data)
        self.run_gpg(["--yes", "--local-user", self.primary + "!", "--digest-algo", "SHA256",
                      "--output", str(path) + ".sig", "--detach-sign", str(path)])

    def verify(self):
        return vendor.verify_runtime(self.root, certificate=self.certificate, supplement=self.supplement, policy=self.policy)

    def test_exact_verified_bytes_and_provenance_without_executing_binary(self):
        result = self.verify()
        self.assertEqual(result.node, self.node)
        self.assertEqual(result.license, self.license)
        self.assertEqual(result.proof.signer, self.primary)
        self.assertEqual(result.proof.sha256, hashlib.sha256(self.node).hexdigest())
        self.assertEqual(result.proof.licenseSha256, hashlib.sha256(self.license).hexdigest())
        self.assertEqual(result.proof.archiveSha256, self.digest)
        self.assertEqual(result.proof.sourceArchiveSha256, self.source_digest)
        self.assertEqual(result.proof.sourceNoticesSha256, hashlib.sha256(result.source_notices).hexdigest())
        self.assertEqual(result.proof.sourceNoticeCount, 5)
        self.assertEqual(result.proof.supplementalNoticeCount, 1)
        self.assertEqual(result.proof.sourceSupplementSha256, self.policy.supplement_sha256)
        self.assertEqual(result.supplemental_source, b"SYNTHETIC SOURCE ONLY")
        self.assertEqual(result.proof.supplementalSourceSha256, hashlib.sha256(result.supplemental_source).hexdigest())
        self.assertIn(b"SYNTHETIC SUPPLEMENT", result.source_notices)
        self.assertIn(vendor.SUPPLEMENT_SOURCE.encode(), result.source_notices)
        self.assertIn(b"SYNTHETIC FDLIBM NOTICE", result.source_notices)
        self.assertNotIn(b"DO NOT COPY API CODE", result.source_notices)

    def test_source_signature_hash_and_regular_file_required_before_parsing(self):
        source = self.root / "node-v22.23.2.tar.xz"
        source.write_bytes(b"tampered source")
        with patch.object(vendor, "source_notices") as parse, self.assertRaisesRegex(ValueError, "Source archive digest"):
            self.verify()
        parse.assert_not_called()
        source.unlink()
        source.symlink_to(self.root / (self.prefix + ".tar.xz"))
        with self.assertRaises(OSError):
            self.verify()
        source.unlink()
        source.write_bytes(self.source)
        self.sign_checksums(f"{self.digest}  {self.prefix}.tar.xz\n".encode())
        with patch.object(vendor, "source_notices") as parse, self.assertRaisesRegex(ValueError, "signed checksums"):
            self.verify()
        parse.assert_not_called()

    def test_supplement_hash_regular_file_and_presence_required_before_parsing(self):
        original = self.supplement.read_bytes()
        self.supplement.write_bytes(b"tampered")
        with patch.object(vendor, "supplement_payload") as parse, self.assertRaisesRegex(ValueError, "Supplement digest"):
            self.verify()
        parse.assert_not_called()
        self.supplement.unlink()
        with self.assertRaises(OSError):
            self.verify()
        other = self.root / "other.json"
        other.write_bytes(original)
        self.supplement.symlink_to(other)
        with self.assertRaises(OSError):
            self.verify()

    def test_supplement_rejects_wrong_identity_scope_counts_paths_or_content(self):
        cases = [{"nodeVersion": "99.0.0"}, {"nodeSourceSha256": "0" * 64},
                 {"status": "COMPLETE"}, {"schema": True}, {"noticeCount": True},
                 {"noticeCount": 0}, {"noticeCount": 513}, {"notices": "changed"},
                 {"notices": "x" * (1024 * 1024 + 1)}]
        cases.extend({"originalSource": {**self.supplement_data["originalSource"], **change}} for change in
                     ({"file": "../../other"}, {"encoding": "url"}, {"data": "not base64!"},
                      {"sha256": "0" * 64}, {"data": ""}, {"data": "x" * (1024 * 1024 + 1)}))
        for change in cases:
            with self.subTest(fields=list(change)), self.assertRaises(ValueError):
                vendor.supplement_payload(json.dumps({**self.supplement_data, **change}).encode(), self.policy)
        duplicate = self.supplement.read_bytes().replace(b'{', b'{"schema": 1,', 1)
        with self.assertRaises(ValueError):
            vendor.supplement_payload(duplicate, self.policy)

    def test_actual_reviewed_supplement_preserves_notices_and_original_source_without_extraction(self):
        raw = vendor.SUPPLEMENT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), vendor.PINNED.supplement_sha256)
        with patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("no extraction")):
            extra = vendor.supplement_payload(raw, vendor.PINNED)
        self.assertEqual(extra.count, 199)
        data = json.loads(raw)
        self.assertEqual(len(data["components"]), 130)
        self.assertEqual(len(data["rustStandardLibraryComponents"]), 5)
        self.assertEqual(sum(c["binaryObserved"] for c in data["components"]), 35)
        self.assertEqual(len(data["resolvedDependencies"]), 127)
        self.assertEqual(data["resolution"]["target"], "wasm32-unknown-unknown")
        self.assertEqual(data["resolution"]["edges"], "normal,no-proc-macro")
        refs = {c["purl"] for c in data["components"]}
        self.assertTrue(all(c["notices"] for c in data["components"]))
        for dependency in data["resolvedDependencies"]:
            self.assertIn(dependency["ref"], refs)
            self.assertTrue(set(dependency["dependsOn"]).issubset(refs))
        self.assertEqual(len(data["additionalNoticeSources"]), 10)
        self.assertIn(b"Mozilla Public License Version 2.0", extra.notices)
        self.assertIn(b"6fb0202a6044b7b3cbd5495bff3fc98b99cd1831/LICENSE", extra.notices)
        self.assertIn(b"Copyright (c) 2021 Nugine", extra.notices)
        self.assertEqual(extra.source_sha256, "3fb72c633efbaa2dd666986505016c32c3044395ceaf881518399d2f4127ee29")
        with tarfile.open(fileobj=io.BytesIO(extra.source), mode="r:gz") as archive:
            self.assertTrue(archive.getmember("smartstring-1.0.1/src/lib.rs").isreg())
            self.assertIn(b"Mozilla Public License", archive.extractfile("smartstring-1.0.1/LICENCE.md").read())

    def test_all_component_notices_resolve_to_hash_matching_original_bodies(self):
        data = json.loads(vendor.SUPPLEMENT.read_bytes())
        parts = re.split(rb"\n===== ([^\r\n]+) \(SHA256 ([0-9a-f]{64})\) =====\n",
                         data["notices"].encode())
        bodies = {}
        for index in range(1, len(parts), 3):
            name, digest, body = parts[index:index + 3]
            self.assertTrue(body.endswith(b"\n"))
            body = body[:-1]  # Only the assembler's separator, not upstream whitespace.
            self.assertEqual(hashlib.sha256(body).hexdigest().encode(), digest)
            self.assertNotIn(name.decode(), bodies)
            bodies[name.decode()] = body
        self.assertEqual(len(bodies), data["noticeCount"])
        for component in [*data["components"], *data["rustStandardLibraryComponents"]]:
            with self.subTest(component=component["name"], version=component["version"]):
                self.assertTrue(component["notices"])
                self.assertTrue(set(component["notices"]).issubset(bodies))
        sourcemap = next(c for c in data["components"] if c["name"] == "swc_sourcemap")
        self.assertEqual(sourcemap["license"], "BSD-3-Clause")
        self.assertEqual(len(sourcemap["notices"]), 1)
        self.assertIn(b"Copyright (c) 2016 by Armin Ronacher.", bodies[sourcemap["notices"][0]])
        self.assertEqual(hashlib.sha256(bodies[sourcemap["notices"][0]]).hexdigest(),
                         "7516e1cf340213f60d96bca77bb012882dbf80e7cca5922c914174f605d9ef71")
        compiler = next(c for c in data["rustStandardLibraryComponents"] if c["name"] == "compiler_builtins")
        compiler_notice = bodies[compiler["notices"][0]]
        self.assertEqual(hashlib.sha256(compiler_notice).hexdigest(),
                         "ab6eec6caf0fa5775e411c7a8bc6a45c4ef2956b0980b157ab74fc5cd62a928b")
        self.assertIn(b"Copyright (c) 2009-2016 by the contributors listed in CREDITS.TXT", compiler_notice)
        self.assertIn(b"LLVM Exceptions to the Apache 2.0 License", compiler_notice)
        unicode = next(c for c in data["rustStandardLibraryComponents"] if c["name"] == "rust-core-unicode-data")
        self.assertEqual(hashlib.sha256(bodies[unicode["notices"][0]]).hexdigest(),
                         "f5062c9a188d81dfe66b56db4182dcf9e4b17c0d9b0d311a8e20b3a1b075c443")

    def test_std_notice_metadata_does_not_relabel_source_dependencies_as_binary_observations(self):
        data = json.loads(vendor.SUPPLEMENT.read_bytes())
        components = {item["name"]: item for item in data["rustStandardLibraryComponents"]}
        self.assertEqual(set(components), {"compiler_builtins", "cfg-if", "libc", "rust-standard-library", "rust-core-unicode-data"})
        compiler = components["compiler_builtins"]
        self.assertEqual(compiler["version"], "0.1.157")
        self.assertEqual(compiler["license"], "MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)")
        self.assertEqual(compiler["archiveSha256"],
                         "74f103f5a97b25e3ed7134dee586e90bbb0496b33ba41816f0e7274e5bb73b50")
        self.assertEqual(components["cfg-if"]["version"], "1.0.0")
        self.assertEqual(components["libc"]["version"], "0.2.172")
        self.assertEqual(components["rust-core-unicode-data"]["version"], "16.0.0")
        self.assertTrue(components["rust-standard-library"]["binaryObserved"])
        for name in ("compiler_builtins", "cfg-if", "libc", "rust-core-unicode-data"):
            self.assertFalse(components[name]["binaryObserved"])
        self.assertIn("cc (optional)", compiler["buildOnlyDependencies"])
        self.assertEqual(data["rustStandardLibraryScope"]["status"],
                         "PINNED_LIBRARY_TARGET_SOURCE_SUBSET_NOT_LINK_MAP_OR_COMPLETE_SBOM")
        self.assertEqual(data["rustStandardLibraryScope"]["compilerCommit"], data["rustCompilerCommit"])
        self.assertEqual(data["status"], "RESOLVED_AND_OBSERVED_SUBSET_NOT_COMPLETE_SBOM_OR_RELEASE_APPROVAL")
        self.assertEqual(len(data["resolvedDependencies"]), 127)
        self.assertTrue(set(item["purl"] for item in components.values()).isdisjoint(
            item["ref"] for item in data["resolvedDependencies"]))

    def test_supplement_notice_count_is_recounted_not_self_declared(self):
        for count in (2, 188):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "notice count"):
                vendor.supplement_payload(json.dumps({**self.supplement_data, "noticeCount": count}).encode(), self.policy)

    def test_provenance_distinguishes_vendor_signature_from_reviewed_supplement(self):
        proof = self.verify().proof
        self.assertIn("separately-reviewed-hash-pinned-supplement", proof.provenance)

    def test_pinned_v8_inventory_distinguishes_second_zlib_and_source_only_evidence(self):
        raw = vendor.SUPPLEMENT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), vendor.PINNED.supplement_sha256)
        data = json.loads(raw)
        components = {item["name"]: item for item in data["nodeSourceComponents"]}
        self.assertEqual(set(components), {"abseil-cpp", "fp16", "rapidhash-v8", "zlib"})
        self.assertEqual(components["zlib"]["version"], "1.3.0.1-motley")
        self.assertIn("Cr_z_crc32_combine64", components["zlib"]["evidence"])
        self.assertTrue(components["zlib"]["binaryObserved"])
        self.assertTrue(components["abseil-cpp"]["binaryObserved"])
        self.assertFalse(components["fp16"]["binaryObserved"])
        self.assertFalse(components["rapidhash-v8"]["binaryObserved"])
        self.assertEqual(len({item["purl"] for item in components.values()}), 4)
        for item in components.values():
            self.assertEqual(item["nodeBinarySha256"],
                             "3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327")
            for entry in [item["sourceMetadata"], *item["buildEvidence"], *item["notices"]]:
                self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
                self.assertFalse(entry["path"].startswith("/"))
                self.assertNotIn("..", entry["path"].split("/"))

    def test_source_notices_retain_nested_files_without_extracting_or_inventing_licenses(self):
        archive = self.make_source(extra=(("node-v22.23.2/deps/v8/nested/NOTICE.txt", b"ORIGINAL nested notice", tarfile.REGTYPE),
                                          ("node-v22.23.2/tools/test/LICENSE-extra", b"BUILD TEST ONLY", tarfile.REGTYPE)))
        with patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("no extraction")):
            notices, count = vendor.source_notices(archive, "node-v22.23.2", self.license)
        self.assertEqual(count, 7)
        self.assertIn(b"Includes source/build/test dependencies NOT necessarily shipped", notices)
        self.assertIn(b"ORIGINAL nested notice", notices)
        self.assertIn(hashlib.sha256(b"ORIGINAL nested notice").hexdigest().encode(), notices)

    def test_source_notice_missing_mismatched_or_unsafe_members_rejected(self):
        for options in ({"omit": ("deps/v8/LICENSE.fdlibm",)}, {"root_license": b"different license"},
                        {"sqlite": b"different header"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                vendor.source_notices(self.make_source(**options), "node-v22.23.2", self.license)
        for name, kind in (("node-v22.23.2/LICENSE", tarfile.REGTYPE),
                           ("node-v22.23.2/../NOTICE", tarfile.REGTYPE),
                           ("/tmp/NOTICE", tarfile.REGTYPE),
                           ("node-v22.23.2/deps/NOTICE", tarfile.SYMTYPE),
                           ("node-v22.23.2/deps/NOTICE", tarfile.LNKTYPE),
                           ("node-v22.23.2/a\nNOTICE", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                vendor.source_notices(self.make_source(extra=((name, b"invalid", kind),)), "node-v22.23.2", self.license)

    def test_source_implementations_are_not_mistaken_for_notice_documents(self):
        sources = ("copying-phase.cc", "copying-phase.h", "license.js", "copyright.pm",
                   "NOTICE.PY", "LICENSE-test.ts", "COPYRIGHT.rs")
        documents = ("LICENSE.strongtalk", "LICENSE-MIT.txt", "LICENSE_nghttp2", "COPYING",
                     "copyright.txt", "NOTICE.md", "LICENCE.rst")
        entries = [(f"node-v22.23.2/deps/fixture/{name}", b"NOT A NOTICE " + name.encode(), tarfile.REGTYPE)
                   for name in sources]
        entries.extend((f"node-v22.23.2/deps/fixture/{name}", b"EXACT NOTICE " + name.encode(), tarfile.REGTYPE)
                       for name in documents)
        notices, count = vendor.source_notices(self.make_source(extra=entries), "node-v22.23.2", self.license)
        self.assertEqual(count, 5 + len(documents))
        self.assertNotIn(b"NOT A NOTICE", notices)
        for name in documents:
            self.assertIn(b"EXACT NOTICE " + name.encode(), notices)

    def test_source_notice_size_bounds_and_non_notice_links(self):
        archive = self.make_source(extra=(("node-v22.23.2/deps/large/LICENSE", b"x" * (2 * 1024 * 1024 + 1), tarfile.REGTYPE),))
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            vendor.source_notices(archive, "node-v22.23.2", self.license)
        archive = self.make_source(extra=(("node-v22.23.2/node_modules/executable", b"", tarfile.SYMTYPE),))
        with patch.object(vendor, "MAX_NOTICES", 1024 * 1024), self.assertRaisesRegex(ValueError, "collection exceeds"):
            vendor.source_notices(archive, "node-v22.23.2", self.license)
        self.assertEqual(vendor.source_notices(archive, "node-v22.23.2", self.license)[1], 5)

    def test_other_vendor_identity_is_not_authorized(self):
        with self.assertRaisesRegex(ValueError, "primary is not pinned"):
            vendor.verify_runtime(self.root, certificate=self.certificate,
                                  policy=replace(self.policy, primary="A" * 40))

    def test_tampered_checksums_fail_before_archive_parsing(self):
        (self.root / "SHASUMS256.txt").write_bytes(b"0" * 64 + b"  altered\n")
        with patch.object(vendor, "archive_payload") as parse, self.assertRaises(ValueError):
            self.verify()
        parse.assert_not_called()

    def test_tampered_archive_fails_before_parsing(self):
        (self.root / (self.prefix + ".tar.xz")).write_bytes(b"hostile archive")
        with patch.object(vendor, "archive_payload") as parse, self.assertRaisesRegex(ValueError, "digest is not pinned"):
            self.verify()
        parse.assert_not_called()

    def test_valid_signature_does_not_authorize_unpinned_version(self):
        self.sign_checksums(f"{'0' * 64}  {self.prefix}.tar.xz\n".encode())
        with self.assertRaisesRegex(ValueError, "not bound by signed checksums"):
            self.verify()

    def test_missing_binary_or_license_cannot_be_replaced_by_a_link(self):
        for options in ({"license": False}, {"node_type": tarfile.SYMTYPE}, {"node_type": tarfile.LNKTYPE}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                vendor.archive_payload(self.make_archive(**options), self.prefix)

    def test_duplicate_traversal_absolute_or_foreign_archive_members_rejected(self):
        for name in (self.prefix + "/bin/node", self.prefix + "/../foreign", "/outside",
                     "another-version/LICENSE", self.prefix + "/./LICENSE", self.prefix + "/a\\b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                vendor.archive_payload(self.make_archive(extra=((name, b"bad", tarfile.REGTYPE),)), self.prefix)

    def test_archive_never_extracts_npm_or_its_symlinks(self):
        data = self.make_archive(extra=((self.prefix + "/bin/npm", b"", tarfile.SYMTYPE),))
        with patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("no extraction")):
            self.assertEqual(vendor.archive_payload(data, self.prefix), (self.node, self.license))

    def test_wrong_binary_architecture_rejected(self):
        with self.assertRaisesRegex(ValueError, "ELF64 x86-64"):
            vendor.archive_payload(self.make_archive(node=b"not a Linux binary"), self.prefix)

    def test_repeated_or_weak_signature_rejected(self):
        signature = self.root / "SHASUMS256.txt.sig"
        signature.write_bytes(signature.read_bytes() * 2)
        with self.assertRaises(ValueError):
            self.verify()
        self.run_gpg(["--yes", "--digest-algo", "SHA1", "--output", str(signature),
                      "--detach-sign", str(self.root / "SHASUMS256.txt")])
        with self.assertRaises(ValueError):
            self.verify()

    def test_expired_or_revoked_certificate_rejected(self):
        with self.assertRaises(ValueError):
            vendor.certificate_valid(self.listing, self.policy, int(time.time()) + 172800)
        with self.assertRaises(ValueError):
            vendor.certificate_valid(self.listing.replace("pub:u:", "pub:r:"), self.policy, int(time.time()))

    def test_signature_time_and_actual_primary_are_required(self):
        now = int(time.time())
        valid = (f"[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {self.primary} 2026-09-09 "
                 f"{now} 0 4 0 1 8 00 {self.primary}\n")
        self.assertEqual(vendor.signature_valid(valid, self.policy, now, now - 60), now)
        for status in (valid.replace(f"{now} 0", f"{now + 3600} 0"),
                       valid.replace(f"{now} 0", f"{now - 30} {now - 1}"),
                       valid.replace(self.primary, "F" * 40, 1),
                       valid + "[GNUPG:] REVKEYSIG\n"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                vendor.signature_valid(status, self.policy, now, now - 60)

    def test_bundled_public_vendor_key_matches_pin(self):
        result = self.run_gpg(["--with-colons", "--import-options", "show-only",
                               "--import", str(vendor.CERTIFICATE)])
        vendor.certificate_valid(result.stdout.decode(), vendor.PINNED, int(time.time()))

    def test_symlinked_archive_not_opened(self):
        path = self.root / (self.prefix + ".tar.xz")
        path.unlink()
        path.symlink_to(self.root / "SHASUMS256.txt")
        with self.assertRaises(OSError):
            self.verify()

    def test_checksum_duplicate_and_noncanonical_lines_rejected(self):
        valid = f"{self.digest}  {self.prefix}.tar.xz\n".encode()
        for value in (valid * 2, valid.replace(b"  ", b" "), valid.upper(), b""):
            with self.subTest(value=value[:70]), self.assertRaises(ValueError):
                vendor.checksum_matches(value, self.prefix + ".tar.xz", self.digest)

    def test_cli_has_no_custom_policy_certificate_or_execution_override(self):
        result = subprocess.run([sys.executable, "-B", "-I", SPEC.origin, "--help"],
                                capture_output=True, check=True, timeout=10)
        for option in (b"--certificate", b"--policy", b"--skip", b"--execute"):
            self.assertNotIn(option, result.stdout)
        source = Path(SPEC.origin).read_text()
        for forbidden in ("urlopen", "extractall(", "--recv-key", "--sign", "--quick-generate-key"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()

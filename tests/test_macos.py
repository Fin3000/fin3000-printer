"""Compile and exercise the Darwin state adapter in a disposable directory."""

import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    platform.system() == "Darwin", "Requires macOS and Xcode Command Line Tools"
)
class MacStateTests(unittest.TestCase):
    def test_durable_state_roundtrip_and_file_ownership(self):
        with tempfile.TemporaryDirectory(prefix="fin3000-mac-test-") as directory:
            where = Path(directory)
            (where / "state.m").write_text("""
#import "native.h"
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 2) return 1;
        int dir = open(argv[1], O_RDONLY|O_DIRECTORY);
        NSError *err = nil;
        if (dir < 0 || F3LoadState(dir, &err) || err) return 2;
        NSData *first = [@"first" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *second = [@"second" dataUsingEncoding:NSUTF8StringEncoding];
        if (!F3SaveState(dir, first) || ![F3LoadState(dir, &err) isEqual:first]) return 3;
        if (!F3SaveState(dir, second) || ![F3LoadState(dir, &err) isEqual:second]) return 4;
        if (renameat(dir, "state.json", dir, "private") || symlinkat("private", dir, "state.json")) return 5;
        if (F3LoadState(dir, &err) || err == nil) return 6;
        close(dir); return 0;
    }
}
""")
            binary = where / "state-test"
            subprocess.run(
                [
                    "xcrun",
                    "clang",
                    "-fobjc-arc",
                    "-Wno-deprecated-declarations",
                    "-I",
                    ROOT / "platforms/macos",
                    where / "state.m",
                    ROOT / "platforms/macos/native.m",
                    "-framework",
                    "Foundation",
                    "-framework",
                    "Security",
                    "-lcups",
                    "-o",
                    binary,
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run([binary, where], check=True)
            self.assertEqual(os.stat(where / "private").st_mode & 0o777, 0o600)

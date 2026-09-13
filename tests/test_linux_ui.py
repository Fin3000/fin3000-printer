"""Private native GTK integration, not an Ubuntu/Wayland release-matrix pass."""
import configparser
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def build_core_guard(directory):
    library = Path(directory) / 'no-core.so'
    subprocess.run(['/usr/bin/gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                    str(ROOT / 'platforms/linux/no-core.c'), '-o', str(library)],
                   check=True, capture_output=True, timeout=10)
    return library


class DesktopLauncherTests(unittest.TestCase):
    def test_remote_command_line_is_completed_without_waiting_for_garbage_collection(self):
        source = (ROOT / 'platforms/linux/app.js').read_text()
        start = source.index("application.connect('command-line', ")
        end = source.index("application.connect('activate',", start)
        handler = source[start:end]
        harness = r'''
import assert from 'node:assert/strict';
let source = '';
for await (const part of process.stdin) source += part;
let callback, presented = 0;
const application = {connect: (name, fn) => { assert.equal(name, 'command-line'); callback = fn; }};
const view = {window: {present: () => presented++}};
new Function('application', 'view', source)(application, view);
for (const [args, expectedStatus, show] of [
    [['fin3000-printer'], 0, true],
    [['fin3000-printer', '--background'], 0, false],
    [['fin3000-printer', '--bad'], 2, false],
    [['fin3000-printer', '--background', '--bad'], 2, false],
]) {
    const calls = [], before = presented;
    const command = {get_arguments: () => args, set_exit_status: status => calls.push(['status', status]),
        done: () => calls.push(['done'])};
    assert.equal(callback(application, command), expectedStatus);
    assert.deepEqual(calls, [['status', expectedStatus], ['done']], 'status must precede explicit completion');
    assert.equal(presented - before, Number(show));
}
console.log('4 command-line completion cases passed');
'''
        with tempfile.TemporaryDirectory(prefix='fin3000-command-completion-') as private:
            script = Path(private) / 'command.mjs'
            script.write_text(harness)
            result = subprocess.run(['node', str(script)], input=handler.encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'4 command-line completion cases passed\n')

    def test_both_module_entrypoints_yield_the_main_loop_to_gjs(self):
        for path, application, executable in (
                ('platforms/linux/app.js', 'application', 'fin3000-printer'),
                ('packaging/linux/bootstrap/app.js', 'app', 'fin3000-printer-setup')):
            with self.subTest(path=path):
                source = (ROOT / path).read_text()
                self.assertIn(f"await {application}.runAsync(['{executable}', ...ARGV]);", source)
                self.assertNotIn(f'{application}.run(', source)

    def test_update_shutdown_never_force_kills_on_late_ui_error_or_exited_child(self):
        # Execute the actual application callbacks with OS/UI ports replaced;
        # no real desktop, subprocess, account or timer is started on the host.
        source = (ROOT / 'platforms/linux/app.js').read_text()
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('import '))
        harness = r'''
import assert from 'node:assert/strict';
let source = '';
for await (const part of process.stdin) source += part;
async function scenario(alreadyExited) {
    const callbacks = {}, timers = [], signals = [];
    let quits = 0, forced = 0, wait, ready = true;
    const child = {get_stdin_pipe: () => ({close(){}}), get_stdout_pipe: () => ({read_bytes_async(){}}),
        send_signal: signal => { if (alreadyExited) throw Error('already exited'); signals.push(signal); },
        force_exit: () => forced++, wait_async: (_cancel, callback) => wait = callback, wait_finish() {}};
    class App { connect(name, callback) { callbacks[name] = callback; } hold() {}
        run() { throw Error('synchronous nested main loop is forbidden'); }
        async runAsync() {} quit() { quits++; } }
    class Window { constructor() { this.dialogs = {cancel(){}}; } fatal() {} }
    const bus = {signal_subscribe(){}, connect(){}, call(){}};
    const Gio = {ApplicationFlags:{HANDLES_COMMAND_LINE:1}, Subprocess:{new: () => child},
        SubprocessFlags:{STDIN_PIPE:1,STDOUT_PIPE:2,STDERR_SILENCE:4}, DBus:{session:bus},
        DBusSignalFlags:{NONE:0}, DBusCallFlags:{NONE:0}, File:{new_for_path: () => ({load_contents: () => [true, new Uint8Array([ready ? 49 : 48, 10])]})}};
    const GLib = {getenv: () => '1', unsetenv(){}, PRIORITY_DEFAULT:0, SOURCE_REMOVE:false, SOURCE_CONTINUE:true, VariantType:class {},
        timeout_add: (_priority, _delay, callback) => timers.push(callback)};
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    const invoke = new AsyncFunction('Gio', 'GLib', 'Gtk', 'Gdk', 'PrinterWindow', 'writeOwnedBytes', 'ARGV', source + '\nreturn {fatal};');
    const exported = await invoke(Gio, GLib, {Application:App}, {}, Window, () => Promise.resolve(), []);
    callbacks.startup();
    assert.equal(timers.length, 1);
    assert.equal(timers[0](), true);
    if (alreadyExited) wait(child, {});
    ready = false;
    assert.equal(timers[0](), false);
    exported.fatal('late pipe error');
    assert.equal(forced, 0);
    assert.deepEqual(signals, alreadyExited ? [] : [15]);
    if (!alreadyExited) {
        assert.equal(quits, 0, 'must await child drain');
        wait(child, {});
    }
    assert.equal(quits, 1);
    callbacks.shutdown();
    assert.equal(forced, 0);
}
await scenario(false); await scenario(true);
console.log('2 callback races passed');
'''
        with tempfile.TemporaryDirectory(prefix='fin3000-gtk-callbacks-') as private:
            script = Path(private) / 'callbacks.mjs'
            script.write_text(harness)
            result = subprocess.run(['node', str(script)], input=source.encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'2 callback races passed\n')

    def test_launcher_preserves_fixed_ubuntu_browser_discovery_not_ambient_injection(self):
        # Compile the actual launcher; replace only process execution. Never
        # launch a desktop application or change this host's MIME defaults.
        harness = r'''
#define _GNU_SOURCE
/* This test covers only environment cleanup. The real lease is exercised
   without ownership mocks in test_linux_package_lifecycle.py's container. */
#include "package-gate.h"
static int qa_package_lease(void) { return 9; }
#define package_lease qa_package_lease
int qa_execv(const char *file, char *const argv[]);
#define execv qa_execv
#define main launcher_main
#include "launcher.c"
#undef main
int qa_execv(const char *file, char *const argv[]) {
    (void)argv;
    if (strcmp(file, "/usr/bin/gjs-console") && strcmp(file, "/usr/bin/python3") &&
        strcmp(file, "/usr/lib/fin3000-printer/runtime/bin/node")) return 1;
    const char *keys[] = {"XDG_DATA_DIRS", "GJS_PATH", "GI_TYPELIB_PATH", "NODE_OPTIONS", "PATH", "G_DEBUG", "LD_PRELOAD", "FIN3000_CORE_GUARD"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *value = getenv(keys[i]);
        printf("%s=%s\n", keys[i], value ? value : "<absent>");
    }
    exit(0);
}
int main(int argc, char **argv) {
    (void)package_lease;
    setenv("XDG_DATA_DIRS", "/tmp/untrusted", 1);
    setenv("GJS_PATH", "/tmp/untrusted", 1);
    setenv("GI_TYPELIB_PATH", "/tmp/untrusted", 1);
    setenv("NODE_OPTIONS", "--import=/tmp/untrusted", 1);
    setenv("G_DEBUG", "fatal-warnings", 1);
    setenv("LD_PRELOAD", "/tmp/untrusted.so", 1);
    setenv("FIN3000_CORE_GUARD", "forged", 1);
    return launcher_main(argc, argv);
}
'''
        # Mark the real function used as well under strict -Wunused-function.
        harness = harness.replace('static int qa_package_lease(void) { return 9; }',
                                  'static int qa_package_lease(void) { (void)package_lease; return 9; }')
        with tempfile.TemporaryDirectory(prefix="fin3000-launcher-test-") as private:
            path = Path(private)
            (path / "test.c").write_text(harness)
            subprocess.run(["/usr/bin/gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(ROOT / "platforms/linux"), str(path / "test.c"), "-o", str(path / "test")],
                           capture_output=True, check=True, timeout=20)
            for mode in (None, '--background', '--runtime', '--ingress', '--secrets'):
                with self.subTest(mode=mode):
                    result = subprocess.run([str(path / "test"), *([mode] if mode else [])],
                                            capture_output=True, check=True, timeout=5)
                    values = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
                    self.assertEqual(values["XDG_DATA_DIRS"], "/usr/share/ubuntu:/usr/share/gnome:/usr/local/share:/usr/share:/var/lib/snapd/desktop")
                    for key in ("GJS_PATH", "GI_TYPELIB_PATH", "NODE_OPTIONS"):
                        self.assertEqual(values[key], "<absent>")
                    self.assertEqual(values["PATH"], "/usr/bin:/bin")
                    self.assertEqual(values["G_DEBUG"], 'fatal-criticals' if mode in (None, '--background') else '<absent>')
                    self.assertEqual(values["LD_PRELOAD"], '/usr/lib/fin3000-printer/bin/no-core.so')
                    self.assertEqual(values["FIN3000_CORE_GUARD"], '<absent>')

    def test_native_guard_blocks_pipe_core_dumps_and_is_not_inherited(self):
        with tempfile.TemporaryDirectory(prefix='fin3000-core-guard-') as private:
            directory = Path(private)
            library = build_core_guard(directory)
            probe = directory / 'probe.c'
            probe.write_text('''#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    if (prctl(PR_GET_DUMPABLE) != 0 || getenv("LD_PRELOAD") ||
        !getenv("FIN3000_CORE_GUARD")) return 1;
    pid_t child = fork();
    if (child < 0) return 2;
    if (!child) { raise(SIGTRAP); _exit(3); }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGTRAP || WCOREDUMP(status)) return 4;
    puts("native dump protection active; no preload inheritance; no core");
    return 0;
}
''')
            binary = directory / 'probe'
            subprocess.run(['/usr/bin/gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(probe), '-o', str(binary)],
                           check=True, capture_output=True, timeout=10)
            result = subprocess.run([str(binary)], env={'PATH': '/usr/bin:/bin', 'LD_PRELOAD': str(library)},
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'no core', result.stdout)

    def test_gtk_refuses_to_start_without_native_guard(self):
        result = subprocess.run(['/usr/bin/gjs-console', '-m', str(ROOT / 'platforms/linux/app.js')],
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'G_DEBUG': 'fatal-criticals'}, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 70)
        self.assertIn(b'UI_NATIVE_GUARD_MISSING', result.stderr)

    def test_private_helpers_refuse_input_without_native_memory_guard(self):
        for command in (
            ['/usr/bin/gjs-console', '-m', str(ROOT / 'platforms/linux/secret-store.js'), '--stdio'],
            ['/usr/bin/python3', '-I', str(ROOT / 'platforms/linux/ingress.py')],
            [shutil.which('node'), '--experimental-strip-types', str(ROOT / 'platforms/linux/runtime.ts')],
        ):
            with self.subTest(executable=command[0]):
                result = subprocess.run(command, input=b'', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 70, result.stderr.decode())
                self.assertEqual(result.stdout, b'')

    def test_browser_launch_context_never_inherits_gtk_fatal_policy(self):
        source = (ROOT / 'platforms/linux/app.js').read_text()
        browser = source.split('function browser(message) {', 1)[1].split('function receive(', 1)[0]
        self.assertIn("context.unsetenv('G_DEBUG');", browser)
        self.assertLess(browser.index("context.unsetenv('G_DEBUG');"), browser.index('handler.launch_uris_async('))

    def test_critical_failure_restarts_are_bounded(self):
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / 'platforms/linux/fin3000-printer.service')
        self.assertEqual(unit['Unit']['StartLimitIntervalSec'], '600')
        self.assertEqual(unit['Unit']['StartLimitBurst'], '5')
        self.assertEqual(unit['Service']['Restart'], 'on-failure')
        self.assertEqual(unit['Service']['KillMode'], 'control-group')
        self.assertEqual(unit['Service']['LimitCORE'], '0')

    def test_native_critical_stops_instead_of_returning_to_a_broken_callback_chain(self):
        # Exercise GLib's native fatal path, not a JS exception/log handler.
        # This does not pretend to reproduce the unidentified GC finalizer.
        source = "imports.gi.GLib.log_structured('Gjs', imports.gi.GLib.LogLevelFlags.LEVEL_CRITICAL, {MESSAGE: 'SYNTHETIC_QA_CRITICAL'}); print('continued');"
        def no_core():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        with tempfile.TemporaryDirectory(prefix='fin3000-critical-guard-') as private:
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LD_PRELOAD': str(build_core_guard(private))}
            for fatal in (False, True):
                with self.subTest(fatal=fatal):
                    result = subprocess.run(['/usr/bin/gjs-console', '-c', source],
                        env={**env, **({'G_DEBUG': 'fatal-criticals'} if fatal else {})},
                        preexec_fn=no_core, capture_output=True, timeout=5)
                    if fatal:
                        self.assertIn(result.returncode, (-signal.SIGABRT, -signal.SIGTRAP))
                        self.assertNotIn(b'continued', result.stdout)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr.decode())
                        self.assertEqual(result.stdout.strip(), b'continued')


class NativeUiTests(unittest.TestCase):
    def run_fixture(self, fixture, expected, *, bootstrap=False):
        # Explicit QA sysroot can supply Xvfb without installing a host package.
        directory = Path(os.environ.get("FIN3000_UI_TOOLS", "/usr"))
        binary = directory / "bin/Xvfb"
        runner = directory / "bin/xvfb-run"
        self.assertTrue(binary.is_file() and runner.is_file(), "QA requires Xvfb, or explicit FIN3000_UI_TOOLS sysroot/usr")
        with tempfile.TemporaryDirectory(prefix="fin3000-ui-qa-") as private:
            extra = []
            if bootstrap:
                staged = Path(private) / "bootstrap"; staged.mkdir()
                shutil.copyfile(ROOT / "packaging/linux/bootstrap/app.js", staged / "app.js")
                shutil.copyfile(ROOT / "platforms/linux/i18n.js", staged / "i18n.js")
                shutil.copytree(ROOT / "platforms/linux/locales", staged / "locales")
                extra = [str(staged / "app.js")]
            env = {"PATH": f"{directory}/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LANGUAGE": "en",
                   "XDG_RUNTIME_DIR": private, "GSETTINGS_BACKEND": "memory", "GTK_USE_PORTAL": "0", "GDK_BACKEND": "x11",
                   "XDG_DATA_HOME": f"{private}/data", "XDG_CONFIG_HOME": f"{private}/config", "XDG_CACHE_HOME": f"{private}/cache",
                   "GIO_USE_VFS": "local", "GTK_A11Y": "none", "G_DEBUG": "fatal-criticals",
                   "GSK_RENDERER": "cairo"}
            result = subprocess.run(["/usr/bin/dbus-run-session", f"--config-file={ROOT / 'tests/fixtures/desktop-test-bus.conf'}", "--", str(runner), "--auto-servernum", "--server-args=-screen 0 1024x900x24 -nolisten tcp",
                                     "/usr/bin/gjs-console", "-m", str(ROOT / "tests/fixtures" / fixture), *extra],
                                    env=env, capture_output=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode()[-3000:])
            self.assertTrue(result.stdout.strip(), result.stderr.decode()[-3000:])
            self.assertEqual(json.loads(result.stdout), expected)

    def test_real_gtk_confirmation_keyboard_focus_lock_and_unknown_state(self):
        self.run_fixture("linux-product-ui.js", {"ok": True, "realGtk": True, "cases": 36, "uploads": 0, "hostPrinters": 0})

    def test_recovery_dialogs_private_export_no_overwrite_and_locked_receipt_input(self):
        self.run_fixture("linux-recovery-ui.js", {"ok": True, "realGtk": True, "privateFileIo": True, "cases": 24, "uploads": 0, "hostPrinters": 0})

    def test_bootstrap_gui_single_flight_close_during_dpkg_and_success_failure(self):
        self.run_fixture("linux-bootstrap-ui.js", {"ok": True, "realGtk": True, "cases": 10, "installs": 0, "hostPrinters": 0}, bootstrap=True)

    def test_german_source_and_english_fallback_have_identical_keys_and_placeholders(self):
        de = json.loads((ROOT / "platforms/linux/locales/de.json").read_text())
        en = json.loads((ROOT / "platforms/linux/locales/en.json").read_text())
        self.assertEqual(de.keys(), en.keys())
        for key in de:
            self.assertTrue(de[key] and en[key])
            self.assertEqual(sorted(re.findall(r"\{\w+\}", de[key])), sorted(re.findall(r"\{\w+\}", en[key])))

    def test_all_native_languages_include_version_and_build_placeholders(self):
        catalogs = list((ROOT / "platforms/linux/locales").glob("*.json"))
        self.assertEqual(len(catalogs), 26)
        for path in catalogs:
            with self.subTest(language=path.stem):
                text = json.loads(path.read_text())["buildVersion"]
                self.assertEqual(sorted(re.findall(r"\{\w+\}", text)), ["{commit}", "{version}"])
                self.assertTrue(text.strip())

    def test_offline_help_uses_bundled_translations_in_all_native_languages(self):
        source = (ROOT / "platforms/linux/ui.js").read_text()
        method = source.split("    showHelp() {", 1)[1].split("    setRelease(", 1)[0]
        for forbidden in ("this.send(", "Gio.", "fetch(", "https://", "load_contents", "this.current", "markup: true"):
            self.assertNotIn(forbidden, method)
        for path in (ROOT / "platforms/linux/locales").glob("*.json"):
            with self.subTest(language=path.stem):
                catalog = json.loads(path.read_text())
                self.assertTrue(catalog["offlineHelp"].strip())
                self.assertTrue(catalog["offlineHelpIntro"].strip())
                self.assertTrue(catalog["helpTroubleshooting"].strip())
                self.assertIn("Chrome", catalog["readyExplanation"])
                self.assertIn("Chromium", catalog["readyExplanation"])
                self.assertIn("+P", catalog["readyExplanation"])
                for key in ("setupExplanation", "connectExplanation", "readyExplanation", "confirmNotice",
                            "uncertain", "originalAccount", "receiptExplanation", "drainExplanation", "installerTrust"):
                    self.assertTrue(catalog[key].strip())


if __name__ == "__main__":
    unittest.main()

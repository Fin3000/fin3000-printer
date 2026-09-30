/** GNOME session owner. Native GTK singleton holds one private coordinator child. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk?version=4.0';
import Gdk from 'gi://Gdk?version=4.0';
import System from 'system';
import {PrinterWindow} from './ui.js';
import {writeOwnedBytes} from './stream.js';

// The launcher scrubs inherited variables; only its fixed native constructor
// can supply this marker. Refuse missing/broken preload instead of continuing
// when ld.so merely warns. The constructor already removed LD_PRELOAD.
if (GLib.getenv('FIN3000_CORE_GUARD') !== '1') {
    printerr('UI_NATIVE_GUARD_MISSING');
    System.exit(70);
}
GLib.unsetenv('FIN3000_CORE_GUARD');

const ROOT = '/usr/lib/fin3000-printer';
// The isolated package renderer changes this literal, never a runtime env var.
const QA_BUILD = false;
const application = new Gtk.Application({application_id: 'com.fin3000.Printer', flags: Gio.ApplicationFlags.HANDLES_COMMAND_LINE});
let view, process, output, writing = false, queuedBytes = 0, stopped = false, updating = false, exited = false;
const queue = [];
let previousJobs = new Map();
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', {fatal: true});

function fatal(code) {
    view?.fatal(code);
    if (!stopped && !updating) process?.force_exit();
}

function send(command) {
    if (stopped || updating || !output) return;
    const bytes = encoder.encode(JSON.stringify(command) + '\n');
    if (bytes.length > 16384 || queuedBytes + bytes.length > 65536) { fatal('UI_UNAVAILABLE'); return; }
    queue.push(bytes); queuedBytes += bytes.length; pump();
}

function pump() {
    if (writing || !queue.length || stopped) return;
    writing = true;
    const bytes = queue.shift();
    void writeOwnedBytes(output, bytes).then(() => {
        writing = false; queuedBytes -= bytes.length; bytes.fill(0); pump();
    }).catch(() => { writing = false; queuedBytes -= bytes.length; bytes.fill(0); fatal('UI_UNAVAILABLE'); });
}

function browser(message) {
    let ok = false;
    const reply = () => send({action: 'browserResult', requestId: message.requestId, ok});
    try {
        if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(message.requestId) ||
            typeof message.url !== 'string' || message.url.length > 8192) throw new Error();
        const uri = GLib.Uri.parse(message.url, GLib.UriFlags.NONE);
        const production = uri.get_scheme() === 'https' && uri.get_host() === 'app.fin3000.com' && [-1, 443].includes(uri.get_port());
        const isolatedQa = uri.get_scheme() === 'http' && uri.get_host() === '127.0.0.1' && uri.get_port() >= 1024;
        if (!(QA_BUILD ? isolatedQa : production) || uri.get_userinfo() || uri.get_fragment() ||
            !['/oauth/authorize', '/accounting/incoming-invoices/upload', '/accounting/incoming-invoices/print-operations'].includes(uri.get_path())) throw new Error();
        // Do not let GIO fetch the URL and fall back to a text editor when
        // there is no registered browser. Launch the chosen scheme handler.
        const handler = Gio.AppInfo.get_default_for_uri_scheme(uri.get_scheme());
        if (!handler) throw new Error();
        const context = Gdk.Display.get_default().get_app_launch_context();
        context.unsetenv('G_DEBUG');
        handler.launch_uris_async([message.url], context, null, (_object, result) => {
            try { ok = handler.launch_uris_finish(result); } catch { ok = false; }
            reply();
        });
    } catch { reply(); }
}

function notifyTransitions(state) {
    const current = new Map(state.jobs.map(job => [job.operationId, job]));
    for (const job of state.jobs) {
        const previous = previousJobs.get(job.operationId);
        let keys = null;
        if (!previous && ['waiting', 'transferring'].includes(job.outcome)) {
            keys = ['title', 'transferring'];
        } else if (previous && previous.outcome !== job.outcome && job.outcome === 'accepted') {
            keys = ['title', 'accepted'];
        } else if (previous && previous.outcome !== job.outcome && job.outcome === 'never_accepted') {
            keys = ['title', 'never_accepted'];
        } else if ((!previous || previous.outcome !== job.outcome) && job.outcome === 'uncertain') {
            keys = ['title', 'uncertain'];
        } else if ((!previous || previous.code !== job.code) &&
            ['REPRINT_AFTER_RESTART', 'REPRINT_AFTER_RECOVERY'].includes(job.code)) {
            keys = ['title', 'reprint'];
        }
        if (!keys) continue;
        const notification = new Gio.Notification();
        notification.set_title(view.t(keys[0]));
        notification.set_body(view.t(keys[1]));
        application.send_notification(`fin3000-print-${job.operationId}`, notification);
    }
    previousJobs = current;
}

function receive(message) {
    if (message?.type === 'state') { view.update(message); notifyTransitions(message); }
    else if (message?.type === 'release') view.setRelease(message);
    else if (message?.type === 'fatal') view.fatal(message.code);
    else if (message?.type === 'browser') browser(message);
    else if (message?.type === 'recoveryExport') view.exportRecovery(message);
    else throw new Error('UI_STATE_INVALID');
}

function readMessages(input) {
    let pending = new Uint8Array(0);
    const read = () => input.read_bytes_async(4096, GLib.PRIORITY_DEFAULT, null, (stream, result) => {
        if (stopped) return;
        try {
            const bytes = stream.read_bytes_finish(result).get_data();
            if (!bytes.length) { if (updating) application.quit(); else fatal('RUNTIME_UNAVAILABLE'); return; }
            const combined = new Uint8Array(pending.length + bytes.length);
            combined.set(pending); combined.set(bytes, pending.length);
            let offset = 0;
            for (let index = 0; index < combined.length; index++) if (combined[index] === 10) {
                if (index - offset > 256 * 1024) throw new Error();
                receive(JSON.parse(decoder.decode(combined.subarray(offset, index)))); offset = index + 1;
            }
            pending = combined.slice(offset);
            if (pending.length > 256 * 1024) throw new Error();
            read();
        } catch { fatal('UI_UNAVAILABLE'); }
    });
    read();
}

function watchSession() {
    const bus = Gio.DBus.session;
    bus.signal_subscribe('org.gnome.ScreenSaver', 'org.gnome.ScreenSaver', 'ActiveChanged', '/org/gnome/ScreenSaver',
        null, Gio.DBusSignalFlags.NONE, (_bus, _sender, _path, _interface, _signal, parameters) => {
            const [active] = parameters.deepUnpack();
            send({action: 'session', locked: typeof active === 'boolean' ? active : true});
        });
    bus.signal_subscribe('org.freedesktop.DBus', 'org.freedesktop.DBus', 'NameOwnerChanged', '/org/freedesktop/DBus',
        'org.gnome.ScreenSaver', Gio.DBusSignalFlags.NONE, (_bus, _sender, _path, _interface, _signal, parameters) => {
            const [, , owner] = parameters.deepUnpack();
            send({action: 'session', locked: true});
            if (owner) query();
        });
    const query = () => bus.call('org.gnome.ScreenSaver', '/org/gnome/ScreenSaver', 'org.gnome.ScreenSaver', 'GetActive',
        null, new GLib.VariantType('(b)'), Gio.DBusCallFlags.NONE, 3000, null, (connection, result) => {
            let locked = true;
            try { [locked] = connection.call_finish(result).deepUnpack(); } catch { /* No session evidence, no uploads. */ }
            send({action: 'session', locked});
        });
    bus.connect('closed', () => application.quit());
    query();
}

application.connect('startup', () => {
    application.hold();
    view = new PrinterWindow(application, send);
    try {
        process = Gio.Subprocess.new(['/usr/bin/fin3000-printer', '--runtime'],
            Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
        output = process.get_stdin_pipe();
        readMessages(process.get_stdout_pipe()); watchSession();
        process.wait_async(null, (_child, result) => {
            try { process.wait_finish(result); } finally {
                exited = true;
                if (updating) application.quit(); else if (!stopped) view.fatal('RUNTIME_UNAVAILABLE');
            }
        });
    } catch { view.fatal('PACKAGE_INCOMPLETE'); }
    // The C launcher holds a package lease before loading this module. The
    // runtime has its own lease, so even GTK death cannot let dpkg overtake
    // its asynchronous shutdown/state checkpoint. Never force-kill for update.
    GLib.timeout_add(GLib.PRIORITY_DEFAULT, 250, () => {
        if (stopped || updating) return GLib.SOURCE_REMOVE;
        let ready = false;
        try {
            const [ok, bytes] = Gio.File.new_for_path('/var/lib/fin3000-printer/lifecycle/ready').load_contents(null);
            ready = ok && bytes.length === 2 && bytes[0] === 49 && bytes[1] === 10;
        } catch { /* Missing/invalid package state closes admission as well. */ }
        if (ready) return GLib.SOURCE_CONTINUE;
        updating = true; view?.dialogs.cancel();
        if (process && !exited) {
            try { process.send_signal(15); } catch { application.quit(); }
        } else application.quit();
        return GLib.SOURCE_REMOVE;
    });
});

application.connect('command-line', (_app, command) => {
    const args = command.get_arguments();
    const status = args.length > 2 || (args.length === 2 && args[1] !== '--background') ? 2 : 0;
    if (status === 0 && !args.includes('--background')) view.window.present();
    // GJS does not dispose this object promptly. Complete remote invocations
    // explicitly instead of keeping launchers alive until garbage collection.
    // Gio.ApplicationCommandLine.done is available on Ubuntu 24/26 (GLib 2.80+).
    command.set_exit_status(status);
    command.done();
    return status;
});
application.connect('activate', () => view.window.present());
application.connect('shutdown', () => {
    stopped = true;
    view?.dialogs.cancel();
    for (const bytes of queue) bytes.fill(0);
    try { output?.close(null); } catch { /* Parent EOF also shuts down coordinator/ingress. */ }
    if (!exited) {
        try { process?.send_signal(15); } catch { /* Child may already have exited. */ }
    }
});
// Follow GJS's asynchronous module entry point so Promise processing can
// yield to its main-loop driver; this alone is not a GC-hang recovery mechanism.
await application.runAsync(['fin3000-printer', ...ARGV]);

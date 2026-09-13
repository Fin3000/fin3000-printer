import Gio from 'gi://Gio';
import Gtk from 'gi://Gtk?version=4.0';
import {translator} from './i18n.js';

const t = translator();
const app = new Gtk.Application({application_id: 'com.fin3000.PrinterSetup'});
let window, busy = false;

app.connect('activate', () => {
    if (window) { window.present(); return; }
    window = new Gtk.ApplicationWindow({application: app, title: t('installerTitle'), default_width: 570});
    const box = new Gtk.Box({orientation: Gtk.Orientation.VERTICAL, spacing: 18,
        margin_top: 30, margin_bottom: 30, margin_start: 30, margin_end: 30});
    const label = text => new Gtk.Label({label: text, wrap: true, xalign: 0, max_width_chars: 65});
    box.append(label(t('installerExplanation')));
    box.append(label(t('installerTrust')));
    box.append(label(t('installerUpdates')));
    const status = label(t('installerReady'));
    const install = new Gtk.Button({label: t('installerInstall')});
    install.add_css_class('suggested-action');
    const open = new Gtk.Button({label: t('installerOpen'), visible: false});
    open.connect('clicked', () => {
        try { Gio.Subprocess.new(['/usr/bin/fin3000-printer'], Gio.SubprocessFlags.NONE); }
        catch { status.set_label(t('installerOpenFailed')); }
    });
    install.connect('clicked', () => {
        if (busy) return;
        busy = true; install.set_sensitive(false); open.set_visible(false); app.hold();
        status.set_label(t('installerWorking'));
        const finish = (ok, code) => {
            busy = false; install.set_sensitive(true); app.release();
            open.set_visible(ok);
            const messages = {INSTALL_COMPLETE: 'installerComplete', INSTALL_RESTORED: 'installerRestored', INSTALL_SOURCE_CHANGED: 'installerSourceChanged',
                INSTALL_UNSUPPORTED_OS: 'installerUnsupported', INSTALL_NO_RELEASE: 'installerUnavailable',
                INSTALL_WRONG_ORIGIN: 'installerSourceChanged', INSTALL_BUSY: 'installerBusy',
                INSTALL_UPDATE_FAILED: 'installerNetwork', INSTALL_NO_DOWNGRADE: 'installerNoDowngrade'};
            status.set_label(t(messages[code] ?? 'installerFailed'));
        };
        try {
            const child = Gio.Subprocess.new(['/usr/bin/pkexec', '/usr/lib/fin3000-printer-setup/install.py'],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
            child.communicate_utf8_async(null, null, (_process, result) => {
                try {
                    const [, stdout] = child.communicate_utf8_finish(result);
                    const code = stdout.trim();
                    const ready = ['INSTALL_COMPLETE', 'INSTALL_RESTORED'].includes(code);
                    const ok = child.get_successful() && ready;
                    finish(ok, !ok && ready ? 'INSTALL_PACKAGE_FAILED' : code);
                } catch { finish(false, 'INSTALL_PACKAGE_FAILED'); }
            });
        } catch { finish(false, 'INSTALL_PACKAGE_FAILED'); }
    });
    box.append(status); box.append(install); box.append(open);
    window.set_child(box);
    window.connect('close-request', () => {
        // Closing the window must not kill an APT/dpkg transaction.
        if (busy) { window.set_visible(false); return true; }
        return false;
    });
    window.present();
});
// Yield module evaluation while GTK runs, including asynchronous APT completion.
await app.runAsync(['fin3000-printer-setup', ...ARGV]);

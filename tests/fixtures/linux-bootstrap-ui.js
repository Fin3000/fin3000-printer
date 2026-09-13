/** Private-bus GTK contract: every subprocess replaced before importing app. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk?version=4.0';
import System from 'system';

const source = ARGV[0]; ARGV.splice(0);
let failed = false, pending, response, launches = 0;
const commands = [];
function assert(value, message) { if (!value) throw new Error(message); }
Gio.Subprocess.new = args => {
    if (args.length === 1 && args[0] === '/usr/bin/fin3000-printer') { launches++; return {}; }
    assert(JSON.stringify(args) === JSON.stringify(['/usr/bin/pkexec', '/usr/lib/fin3000-printer-setup/install.py']), 'unexpected subprocess');
    commands.push(args);
    return {
        communicate_utf8_async: (_input, _cancel, callback) => { pending = () => callback(null, null); },
        communicate_utf8_finish: () => [true, response.code, null],
        get_successful: () => response.ok,
        force_exit: () => { throw new Error('must not terminate dpkg'); },
    };
};
function descendants(widget) {
    const result = [widget];
    for (let child = widget.get_first_child(); child; child = child.get_next_sibling()) result.push(...descendants(child));
    return result;
}
GLib.timeout_add(GLib.PRIORITY_DEFAULT, 150, () => {
    const app = Gio.Application.get_default(), window = app?.get_active_window();
    try {
        assert(window, 'setup window must exist');
        const widgets = descendants(window), buttons = widgets.filter(widget => widget instanceof Gtk.Button);
        const labels = () => widgets.filter(widget => widget instanceof Gtk.Label).map(widget => widget.get_label()).join('\n');
        const install = buttons.find(button => button.get_label() === 'Install');
        const open = buttons.find(button => button.get_label() === 'Open printer and connect account');
        assert(install && open && !open.get_visible() && !commands.length, 'no automatic install or open');
        assert(labels().includes('does not automatically verify our separate signature'), 'bootstrap trust must be explicit');
        install.emit('clicked'); install.emit('clicked');
        assert(commands.length === 1 && !install.get_sensitive(), 'single-flight installation');
        window.close();
        assert(!window.get_visible() && app.get_windows().includes(window), 'close hides but does not terminate transaction');
        response = {ok: true, code: 'INSTALL_COMPLETE'}; pending();
        assert(open.get_visible() && install.get_sensitive() && labels().includes('Installation completed.'), 'successful installation');
        app.activate();
        assert(window.get_visible(), 'reopen existing window after close');
        open.emit('clicked'); assert(launches === 1, 'open printer as user, not through pkexec');
        install.emit('clicked'); response = {ok: false, code: 'INSTALL_COMPLETE'}; pending();
        assert(!open.get_visible() && !labels().includes('Installation completed.'), 'nonzero exit must not show successful installation');
        install.emit('clicked'); response = {ok: true, code: 'INSTALL_RESTORED'}; pending();
        assert(open.get_visible() && labels().includes('The update failed.') && labels().includes('previous printer version has been restored'), 'restored previous version is usable but not a successful update');
        install.emit('clicked'); response = {ok: false, code: 'INSTALL_RESTORED'}; pending();
        assert(!open.get_visible() && !labels().includes('has been restored'), 'failed recovery cannot claim restore success');
        install.emit('clicked'); response = {ok: false, code: 'INSTALL_SOURCE_CHANGED'}; pending();
        assert(labels().includes('has not overwritten or reenabled anything'), 'changed source is actionable, no repair bypass');
        print(JSON.stringify({ok: true, realGtk: true, cases: 10, installs: 0, hostPrinters: 0}));
    } catch (error) { failed = true; printerr(error.message); }
    finally { window?.destroy(); app?.quit(); }
    return GLib.SOURCE_REMOVE;
});
await import(GLib.filename_to_uri(source, null));
System.exit(failed ? 1 : 0);

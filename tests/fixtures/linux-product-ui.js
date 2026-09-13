/** Real GTK widgets on a private X server; synthetic state, no coordinator/backend. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk?version=4.0';
import Gdk from 'gi://Gdk?version=4.0';
import System from 'system';
import {PrinterWindow, validateState, validateRelease} from '../../platforms/linux/ui.js';

function assert(value, message) { if (!value) throw new Error(message); }
Gtk.init();
const application = new Gtk.Application({application_id: 'com.fin3000.Printer.UiContract', flags: Gio.ApplicationFlags.NON_UNIQUE});
application.register(null);
const actions = [], view = new PrinterWindow(application, command => actions.push(command));
assert(view.helpWindow === null && view.help.get_label() === 'Offline help', 'help is explicit, not a startup popup');
view.help.emit('clicked');
const help = view.helpWindow;
assert(help.get_visible() && !help.get_modal() && actions.length === 0, 'help works before runtime without commands or blocking confirmation');
view.help.emit('clicked');
assert(view.helpWindow === help, 'repeated help action reuses one window');
assert(!view.helpTroubleshooting.get_expanded(), 'possible errors do not obscure normal setup instructions');
view.helpKeys.emit('key-pressed', Gdk.KEY_Escape, 0, 0);
assert(!help.get_visible() && actions.length === 0, 'help Escape only closes help, never cancels or sends a print');
assert(!view.releaseInfo.get_visible(), 'no made-up version before validated runtime identity');
const release = {type: 'release', version: '0.0.0~qa3', sourceCommit: 'abcdef01'.repeat(5)};
view.setRelease(release); view.setRelease({...release});
assert(view.releaseInfo.get_label() === 'Version 0.0.0~qa3 · build abcdef0' &&
    view.releaseInfo.get_tooltip_text() === release.sourceCommit && !view.releaseInfo.get_use_markup(), 'exact plain-text installed version');
for (const invalid of [null, {}, {...release, version: '<b>0.1.0</b>'}, {...release, version: '0.01.0'},
    {...release, version: '0.1.0~qa0'}, {...release, version: '0.1.0\nsecret'}, {...release, version: '0.1.0\n'},
    {...release, sourceCommit: release.sourceCommit + '\n'},
    {...release, sourceCommit: '0'.repeat(40)}, {...release, sourceCommit: '<a>not-a-commit</a>'}, {...release, token: 'forbidden'}]) {
    let rejected = false;
    try { validateRelease(invalid); } catch { rejected = true; }
    assert(rejected, 'invalid release metadata rejected');
}
assert(validateRelease({...release, version: '0.1.0'}).version === '0.1.0', 'production version accepted');
let changed = false;
try { view.setRelease({...release, version: '0.0.0~qa4'}); } catch { changed = true; }
assert(changed && view.releaseInfo.get_label().includes('~qa3') && actions.length === 0, 'running build identity cannot silently change or trigger action');
const id = GLib.uuid_string_random();
const job = {operationId: id, name: '<b>Synthetic invoice & only test</b>.pdf', size: 1024, outcome: 'confirming',
    receivedAt: 1_000_000, extended: false, target: 'Synthetic <company>', remainingSeconds: 120, canSend: true};
const state = {type: 'state', queueReady: true, locked: false, connected: true, target: job.target,
    busy: null, code: null, draining: false, removalReady: false, removed: false, jobs: [job]};
view.update(state);
const loop = GLib.MainLoop.new(null, false);
let failed = false;
GLib.timeout_add(GLib.PRIORITY_DEFAULT, 150, () => {
    try {
        const row = view.rows.get(id);
        assert(view.window.get_focus() === row.cancel, 'initial focus must be Cancel');
        assert(row.name.get_label() === job.name && !row.name.get_use_markup(), 'job title must be plain text');
        assert(row.target.get_label().includes(job.target) && !row.target.get_use_markup(), 'target must be plain text');
        view.update({...state, target: null, jobs: [{...job, target: null}]});
        assert(row.target.get_label().includes('No fixed assignment'), 'unassigned job has localized destination');
        assert(view.status.get_label().includes('No fixed assignment'), 'unassigned connection is ready');
        view.update(state);
        assert(row.send.get_sensitive() && !row.extend.get_visible(), 'initial confirmation controls');
        row.send.emit('clicked');
        assert(actions.length === 1 && actions[0].action === 'confirm' && actions[0].operationId === id, 'explicit send action only');
        assert(!row.send.get_sensitive(), 'double click disabled immediately');
        view.update({...state, jobs: [{...job, remainingSeconds: 30}]});
        assert(view.rows.get(id) === row && row.extend.get_visible(), 'countdown must preserve widgets/focus');
        view.update({...state, locked: true, connected: false, jobs: [{...job, canSend: false}]});
        assert(!row.send.get_sensitive() && !row.cancel.get_sensitive(), 'locked session disables mutation');
        view.update({...state, jobs: [{...job, outcome: 'uncertain', remainingSeconds: null, canSend: false}]});
        assert(!row.send.get_visible() && !row.original.get_visible() && row.reconcile.get_visible(), 'uncertain may reconcile, not resend/original');
        assert(row.exportRecovery.get_visible() && row.importReceipt.get_visible(), 'uncertain offers explicit local recovery');
        view.update({...state, connected: false, jobs: [{...job, outcome: 'uncertain', remainingSeconds: null, canSend: false}]});
        assert(!row.reconcile.get_sensitive() && row.exportRecovery.get_sensitive() && row.importReceipt.get_sensitive(), 'offline recovery does not need OAuth');
        row.importReceipt.emit('clicked');
        assert(view.dialogs.pending?.operationId === id, 'receipt dialog is bound to clicked job');
        view.update({...state, locked: true, jobs: [{...job, outcome: 'uncertain', remainingSeconds: null, canSend: false}]});
        assert(view.dialogs.pending === null && !row.importReceipt.get_sensitive(), 'locking closes recovery dialog');
        view.update({...state, jobs: [{...job, outcome: 'uncertain', remainingSeconds: null, canSend: false}]});
        assert(row.outcome.get_label().includes('Do not print again'), 'explicit unknown outcome warning');
        view.update({...state, jobs: [{...job, outcome: 'accepted', remainingSeconds: null, canSend: false}]});
        assert(row.outcome.get_label() === 'Print copy received. Checks are running.', 'received is not finished accounting');
        const nextId = '22222222-2222-4222-8222-222222222222';
        const nextJob = {...job, operationId: nextId, receivedAt: job.receivedAt + 1};
        const history = {...job, outcome: 'accepted', remainingSeconds: null, canSend: false};
        view.update({...state, jobs: [nextJob, history]});
        const nextRow = view.rows.get(nextId);
        assert(view.list.get_first_child() === nextRow.frame && nextRow.frame.get_next_sibling() === row.frame,
            'new confirmation must precede existing history, matching coordinator order');
        assert(view.rows.get(id) === row && view.window.get_focus() === nextRow.cancel,
            'reordering keeps existing widgets and never focuses Send');
        view.update({...state, jobs: [history, {...nextJob, outcome: 'accepted', remainingSeconds: null, canSend: false}]});
        assert(view.list.get_first_child() === row.frame && row.frame.get_next_sibling() === nextRow.frame,
            'existing rows follow changed authoritative order too');
        view.update({...state, jobs: [history]});
        assert(row.frame.get_next_sibling() === null && !view.rows.has(nextId), 'removed jobs leave no stale row');
        const before = actions.length;
        view.window.close();
        assert(actions.length === before, 'closing window does not send or cancel a server operation');
        for (const invalid of [{...state, jobs: [...state.jobs, job]}, {...state, jobs: [{...job, operationId: '../path'}]},
            {...state, code: 'provider\nsecret'}, {...state, jobs: [{...job, size: 21 * 1024 * 1024}]}]) {
            let rejected = false;
            try { validateState(invalid); } catch { rejected = true; }
            assert(rejected, 'invalid state rejected');
        }
        view.update({...state, queueReady: false, connected: false, draining: true, removalReady: true, removed: true, jobs: []});
        assert(view.status.get_label() === 'Print destination removed', 'removed is a distinct completed state');
        assert(!view.remove.get_visible() && !view.prepare.get_visible() && view.close.get_visible(), 'no repeated remove or stuck draining buttons');
        assert(view.explanation.get_label().includes('app is still installed'), 'removing a queue is not uninstalling the package');
        view.fatal('BUILD_CONFIG_INVALID');
        assert(!view.buttons.get_sensitive(), 'fatal state disables actions');
        view.fatal('RUNTIME_UNAVAILABLE'); view.update(state);
        assert(view.explanation.get_label().includes('BUILD_CONFIG_INVALID'), 'EOF and later states must not hide original error');
        assert(view.close.get_visible() && view.close.get_sensitive(), 'fatal application can be closed explicitly');
        const count = actions.length;
        view.help.emit('clicked');
        assert(view.help.get_sensitive() && help.get_visible() && actions.length === count, 'offline help survives fatal runtime without commands');
        const texts = [];
        view.helpTroubleshooting.set_expanded(true);
        function helpText(widget) {
            if (widget instanceof Gtk.Label) {
                assert(!widget.get_use_markup(), 'help text cannot contain active links or markup');
                texts.push(widget.get_label());
            }
            for (let child = widget.get_first_child(); child; child = child.get_next_sibling()) helpText(child);
        }
        helpText(help);
        assert(texts.some(text => text.includes('Do not print again')) &&
            texts.some(text => text.includes('structured e-invoice')) &&
            !texts.some(text => text.includes(id) || text.includes(job.name) || text.includes(job.target)),
        'bundled help explains uncertainty and print-copy limits without exposing job or account data');
        print(JSON.stringify({ok: true, realGtk: true, cases: 36, uploads: 0, hostPrinters: 0}));
    } catch (error) {
        failed = true; printerr(error.message);
    } finally { view.window.destroy(); loop.quit(); }
    return GLib.SOURCE_REMOVE;
});
loop.run();
System.exit(failed ? 1 : 0);

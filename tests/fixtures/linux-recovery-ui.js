/** Actual GTK controls and private GIO files; no account, keyring or upload. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk?version=4.0';
import Gdk from 'gi://Gdk?version=4.0';
import System from 'system';
import {RecoveryDialogs, validateRecoveryExport, saveNewRecoveryFile} from '../../platforms/linux/recovery-ui.js';
import {translator} from '../../platforms/linux/i18n.js';
import {writeOwnedBytes} from '../../platforms/linux/stream.js';

const assert = (condition, text) => { if (!condition) throw new Error(text); };
Gtk.init();
const application = new Gtk.Application({application_id: 'com.fin3000.Printer.RecoveryContract', flags: Gio.ApplicationFlags.NON_UNIQUE});
application.register(null);
const parent = new Gtk.ApplicationWindow({application});
const id = GLib.uuid_string_random(), target = GLib.uuid_string_random();
const payload = {format: 'fin3000-print-recovery', version: 1, issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa',
    clientId: 'fin3000-system-print-qa', subject: `sp_${'a'.repeat(32)}`, targetId: target, operationId: id,
    clientBatchId: GLib.uuid_string_random(), clientItemId: GLib.uuid_string_random(), requestFingerprint: 'b'.repeat(64), callbackNonce: 'c'.repeat(43)};
const content = JSON.stringify({...payload, checksum: GLib.compute_checksum_for_string(GLib.ChecksumType.SHA256, JSON.stringify(payload), -1)}) + '\n';
const job = {operationId: id, target: 'Synthetic <company>'};
const actions = [], notices = [];
let allowed = true, failed = false;
const privatePath = GLib.getenv('XDG_RUNTIME_DIR');
const file = Gio.File.new_for_path(`${privatePath}/synthetic-export.json`);
const dialogs = new RecoveryDialogs(parent, action => actions.push(action), translator(), () => allowed, key => notices.push(key), async () => file);
const loop = GLib.MainLoop.new(null, false);

async function run() {
    const original = new TextEncoder().encode('synthetic-ä-command\n'), expectedBytes = new Uint8Array(original), parts = [];
    const partial = {write_bytes_async(bytes, _priority, _cancel, callback) {
        GLib.idle_add(GLib.PRIORITY_DEFAULT, () => { parts.push(...bytes.get_data().slice(0, 3)); callback(partial, Math.min(3, bytes.get_size())); return GLib.SOURCE_REMOVE; });
    }, write_bytes_finish(result) { return result; }};
    const writing = writeOwnedBytes(partial, original); original.fill(0); await writing;
    assert(JSON.stringify(parts) === JSON.stringify([...expectedBytes]), 'immutable async ownership and partial write offsets preserve exact bytes');
    for (const result of [0, -1, 200, NaN]) {
        const broken = {write_bytes_async(_bytes, _priority, _cancel, callback) { callback(broken, result); }, write_bytes_finish(value) { return value; }};
        let rejected = false; try { await writeOwnedBytes(broken, new Uint8Array([1, 2, 3])); } catch { rejected = true; }
        assert(rejected, 'invalid partial write count fails closed');
    }
    const child = Gio.Subprocess.new(['/usr/bin/cat'], Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
    try {
        const input = new TextEncoder().encode(content), stream = child.get_stdin_pipe();
        await writeOwnedBytes(stream, input);
        await new Promise((resolve, reject) => stream.close_async(GLib.PRIORITY_DEFAULT, null,
            (source, result) => { try { source.close_finish(result); resolve(); } catch (error) { reject(error); } }));
        const output = child.get_stdout_pipe(), received = [];
        for (;;) {
            const block = await new Promise((resolve, reject) => output.read_bytes_async(4096, GLib.PRIORITY_DEFAULT, null,
                (source, result) => { try { resolve(source.read_bytes_finish(result)); } catch (error) { reject(error); } }));
            if (!block.get_size()) break;
            received.push(...block.get_data()); assert(received.length <= 4096, 'bounded synthetic echo');
        }
        assert(new TextDecoder().decode(new Uint8Array(received)) === content, 'actual private subprocess pipe preserves exact commands');
        await new Promise((resolve, reject) => child.wait_check_async(null,
            (source, result) => { try { source.wait_check_finish(result); resolve(); } catch (error) { reject(error); } }));
    } finally { child.force_exit(); }
    assert(validateRecoveryExport(content, id) === content, 'canonical content preserved');
    const unassignedPayload = {...payload, targetId: null};
    const unassignedContent = JSON.stringify({...unassignedPayload, checksum: GLib.compute_checksum_for_string(GLib.ChecksumType.SHA256, JSON.stringify(unassignedPayload), -1)}) + '\n';
    assert(validateRecoveryExport(unassignedContent, id) === unassignedContent, 'explicit null target preserved with checksum');
    for (const bad of [content.replace('b'.repeat(64), 'd'.repeat(64)), JSON.stringify({...JSON.parse(content), name: 'secret'}),
        content.replace(id, '../path'), unassignedContent.replace('"targetId":null,', ''), '{}', 'x'.repeat(4097)]) {
        let rejected = false; try { validateRecoveryExport(bad, id); } catch { rejected = true; }
        assert(rejected, 'malformed, tampered or excessive export rejected');
    }
    dialogs.receipt(job);
    assert(dialogs.pending && !dialogs.pending.submit.get_sensitive(), 'empty receipt cannot submit');
    const pending = dialogs.pending;
    dialogs.receipt(job); assert(dialogs.pending === pending, 'one dialog at a time');
    pending.entry.set_text('not a signed confirmation'); assert(!pending.submit.get_sensitive(), 'invalid syntax cannot submit');
    pending.entry.set_text('ey.aWQ.sig'); assert(pending.submit.get_sensitive(), 'syntactic receipt can request core verification');
    pending.submit.emit('clicked');
    assert(actions.length === 1 && actions[0].action === 'importReceipt' && actions[0].operationId === id, 'only bound import action sent');
    assert(dialogs.pending === null && pending.entry.get_text() === '' && notices.length === 0, 'input cleared, no unverified success');
    dialogs.receipt(job); const escape = dialogs.pending; escape.entry.set_text('ey.aWQ.sig');
    escape.keyboard.emit('key-pressed', Gdk.KEY_Escape, 0, 0);
    assert(dialogs.pending === null && escape.entry.get_text() === '' && actions.length === 1, 'Escape cancels and clears without importing');
    dialogs.receipt(job); const locked = dialogs.pending; locked.entry.set_text('ey.aWQ.sig'); allowed = false; dialogs.cancel();
    assert(locked.entry.get_text() === '' && dialogs.pending === null, 'lock closes and clears receipt');
    dialogs.receipt(job); assert(dialogs.pending === null && actions.length === 1, 'locked session cannot reopen');
    allowed = true;
    await dialogs.save({operationId: id, content});
    assert(notices.at(-1) === 'exportSaved', 'success only after completed write/close');
    const [, bytes] = file.load_contents(null);
    const actual = new TextDecoder().decode(bytes);
    assert(actual === content, `actual GIO file contains exact canonical export (expected=${content.length}, actual=${actual.length}, first difference=${[...content].findIndex((char, index) => char !== actual[index])})`);
    assert((file.query_info('unix::mode', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null).get_attribute_uint32('unix::mode') & 0o777) === 0o600, 'new file is user-private');
    await dialogs.save({operationId: id, content});
    assert(notices.at(-1) === 'exportFailed', 'existing file never overwritten');
    assert(new TextDecoder().decode(file.load_contents(null)[1]) === content, 'existing bytes preserved');
    const link = Gio.File.new_for_path(`${privatePath}/synthetic-link.json`); link.make_symbolic_link(file.get_path(), null);
    let rejected = false;
    try { await saveNewRecoveryFile(link, content, new Gio.Cancellable()); } catch { rejected = true; }
    assert(rejected && new TextDecoder().decode(file.load_contents(null)[1]) === content, 'symlink destination does not overwrite target');
    rejected = false;
    try { await saveNewRecoveryFile(Gio.File.new_for_uri('https://foreign.example.test/export'), content, new Gio.Cancellable()); } catch { rejected = true; }
    assert(rejected, 'remote destination rejected before IO');
    let choose;
    dialogs.chooseFile = () => new Promise(resolve => { choose = resolve; });
    const late = dialogs.save({operationId: id, content});
    const beforeCancel = notices.length;
    dialogs.cancel(); choose(Gio.File.new_for_path(`${privatePath}/late-export.json`)); await late;
    assert(notices.length === beforeCancel && !Gio.File.new_for_path(`${privatePath}/late-export.json`).query_exists(null), 'cancelled chooser cannot write a late selection');
    dialogs.chooseFile = async () => { throw new GLib.Error(Gtk.dialog_error_quark(), Gtk.DialogError.DISMISSED, 'synthetic cancel'); };
    await dialogs.save({operationId: id, content});
    assert(notices.length === beforeCancel, 'user dismiss is not a save error');
    print(JSON.stringify({ok: true, realGtk: true, privateFileIo: true, cases: 24, uploads: 0, hostPrinters: 0}));
}

void run().catch(error => { failed = true; printerr(`${error.name}: ${error.message}`); }).finally(() => { dialogs.cancel(); parent.destroy(); loop.quit(); });
loop.run();
System.exit(failed ? 1 : 0);

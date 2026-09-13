/** Explicit local recovery dialogs. No network, credentials or trust-key input. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Gtk from 'gi://Gtk?version=4.0';
import Gdk from 'gi://Gdk?version=4.0';
import {writeOwnedBytes} from './stream.js';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const FIELDS = ['format', 'version', 'issuer', 'audience', 'clientId', 'subject', 'targetId',
    'operationId', 'clientBatchId', 'clientItemId', 'requestFingerprint', 'callbackNonce'];
const receiptSyntax = text => text.length <= 8192 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text);

export function validateRecoveryExport(content, operationId) {
    if (typeof content !== 'string' || new TextEncoder().encode(content).length > 4096 || !UUID.test(operationId)) throw new Error('RECOVERY_EXPORT_INVALID');
    const data = JSON.parse(content);
    if (!data || Array.isArray(data) || Object.keys(data).sort().join(',') !== [...FIELDS, 'checksum'].sort().join(',') ||
        data.format !== 'fin3000-print-recovery' || data.version !== 1 || data.operationId !== operationId ||
        ['operationId', 'clientBatchId', 'clientItemId'].some(key => typeof data[key] !== 'string' || !UUID.test(data[key])) ||
        (data.targetId !== null && (typeof data.targetId !== 'string' || !UUID.test(data.targetId))) ||
        typeof data.subject !== 'string' || !/^sp_[0-9a-f]{32}$/.test(data.subject) ||
        typeof data.requestFingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(data.requestFingerprint) ||
        typeof data.callbackNonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.callbackNonce) ||
        typeof data.issuer !== 'string' || data.issuer.length > 512 ||
        typeof data.checksum !== 'string' || !/^[0-9a-f]{64}$/.test(data.checksum)) throw new Error('RECOVERY_EXPORT_INVALID');
    const qa = data.clientId === 'fin3000-system-print-qa';
    if ((!qa && data.clientId !== 'fin3000-system-print') ||
        data.audience !== `fin3000-printer:${qa ? 'qa' : 'production'}`) throw new Error('RECOVERY_EXPORT_INVALID');
    const uri = GLib.Uri.parse(data.issuer, GLib.UriFlags.NONE);
    if (uri.get_userinfo() || uri.get_query() || uri.get_fragment() || !uri.get_host() ||
        (uri.get_path() && uri.get_path() !== '/') ||
        (uri.get_scheme() !== 'https' && !(qa && uri.get_scheme() === 'http' && uri.get_host() === '127.0.0.1'))) throw new Error('RECOVERY_EXPORT_INVALID');
    const payload = Object.fromEntries(FIELDS.map(key => [key, data[key]]));
    if (GLib.compute_checksum_for_string(GLib.ChecksumType.SHA256, JSON.stringify(payload), -1) !== data.checksum) throw new Error('RECOVERY_EXPORT_INVALID');
    return JSON.stringify({...payload, checksum: data.checksum}) + '\n';
}

function selectFile(parent, title, name, cancellable) {
    return new Promise((resolve, reject) => {
        const dialog = new Gtk.FileDialog({title, initial_name: name, modal: true});
        dialog.save(parent, cancellable, (source, result) => {
            try { resolve(source.save_finish(result)); } catch (error) { reject(error); }
        });
    });
}

export async function saveNewRecoveryFile(file, content, cancellable) {
    if (!file?.is_native() || !file.get_path() || cancellable.is_cancelled()) throw new Error('RECOVERY_EXPORT_FAILED');
    const bytes = new TextEncoder().encode(content);
    if (bytes.length > 4096) throw new Error('RECOVERY_EXPORT_INVALID');
    let stream;
    try {
        stream = await new Promise((resolve, reject) => file.create_async(Gio.FileCreateFlags.PRIVATE, GLib.PRIORITY_DEFAULT, cancellable,
            (source, result) => { try { resolve(source.create_finish(result)); } catch (error) { reject(error); } }));
        const info = await new Promise((resolve, reject) => stream.query_info_async('standard::type,unix::mode,unix::uid', GLib.PRIORITY_DEFAULT, cancellable,
            (source, result) => { try { resolve(source.query_info_finish(result)); } catch (error) { reject(error); } }));
        if (info.get_file_type() !== Gio.FileType.REGULAR || !info.has_attribute('unix::mode') || !info.has_attribute('unix::uid') ||
            (info.get_attribute_uint32('unix::mode') & 0o777) !== 0o600 ||
            info.get_attribute_uint32('unix::uid') !== Gio.Credentials.new().get_unix_user()) throw new Error('RECOVERY_EXPORT_FAILED');
        await writeOwnedBytes(stream, bytes, cancellable);
        await new Promise((resolve, reject) => stream.close_async(GLib.PRIORITY_DEFAULT, null,
            (source, result) => { try { if (!source.close_finish(result)) throw new Error(); resolve(); } catch (error) { reject(error); } }));
    } finally {
        bytes.fill(0);
        // Never unlink by path: another process could have replaced that path.
        // An incomplete new export remains harmless (checksum/import rejects it).
        if (stream && !stream.is_closed()) await new Promise(resolve => stream.close_async(GLib.PRIORITY_DEFAULT, null,
            (source, result) => { try { source.close_finish(result); } catch { /* No successful-export claim. */ } resolve(); }));
    }
}

export class RecoveryDialogs {
    constructor(parent, send, translate, allowed, notify, chooseFile = selectFile) {
        this.parent = parent; this.send = send; this.t = translate; this.allowed = allowed; this.notify = notify; this.chooseFile = chooseFile;
        this.pending = null;
    }

    cancel() {
        const pending = this.pending; this.pending = null;
        pending?.cancel.cancel();
        pending?.entry?.set_text(''); pending?.window?.destroy();
    }

    receipt(job) {
        if (!job || this.pending || !this.allowed(job.operationId)) return;
        const pending = {operationId: job.operationId, cancel: new Gio.Cancellable()}; this.pending = pending;
        const dialog = new Gtk.Window({transient_for: this.parent, modal: true, title: this.t('receiptTitle'), default_width: 560});
        pending.window = dialog;
        const body = new Gtk.Box({orientation: Gtk.Orientation.VERTICAL, spacing: 16});
        for (const side of ['top', 'bottom', 'start', 'end']) body[`margin_${side}`] = 24;
        for (const text of [this.t('receiptExplanation'), this.t('target', {target: job.target ?? this.t('unassigned')}), this.t('operation', {id: job.operationId})]) {
            body.append(new Gtk.Label({label: text, wrap: true, xalign: 0, selectable: true}));
        }
        const entry = new Gtk.Entry({max_length: 8192, placeholder_text: this.t('receiptPlaceholder')}); pending.entry = entry; body.append(entry);
        const cancel = new Gtk.Button({label: this.t('cancel')}); body.append(cancel);
        const submit = new Gtk.Button({label: this.t('receiptCheck'), sensitive: false}); pending.submit = submit; body.append(submit);
        entry.connect('changed', () => submit.set_sensitive(receiptSyntax(entry.get_text().trim()) && this.allowed(job.operationId)));
        cancel.connect('clicked', () => this.cancel());
        dialog.connect('close-request', () => { this.cancel(); return false; });
        const keyboard = new Gtk.EventControllerKey(); pending.keyboard = keyboard;
        keyboard.connect('key-pressed', (_controller, key) => {
            if (key !== Gdk.KEY_Escape) return false;
            this.cancel(); return true;
        }); dialog.add_controller(keyboard);
        submit.connect('clicked', () => {
            const receipt = entry.get_text().trim();
            if (this.pending !== pending || !this.allowed(job.operationId) || !receiptSyntax(receipt)) { this.cancel(); return; }
            this.cancel(); this.send({action: 'importReceipt', operationId: job.operationId, receipt});
        });
        dialog.set_child(body); dialog.present(); cancel.grab_focus();
    }

    async save(message) {
        if (this.pending || !this.allowed(message.operationId)) return;
        let content;
        try { content = validateRecoveryExport(message.content, message.operationId); }
        catch { this.notify('exportFailed'); return; }
        const pending = {operationId: message.operationId, cancel: new Gio.Cancellable()}; this.pending = pending;
        try {
            const file = await this.chooseFile(this.parent, this.t('exportTitle'), `fin3000-print-${message.operationId}.json`, pending.cancel);
            if (this.pending !== pending || !this.allowed(message.operationId) || pending.cancel.is_cancelled()) return;
            await saveNewRecoveryFile(file, content, pending.cancel);
            if (this.pending === pending && this.allowed(message.operationId)) this.notify('exportSaved');
        } catch (error) {
            const dismissed = error.matches?.(Gtk.dialog_error_quark(), Gtk.DialogError.DISMISSED) || error.matches?.(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED);
            if (this.pending === pending && !pending.cancel.is_cancelled() && !dismissed) this.notify('exportFailed');
        } finally { content = ''; if (this.pending === pending) this.pending = null; }
    }
}

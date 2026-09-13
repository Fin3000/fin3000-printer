/** Native GTK4 presentation only: no tokens, upload, receipt verification or root work. */
import Gtk from 'gi://Gtk?version=4.0';
import Gdk from 'gi://Gdk?version=4.0';
import {translator} from './i18n.js';
import {RecoveryDialogs} from './recovery-ui.js';

const OUTCOMES = new Set(['waiting', 'confirming', 'transferring', 'uncertain', 'accepted', 'never_accepted', 'cancelled']);
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const label = text => new Gtk.Label({label: text, wrap: true, xalign: 0, selectable: true});
const box = () => new Gtk.Box({orientation: Gtk.Orientation.VERTICAL, spacing: 12});

export function validateRelease(input) {
    if (!input || Object.keys(input).sort().join(',') !== 'sourceCommit,type,version' || input.type !== 'release' ||
        typeof input.version !== 'string' || input.version.length > 64 || input.version !== input.version.trim() ||
        !/^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:~qa[1-9][0-9]*)?$/.test(input.version) ||
        typeof input.sourceCommit !== 'string' || input.sourceCommit.length !== 40 ||
        !/^[0-9a-f]{40}$/.test(input.sourceCommit) || /^0+$/.test(input.sourceCommit)) {
        throw new Error('UI_RELEASE_INVALID');
    }
    return input;
}

export function validateState(state) {
    if (!state || state.type !== 'state' || typeof state.queueReady !== 'boolean' || typeof state.locked !== 'boolean' ||
        typeof state.connected !== 'boolean' || typeof state.draining !== 'boolean' ||
        typeof state.removalReady !== 'boolean' || typeof state.removed !== 'boolean' ||
        (state.removed && (!state.draining || !state.removalReady || state.queueReady || state.connected)) ||
        (state.target !== null && (typeof state.target !== 'string' || state.target.length > 120)) ||
        (state.busy !== null && !['login', 'restore', 'setup', 'transfer', 'reconcile', 'importReceipt', 'drain', 'remove'].includes(state.busy)) ||
        (state.code !== null && (typeof state.code !== 'string' || !/^[A-Z0-9_]{1,80}$/.test(state.code))) ||
        !Array.isArray(state.jobs) || state.jobs.length > 50) throw new Error('UI_STATE_INVALID');
    const seen = new Set();
    for (const job of state.jobs) {
        if (!job || !UUID.test(job.operationId) || seen.has(job.operationId) || !OUTCOMES.has(job.outcome) ||
            typeof job.name !== 'string' || job.name.length > 200 || (job.target !== null && (typeof job.target !== 'string' || job.target.length > 120)) ||
            typeof job.canSend !== 'boolean' || typeof job.extended !== 'boolean' || !Number.isSafeInteger(job.size) || job.size < 5 || job.size > 20 * 1024 * 1024 ||
            (job.remainingSeconds !== null && (!Number.isSafeInteger(job.remainingSeconds) || job.remainingSeconds < 0 || job.remainingSeconds > 240))) throw new Error('UI_STATE_INVALID');
        seen.add(job.operationId);
    }
    return state;
}

export class PrinterWindow {
    constructor(application, send, translate = translator()) {
        this.t = translate; this.send = send; this.rows = new Map(); this.current = null; this.failed = false;
        this.window = new Gtk.ApplicationWindow({application, title: this.t('title'), default_width: 680, default_height: 740});
        const header = new Gtk.HeaderBar(); this.window.set_titlebar(header);
        this.helpWindow = null;
        this.help = this.button('offlineHelp', () => this.showHelp()); header.pack_end(this.help);
        this.window.connect('close-request', () => {
            if (this.current?.removed || this.failed) { application.quit(); return false; }
            this.window.set_visible(false); return true;
        });
        const scroll = new Gtk.ScrolledWindow({hscrollbar_policy: Gtk.PolicyType.NEVER, vexpand: true});
        const content = box(); content.spacing = 20;
        for (const side of ['top', 'bottom', 'start', 'end']) content[`margin_${side}`] = 24;
        scroll.set_child(content); this.window.set_child(scroll);
        this.status = label(this.t('starting')); this.status.add_css_class('title-2'); content.append(this.status);
        this.releaseInfo = label(''); this.releaseInfo.add_css_class('dim-label');
        this.releaseInfo.set_visible(false); content.append(this.releaseInfo);
        this.release = null;
        this.explanation = label(''); content.append(this.explanation);
        this.error = label(''); this.error.set_visible(false); content.append(this.error);
        this.recoveryNotice = label(''); this.recoveryNotice.set_visible(false); content.append(this.recoveryNotice);
        this.dialogs = new RecoveryDialogs(this.window, this.send, this.t,
            id => !this.failed && !this.current?.locked && !this.current?.busy && this.current?.jobs.some(job => job.operationId === id && job.outcome === 'uncertain'),
            key => { this.recoveryNotice.set_label(this.t(key)); this.recoveryNotice.set_visible(true); });
        this.exportRequested = null;
        this.buttons = box(); content.append(this.buttons);
        this.configure = this.button('configure', () => this.send({action: 'configure'}));
        this.connect = this.button('connect', () => this.send({action: 'connect'}));
        this.cancelLogin = this.button('cancelLogin', () => this.send({action: 'cancelLogin'}));
        for (const button of [this.configure, this.connect, this.cancelLogin]) this.buttons.append(button);
        const heading = label(this.t('jobs')); heading.add_css_class('title-3'); content.append(heading);
        this.empty = label(this.t('empty')); content.append(this.empty);
        this.list = box(); this.list.spacing = 16; content.append(this.list);
        content.append(new Gtk.Separator({orientation: Gtk.Orientation.HORIZONTAL}));
        this.recovery = this.button('recovery', () => this.send({action: 'openRecovery'})); content.append(this.recovery);
        this.prepare = this.button('prepareRemoval', () => this.send({action: 'prepareRemoval'})); content.append(this.prepare);
        this.remove = this.button('remove', () => this.send({action: 'remove'})); content.append(this.remove); this.remove.set_visible(false);
        this.close = this.button('closeApp', () => application.quit()); content.append(this.close); this.close.set_visible(false);
        const keyboard = new Gtk.EventControllerKey();
        keyboard.connect('key-pressed', (_controller, key) => {
            if (key === Gdk.KEY_F1) { this.showHelp(); return true; }
            if (key !== Gdk.KEY_Escape) return false;
            const confirming = this.current?.jobs.find(job => job.outcome === 'confirming');
            if (confirming) this.send({action: 'cancel', operationId: confirming.operationId});
            else this.window.set_visible(false);
            return true;
        });
        this.window.add_controller(keyboard);
    }

    button(key, clicked) {
        const button = new Gtk.Button({label: this.t(key), halign: Gtk.Align.FILL});
        button.connect('clicked', clicked); return button;
    }

    showHelp() {
        // Bundled catalog text only: no browser, filesystem chooser, runtime
        // command, account data or network. Remains usable if startup fails.
        if (!this.helpWindow) {
            this.helpWindow = new Gtk.Window({title: this.t('offlineHelp'), transient_for: this.window,
                destroy_with_parent: true, hide_on_close: true, modal: false,
                default_width: 640, default_height: 700});
            this.helpWindow.set_titlebar(new Gtk.HeaderBar());
            const scroll = new Gtk.ScrolledWindow({hscrollbar_policy: Gtk.PolicyType.NEVER, vexpand: true});
            const content = box(); content.spacing = 20;
            for (const side of ['top', 'bottom', 'start', 'end']) content[`margin_${side}`] = 24;
            scroll.set_child(content); this.helpWindow.set_child(scroll);
            content.append(label(this.t('offlineHelpIntro')));
            // Reuse the same translated instructions and outcome definitions
            // as the live UI; a second manual must not drift on delivery safety.
            for (const [heading, ...paragraphs] of [
                ['setupRequired', 'setupExplanation'],
                ['connectRequired', 'connectExplanation'],
                ['jobs', 'readyExplanation', 'confirmNotice'],
                ['recovery', 'uncertain', 'receiptExplanation'],
                ['prepareRemoval', 'drainExplanation'],
                ['installerTitle', 'installerExplanation', 'installerTrust', 'installerUpdates'],
            ]) {
                const section = box(), title = label(this.t(heading)); title.add_css_class('title-3');
                section.append(title);
                if (heading === 'prepareRemoval') section.append(label(`${this.t('prepareRemoval')} → ${this.t('remove')}`));
                for (const key of paragraphs) section.append(label(this.t(key)));
                content.append(section);
            }
            this.helpTroubleshooting = new Gtk.Expander({label: this.t('helpTroubleshooting'), expanded: false});
            const messages = box();
            for (const key of ['autostartUnavailable', 'keyringLocked', 'secretUnavailable', 'queueFull',
                'lockedExplanation', 'accepted', 'originalAccount', 'exportSaved', 'pendingJobs', 'removedExplanation']) {
                messages.append(label(this.t(key)));
            }
            this.helpTroubleshooting.set_child(messages); content.append(this.helpTroubleshooting);
            this.helpKeys = new Gtk.EventControllerKey();
            this.helpKeys.connect('key-pressed', (_controller, key) => {
                if (key !== Gdk.KEY_Escape) return false;
                this.helpWindow.close(); return true;
            });
            this.helpWindow.add_controller(this.helpKeys);
        }
        this.helpWindow.present();
    }

    setRelease(input) {
        const release = validateRelease(input);
        if (this.release && (this.release.version !== release.version || this.release.sourceCommit !== release.sourceCommit)) {
            throw new Error('UI_RELEASE_INVALID');
        }
        this.release = {version: release.version, sourceCommit: release.sourceCommit};
        this.releaseInfo.set_label(this.t('buildVersion', {version: release.version, commit: release.sourceCommit.slice(0, 7)}));
        this.releaseInfo.set_tooltip_text(release.sourceCommit);
        this.releaseInfo.set_visible(true);
    }

    errorText(code) {
        if (!code || code === 'SETUP_REQUIRED' || code === 'LOGIN_REQUIRED') return '';
        let key = 'actionFailed';
        if (code === 'KEYRING_LOCKED') key = 'keyringLocked';
        else if (code === 'AUTOSTART_UNAVAILABLE') key = 'autostartUnavailable';
        else if (code.startsWith('SECRET_')) key = 'secretUnavailable';
        else if (['QUEUE_NAME_OCCUPIED', 'QUEUE_DRIFT', 'INSTALLATION_DRIFT', 'APPARMOR_DRIFT', 'CUPS_POLICY_UNSUPPORTED'].includes(code)) key = 'setupConflict';
        else if (code === 'PRINT_JOBS_PENDING') key = 'pendingJobs';
        else if (code === 'ORIGINAL_ACCOUNT_REQUIRED') key = 'originalAccount';
        else if (code === 'QUEUE_FULL') key = 'queueFull';
        else if (code === 'CONNECT_AND_REPRINT') key = 'reprint';
        else if (code === 'RECONCILE_REQUIRED') key = 'uncertain';
        else if (code === 'SESSION_LOCKED') key = 'lockedExplanation';
        else if (code === 'REVOCATION_PENDING') key = 'revocationPending';
        else if (code === 'REVOCATION_NEEDS_ACCOUNT') key = 'revocationNeedsAccount';
        else if (code === 'REMOVED_RESTART_REQUIRED') key = 'removedExplanation';
        else if (code === 'RECEIPT_INVALID') key = 'receiptInvalid';
        else if (code === 'RECEIPT_NOT_EXPECTED' || code === 'RECOVERY_NOT_AVAILABLE') key = 'recoveryNotAvailable';
        return `${this.t(key)}\n${this.t('errorCode', {code})}`;
    }

    update(input) {
        if (this.failed) return;
        const state = validateState(input), previous = this.current; this.current = state;
        if (this.dialogs.pending && !this.dialogs.allowed(this.dialogs.pending.operationId)) this.dialogs.cancel();
        if (state.locked) { this.exportRequested = null; this.recoveryNotice.set_visible(false); }
        const status = state.removed ? 'removed' : state.draining ? 'draining' : state.locked ? 'locked' : !state.queueReady ? 'setupRequired' : !state.connected ? 'connectRequired' : 'ready';
        const explanations = {removed: 'removedExplanation', draining: 'drainExplanation', locked: 'lockedExplanation', setupRequired: 'setupExplanation', connectRequired: 'connectExplanation', ready: 'readyExplanation'};
        this.status.set_label(this.t(status, {target: state.target ?? this.t('unassigned')}));
        this.explanation.set_label(this.t(state.busy === 'login' ? 'loginWorking' : explanations[status]));
        const error = this.errorText(state.code); this.error.set_label(error); this.error.set_visible(Boolean(error));
        this.configure.set_visible(!state.draining && !state.queueReady);
        this.connect.set_visible(!state.draining && state.queueReady && !state.connected && state.busy !== 'login');
        this.cancelLogin.set_visible(state.busy === 'login');
        this.configure.set_sensitive(!state.locked && !state.busy); this.connect.set_sensitive(!state.locked && !state.busy);
        this.prepare.set_visible(!state.removalReady); this.prepare.set_sensitive(!state.locked && !state.busy);
        this.remove.set_visible(state.draining && !state.removed); this.remove.set_sensitive(state.removalReady && !state.locked && !state.busy);
        this.close.set_visible(state.removed); this.close.set_sensitive(!state.busy);
        this.recovery.set_sensitive(!state.locked);
        this.empty.set_visible(!state.jobs.length);
        const wanted = new Set(state.jobs.map(job => job.operationId));
        for (const [id, row] of this.rows) if (!wanted.has(id)) { this.list.remove(row.frame); this.rows.delete(id); }
        let sibling = null, confirmation = null;
        for (const job of state.jobs) {
            let row = this.rows.get(job.operationId);
            if (!row) { row = this.createJob(job); this.rows.set(job.operationId, row); this.list.append(row.frame); }
            // Preserve widget identity/focus but follow the coordinator's active-
            // first ordering; appending new rows hid confirmations below history.
            if (row.frame.get_prev_sibling() !== sibling) this.list.reorder_child_after(row.frame, sibling);
            sibling = row.frame;
            this.updateJob(row, job, state);
            if (job.outcome === 'confirming' && previous?.jobs.find(old => old.operationId === job.operationId)?.outcome !== 'confirming') {
                confirmation = row;
            }
        }
        if (confirmation) {
            this.window.present();
            this.window.get_child().get_vadjustment().set_value(0);
            confirmation.cancel.grab_focus(); // Never initial-focus Send.
        }
        if (state.code === 'CONNECT_AND_REPRINT' && previous?.code !== state.code) this.window.present();
    }

    createJob(job) {
        const frame = new Gtk.Frame(), body = box();
        for (const side of ['top', 'bottom', 'start', 'end']) body[`margin_${side}`] = 16;
        frame.set_child(body);
        const target = label(''); target.add_css_class('heading'); body.append(target);
        const name = label(''); body.append(name);
        const details = label(''); body.append(details);
        const outcome = label(''); body.append(outcome);
        const notice = label(this.t('confirmNotice')); body.append(notice);
        const countdown = label(''); body.append(countdown);
        const buttons = {};
        for (const [key, action] of [['cancel', 'cancel'], ['send', 'confirm'], ['extend', 'extend'], ['original', 'original'], ['reconcile', 'reconcile']]) {
            buttons[key] = this.button(key, () => { if (key === 'send') buttons.send.set_sensitive(false); this.send({action, operationId: job.operationId}); });
            body.append(buttons[key]);
        }
        buttons.exportRecovery = this.button('exportRecovery', () => {
            if (this.dialogs.pending || !this.dialogs.allowed(job.operationId)) return;
            this.exportRequested = job.operationId; this.send({action: 'exportRecovery', operationId: job.operationId});
        }); body.append(buttons.exportRecovery);
        buttons.importReceipt = this.button('importReceipt', () => this.dialogs.receipt(this.current.jobs.find(item => item.operationId === job.operationId)));
        body.append(buttons.importReceipt);
        const operation = label(this.t('operation', {id: job.operationId})); operation.add_css_class('dim-label'); body.append(operation);
        return {frame, target, name, details, outcome, notice, countdown, ...buttons};
    }

    updateJob(row, job, state) {
        row.target.set_label(this.t('target', {target: job.target ?? this.t('unassigned')})); row.name.set_label(job.name);
        row.details.set_label(this.t('details', {size: (job.size / 1024 / 1024).toFixed(2)}));
        row.outcome.set_label(this.t(job.outcome));
        const confirming = job.outcome === 'confirming';
        row.notice.set_visible(confirming); row.countdown.set_visible(confirming);
        row.countdown.set_label(confirming ? this.t('countdown', {seconds: job.remainingSeconds}) : '');
        row.send.set_visible(confirming); row.send.set_sensitive(job.canSend && !state.busy);
        row.cancel.set_visible(['waiting', 'confirming', 'transferring'].includes(job.outcome)); row.cancel.set_sensitive(!state.locked);
        row.extend.set_visible(confirming && !job.extended && job.remainingSeconds <= 30); row.extend.set_sensitive(!state.locked);
        row.original.set_visible(confirming); row.original.set_sensitive(!state.locked && !state.busy);
        row.reconcile.set_visible(job.outcome === 'uncertain'); row.reconcile.set_sensitive(state.connected && !state.locked && !state.busy);
        for (const button of [row.exportRecovery, row.importReceipt]) {
            button.set_visible(job.outcome === 'uncertain'); button.set_sensitive(!state.locked && !state.busy);
        }
    }

    exportRecovery(message) {
        if (message.operationId !== this.exportRequested) return;
        this.exportRequested = null;
        void this.dialogs.save(message);
    }

    fatal(code) {
        if (this.failed) return;
        this.failed = true;
        this.dialogs.cancel(); this.exportRequested = null;
        this.status.set_label(this.t('runtimeFailed'));
        this.explanation.set_label(this.t('errorCode', {code: /^[A-Z0-9_]{1,80}$/.test(code) ? code : 'RUNTIME_UNAVAILABLE'}));
        for (const widget of [this.buttons, this.list, this.prepare, this.remove, this.recovery]) widget.set_sensitive(false);
        this.close.set_visible(true); this.close.set_sensitive(true);
    }
}

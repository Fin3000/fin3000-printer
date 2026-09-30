/** Strict metadata-only persisted schema. Never store tokens or PDF data here. */
import { PrinterError, UUID_PATTERN, jobKey, validateBinding } from './protocol.ts';
import type { JobRecord, StateSnapshot } from './protocol.ts';

const KEYS = new Set(['operationId', 'clientBatchId', 'clientItemId', 'identity', 'binding', 'name', 'size',
  'requestFingerprint', 'pdfSha256', 'callbackNonce', 'outcome', 'delivery', 'receivedAt',
  'confirmationDeadline', 'extended', 'code', 'receipt', 'recovery']);
export const MAX_STATE_BYTES = 4 * 1024 * 1024;

export interface StateRelease {
  package: 'fin3000-printer' | 'fin3000-printer-qa';
  version: string;
  sourceCommit: string;
  stateSchemaVersion: 1;
  protocolVersion: 2;
}

/** Compatibility identity only, never a caller-selected path or trust source. */
export function validateStateRelease(value: unknown): StateRelease {
  try {
    const release = value as StateRelease;
    exactKeys(release, new Set(['package', 'version', 'sourceCommit', 'stateSchemaVersion', 'protocolVersion']));
    const qa = release.package === 'fin3000-printer-qa';
    if (!['fin3000-printer', 'fin3000-printer-qa'].includes(release.package) ||
        typeof release.version !== 'string' || release.version.length > 64 ||
        !(qa ? /^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)~qa[1-9][0-9]*$/ : /^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/).test(release.version) ||
        typeof release.sourceCommit !== 'string' || !/^[0-9a-f]{40}$/.test(release.sourceCommit) || /^0+$/.test(release.sourceCommit) ||
        release.stateSchemaVersion !== 1 || release.protocolVersion !== 2) throw new Error();
    return { package: release.package, version: release.version, sourceCommit: release.sourceCommit,
      stateSchemaVersion: 1, protocolVersion: 2 };
  } catch { throw new PrinterError('STATE_VERSION_UNSUPPORTED'); }
}

export function stateReleaseFromManifest(value: unknown, environment: 'production' | 'qa'): StateRelease {
  try {
    const manifest = value as StateRelease;
    const release = validateStateRelease({ package: manifest.package, version: manifest.version,
      sourceCommit: manifest.sourceCommit, stateSchemaVersion: manifest.stateSchemaVersion, protocolVersion: manifest.protocolVersion });
    if (!['production', 'qa'].includes(environment) || release.package !== `fin3000-printer${environment === 'qa' ? '-qa' : ''}`) throw new Error();
    return release;
  } catch { throw new PrinterError('BUILD_CONFIG_INVALID'); }
}

function exactKeys(value: object, keys: Set<string>): void {
  if (value === null || Array.isArray(value) || Object.keys(value).some(key => !keys.has(key))) throw new Error();
}

export function validateSnapshot(value: unknown): StateSnapshot {
  try {
    const state = value as StateSnapshot;
    exactKeys(state, new Set(['version', 'jobs']));
    if (state.version !== 1 || !Array.isArray(state.jobs) || state.jobs.length > 5000) throw new Error();
    const ids = new Set(), identities = new Set();
    for (const row of state.jobs) {
      exactKeys(row, KEYS);
      exactKeys(row.identity, new Set(['generation', 'nativeJobUuid']));
      exactKeys(row.binding, new Set(['issuer', 'audience', 'clientId', 'subject', 'accountName', 'target']));
      exactKeys(row.binding.target, new Set(['id', 'name']));
      // Schema-v1 records created before account display used the target label
      // as their only safe human-readable fallback.
      row.binding.accountName ??= row.binding.target.name;
      validateBinding(row.binding);
      if (!UUID_PATTERN.test(row.operationId) || !UUID_PATTERN.test(row.clientBatchId) || !UUID_PATTERN.test(row.clientItemId) ||
          ids.has(row.operationId) || identities.has(jobKey(row.identity)) ||
          typeof row.name !== 'string' || row.name.length > 255 || /[\p{C}]/u.test(row.name) ||
          !Number.isSafeInteger(row.size) || row.size < 5 || row.size > 20 * 1024 * 1024 ||
          !/^[0-9a-f]{64}$/.test(row.requestFingerprint) || !/^[0-9a-f]{64}$/.test(row.pdfSha256) ||
          !/^[A-Za-z0-9_-]{43}$/.test(row.callbackNonce) || !Number.isSafeInteger(row.receivedAt) ||
          typeof row.extended !== 'boolean' ||
          (row.confirmationDeadline !== undefined && !Number.isSafeInteger(row.confirmationDeadline)) ||
          (row.code !== undefined && (typeof row.code !== 'string' || !/^[A-Z0-9_]{1,80}$/.test(row.code)))) throw new Error();
      const valid = row.delivery === 'not_dispatched' ? ['waiting', 'confirming', 'cancelled'] :
        row.delivery === 'possibly_delivered' ? ['transferring', 'uncertain'] :
        row.delivery === 'settled' ? ['accepted', 'never_accepted'] : [];
      if (!valid.includes(row.outcome) || (row.outcome === 'confirming' && !row.confirmationDeadline)) throw new Error();
      if (row.delivery === 'settled' && (typeof row.receipt !== 'string' || row.receipt.length > 8192)) throw new Error();
      if (row.recovery !== undefined) {
        exactKeys(row.recovery, new Set(['attempt', 'nextAttemptAt', 'notBefore']));
        if (!Number.isSafeInteger(row.recovery.attempt) || row.recovery.attempt < 0 || row.recovery.attempt > 1_000_000 ||
            !Number.isSafeInteger(row.recovery.nextAttemptAt) || !Number.isSafeInteger(row.recovery.notBefore) ||
            row.recovery.nextAttemptAt < row.recovery.notBefore || row.recovery.notBefore < 0) throw new Error();
      }
      ids.add(row.operationId); identities.add(jobKey(row.identity));
    }
    return structuredClone(state);
  } catch { throw new PrinterError('STATE_INVALID'); }
}

export function validateRecord(record: JobRecord): void { validateSnapshot({ version: 1, jobs: [record] }); }

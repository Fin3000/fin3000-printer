/** Native protocol contracts. No OS adapter may bypass coordinator admission. */
import { createHash } from 'node:crypto';
import type { RecoverySchedule } from './retry.ts';

export const MAX_PDF_BYTES = 20 * 1024 * 1024;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const CLIENT_IDS = new Set(['fin3000-system-print', 'fin3000-system-print-qa']);

export class PrinterError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; this.name = 'PrinterError'; }
}

export type Outcome = 'waiting' | 'confirming' | 'transferring' | 'uncertain' | 'accepted' | 'never_accepted' | 'cancelled';
export type Delivery = 'not_dispatched' | 'possibly_delivered' | 'settled';

export interface Binding {
  issuer: string;
  audience: 'fin3000-printer:production' | 'fin3000-printer:qa';
  clientId: string;
  subject: string;
  target: { id: string | null; name: string };
}

export interface JobIdentity {
  generation: string;
  nativeJobUuid: string;
}

export interface JobRecord {
  operationId: string;
  clientBatchId: string;
  clientItemId: string;
  identity: JobIdentity;
  binding: Binding;
  name: string;
  size: number;
  requestFingerprint: string;
  pdfSha256: string;
  callbackNonce: string;
  outcome: Outcome;
  delivery: Delivery;
  receivedAt: number;
  confirmationDeadline?: number;
  extended: boolean;
  code?: string;
  receipt?: string;
  recovery?: RecoverySchedule;
}

export interface StateSnapshot { version: 1; jobs: JobRecord[] }
export interface SecureStateStore {
  load(): Promise<StateSnapshot | null>;
  save(snapshot: StateSnapshot): Promise<void>;
}
export interface Clock { now(): number }
export interface TransferPort {
  send(record: Readonly<JobRecord>, pdf: Buffer, signal: AbortSignal): Promise<string>;
  reconcile(record: Readonly<JobRecord>, signal: AbortSignal): Promise<string>;
}
export interface ReceiptVerifier {
  verify(token: string, record: Readonly<JobRecord>): 'accepted' | 'never_accepted';
}

export function jobKey(identity: JobIdentity): string {
  if (!UUID_PATTERN.test(identity.generation) || !UUID_PATTERN.test(identity.nativeJobUuid)) {
    throw new PrinterError('NATIVE_IDENTITY_INVALID');
  }
  return `${identity.generation}/${identity.nativeJobUuid}`;
}

export function validateBinding(binding: Binding): void {
  if (!CLIENT_IDS.has(binding.clientId) || typeof binding.issuer !== 'string' || !/^sp_[0-9a-f]{32}$/.test(binding.subject) ||
      (binding.target.id !== null && (typeof binding.target.id !== 'string' || !UUID_PATTERN.test(binding.target.id))) || typeof binding.target.name !== 'string' || !binding.target.name || binding.target.name.length > 120 || /[\p{C}]/u.test(binding.target.name) ||
      !['fin3000-printer:production', 'fin3000-printer:qa'].includes(binding.audience)) {
    throw new PrinterError('PRINCIPAL_INVALID');
  }
  const origin = new URL(binding.issuer);
  const qaLoopback = binding.audience === 'fin3000-printer:qa' && origin.hostname === '127.0.0.1';
  if (origin.origin !== binding.issuer || origin.username || origin.password ||
      (origin.protocol !== 'https:' && !(qaLoopback && origin.protocol === 'http:')) ||
      binding.clientId.endsWith('-qa') !== (binding.audience === 'fin3000-printer:qa')) {
    throw new PrinterError('PRINCIPAL_INVALID');
  }
}

export function sameBinding(a: Binding, b: Binding): boolean {
  return a.issuer === b.issuer && a.audience === b.audience && a.clientId === b.clientId &&
    a.subject === b.subject && a.target.id === b.target.id;
}

export function safeDocumentName(title: string): string {
  const name = title.normalize('NFC').replaceAll('\\', '/').split('/').at(-1)!
    .replace(/[\p{C}]/gu, '').trim().slice(0, 180).replace(/\.pdf$/i, '');
  return `${name && name !== '.' && name !== '..' ? name : 'Druckkopie'}.pdf`;
}

export function manifestFingerprint(itemId: string, name: string, size: number): string {
  // Django uses json.dumps(sort_keys=True, ensure_ascii=True, separators=...).
  // Property order and UTF-16 \u escaping must agree even for German titles.
  const json = JSON.stringify([{ clientItemId: itemId, contentType: 'application/pdf', name, position: 0, size }])
    .replace(/[\u007f-\uffff]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return createHash('sha256').update(json).digest('hex');
}

export function validatePdf(bytes: Buffer): void {
  if (!Buffer.isBuffer(bytes) || bytes.length < 5 || bytes.length > MAX_PDF_BYTES ||
      bytes.subarray(0, 5).toString('ascii') !== '%PDF-') throw new PrinterError('PDF_INVALID');
  // Structural parsing happens in the sandboxed native worker, never as root.
}

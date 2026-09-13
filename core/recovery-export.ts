/** User-requested opaque recovery claim. Its checksum is NOT authorization. */
import { createHash } from 'node:crypto';
import { PrinterError } from './protocol.ts';
import type { JobRecord } from './protocol.ts';
import { validateRecord } from './state-store.ts';

export function recoveryExport(record: JobRecord): string {
  validateRecord(record);
  if (record.outcome !== 'uncertain' || record.delivery !== 'possibly_delivered') throw new PrinterError('RECOVERY_NOT_AVAILABLE');
  // Explicit projection: never serialize a JobRecord, binding or OAuth object.
  const payload = {
    format: 'fin3000-print-recovery', version: 1,
    issuer: record.binding.issuer, audience: record.binding.audience,
    clientId: record.binding.clientId, subject: record.binding.subject,
    targetId: record.binding.target.id,
    operationId: record.operationId, clientBatchId: record.clientBatchId,
    clientItemId: record.clientItemId, requestFingerprint: record.requestFingerprint,
    callbackNonce: record.callbackNonce,
  };
  const content = JSON.stringify({ ...payload, checksum: createHash('sha256').update(JSON.stringify(payload)).digest('hex') }) + '\n';
  if (Buffer.byteLength(content) > 4096) throw new PrinterError('RECOVERY_EXPORT_INVALID');
  return content;
}

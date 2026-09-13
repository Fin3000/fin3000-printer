/** One immutable operation; recovery NEVER re-uploads or invents a negative. */
import { createHash } from 'node:crypto';
import { PRINT_API } from './config.ts';
import { HttpFailure } from './http.ts';
import type { HttpPort, UploadIntent } from './http.ts';
import type { AuthorizedToken } from './oauth.ts';
import { PrinterError, sameBinding, UUID_PATTERN } from './protocol.ts';
import type { JobRecord, TransferPort } from './protocol.ts';

export interface TokenPort { access(signal: AbortSignal): Promise<AuthorizedToken> }
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PrinterError('OPERATION_RESPONSE_INVALID');
  return value as Record<string, unknown>;
};

export function operationManifest(record: Readonly<JobRecord>): unknown {
  return { operationId: record.operationId, clientBatchId: record.clientBatchId, targetId: record.binding.target.id,
    items: [{ clientItemId: record.clientItemId, position: 0, name: record.name, size: record.size, contentType: 'application/pdf' }] };
}

export class NativeTransfer implements TransferPort {
  private http: HttpPort;
  private tokens: TokenPort;
  constructor(http: HttpPort, tokens: TokenPort) { this.http = http; this.tokens = tokens; }

  async send(record: Readonly<JobRecord>, pdf: Buffer, signal: AbortSignal): Promise<string> {
    if (pdf.length !== record.size || createHash('sha256').update(pdf).digest('hex') !== record.pdfSha256) throw new PrinterError('PDF_IDENTITY_CHANGED');
    const response = await this.call(record, 'POST', 'manifest/', operationManifest(record), signal);
    const operation = this.operation(response, record);
    if (operation.outcome !== 'pending') return this.receipt(record, signal);
    const batch = object(operation.batch);
    if (batch.clientBatchId !== record.clientBatchId || batch.source !== 'system_print' || batch.businessUnit !== record.binding.target.id ||
        !Array.isArray(batch.items) || batch.items.length !== 1) throw new PrinterError('OPERATION_RESPONSE_INVALID');
    const item = object(batch.items[0]);
    if (!UUID_PATTERN.test(item.id as string) || item.clientItemId !== record.clientItemId || item.expectedSize !== record.size ||
        item.name !== record.name || item.contentType !== 'application/pdf') throw new PrinterError('OPERATION_RESPONSE_INVALID');
    const rawIntent = object(await this.call(record, 'POST', `items/${item.id}/intent/`, {}, signal));
    const fields = object(rawIntent.fields);
    if (fields['x-amz-meta-intake-item'] !== item.id || typeof fields.key !== 'string' || !fields.key.endsWith(`/${item.id}/payload`) ||
        rawIntent.minimumBytes !== record.size || rawIntent.maximumBytes !== record.size) throw new PrinterError('UPLOAD_INTENT_INVALID');
    await this.http.upload(rawIntent as unknown as UploadIntent, pdf, signal);
    this.operation(await this.call(record, 'POST', `items/${item.id}/complete/`, { clientItemId: record.clientItemId }, signal), record);
    return this.receipt(record, signal);
  }

  async reconcile(record: Readonly<JobRecord>, signal: AbortSignal): Promise<string> {
    const path = `operations/${record.operationId}/`;
    let operation: Record<string, unknown>;
    try { operation = this.operation(await this.call(record, 'GET', path, undefined, signal), record); }
    catch (error) {
      if (!(error instanceof HttpFailure) || error.status !== 404) throw error;
      // 404 is not proof of absence. This POST races admission under the same
      // server lock and permanently fences these original operation/batch IDs.
      operation = this.operation(await this.call(record, 'POST', `${path}settle/`, operationManifest(record), signal), record);
    }
    if (operation.outcome === 'pending') operation = this.operation(await this.call(record, 'POST', `${path}settle/`, {}, signal), record);
    if (operation.outcome === 'pending') throw new PrinterError('SETTLEMENT_PENDING');
    return this.receipt(record, signal);
  }

  private async call(record: Readonly<JobRecord>, method: 'GET' | 'POST', suffix: string, body: unknown, signal: AbortSignal): Promise<unknown> {
    const auth = await this.tokens.access(signal);
    if (!sameBinding(auth.binding, record.binding)) throw new PrinterError('PRINCIPAL_CHANGED');
    return this.http.api(method, `${PRINT_API}${suffix}`, body, auth.accessToken, signal);
  }

  private operation(value: unknown, record: Readonly<JobRecord>): Record<string, unknown> {
    const operation = object(value), target = object(operation.target);
    if (operation.protocolVersion !== 2 || operation.operationId !== record.operationId || operation.clientBatchId !== record.clientBatchId ||
        operation.clientItemId !== record.clientItemId || operation.requestFingerprint !== record.requestFingerprint || target.id !== record.binding.target.id ||
        !['pending', 'accepted', 'never_accepted'].includes(operation.outcome as string)) throw new PrinterError('OPERATION_RESPONSE_INVALID');
    return operation;
  }

  private async receipt(record: Readonly<JobRecord>, signal: AbortSignal): Promise<string> {
    const raw = object(await this.call(record, 'POST', `operations/${record.operationId}/receipt/`, { callbackNonce: record.callbackNonce }, signal));
    if (typeof raw.receipt !== 'string' || raw.receipt.length > 8192) throw new PrinterError('RECEIPT_INVALID');
    // Only the pinned verifier inside Coordinator can mark this job settled.
    return raw.receipt;
  }
}

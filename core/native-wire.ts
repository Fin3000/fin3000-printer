/** Bounded binary framing for a private native-child pipe, not a public socket. */
import { createHash } from 'node:crypto';
import { PrinterError, UUID_PATTERN, MAX_PDF_BYTES } from './protocol.ts';
import type { JobIdentity } from './protocol.ts';

export interface NativeJob { identity: JobIdentity; nativeJobUuid: string; title: string; size: number; sha256: string }
export interface NativeAdmission { admit(identity: JobIdentity, title: string, bytes: Buffer): Promise<{ operationId: string; replay: boolean }> }

function header(bytes: Buffer, generation: string): NativeJob {
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (Object.keys(value).sort().join(',') !== 'generation,jobId,nativeJobUuid,sha256,size,title,type,version' ||
        value.type !== 'job' || value.version !== 2 || value.generation !== generation || !UUID_PATTERN.test(value.generation) ||
        !UUID_PATTERN.test(value.nativeJobUuid) || !Number.isSafeInteger(value.jobId) || value.jobId < 1 || value.jobId > 2147483647 ||
        !Number.isSafeInteger(value.size) || value.size < 5 || value.size > MAX_PDF_BYTES ||
        typeof value.title !== 'string' || [...value.title].length > 180 || /[\p{C}]/u.test(value.title) || !/^[0-9a-f]{64}$/.test(value.sha256)) throw new Error();
    return { identity: { generation, nativeJobUuid: value.nativeJobUuid }, nativeJobUuid: value.nativeJobUuid,
      title: value.title, size: value.size, sha256: value.sha256 };
  } catch { throw new PrinterError('NATIVE_FRAME_INVALID'); }
}

export async function consumeNativeJobs(input: AsyncIterable<Buffer>, reply: (frame: Buffer) => Promise<void>, admission: NativeAdmission, generation: string): Promise<void> {
  let expected = 4, collected = 0, phase: 'length' | 'header' | 'pdf' = 'length';
  let buffer = Buffer.alloc(4), job: NativeJob | null = null;
  try {
    for await (const chunk of input) {
      let offset = 0;
      while (offset < chunk.length) {
        const count = Math.min(expected - collected, chunk.length - offset);
        chunk.copy(buffer, collected, offset, offset + count); collected += count; offset += count;
        if (collected !== expected) continue;
        if (phase === 'length') {
          expected = buffer.readUInt32BE();
          if (expected < 1 || expected > 4096) throw new PrinterError('NATIVE_FRAME_INVALID');
          phase = 'header'; buffer = Buffer.alloc(expected);
        } else if (phase === 'header') {
          job = header(buffer, generation); expected = job.size; buffer = Buffer.alloc(expected); phase = 'pdf';
        } else {
          if (createHash('sha256').update(buffer).digest('hex') !== job!.sha256) throw new PrinterError('PDF_IDENTITY_CHANGED');
          let response;
          try {
            const result = await admission.admit(job!.identity, job!.title, buffer);
            response = { nativeJobUuid: job!.nativeJobUuid, accepted: true, operationId: result.operationId };
          } catch (error) {
            const code = error instanceof PrinterError ? error.code : 'HANDOFF_REJECTED';
            response = { nativeJobUuid: job!.nativeJobUuid, accepted: false,
              code: ['QUEUE_FULL', 'CONNECT_AND_REPRINT', 'RECONCILE_REQUIRED', 'DRAINING', 'PDF_INVALID'].includes(code) ? code : 'HANDOFF_REJECTED' };
          }
          buffer.fill(0);
          const body = Buffer.from(JSON.stringify(response)), size = Buffer.alloc(4); size.writeUInt32BE(body.length);
          await reply(Buffer.concat([size, body]));
          expected = 4; phase = 'length'; buffer = Buffer.alloc(4); job = null;
        }
        collected = 0;
      }
    }
    if (phase !== 'length' || collected) throw new PrinterError('NATIVE_FRAME_TRUNCATED');
  } finally { buffer.fill(0); }
}

import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import test from 'node:test';
import { consumeNativeJobs } from '../../core/native-wire.ts';
import { PrinterError } from '../../core/protocol.ts';

const generation = randomUUID();
const pdf = Buffer.from('%PDF-Synthetic only');
function frame(change = {}) {
  const metadata = { type: 'job', version: 2, generation, nativeJobUuid: randomUUID(), jobId: 12, title: 'Änderung', size: pdf.length,
    sha256: createHash('sha256').update(pdf).digest('hex'), ...change };
  const body = Buffer.from(JSON.stringify(metadata)), length = Buffer.alloc(4); length.writeUInt32BE(body.length);
  return { metadata, bytes: Buffer.concat([length, body, pdf]) };
}
async function* chunks(value, size = 1) { for (let offset = 0; offset < value.length; offset += size) yield value.subarray(offset, offset + size); }
const ack = value => JSON.parse(value.subarray(4));

test('fragmented and concatenated frames admit only complete matching PDFs; ACK follows persistence', async () => {
  const a = frame(), b = frame(), replies = [], jobs = [], allocated = [];
  const admission = { async admit(identity, title, bytes) {
    jobs.push({ identity, title, bytes: Buffer.from(bytes) }); allocated.push(bytes);
    await Promise.resolve(); return { operationId: randomUUID(), replay: false };
  } };
  await consumeNativeJobs(chunks(Buffer.concat([a.bytes, b.bytes])), async value => { assert.equal(jobs.length, replies.length + 1); replies.push(ack(value)); }, admission, generation);
  assert.equal(jobs.length, 2); assert.ok(jobs.every(job => job.bytes.equals(pdf)));
  assert.equal(replies[0].nativeJobUuid, a.metadata.nativeJobUuid); assert.equal(replies[1].accepted, true);
  assert.ok(allocated.every(value => value.every(byte => byte === 0)));
});

test('wrong generation, noncanonical IDs, huge sizes and unexpected metadata fail before admission', async () => {
  let calls = 0;
  const admission = { async admit() { calls++; } };
  for (const change of [{ generation: randomUUID() }, { nativeJobUuid: 'not-an-id' }, { size: 21 * 1024 * 1024 },
    { size: -1 }, { jobId: 0 }, { title: 'bad\u202econtent' }, { account: 'forged' }, { version: 1 }]) {
    await assert.rejects(consumeNativeJobs(chunks(frame(change).bytes, 65536), async () => {}, admission, generation), { code: 'NATIVE_FRAME_INVALID' });
  }
  assert.equal(calls, 0);
});

test('truncated length/header/PDF and hash mismatch do not emit success', async () => {
  const source = frame(); let admitted = 0, replies = 0;
  const admission = { async admit() { admitted++; } };
  for (const size of [1, 6, source.bytes.length - 1]) {
    await assert.rejects(consumeNativeJobs(chunks(source.bytes.subarray(0, size), 4096), async () => { replies++; }, admission, generation), { code: 'NATIVE_FRAME_TRUNCATED' });
  }
  const bad = Buffer.from(source.bytes); bad[bad.length - 1] ^= 1;
  await assert.rejects(consumeNativeJobs(chunks(bad, 4096), async () => { replies++; }, admission, generation), { code: 'PDF_IDENTITY_CHANGED' });
  assert.equal(admitted, 0); assert.equal(replies, 0);
});

test('queue/full/login rejection is explicit and arbitrary exception details stay private', async () => {
  for (const error of [new PrinterError('QUEUE_FULL'), new PrinterError('CONNECT_AND_REPRINT'), new Error('private secret exception')]) {
    const replies = [];
    await consumeNativeJobs(chunks(frame().bytes, 4096), async value => replies.push(ack(value)), { async admit() { throw error; } }, generation);
    assert.equal(replies[0].accepted, false); assert.equal(replies[0].code, error instanceof PrinterError ? error.code : 'HANDOFF_REJECTED');
    assert.equal(JSON.stringify(replies).includes('private'), false);
  }
});

test('oversized header is rejected before allocating its claimed size', async () => {
  const bytes = Buffer.alloc(4); bytes.writeUInt32BE(0xffffffff);
  await assert.rejects(consumeNativeJobs(chunks(bytes), async () => {}, { async admit() {} }, generation), { code: 'NATIVE_FRAME_INVALID' });
});

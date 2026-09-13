import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { control, consumeControls } from '../../core/control-wire.ts';

async function* chunks(...values) { for (const value of values) yield Buffer.from(value); }

test('strict desktop action grammar has no arbitrary URL, path, account or executable', () => {
  assert.deepEqual(control({ action: 'configure' }), { action: 'configure' });
  assert.deepEqual(control({ action: 'confirm', operationId: randomUUID() }).action, 'confirm');
  for (const bad of [null, [], { action: 'exec', command: 'anything' }, { action: 'connect', targetId: randomUUID() },
    { action: 'openRecovery', url: 'https://foreign.test' }, { action: 'confirm', operationId: '../file' },
    { action: 'session', locked: 'false' }, { action: 'importReceipt', operationId: randomUUID(), receipt: 'invalid' }]) {
    assert.throws(() => control(bad), { code: 'CONTROL_INVALID' });
  }
});

test('private control framing accepts split UTF-8 JSON and multiple bounded commands', async () => {
  const calls = [];
  await consumeControls(chunks('{"action":"conf', 'igure"}\n{"action":"session","locked":false}\n'), async item => calls.push(item));
  assert.deepEqual(calls, [{ action: 'configure' }, { action: 'session', locked: false }]);
});

test('oversize, malformed UTF-8, truncated or empty input frame fails closed', async () => {
  for (const values of [['x'.repeat(16385)], [Buffer.from([255, 10])], ['{"action":"connect"}'], ['\n'], ['{}\n']]) {
    await assert.rejects(consumeControls(chunks(...values), async () => {}));
  }
});

test('receipt import is bounded and does not introduce another trust source', () => {
  const request = { action: 'importReceipt', operationId: randomUUID(), receipt: 'ey.aWQ.sig' };
  assert.equal(control(request).receipt, request.receipt);
  assert.throws(() => control({ ...request, publicKey: 'untrusted' }), { code: 'CONTROL_INVALID' });
  assert.throws(() => control({ ...request, receipt: 'a'.repeat(8193) }), { code: 'CONTROL_INVALID' });
});

test('export control contains only the operation ID, never a caller-specified path or payload', () => {
  const request = {action: 'exportRecovery', operationId: randomUUID()};
  assert.deepEqual(control(request), request);
  for (const extra of [{path: '/tmp/anything'}, {content: 'secret'}, {clientId: 'foreign'}, {operationId: '../path'}]) {
    assert.throws(() => control({...request, ...extra}), {code: 'CONTROL_INVALID'});
  }
});

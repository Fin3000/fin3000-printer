import assert from 'node:assert/strict';
import test from 'node:test';
import { recoverySchedule, retryAfterSeconds } from '../../core/retry.ts';

test('recovery delays follow the approved cadence with bounded independent jitter', () => {
  const delays = [30000, 120000, 600000, 3600000, 21600000, 21600000];
  for (const [attempt, delay] of delays.entries()) {
    assert.equal(recoverySchedule(attempt, 1000, 0.5).nextAttemptAt, 1000 + delay);
    assert.equal(recoverySchedule(attempt, 1000, 0).nextAttemptAt, 1000 + Math.round(delay * 0.8));
    assert.equal(recoverySchedule(attempt, 1000, 1).nextAttemptAt, 1000 + Math.round(delay * 1.2));
  }
  assert.equal(recoverySchedule(1000001, 0, 0.5).attempt, 1000000);
});

test('Retry-After is a hard lower bound capped at 24h and survives a prior attempt', () => {
  const scheduled = recoverySchedule(0, 1000, 0, 999999);
  assert.equal(scheduled.nextAttemptAt, 1000 + 86400000);
  assert.equal(scheduled.notBefore, scheduled.nextAttemptAt);
  assert.equal(recoverySchedule(1, 2000, 0.5, 0, scheduled.notBefore).nextAttemptAt, scheduled.notBefore);
});

test('HTTP Retry-After supports seconds and dates, rejecting missing or malformed values', () => {
  const now = Date.parse('Wed, 09 Sep 2026 12:00:00 GMT');
  assert.equal(retryAfterSeconds('120', now), 120);
  assert.equal(retryAfterSeconds('999999999', now), 86400);
  assert.equal(retryAfterSeconds('Wed, 09 Sep 2026 12:02:00 GMT', now), 120);
  assert.equal(retryAfterSeconds('Wed, 09 Sep 2026 11:59:00 GMT', now), 0);
  assert.equal(retryAfterSeconds('Wed, 09 Sep 2037 11:59:00 GMT', now), 86400);
  for (const raw of [undefined, '', '3.5', '-2', '2026-09-09T12:02:00Z', 'not a date', 'x'.repeat(129)]) assert.equal(retryAfterSeconds(raw, now), undefined);
});

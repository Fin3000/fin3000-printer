/** Persisted recovery cadence; never retries a PDF upload. */
export interface RecoverySchedule { attempt: number; nextAttemptAt: number; notBefore: number }
export const AUTH_RECOVERY_ERRORS = new Set(['LOGIN_REQUIRED', 'SESSION_LOCKED', 'PRINCIPAL_CHANGED', 'SECRET_STORE_UNAVAILABLE', 'KEYRING_LOCKED']);
const DELAYS = [30_000, 120_000, 600_000, 3_600_000, 21_600_000];

export function recoverySchedule(attempt: number, now: number, random: number, retryAfter = 0, previousNotBefore = 0): RecoverySchedule {
  const index = Math.min(Math.max(0, Math.floor(attempt)), 1_000_000);
  const jitter = Number.isFinite(random) ? Math.min(1, Math.max(0, random)) : 0.5;
  const notBefore = Math.max(previousNotBefore, now + (Number.isFinite(retryAfter) ? Math.min(86400, Math.max(0, retryAfter)) * 1000 : 0));
  return { attempt: index, notBefore, nextAttemptAt: Math.max(notBefore, now + Math.round(DELAYS[Math.min(index, 4)] * (0.8 + 0.4 * jitter))) };
}

export function retryAfterSeconds(value: string | undefined, now: number): number | undefined {
  if (!value || value.length > 128) return undefined;
  if (/^\d{1,10}$/.test(value)) return Math.min(Number(value), 86400);
  // Date.parse accepts decimals and ISO dates that are not HTTP-date values.
  if (!/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) return undefined;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return undefined;
  return Math.min(86400, Math.max(0, Math.ceil((timestamp - now) / 1000)));
}

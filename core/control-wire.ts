/** Private desktop-control pipe. No URLs, shell commands, paths or account overrides. */
import { PrinterError, UUID_PATTERN } from './protocol.ts';

export type Control = { action: 'connect' | 'cancelLogin' | 'configure' | 'prepareRemoval' | 'remove' | 'openRecovery' }
  | { action: 'cancel' | 'reconcile' | 'exportRecovery'; operationId: string }
  | { action: 'importReceipt'; operationId: string; receipt: string }
  | { action: 'session'; locked: boolean }
  | { action: 'browserResult'; requestId: string; ok: boolean };

export function control(value: unknown): Control {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PrinterError('CONTROL_INVALID');
  const raw = value as Record<string, unknown>, keys = Object.keys(raw).sort().join(',');
  if (typeof raw.action !== 'string') throw new PrinterError('CONTROL_INVALID');
  if (['connect', 'cancelLogin', 'configure', 'prepareRemoval', 'remove', 'openRecovery'].includes(raw.action) && keys === 'action') return raw as Control;
  if (['cancel', 'reconcile', 'exportRecovery'].includes(raw.action) && keys === 'action,operationId' &&
      typeof raw.operationId === 'string' && UUID_PATTERN.test(raw.operationId)) return raw as Control;
  if (raw.action === 'importReceipt' && keys === 'action,operationId,receipt' && typeof raw.operationId === 'string' &&
      UUID_PATTERN.test(raw.operationId) && typeof raw.receipt === 'string' && raw.receipt.length <= 8192 &&
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw.receipt)) return raw as Control;
  if (raw.action === 'session' && keys === 'action,locked' && typeof raw.locked === 'boolean') return raw as Control;
  if (raw.action === 'browserResult' && keys === 'action,ok,requestId' && typeof raw.ok === 'boolean' &&
      typeof raw.requestId === 'string' && UUID_PATTERN.test(raw.requestId)) return raw as Control;
  throw new PrinterError('CONTROL_INVALID');
}

export async function consumeControls(input: AsyncIterable<Buffer>, receive: (value: Control) => Promise<void>): Promise<void> {
  let buffer = Buffer.alloc(16384), length = 0;
  try {
    for await (const chunk of input) {
      for (const byte of chunk) {
        if (byte === 10) {
          if (!length) throw new PrinterError('CONTROL_INVALID');
          let value;
          try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length))); }
          catch { throw new PrinterError('CONTROL_INVALID'); }
          buffer.fill(0, 0, length); length = 0;
          await receive(control(value));
        } else {
          if (length === buffer.length) throw new PrinterError('CONTROL_LIMIT_REACHED');
          buffer[length++] = byte;
        }
      }
    }
    if (length) throw new PrinterError('CONTROL_TRUNCATED');
  } finally { buffer.fill(0); buffer = Buffer.alloc(0); }
}

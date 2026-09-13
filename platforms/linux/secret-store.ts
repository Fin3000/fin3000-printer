import type { SecretStore } from '../../core/oauth.ts';
import { PrinterError } from '../../core/protocol.ts';
import { secretProcess } from './process.ts';

export class LinuxSecretStore implements SecretStore {
  private environment: 'production' | 'qa';
  private run: (request: unknown) => Promise<unknown>;
  constructor(environment: 'production' | 'qa', run = secretProcess) {
    if (!['production', 'qa'].includes(environment)) throw new PrinterError('SECRET_REQUEST_INVALID');
    this.environment = environment; this.run = run;
  }
  private async call(action: string, value?: string): Promise<Record<string, unknown>> {
    const raw = await this.run({ action, environment: this.environment, ...(value === undefined ? {} : { value }) });
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new PrinterError('SECRET_RESPONSE_INVALID');
    const result = raw as Record<string, unknown>;
    if (typeof result.error === 'string') {
      throw new PrinterError(['KEYRING_LOCKED', 'SECRET_COLLECTION_MISSING', 'SECRET_STATE_AMBIGUOUS', 'SECRET_STATE_INVALID'].includes(result.error)
        ? result.error : 'SECRET_STORE_UNAVAILABLE');
    }
    return result;
  }
  async load(): Promise<string | null> {
    const result = await this.call('load');
    if (Object.keys(result).join(',') !== 'value' || (result.value !== null &&
        (typeof result.value !== 'string' || Buffer.byteLength(result.value) > 16384))) throw new PrinterError('SECRET_RESPONSE_INVALID');
    return result.value as string | null;
  }
  async save(value: string): Promise<void> {
    if (typeof value !== 'string' || Buffer.byteLength(value) > 16384) throw new PrinterError('SECRET_REQUEST_INVALID');
    const result = await this.call('save', value);
    if (Object.keys(result).join(',') !== 'ok' || result.ok !== true) throw new PrinterError('SECRET_RESPONSE_INVALID');
  }
  async clear(): Promise<void> {
    const result = await this.call('clear');
    if (Object.keys(result).join(',') !== 'ok' || result.ok !== true) throw new PrinterError('SECRET_RESPONSE_INVALID');
  }
}

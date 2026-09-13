/** Supplied by the root-owned, signed build. Never read API hosts from user env. */
import { PrinterError } from './protocol.ts';

export interface BuildConfig {
  environment: 'production' | 'qa';
  apiOrigin: string;
  appOrigin: string;
  quarantineOrigins: readonly string[];
  clientId: 'fin3000-system-print' | 'fin3000-system-print-qa';
  audience: 'fin3000-printer:production' | 'fin3000-printer:qa';
  receiptKeys: Readonly<Record<string, string>>;
}

export const PRINT_API = '/api/v1/accounting/incoming-invoices/browser-print/';

export function validateBuildConfig(input: BuildConfig): Readonly<BuildConfig> {
  try {
    const qa = input.environment === 'qa';
    if (!['production', 'qa'].includes(input.environment) ||
        input.clientId !== `fin3000-system-print${qa ? '-qa' : ''}` ||
        input.audience !== `fin3000-printer:${input.environment}` ||
        !Array.isArray(input.quarantineOrigins) || !input.quarantineOrigins.length ||
        input.quarantineOrigins.length > 4 || !Object.keys(input.receiptKeys).length) throw new Error();
    for (const value of [input.apiOrigin, input.appOrigin, ...input.quarantineOrigins]) {
      const url = new URL(value);
      if (url.origin !== value || url.username || url.password ||
          (url.protocol !== 'https:' && !(qa && url.protocol === 'http:' && url.hostname === '127.0.0.1'))) throw new Error();
      if (qa && !(url.hostname === '127.0.0.1' || url.hostname.endsWith('.test'))) throw new Error();
    }
    if (!qa && (input.apiOrigin !== 'https://api.fin3000.com' || input.appOrigin !== 'https://app.fin3000.com')) throw new Error();
    return Object.freeze({ ...input, quarantineOrigins: Object.freeze([...input.quarantineOrigins]), receiptKeys: Object.freeze({ ...input.receiptKeys }) });
  } catch { throw new PrinterError('BUILD_CONFIG_INVALID'); }
}

/** Pinned Ed25519 receipts, not a remotely downloaded key or an HTTP status. */
import { createPublicKey, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { PrinterError, UUID_PATTERN } from './protocol.ts';
import type { Clock, JobRecord, ReceiptVerifier } from './protocol.ts';

export class PinnedReceiptVerifier implements ReceiptVerifier {
  private keys = new Map<string, KeyObject>();
  private clock: Clock;
  constructor(publicKeys: Readonly<Record<string, string>>, clock: Clock) {
    this.clock = clock;
    for (const [kid, pem] of Object.entries(publicKeys)) {
      if (!/^[A-Za-z0-9_-]{1,80}$/.test(kid)) throw new PrinterError('RECEIPT_KEY_INVALID');
      const key = createPublicKey(pem);
      if (key.asymmetricKeyType !== 'ed25519') throw new PrinterError('RECEIPT_KEY_INVALID');
      this.keys.set(kid, key);
    }
    if (!this.keys.size) throw new PrinterError('RECEIPT_KEY_MISSING');
  }

  verify(token: string, record: Readonly<JobRecord>): 'accepted' | 'never_accepted' {
    try {
      if (typeof token !== 'string' || token.length > 8192) throw new Error();
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error();
      const [headerPart, payloadPart, signaturePart] = parts;
      const decode = (part: string) => {
        const bytes = Buffer.from(part, 'base64url');
        if (bytes.toString('base64url') !== part) throw new Error();
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      };
      const header = decode(headerPart);
      if (Object.keys(header).sort().join(',') !== 'alg,kid,typ' || header.alg !== 'EdDSA' ||
          header.typ !== 'fin3000-print-receipt+jwt' || !this.keys.has(header.kid)) throw new Error();
      const signature = Buffer.from(signaturePart, 'base64url');
      if (signature.length !== 64 || signature.toString('base64url') !== signaturePart ||
          !verify(null, Buffer.from(`${headerPart}.${payloadPart}`), this.keys.get(header.kid)!, signature)) throw new Error();
      const claims = decode(payloadPart), now = Math.floor(this.clock.now() / 1000);
      if (claims.iss !== record.binding.issuer || claims.aud !== record.binding.audience ||
          claims.sub !== record.binding.subject || claims.client_id !== record.binding.clientId ||
          claims.target_id !== record.binding.target.id || claims.operation_id !== record.operationId ||
          claims.client_batch_id !== record.clientBatchId || claims.client_item_id !== record.clientItemId ||
          claims.request_fingerprint !== record.requestFingerprint || claims.nonce !== record.callbackNonce ||
          claims.protocol_version !== 2 || !Number.isSafeInteger(claims.generation) || claims.generation < 1 ||
          !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.nbf) || !Number.isSafeInteger(claims.exp) ||
          claims.iat !== claims.nbf || claims.exp - claims.iat !== 120 || claims.iat > now + 30 ||
          claims.exp <= now || !UUID_PATTERN.test(claims.jti) ||
          !['accepted', 'never_accepted'].includes(claims.outcome)) throw new Error();
      return claims.outcome;
    } catch { throw new PrinterError('RECEIPT_INVALID'); }
  }
}

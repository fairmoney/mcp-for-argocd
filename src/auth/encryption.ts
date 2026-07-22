import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// A reversible string codec used to protect token values written to an external
// store (Redis). plainCodec is a no-op; aesGcmCodec encrypts at rest.
export interface ValueCodec {
  encode(plaintext: string): string;
  decode(encoded: string): string;
}

export const plainCodec: ValueCodec = {
  encode: (s) => s,
  decode: (s) => s
};

// AES-256-GCM. Output format: base64(iv).base64(authTag).base64(ciphertext).
export const aesGcmCodec = (key: Buffer): ValueCodec => {
  if (key.length !== 32) throw new Error('aesGcmCodec requires a 32-byte key');
  return {
    encode(plaintext: string): string {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      return `${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
    },
    decode(encoded: string): string {
      const [ivB64, tagB64, dataB64] = encoded.split('.');
      if (!ivB64 || !tagB64 || !dataB64) throw new Error('malformed encrypted value');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
      decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(dataB64, 'base64')),
        decipher.final()
      ]).toString('utf8');
    }
  };
};

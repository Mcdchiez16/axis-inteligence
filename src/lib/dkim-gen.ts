/**
 * DKIM key generation in the browser with WebCrypto. The private key is created on the visitor's
 * device and is never sent anywhere.
 */

const b64 = (buf: ArrayBuffer) => {
  let s = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
};

const pem = (label: string, body: string) => `-----BEGIN ${label}-----\n${body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END ${label}-----\n`;

export type DkimKeyPair = { selector: string; domain: string; bits: number; host: string; record: string; recordChunks: string[]; publicPem: string; privatePem: string };

/** DNS TXT strings are limited to 255 characters each; long records are published as several quoted strings. */
export function chunk(value: string, size = 255): string[] {
  const out: string[] = [];
  for (let i = 0; i < value.length; i += size) out.push(value.slice(i, i + size));
  return out;
}

export async function generateDkimKey(domain: string, selector: string, bits: 1024 | 2048 | 4096 = 2048): Promise<DkimKeyPair> {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const spki = b64(await crypto.subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = b64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const record = `v=DKIM1; k=rsa; p=${spki}`;
  return { selector, domain, bits, host: `${selector}._domainkey.${domain}`, record, recordChunks: chunk(record), publicPem: pem('PUBLIC KEY', spki), privatePem: pem('PRIVATE KEY', pkcs8) };
}

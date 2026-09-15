import { IGE } from '@cryptography/aes';

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export async function digest(algorithm: 'SHA-1' | 'SHA-256', value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(algorithm, value.slice().buffer));
}

function wordsToBytes(words: Uint32Array): Uint8Array {
  const bytes = new Uint8Array(words.length * 4);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < words.length; index += 1) {
    view.setUint32(index * 4, words[index], false);
  }
  return bytes;
}

export function igeEncrypt(value: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  return wordsToBytes(new IGE(key, iv).encrypt(value));
}

export function igeDecrypt(value: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  return wordsToBytes(new IGE(key, iv).decrypt(value));
}

function incrementCounter(counter: Uint8Array, blocks: number): void {
  for (let block = 0; block < blocks; block += 1) {
    for (let index = counter.length - 1; index >= 0; index -= 1) {
      counter[index] = (counter[index] + 1) & 0xff;
      if (counter[index] !== 0) break;
    }
  }
}

/** Stateful AES-CTR stream over WebCrypto, including partial-block carry. */
export class AesCtrStream {
  private leftover = new Uint8Array();

  private constructor(
    private readonly key: CryptoKey,
    private readonly counter: Uint8Array<ArrayBuffer>,
  ) {}

  static async create(key: Uint8Array, counter: Uint8Array): Promise<AesCtrStream> {
    return new AesCtrStream(
      await crypto.subtle.importKey('raw', key.slice().buffer, { name: 'AES-CTR' }, false, ['encrypt']),
      counter.slice(),
    );
  }

  async apply(value: Uint8Array): Promise<Uint8Array> {
    const result = new Uint8Array(value.length);
    let offset = 0;
    if (this.leftover.length > 0) {
      const length = Math.min(value.length, this.leftover.length);
      for (let index = 0; index < length; index += 1) {
        result[index] = value[index] ^ this.leftover[index];
      }
      this.leftover = this.leftover.subarray(length);
      offset = length;
    }
    if (offset === value.length) return result;

    const remaining = value.length - offset;
    const blocks = Math.ceil(remaining / 16);
    const stream = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: this.counter, length: 128 },
      this.key,
      new Uint8Array(blocks * 16).buffer,
    ));
    incrementCounter(this.counter, blocks);
    for (let index = 0; index < remaining; index += 1) {
      result[offset + index] = value[offset + index] ^ stream[index];
    }
    this.leftover = stream.subarray(remaining);
    return result;
  }
}


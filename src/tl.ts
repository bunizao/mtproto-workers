import { __tlReaderMap } from '@mtcute/tl/binary/reader.js';
import { TlBinaryReader } from '@mtcute/tl-runtime';

export type TlObject = { _: string; [key: string]: unknown };

const CHANNEL_DIFFERENCE_EMPTY = 0x3e11affb;
const RPC_ERROR = 0x2144ca19;
const GZIP_PACKED = 0x3072cfa1;
const VECTOR = 0x1cb5c415;
const MSGS_ACK = 0x62d6b459;
const INVOKE_WITH_LAYER = 0xda9b0d0d;
const INIT_CONNECTION = 0xc1cd5ea9;

/** The API layer the bundled `@mtcute/tl` schema was generated from. */
export const TL_LAYER = 223;

/** Minimal little-endian TL serializer: enough to hand-write any method. */
export class TlWriter {
  private value = new Uint8Array(256);
  private offset = 0;

  uint(value: number): this {
    this.ensure(4);
    new DataView(this.value.buffer).setUint32(this.offset, value >>> 0, true);
    this.offset += 4;
    return this;
  }

  int(value: number): this {
    this.ensure(4);
    new DataView(this.value.buffer).setInt32(this.offset, value, true);
    this.offset += 4;
    return this;
  }

  long(value: bigint): this {
    this.ensure(8);
    new DataView(this.value.buffer).setBigInt64(this.offset, value, true);
    this.offset += 8;
    return this;
  }

  string(value: string): this {
    return this.bytes(new TextEncoder().encode(value));
  }

  bytes(value: Uint8Array): this {
    const headerLength = value.length <= 253 ? 1 : 4;
    const padding = (4 - ((headerLength + value.length) % 4)) % 4;
    this.ensure(headerLength + value.length + padding);
    if (headerLength === 1) {
      this.value[this.offset] = value.length;
      this.offset += 1;
    } else {
      this.value[this.offset] = 254;
      this.value[this.offset + 1] = value.length & 0xff;
      this.value[this.offset + 2] = (value.length >>> 8) & 0xff;
      this.value[this.offset + 3] = (value.length >>> 16) & 0xff;
      this.offset += 4;
    }
    this.value.set(value, this.offset);
    this.offset += value.length + padding;
    return this;
  }

  /** `Vector<T>` header; write the items yourself afterwards. */
  vector(length: number): this {
    return this.uint(VECTOR).uint(length);
  }

  raw(value: Uint8Array): this {
    this.ensure(value.length);
    this.value.set(value, this.offset);
    this.offset += value.length;
    return this;
  }

  result(): Uint8Array {
    return this.value.slice(0, this.offset);
  }

  private ensure(length: number): void {
    if (this.offset + length <= this.value.length) return;
    const expanded = new Uint8Array(Math.max(this.value.length * 2, this.offset + length));
    expanded.set(this.value);
    this.value = expanded;
  }
}

export type InitConnection = {
  apiId: number;
  deviceModel?: string;
  systemVersion?: string;
  appVersion?: string;
  langCode?: string;
};

/**
 * Wrap a method in `invokeWithLayer(initConnection(...))`. Telegram needs
 * this once per auth key + layer; every later call on the same key can go
 * naked, so callers persist an `initialized` flag and stop wrapping.
 */
export function wrapInitConnection(body: Uint8Array, init: InitConnection): Uint8Array {
  return new TlWriter()
    .uint(INVOKE_WITH_LAYER)
    .int(TL_LAYER)
    .uint(INIT_CONNECTION)
    .uint(0)
    .int(init.apiId)
    .string(init.deviceModel ?? 'Cloudflare Worker')
    .string(init.systemVersion ?? 'workerd')
    .string(init.appVersion ?? 'mtproto-workers')
    .string(init.langCode ?? 'en')
    .string('')
    .string(init.langCode ?? 'en')
    .raw(body)
    .result();
}

export function encodeMsgsAck(ids: bigint[]): Uint8Array {
  const writer = new TlWriter().uint(MSGS_ACK).vector(ids.length);
  for (const id of ids) writer.long(id);
  return writer.result();
}

export function readTlBytes(value: Uint8Array, offset: number): Uint8Array {
  const first = value[offset];
  const headerLength = first === 254 ? 4 : 1;
  const length = first === 254
    ? value[offset + 1] | (value[offset + 2] << 8) | (value[offset + 3] << 16)
    : first;
  return value.slice(offset + headerLength, offset + headerLength + length);
}

function readTlString(value: Uint8Array, offset: number): string {
  return new TextDecoder().decode(readTlBytes(value, offset));
}

export async function gunzip(value: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([value.slice().buffer]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Decode an RPC result body into a plain object. `rpc_error` and
 * `gzip_packed` are handled here; everything else goes through the generated
 * `@mtcute/tl` reader map, so any API-layer constructor decodes.
 */
export async function decodeTlObject(value: Uint8Array): Promise<TlObject> {
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const constructor = view.getUint32(0, true);
  if (constructor === CHANNEL_DIFFERENCE_EMPTY) {
    const flags = view.getUint32(4, true);
    return {
      _: 'updates.channelDifferenceEmpty',
      final: Boolean(flags & 1),
      pts: view.getInt32(8, true),
      ...(flags & 2 ? { timeout: view.getInt32(12, true) } : {}),
    };
  }
  if (constructor === RPC_ERROR) {
    return {
      _: 'mt_rpc_error',
      errorCode: view.getInt32(4, true),
      errorMessage: readTlString(value, 8),
    };
  }
  if (constructor === GZIP_PACKED) {
    return decodeTlObject(await gunzip(readTlBytes(value, 4)));
  }
  return new TlBinaryReader(__tlReaderMap, value).object() as TlObject;
}

export class RpcError extends Error {
  constructor(readonly code: number, readonly text: string) {
    super(`Telegram RPC error ${code}: ${text}`);
    this.name = 'RpcError';
  }
}

export function rpcErrorFrom(value: TlObject): RpcError {
  return new RpcError(Number(value.errorCode), String(value.errorMessage));
}

import { concatBytes, digest, equalBytes, igeDecrypt, igeEncrypt, randomBytes } from './crypto';
import { TELEGRAM_DC_HOSTS, parseStringSession } from './session';
import { decodeTlObject, encodeMsgsAck, gunzip, readTlBytes, rpcErrorFrom, type TlObject } from './tl';
import { WorkerWebSocketTransport } from './transport';

const RPC_RESULT = 0xf35c6d01;
const MSG_CONTAINER = 0x73f1f8dc;
const GZIP_PACKED = 0x3072cfa1;
const BAD_MSG_NOTIFICATION = 0xa7eff811;
const BAD_SERVER_SALT = 0xedab447b;
const NEW_SESSION_CREATED = 0x9ec20908;
const MSGS_ACK = 0x62d6b459;

export type InvokeInput = {
  /** gramJS `StringSession` holding the auth key. */
  session: string;
  /** Serialized TL method (see `wrapInitConnection` for the first call). */
  body: Uint8Array;
  /** Last salt Telegram handed back; persist it between calls. */
  serverSalt?: string;
  /** Attempts per call. Retries only follow `bad_server_salt` / `bad_msg_notification`. */
  attempts?: number;
  /** Receive timeout per packet. */
  timeoutMs?: number;
};

export type InvokeResult = {
  value: TlObject;
  /** Persist this; the next call skips one round trip when it is current. */
  serverSalt: string;
  requestMessages: number;
  responseBytes: number;
};

type Envelope = {
  serverSalt: bigint;
  messageId: bigint;
  sequence: number;
  body: Uint8Array;
};

type ProtocolEvent =
  | { type: 'result'; value: TlObject }
  | { type: 'retry'; serverSalt?: bigint }
  | { type: 'salt'; serverSalt: bigint }
  | { type: 'ignore' };

class ByteReader {
  private readonly view: DataView;
  private offset = 0;

  constructor(private readonly value: Uint8Array) {
    this.view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  }

  uint(): number {
    const result = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return result;
  }

  int(): number {
    const result = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return result;
  }

  long(): bigint {
    const result = this.view.getBigInt64(this.offset, true);
    this.offset += 8;
    return result;
  }

  bytes(length: number): Uint8Array {
    const result = this.value.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  rest(): Uint8Array {
    return this.value.slice(this.offset);
  }
}

/** Open and close one obfuscated socket without sending anything. Useful as a CPU-budget floor. */
export async function probeTransport(sessionValue: string): Promise<void> {
  const session = parseStringSession(sessionValue);
  const transport = new WorkerWebSocketTransport();
  try {
    await transport.connect(TELEGRAM_DC_HOSTS[session.dcId]);
  } finally {
    transport.close();
  }
}

function longBytes(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigInt64(0, value, true);
  return result;
}

function intBytes(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setInt32(0, value, true);
  return result;
}

// msg_id is unix time in 2^-32 seconds, divisible by 4, strictly increasing.
function nextMessageId(previous: bigint, timeOffsetSeconds: number): bigint {
  const milliseconds = BigInt(Date.now() + timeOffsetSeconds * 1_000);
  let value = ((milliseconds << 32n) / 1_000n) & ~3n;
  if (value <= previous) value = previous + 4n;
  return value;
}

// MTProto 2.0 KDF: x = 0 for client→server, 8 for server→client.
async function deriveMessageKey(authKey: Uint8Array, messageKey: Uint8Array, outgoing: boolean) {
  const offset = outgoing ? 0 : 8;
  const [a, b] = await Promise.all([
    digest('SHA-256', concatBytes(messageKey, authKey.slice(offset, offset + 36))),
    digest('SHA-256', concatBytes(authKey.slice(offset + 40, offset + 76), messageKey)),
  ]);
  return {
    key: concatBytes(a.slice(0, 8), b.slice(8, 24), a.slice(24, 32)),
    iv: concatBytes(b.slice(0, 8), a.slice(8, 24), b.slice(24, 32)),
  };
}

async function encryptMessage(input: {
  authKey: Uint8Array;
  authKeyId: Uint8Array;
  serverSalt: bigint;
  sessionId: bigint;
  messageId: bigint;
  sequence: number;
  body: Uint8Array;
}): Promise<Uint8Array> {
  const header = concatBytes(
    longBytes(input.serverSalt),
    longBytes(input.sessionId),
    longBytes(input.messageId),
    intBytes(input.sequence),
    intBytes(input.body.length),
    input.body,
  );
  const minimumPadding = 12;
  const padding = minimumPadding + ((16 - ((header.length + minimumPadding) % 16)) % 16);
  const inner = concatBytes(header, randomBytes(padding));
  const largeKey = await digest('SHA-256', concatBytes(input.authKey.slice(88, 120), inner));
  const messageKey = largeKey.slice(8, 24);
  const { key, iv } = await deriveMessageKey(input.authKey, messageKey, true);
  return concatBytes(input.authKeyId, messageKey, igeEncrypt(inner, key, iv));
}

async function decryptMessage(input: {
  packet: Uint8Array;
  authKey: Uint8Array;
  authKeyId: Uint8Array;
  sessionId: bigint;
}): Promise<Envelope> {
  if (!equalBytes(input.packet.slice(0, 8), input.authKeyId)) {
    throw new Error('Telegram response used an unexpected auth key');
  }
  const messageKey = input.packet.slice(8, 24);
  const { key, iv } = await deriveMessageKey(input.authKey, messageKey, false);
  const inner = igeDecrypt(input.packet.slice(24), key, iv);
  const expected = (await digest('SHA-256', concatBytes(input.authKey.slice(96, 128), inner))).slice(8, 24);
  if (!equalBytes(messageKey, expected)) throw new Error('Telegram response msg_key mismatch');

  const reader = new ByteReader(inner);
  const serverSalt = reader.long();
  const returnedSessionId = reader.long();
  if (returnedSessionId !== input.sessionId) throw new Error('Telegram response session mismatch');
  const messageId = reader.long();
  const sequence = reader.int();
  const length = reader.int();
  if (length <= 0 || length % 4 !== 0 || length > inner.length - 32) {
    throw new Error('Telegram response length is invalid');
  }
  return { serverSalt, messageId, sequence, body: reader.bytes(length) };
}

async function readProtocolEvents(body: Uint8Array, requestId: bigint, ackIds: bigint[]): Promise<ProtocolEvent[]> {
  const reader = new ByteReader(body);
  const constructor = reader.uint();
  if (constructor === MSG_CONTAINER) {
    const count = reader.int();
    const events: ProtocolEvent[] = [];
    for (let index = 0; index < count; index += 1) {
      const messageId = reader.long();
      const sequence = reader.int();
      const length = reader.int();
      const inner = reader.bytes(length);
      if (sequence % 2 === 1) ackIds.push(messageId);
      events.push(...await readProtocolEvents(inner, requestId, ackIds));
    }
    return events;
  }
  if (constructor === RPC_RESULT) {
    const returnedRequestId = reader.long();
    if (returnedRequestId !== requestId) return [{ type: 'ignore' }];
    const result = await decodeTlObject(reader.rest());
    if (result._ === 'mt_rpc_error') throw rpcErrorFrom(result);
    return [{ type: 'result', value: result }];
  }
  if (constructor === BAD_SERVER_SALT) {
    reader.long();
    reader.int();
    reader.int();
    return [{ type: 'retry', serverSalt: reader.long() }];
  }
  if (constructor === BAD_MSG_NOTIFICATION) {
    reader.long();
    reader.int();
    const errorCode = reader.int();
    // 16/17: msg_id too low/high, the clock skew case. Re-send with a fresh id.
    if (errorCode === 16 || errorCode === 17) return [{ type: 'retry' }];
    throw new Error(`Telegram bad_msg_notification ${errorCode}`);
  }
  if (constructor === NEW_SESSION_CREATED) {
    reader.long();
    reader.long();
    return [{ type: 'salt', serverSalt: reader.long() }];
  }
  if (constructor === GZIP_PACKED) {
    return readProtocolEvents(await gunzip(readTlBytes(body, 4)), requestId, ackIds);
  }
  if (constructor === MSGS_ACK) return [{ type: 'ignore' }];
  return [{ type: 'ignore' }];
}

/**
 * One MTProto RPC over a fresh obfuscated WebSocket: connect, send, absorb
 * salt and msg_id corrections, ack what the server sent, return the decoded
 * result, close. No client class, no update loop, no DH, no Node polyfills.
 */
export async function invoke(input: InvokeInput): Promise<InvokeResult> {
  const session = parseStringSession(input.session);
  const authKeyId = (await digest('SHA-1', session.authKey)).slice(-8);
  const randomSession = randomBytes(8);
  const sessionId = new DataView(randomSession.buffer).getBigInt64(0, true);
  const transport = new WorkerWebSocketTransport();
  await transport.connect(TELEGRAM_DC_HOSTS[session.dcId]);

  let serverSalt = input.serverSalt ? BigInt(input.serverSalt) : 0n;
  let lastMessageId = 0n;
  let contentCount = 0;
  let requestMessages = 0;
  let responseBytes = 0;
  const attempts = input.attempts ?? 3;
  const ackIds: bigint[] = [];

  try {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const requestId = nextMessageId(lastMessageId, 0);
      lastMessageId = requestId;
      const sequence = contentCount * 2 + 1;
      contentCount += 1;
      const packet = await encryptMessage({
        authKey: session.authKey,
        authKeyId,
        serverSalt,
        sessionId,
        messageId: requestId,
        sequence,
        body: input.body,
      });
      requestMessages += 1;
      await transport.send(packet);

      let retry = false;
      while (!retry) {
        const encryptedResponse = await transport.receivePacket(input.timeoutMs);
        responseBytes += encryptedResponse.length;
        const envelope = await decryptMessage({
          packet: encryptedResponse,
          authKey: session.authKey,
          authKeyId,
          sessionId,
        });
        serverSalt = envelope.serverSalt;
        if (envelope.sequence % 2 === 1) ackIds.push(envelope.messageId);
        const events = await readProtocolEvents(envelope.body, requestId, ackIds);
        for (const event of events) {
          if (event.type === 'salt') serverSalt = event.serverSalt;
          if (event.type === 'retry') {
            if (event.serverSalt !== undefined) serverSalt = event.serverSalt;
            retry = true;
          }
          if (event.type === 'result') {
            if (ackIds.length > 0) {
              const ackMessageId = nextMessageId(lastMessageId, 0);
              lastMessageId = ackMessageId;
              await transport.send(await encryptMessage({
                authKey: session.authKey,
                authKeyId,
                serverSalt,
                sessionId,
                messageId: ackMessageId,
                sequence: contentCount * 2,
                body: encodeMsgsAck([...new Set(ackIds)]),
              }));
            }
            return {
              value: event.value,
              requestMessages,
              responseBytes,
              serverSalt: serverSalt.toString(),
            };
          }
        }
      }
    }
    throw new Error(`Telegram rejected the request ${attempts} times`);
  } finally {
    transport.close();
  }
}

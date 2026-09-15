import { AesCtrStream, concatBytes, randomBytes } from './crypto';

type PacketWaiter = {
  resolve: (packet: Uint8Array) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

const CLOSED = new Error('Telegram WebSocket closed');
const ABRIDGED_TAG = new Uint8Array([0xef, 0xef, 0xef, 0xef]);

function isForbiddenHeader(value: Uint8Array): boolean {
  const first = new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(0, false);
  return value[0] === 0xef
    || first === 0x44414548
    || first === 0x54534f50
    || first === 0x20544547
    || first === 0xeeeeeeee
    || value.subarray(4, 8).every((byte) => byte === 0);
}

/** One obfuscated abridged MTProto stream over a Workers outbound WebSocket. */
export class WorkerWebSocketTransport {
  private socket?: WebSocket;
  private encryptor?: AesCtrStream;
  private decryptor?: AesCtrStream;
  private buffered = new Uint8Array();
  private packets: Uint8Array[] = [];
  private waiters: PacketWaiter[] = [];
  private processing = Promise.resolve();
  private closed = true;

  async connect(host: string): Promise<void> {
    const response = await fetch(`https://${host}/apiws`, {
      headers: {
        Upgrade: 'websocket',
        'Sec-WebSocket-Protocol': 'binary',
      },
    });
    const socket = (response as Response & { webSocket?: WebSocket }).webSocket;
    if (!socket) throw new Error(`Telegram WebSocket upgrade failed with ${response.status}`);

    let header = randomBytes(64);
    while (isForbiddenHeader(header)) header = randomBytes(64);
    const reversed = header.slice(8, 56).reverse();
    this.encryptor = await AesCtrStream.create(header.slice(8, 40), header.slice(40, 56));
    this.decryptor = await AesCtrStream.create(reversed.slice(0, 32), reversed.slice(32, 48));
    header.set(ABRIDGED_TAG, 56);
    const encryptedHeader = await this.encryptor.apply(header);
    header.set(encryptedHeader.slice(56, 64), 56);

    this.socket = socket;
    this.closed = false;
    socket.binaryType = 'arraybuffer';
    socket.addEventListener('message', (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        this.fail(new Error('Telegram WebSocket returned text data'));
        return;
      }
      const data = new Uint8Array(event.data as ArrayBuffer);
      this.processing = this.processing
        .then(() => this.receive(data))
        .catch((error) => this.fail(error instanceof Error ? error : new Error(String(error))));
    });
    socket.addEventListener('close', () => this.fail(CLOSED));
    socket.addEventListener('error', () => this.fail(new Error('Telegram WebSocket failed')));
    (socket as WebSocket & { accept(): void }).accept();
    socket.send(header);
  }

  async send(packet: Uint8Array): Promise<void> {
    if (this.closed || !this.socket || !this.encryptor) throw CLOSED;
    const words = packet.length / 4;
    const prefix = words < 127
      ? new Uint8Array([words])
      : new Uint8Array([0x7f, words & 0xff, (words >>> 8) & 0xff, (words >>> 16) & 0xff]);
    this.socket.send(await this.encryptor.apply(concatBytes(prefix, packet)));
  }

  receivePacket(timeoutMs = 15_000): Promise<Uint8Array> {
    const packet = this.packets.shift();
    if (packet) return Promise.resolve(packet);
    if (this.closed) return Promise.reject(CLOSED);
    return new Promise((resolve, reject) => {
      const waiter: PacketWaiter = {
        resolve,
        reject,
        timeout: setTimeout(() => {
          this.waiters = this.waiters.filter((candidate) => candidate !== waiter);
          reject(new Error('Telegram response timed out'));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket?.close(1000, 'tick complete');
    this.fail(CLOSED);
  }

  private async receive(encrypted: Uint8Array): Promise<void> {
    if (!this.decryptor) throw new Error('Telegram decryptor is not initialized');
    this.buffered = concatBytes(this.buffered, await this.decryptor.apply(encrypted));
    while (this.buffered.length > 0) {
      const first = this.buffered[0];
      const prefixLength = first === 0x7f ? 4 : 1;
      if (this.buffered.length < prefixLength) return;
      const words = first === 0x7f
        ? this.buffered[1] | (this.buffered[2] << 8) | (this.buffered[3] << 16)
        : first;
      const length = words * 4;
      if (length <= 0) throw new Error('Telegram returned an invalid abridged frame');
      if (this.buffered.length < prefixLength + length) return;
      const packet = this.buffered.slice(prefixLength, prefixLength + length);
      this.buffered = this.buffered.slice(prefixLength + length);
      const waiter = this.waiters.shift();
      if (waiter) {
        clearTimeout(waiter.timeout);
        waiter.resolve(packet);
      } else {
        this.packets.push(packet);
      }
    }
  }

  private fail(error: Error): void {
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timeout);
      waiter.reject(error);
    }
  }
}

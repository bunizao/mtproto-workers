export type Session = { dcId: number; authKey: Uint8Array };

/** Telegram's WebSocket front doors, one per production data center. */
export const TELEGRAM_DC_HOSTS: Record<number, string> = {
  1: 'pluto.web.telegram.org',
  2: 'venus.web.telegram.org',
  3: 'aurora.web.telegram.org',
  4: 'vesta.web.telegram.org',
  5: 'flora.web.telegram.org',
};

/**
 * Parse a gramJS `StringSession` (version 1): `'1' + base64(dcId u8,
 * addressLength i16 BE, address, port i16 BE, authKey 256 bytes)`. The auth
 * key is the only thing the Worker needs; the DH handshake that produced it
 * happened once, on a laptop.
 */
export function parseStringSession(value: string): Session {
  if (!value.startsWith('1')) throw new Error('Unsupported StringSession version');
  const binary = atob(value.slice(1));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const view = new DataView(bytes.buffer);
  const dcId = view.getUint8(0);
  const addressLength = view.getInt16(1, false);
  const keyOffset = 1 + 2 + addressLength + 2;
  const authKey = bytes.slice(keyOffset);
  if (!TELEGRAM_DC_HOSTS[dcId] || authKey.length !== 256) {
    throw new Error('Invalid StringSession payload');
  }
  return { dcId, authKey };
}

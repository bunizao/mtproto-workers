import { describe, expect, test } from 'bun:test';
import { createCipheriv } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { __tlWriterMap } from '@mtcute/tl/binary/writer.js';
import { TlBinaryWriter } from '@mtcute/tl-runtime';
import Long from 'long';
import { AesCtrStream, concatBytes, igeDecrypt, igeEncrypt } from '../src/crypto';
import { parseStringSession } from '../src/session';
import { TlWriter, decodeTlObject, encodeMsgsAck, wrapInitConnection } from '../src/tl';
import {
  encodeChannelDifferenceRequest,
  encodeGetMessagesRequest,
  reduceDifference,
  reduceMessages,
} from '../src/methods/channels';

const serialize = (value: unknown) => TlBinaryWriter.serializeObject(__tlWriterMap, value as never);

describe('crypto', () => {
  test('keeps AES-CTR state across partial chunks', async () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const counter = Uint8Array.from({ length: 16 }, (_, index) => 31 - index);
    const input = Uint8Array.from({ length: 137 }, (_, index) => (index * 29) & 0xff);
    const expected = createCipheriv('aes-256-ctr', key, counter).update(input);
    const stream = await AesCtrStream.create(key, counter);
    const actual = concatBytes(
      await stream.apply(input.slice(0, 7)),
      await stream.apply(input.slice(7, 26)),
      await stream.apply(input.slice(26)),
    );
    expect(Buffer.from(actual)).toEqual(expected);
  });

  test('matches the GramJS AES-IGE reference vector', () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => (index * 7) & 0xff);
    const iv = Uint8Array.from({ length: 32 }, (_, index) => (index * 11) & 0xff);
    const input = Uint8Array.from({ length: 128 }, (_, index) => (index * 13) & 0xff);
    const expected = Buffer.from(
      '8e5be52ef451cfddd429c1230ca9e2355c9518c96f1c1f4c7c58fa63c4d27cb6'
      + '2469924fe8a1561f76b8d81cd92020f5b18c2b6b9b3bf2812f10fa7d99032550'
      + '6d2398d50f04d33dceb55f3a22c8ed680d4005e7a3802f12bd0d9e9ceb8621e8'
      + '082032ff9ad24a3939a5f717bc4a33accf26fc041e42ebd4efb53b3bd3c9a7a5',
      'hex',
    );
    const encrypted = igeEncrypt(input, key, iv);
    expect([...encrypted]).toEqual([...expected]);
    expect(igeDecrypt(encrypted, key, iv)).toEqual(input);
  });
});

describe('session', () => {
  test('parses a version 1 StringSession', () => {
    const authKey = Uint8Array.from({ length: 256 }, (_, index) => index & 0xff);
    const address = new TextEncoder().encode('149.154.167.51');
    const header = new Uint8Array(1 + 2 + address.length + 2);
    const view = new DataView(header.buffer);
    view.setUint8(0, 2);
    view.setInt16(1, address.length, false);
    header.set(address, 3);
    view.setInt16(3 + address.length, 443, false);
    const session = '1' + Buffer.from(concatBytes(header, authKey)).toString('base64');
    expect(parseStringSession(session)).toEqual({ dcId: 2, authKey });
    expect(() => parseStringSession('0abc')).toThrow('Unsupported');
  });
});

describe('TL writer', () => {
  const channel = { channelId: '1234567890', accessHash: '-4567890123456789012' };
  const inputChannel = {
    _: 'inputChannel',
    channelId: Number(channel.channelId),
    accessHash: Long.fromString(channel.accessHash),
  };

  test('matches the generated writer for a naked getChannelDifference', () => {
    const expected = serialize({
      _: 'updates.getChannelDifference',
      force: false,
      channel: inputChannel,
      filter: { _: 'channelMessagesFilterEmpty' },
      pts: 9058,
      limit: 10,
    });
    expect(encodeChannelDifferenceRequest({ ...channel, pts: 9058, limit: 10 })).toEqual(expected);
  });

  test('matches the generated writer for invokeWithLayer(initConnection(...))', () => {
    const body = encodeChannelDifferenceRequest({ ...channel, pts: 9058, limit: 10 });
    const expected = serialize({
      _: 'invokeWithLayer',
      layer: 223,
      query: {
        _: 'initConnection',
        apiId: 12345,
        deviceModel: 'Cloudflare Worker',
        systemVersion: 'workerd',
        appVersion: 'mtproto-workers',
        systemLangCode: 'en',
        langPack: '',
        langCode: 'en',
        query: {
          _: 'updates.getChannelDifference',
          force: false,
          channel: inputChannel,
          filter: { _: 'channelMessagesFilterEmpty' },
          pts: 9058,
          limit: 10,
        },
      },
    });
    expect(wrapInitConnection(body, { apiId: 12345 })).toEqual(expected);
  });

  test('matches the generated writer for channels.getMessages', () => {
    const messageIds = [3720, 3721, 3723];
    const expected = serialize({
      _: 'channels.getMessages',
      channel: inputChannel,
      id: messageIds.map((id) => ({ _: 'inputMessageID', id })),
    });
    expect(encodeGetMessagesRequest({ ...channel, messageIds })).toEqual(expected);
  });

  test('writes long strings with the 254 header', () => {
    const value = 'x'.repeat(300);
    const expected = new Uint8Array(4 + 300);
    expected.set([254, 300 & 0xff, (300 >> 8) & 0xff, 0]);
    expected.set(new TextEncoder().encode(value), 4);
    expect(new TlWriter().string(value).result()).toEqual(expected);
  });

  test('writes msgs_ack as Vector<long>', () => {
    const bytes = encodeMsgsAck([1n, 2n]);
    const view = new DataView(bytes.buffer);
    expect(view.getUint32(0, true)).toBe(0x62d6b459);
    expect(view.getUint32(4, true)).toBe(0x1cb5c415);
    expect(view.getUint32(8, true)).toBe(2);
    expect(view.getBigInt64(12, true)).toBe(1n);
    expect(view.getBigInt64(20, true)).toBe(2n);
  });
});

describe('TL reader', () => {
  test('decodes an API object through the generated reader map', async () => {
    const bytes = serialize({ _: 'messages.messages', messages: [{ _: 'messageEmpty', id: 7 }], topics: [], chats: [], users: [] });
    const value = await decodeTlObject(bytes);
    expect(value._).toBe('messages.messages');
    expect((value.messages as Array<{ id: number }>)[0].id).toBe(7);
  });

  test('decodes rpc_error and gzip_packed', async () => {
    const error = new TlWriter().uint(0x2144ca19).int(400).string('CHANNEL_INVALID').result();
    expect(await decodeTlObject(error)).toEqual({ _: 'mt_rpc_error', errorCode: 400, errorMessage: 'CHANNEL_INVALID' });

    const inner = serialize({ _: 'messages.messages', messages: [], topics: [], chats: [], users: [] });
    const compressed = new Uint8Array(await new Response(
      new Blob([inner.slice().buffer as ArrayBuffer]).stream().pipeThrough(new CompressionStream('gzip')),
    ).arrayBuffer());
    const packed = new TlWriter().uint(0x3072cfa1).bytes(compressed).result();
    expect((await decodeTlObject(packed))._).toBe('messages.messages');
  });
});

describe('channel reducers', () => {
  test('reduces a difference page to ids, dates, and kinds', () => {
    const diff = reduceDifference({
      _: 'updates.channelDifference',
      final: true,
      pts: 9100,
      newMessages: [
        { _: 'message', id: 3730, date: 1_787_000_000, message: 'content never leaves the decoder' },
        { _: 'messageService', id: 3731, date: 1_787_000_100 },
      ],
      otherUpdates: [
        { _: 'updateEditChannelMessage', message: { _: 'message', id: 3720, date: 1, editDate: 1_787_000_200 } },
        { _: 'updateDeleteChannelMessages', messages: [3723, 3724] },
        { _: 'updateChannelMessageViews', id: 3720, views: 4 },
      ],
    });
    expect(diff).toEqual({
      kind: 'page',
      pts: 9100,
      final: true,
      newMessages: [
        { id: 3730, date: 1_787_000_000, kind: 'message' },
        { id: 3731, date: 1_787_000_100, kind: 'service' },
      ],
      edits: [{ id: 3720, editDate: 1_787_000_200 }],
      deleted: [3723, 3724],
    });
    expect(reduceDifference({ _: 'updates.channelDifferenceEmpty', final: true, pts: 9058 })).toMatchObject({ kind: 'empty', pts: 9058 });
    expect(reduceDifference({ _: 'updates.channelDifferenceTooLong', dialog: { _: 'dialog', pts: 9300 } })).toMatchObject({ kind: 'too_long', pts: 9300 });
    expect(() => reduceDifference({ _: 'mt_rpc_error', errorCode: 400, errorMessage: 'CHANNEL_INVALID' })).toThrow('CHANNEL_INVALID');
  });

  test('splits a getMessages result into present and absent ids', () => {
    expect(reduceMessages({
      _: 'messages.channelMessages',
      messages: [
        { _: 'message', id: 3720 },
        { _: 'messageEmpty', id: 3721 },
        { _: 'messageService', id: 3723 },
      ],
    }, [3720, 3721, 3723, 3724])).toEqual({ present: [3720, 3723], absent: [3721, 3724] });
  });
});

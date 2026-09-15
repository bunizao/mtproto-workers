import { invoke, type InvokeResult } from '../client';
import { TlWriter, rpcErrorFrom, wrapInitConnection, type InitConnection, type TlObject } from '../tl';

const GET_CHANNEL_DIFFERENCE = 0x03173d78;
const GET_MESSAGES = 0xad8c9a23;
const INPUT_CHANNEL = 0xf35aec28;
const CHANNEL_MESSAGES_FILTER_EMPTY = 0x94d42ee7;
const INPUT_MESSAGE_ID = 0xa676a322;

export type InputChannel = {
  /** Bare channel id (no `-100` prefix), as a string so the full 64 bits survive JSON. */
  channelId: string;
  /** Signed 64-bit access hash from `contacts.resolveUsername`, as a string. */
  accessHash: string;
};

/** A difference page reduced to ids, dates and kinds. Message content never leaves the decoder. */
export type ChannelDiff = {
  kind: 'empty' | 'page' | 'too_long';
  pts: number | null;
  final: boolean;
  newMessages: Array<{ id: number; date: number; kind: 'message' | 'service' }>;
  edits: Array<{ id: number; editDate: number | null }>;
  deleted: number[];
};

function writeInputChannel(writer: TlWriter, input: InputChannel): TlWriter {
  return writer.uint(INPUT_CHANNEL).long(BigInt(input.channelId)).long(BigInt(input.accessHash));
}

/** `updates.getChannelDifference#03173d78` with `channelMessagesFilterEmpty`. */
export function encodeChannelDifferenceRequest(input: InputChannel & { pts: number; limit: number }): Uint8Array {
  const writer = new TlWriter().uint(GET_CHANNEL_DIFFERENCE).uint(0);
  writeInputChannel(writer, input).uint(CHANNEL_MESSAGES_FILTER_EMPTY).int(input.pts).int(input.limit);
  return writer.result();
}

/** `channels.getMessages#ad8c9a23` by id. Absent ids come back as `messageEmpty`. */
export function encodeGetMessagesRequest(input: InputChannel & { messageIds: number[] }): Uint8Array {
  const writer = new TlWriter().uint(GET_MESSAGES);
  writeInputChannel(writer, input).vector(input.messageIds.length);
  for (const id of input.messageIds) writer.uint(INPUT_MESSAGE_ID).int(id);
  return writer.result();
}

const emptyDiff = (): Pick<ChannelDiff, 'newMessages' | 'edits' | 'deleted'> => ({
  newMessages: [],
  edits: [],
  deleted: [],
});

export function reduceDifference(difference: TlObject): ChannelDiff {
  if (difference._ === 'mt_rpc_error') throw rpcErrorFrom(difference);
  if (difference._ === 'updates.channelDifferenceEmpty') {
    return { kind: 'empty', pts: Number(difference.pts), final: true, ...emptyDiff() };
  }
  if (difference._ === 'updates.channelDifferenceTooLong') {
    const dialog = difference.dialog as TlObject | undefined;
    return {
      kind: 'too_long',
      pts: typeof dialog?.pts === 'number' ? dialog.pts : null,
      final: true,
      ...emptyDiff(),
    };
  }
  if (difference._ !== 'updates.channelDifference') {
    throw new Error(`Unexpected difference result: ${difference._}`);
  }
  const updates = difference.otherUpdates as TlObject[];
  return {
    kind: 'page',
    pts: Number(difference.pts),
    final: difference.final === true,
    newMessages: (difference.newMessages as TlObject[]).flatMap((message): ChannelDiff['newMessages'] => {
      if (typeof message.id !== 'number') return [];
      if (message._ === 'message') return [{ id: message.id, date: Number(message.date), kind: 'message' }];
      if (message._ === 'messageService') return [{ id: message.id, date: Number(message.date), kind: 'service' }];
      return [];
    }),
    edits: updates
      .filter((update) => update._ === 'updateEditChannelMessage')
      .flatMap((update) => {
        const message = update.message as TlObject | undefined;
        if (typeof message?.id !== 'number') return [];
        return [{ id: message.id, editDate: typeof message.editDate === 'number' ? message.editDate : null }];
      }),
    deleted: updates
      .filter((update) => update._ === 'updateDeleteChannelMessages')
      .flatMap((update) => (update.messages as number[])),
  };
}

export function reduceMessages(value: TlObject, requested: number[]): { present: number[]; absent: number[] } {
  if (value._ === 'mt_rpc_error') throw rpcErrorFrom(value);
  if (value._ !== 'messages.channelMessages' && value._ !== 'messages.messages') {
    throw new Error(`Unexpected getMessages result: ${value._}`);
  }
  const present = new Set((value.messages as TlObject[])
    .filter((message) => message._ !== 'messageEmpty' && typeof message.id === 'number')
    .map((message) => message.id as number));
  return {
    present: requested.filter((id) => present.has(id)),
    absent: requested.filter((id) => !present.has(id)),
  };
}

export type ChannelCallInput = InputChannel & {
  session: string;
  serverSalt?: string;
  /** `false` on the first call after a new auth key; the result flips it to `true`. */
  initialized: boolean;
  init: InitConnection;
};

type CallState = Pick<InvokeResult, 'responseBytes' | 'serverSalt'> & { initialized: true };

async function call(input: ChannelCallInput, body: Uint8Array): Promise<InvokeResult> {
  return invoke({
    session: input.session,
    serverSalt: input.serverSalt,
    body: input.initialized ? body : wrapInitConnection(body, input.init),
  });
}

/** Everything that changed in a channel since `pts`: new, edited and deleted message ids. */
export async function getChannelDifference(
  input: ChannelCallInput & { pts: number; limit: number },
): Promise<CallState & { diff: ChannelDiff; raw: TlObject }> {
  const result = await call(input, encodeChannelDifferenceRequest(input));
  return {
    diff: reduceDifference(result.value),
    raw: result.value,
    responseBytes: result.responseBytes,
    serverSalt: result.serverSalt,
    initialized: true,
  };
}

/** Which of `messageIds` still exist. Telegram answers `messageEmpty` for deleted ones. */
export async function checkMessages(
  input: ChannelCallInput & { messageIds: number[] },
): Promise<CallState & { present: number[]; absent: number[]; raw: TlObject }> {
  const result = await call(input, encodeGetMessagesRequest(input));
  return {
    ...reduceMessages(result.value, input.messageIds),
    raw: result.value,
    responseBytes: result.responseBytes,
    serverSalt: result.serverSalt,
    initialized: true,
  };
}

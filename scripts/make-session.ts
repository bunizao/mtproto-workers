// One-time bootstrap on a laptop: log in with gramJS, resolve the channel,
// and print everything the Worker needs. The DH handshake happens here, once;
// the Worker only ever reuses the resulting auth key.
//
//   API_ID=... API_HASH=... bun run scripts/make-session.ts @channel
//
// Prints MT_SESSION, CHANNEL_ID, ACCESS_HASH and the current pts. Store the
// first three as Worker secrets, pass pts to POST /bootstrap.
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { Api, TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';

const apiId = Number(process.env.API_ID);
const apiHash = process.env.API_HASH ?? '';
const target = process.argv[2];
if (!apiId || !apiHash || !target) {
  console.error('usage: API_ID=... API_HASH=... bun run scripts/make-session.ts @channel');
  process.exit(1);
}

const prompt = createInterface({ input: stdin, output: stdout });
const ask = (question: string) => prompt.question(question);

const client = new TelegramClient(new StringSession(''), apiId, apiHash, { connectionRetries: 3 });
await client.start({
  phoneNumber: () => ask('phone: '),
  password: () => ask('2fa password: '),
  phoneCode: () => ask('code: '),
  onError: async (error) => { console.error(error); return true; },
});

const entity = await client.getEntity(target);
if (!(entity instanceof Api.Channel)) throw new Error(`${target} is not a channel`);
const full = await client.invoke(new Api.channels.GetFullChannel({ channel: entity }));
const pts = (full.fullChat as Api.ChannelFull).pts;

console.log('\nMT_SESSION=' + client.session.save());
console.log('CHANNEL_ID=' + entity.id.toString());
console.log('ACCESS_HASH=' + entity.accessHash?.toString());
console.log('pts=' + pts);
console.log('\nThe session above is a logged-in user account. Treat it like a password.');

prompt.close();
await client.disconnect();
process.exit(0);

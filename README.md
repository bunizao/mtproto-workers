# mtproto-workers

**A real MTProto 2.0 client that runs inside a Cloudflare Worker.** Not a proxy. Not a relay. The Worker itself opens the obfuscated transport, encrypts the request with your auth key, calls the Telegram API, and decodes the answer, in about 3 ms of CPU, on the free tier.

It has been doing exactly that in production since 2026-09-03: a Durable Object wakes up every five minutes, asks Telegram what changed in a channel (`updates.getChannelDifference`), and forwards the result. Zero VPS. Zero long-lived process. Zero gramJS.

```ts
import { getChannelDifference } from 'mtproto-workers';

const result = await getChannelDifference({
  session: env.MT_SESSION,          // gramJS StringSession, made once on your laptop
  channelId: '1234567890',
  accessHash: '-4567890123456789012',
  pts: 9150,
  limit: 100,
  initialized: true,
  init: { apiId: Number(env.API_ID) },
});

result.diff;
// { kind: 'page', pts: 9153, final: true,
//   newMessages: [{ id: 3851, date: 1789...., kind: 'message' }],
//   edits: [{ id: 3819, editDate: 1789.... }],
//   deleted: [3842] }
```

## Why this did not exist

Everyone who tried to run a Telegram *client* (not a bot) on Workers hit the same wall, and the graveyard is public:

| Where | What happened |
|---|---|
| [mtcute#54](https://github.com/mtcute/mtcute/issues/54) "Cloudflare Workers support" | Open since May 2024. mtcute's transport layer assumes a persistent socket owner. |
| [alik0211/mtproto-core#229](https://github.com/alik0211/mtproto-core/pull/229) "Cloudflare Workers transport" | Opened December 2021, never merged, repo archived September 2024. One commenter confirmed the fork ran in prod; the fork then died with the repo. |
| Cloudflare community: *"GramJS authentication in a worker"*, *"Unable to use Telegram (gram.js) library in Cloudflare Workers"* | gramJS drags in `net`, `ws`, `big-integer`, its own AES, and a reconnect loop that wants a process. Polyfilled builds "fail after 5 days". |
| Every GitHub repo named `tg-ws-api`, `TG-WebApp-Proxy`, `Telegram-WEB-Cloudflare-Workers`, and their forks | Byte relays. They forward a browser's WebSocket to `*.web.telegram.org` and never look inside a packet. The Worker is a pipe, not a client. |
| [teleproto](https://github.com/sanyok12345/teleproto) (312 stars) | Advertises "serverless runtimes" but has no Workers transport and no story for a runtime that cannot hold a socket between requests. |

The blocker was never crypto or TL. It was the mental model: every client library is built as a long-lived object with a socket, an update loop, a session store and a DH handshake at startup. Workers give you none of that. A Durable Object alarm gives you ~10 ms of CPU and then evicts you.

## What is actually inside

The whole client is ~900 lines of TypeScript and three small dependencies. Nothing here is a wrapper around gramJS or mtcute's client class.

- **Transport** (`src/transport.ts`): obfuscated abridged MTProto over a Workers *outbound* WebSocket. `fetch('https://venus.web.telegram.org/apiws', { headers: { Upgrade: 'websocket' } })`, then `response.webSocket.accept()`. The 64-byte obfuscation header is generated with the forbidden-prefix rules (`0xef`, `HEAD`, `POST`, `GET `, `0xeeeeeeee`, zero bytes 4..8). AES-256-CTR runs on WebCrypto with a partial-block carry so packets need not align to 16 bytes. Abridged framing handles both the 1-byte and the `0x7f` + 3-byte length forms.
- **Message layer** (`src/client.ts`): MTProto 2.0 KDF (`x = 0` client → server, `8` server → client), `msg_key` from `SHA-256(authKey[88..120] ‖ plaintext)[8..24]`, AES-IGE via `@cryptography/aes`, 12–27 bytes of random padding, `msg_id` as unix time in 2⁻³² s rounded to a multiple of 4 and strictly increasing. Inbound: `auth_key_id` check, `msg_key` recomputation, session id check, length sanity.
- **Protocol state machine** (`src/client.ts`): `msg_container`, `rpc_result`, `bad_server_salt` (retry with the salt Telegram sent), `bad_msg_notification` codes 16/17 (clock skew, retry with a fresh id), `new_session_created` (adopt salt), `gzip_packed`, `msgs_ack`. Content-related server messages are acked before the socket closes, so Telegram does not resend them into the void.
- **TL** (`src/tl.ts`): a 60-line hand writer (`uint`, `int`, `long`, `string`, `bytes`, `vector`) for requests, and the generated `@mtcute/tl` reader map for responses. That reader map is the one dependency that costs bytes, and it is why any layer-223 constructor decodes without you writing a parser.
- **Session** (`src/session.ts`): parses a gramJS `StringSession` (version 1). The auth key inside it is the product of the DH handshake you ran once on a laptop. The Worker never runs `req_pq`. It reuses the key across every alarm, every eviction, every redeploy.

Design rule that makes it fit in the budget: **one RPC per socket.** Connect, send, read until `rpc_result`, ack, close. No connection pool, no keepalive, no update loop, no reconnect logic. The DO's alarm is the loop.

## Numbers (Workers Free plan, 10 ms CPU limit, 2026-09-03)

| Measurement | p95 CPU | max CPU |
|---|---|---|
| Alarm with no RPC (floor) | 2 ms | 3 ms |
| `getChannelDifference`, empty result | 3 ms | 4 ms |
| `getChannelDifference`, one page of updates | 4 ms | 8 ms |

50 alarms in a row, 0 killed by `exceededResources`. Wall time per tick is 1.5–2.5 s, almost all of it waiting on Telegram; CPU is what the platform bills and kills on.

Bundle for the example Durable Object: **392 KiB raw, 72.7 KiB gzip**, of which the TL reader map is the majority. The production deployment this was extracted from measures 65.7 KiB.

The auth key survived every DO eviction, `wrangler deploy`, and a deliberate `ctx.abort()` test. Telegram only requires `initConnection` once per key + layer, so after the first successful call every subsequent request is a naked method.

## What people would use this for

Things the Bot API cannot do, and a VPS used to be the only answer for:

- **See deletions and edits in a channel.** Bot webhooks never fire for a deleted message. `getChannelDifference` returns `updateDeleteChannelMessages` and `updateEditChannelMessage` with the message ids, so an archive can tombstone and re-fetch without diffing the whole channel. This is the production use case: a personal blog mirrors a Telegram channel into D1, and this client is what keeps the mirror honest.
- **Presence checks by id.** `channels.getMessages` returns `messageEmpty` for ids that are gone. Feed it a batch of 100 archived ids and you get `{ present, absent }`. Cheap, exact, no scraping.
- **Poll a channel you do not own.** Public channels, or private ones you are a member of, as a user account. No admin rights needed, no bot to add.
- **Cron-shaped userbot reads without a process.** Anything that fits "wake up, ask one thing, go back to sleep": unread counters, pinned message, dialog list, a search. Durable Object alarms are the scheduler; the DO's storage holds `pts` and the server salt.
- **A backend for the relay projects.** The `tg-ws-api` family proxies a browser's bytes to Telegram. With this library the Worker can *be* the client and hand JSON to the browser instead of raw MTProto frames.

Things it is **not** for: sending messages at volume, file uploads, being a general-purpose userbot with an update stream. It has no update loop by design.

## Bootstrap

You need three things a Worker cannot produce for itself: an auth key, the channel's id + access hash, and a starting `pts`. `scripts/make-session.ts` produces all of them with gramJS, on your laptop, once.

```bash
bun install
API_ID=12345 API_HASH=... bun run scripts/make-session.ts @your_channel
```

It logs in interactively and prints:

```
MT_SESSION=1BQANOTEuMTA4LjU2LjE2OAG7...
CHANNEL_ID=1234567890
ACCESS_HASH=-4567890123456789012
pts=9150
```

Then, for the example watcher:

```bash
cd examples/channel-watcher
wrangler secret put ADMIN_SECRET
wrangler secret put API_ID
wrangler secret put MT_SESSION
wrangler secret put CHANNEL_ID
wrangler secret put ACCESS_HASH
wrangler deploy
curl -X POST -H "Authorization: Bearer $ADMIN_SECRET" -d '{"pts":9150}' https://channel-watcher.<you>.workers.dev/bootstrap
curl -X POST -H "Authorization: Bearer $ADMIN_SECRET" -d '{"intervalMs":300000}' https://channel-watcher.<you>.workers.dev/start
wrangler secret delete MT_SESSION   # the DO owns it now
```

`GET /status` shows the cursor and the alarm. `POST /tick` runs one step on demand. Set `WEBHOOK_URL` (and `WEBHOOK_SECRET` for an HMAC-SHA256 signature over `${timestamp}.${body}`) to receive every page; leave it empty and pages go to the Worker log.

The session string is a logged-in user account. Treat it like a password: Worker secret, then DO storage, never a `vars` entry, never a repo.

## API

```ts
// The primitive. Any method you can serialize.
invoke({ session, body, serverSalt?, attempts?, timeoutMs? })
  → { value, serverSalt, requestMessages, responseBytes }

// Wrap the first call after a new auth key.
wrapInitConnection(body, { apiId, deviceModel?, systemVersion?, appVersion?, langCode? })

// Hand-write a request.
new TlWriter().uint(0x...).long(123n).string('x').vector(2).int(1).int(2).result()

// Decode a response (rpc_error, gzip_packed, then the generated reader map).
decodeTlObject(bytes) → { _: 'messages.messages', ... }

// Two methods shipped ready-made, with reducers that keep message content out of your logs.
getChannelDifference({ ...channel, pts, limit, session, serverSalt, initialized, init })
checkMessages({ ...channel, messageIds, session, serverSalt, initialized, init })
```

Persist `serverSalt` and `initialized: true` from every result. Both are tiny and both save a round trip next time.

To call any other method: serialize it with `@mtcute/tl`'s writer map (`TlBinaryWriter.serializeObject(__tlWriterMap, { _: 'help.getConfig' })`) or with `TlWriter`, pass the bytes to `invoke`, decode with `decodeTlObject`. The test suite does exactly this to prove the hand writer is byte-identical to the generated one.

## Limits, honestly

- One RPC per WebSocket. Fine for polling; wrong for chatty flows.
- No update stream, no `getDifference` for the account as a whole, no file parts. Add them by serializing the method; the message layer does not care.
- Layer 223, pinned by `@mtcute/tl`. Bump the dependency to move.
- `msg_id` uses `Date.now()` with no server time offset. Telegram tolerates ~30 s of skew and the client retries on codes 16/17; Workers clocks have not been a problem in production.
- Only the DC the session was created on is contacted. No DC migration. If your account lives on DC 4 the session says so and the client goes to `vesta`.
- Not audited. The crypto matches the gramJS IGE vectors and Node's AES-CTR bit for bit (see `test/`), and the TL encoder is checked against mtcute's generated writer, but this is a from-scratch implementation of a protocol with sharp edges. Use a dedicated account.

## Development

```bash
bun install
bun run check     # tsc
bun test          # crypto vectors, TL oracle, reducers
bun run size      # wrangler dry-run of the example + gzip
bun run build     # dist/ with declarations
```

## Credits

Extracted from the `mood-converge` Worker behind [buxx.me](https://buxx.me), where it replaced a VPS reconcile job. IGE from [`@cryptography/aes`](https://github.com/spalt08/cryptography). TL schema and reader from [mtcute](https://github.com/mtcute/mtcute). Session format from [gramJS](https://github.com/gram-js/gramjs).

MIT.

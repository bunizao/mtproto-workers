// Channel watcher: one Durable Object polls a Telegram channel's difference
// on an alarm, keeps the pts cursor in its own storage, and POSTs each reduced
// page to a webhook. This is the shape that runs in production behind
// buxx.me/mood (five-minute alarms since 2026-09-03).
import { DurableObject } from 'cloudflare:workers';
import { checkMessages, getChannelDifference, type ChannelDiff } from '../../../src';

interface Env {
  WATCHER: DurableObjectNamespace<ChannelWatcher>;
  ADMIN_SECRET: string;
  API_ID: string;
  WEBHOOK_URL?: string;
  WEBHOOK_SECRET?: string;
  // Bootstrap-only; delete from the Worker once copied into DO storage.
  MT_SESSION?: string;
  CHANNEL_ID?: string;
  ACCESS_HASH?: string;
}

type Config = { session: string; channelId: string; accessHash: string };
type Progress = { pts: number; serverSalt?: string; initialized: boolean };
type Loop = {
  enabled: boolean;
  intervalMs: number;
  limit: number;
  ticks: number;
  failures: number;
  lastRunAt?: string;
  lastKind?: string;
  lastError?: string;
  lastResponseBytes?: number;
};

const objectName = 'default';
const defaultLoop: Loop = { enabled: false, intervalMs: 5 * 60_000, limit: 100, ticks: 0, failures: 0 };
const json = (value: unknown, status = 200) => Response.json(value, { status });

function clampInteger(value: unknown, fallback: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.min(Math.max(Number(value), minimum), maximum);
}

export class ChannelWatcher extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    const post = request.method === 'POST';
    if (pathname === '/bootstrap' && post) return this.bootstrap(request);
    if (pathname === '/start' && post) return this.start(request);
    if (pathname === '/stop' && post) {
      await this.ctx.storage.put('loop', { ...(await this.loop()), enabled: false });
      await this.ctx.storage.deleteAlarm();
      return json({ stopped: true });
    }
    if (pathname === '/tick' && post) return json({ kind: await this.step(), ...(await this.status()) });
    if (pathname === '/check' && post) {
      const body = await request.json() as { ids?: number[] };
      const ids = (body.ids ?? []).filter((id) => Number.isSafeInteger(id) && id > 0).slice(0, 100);
      const result = await checkMessages({ ...(await this.callInput()), messageIds: ids });
      await this.saveProgress({ serverSalt: result.serverSalt, initialized: true });
      return json({ present: result.present, absent: result.absent });
    }
    if (pathname === '/status') return json(await this.status());
    return json({ error: 'not_found' }, 404);
  }

  // The alarm reschedules itself while enabled. A failed step leaves the
  // cursor alone and the next alarm retries the same page.
  async alarm(): Promise<void> {
    const loop = await this.ctx.storage.get<Loop>('loop');
    if (!loop?.enabled) return;
    try {
      await this.step();
    } catch (error) {
      const latest = await this.loop();
      await this.ctx.storage.put('loop', {
        ...latest,
        failures: latest.failures + 1,
        lastRunAt: new Date().toISOString(),
        lastError: error instanceof Error ? error.message : String(error),
      });
      console.error('channel-watcher step failed', { error: String(error) });
    } finally {
      const latest = await this.ctx.storage.get<Loop>('loop');
      if (latest?.enabled) await this.ctx.storage.setAlarm(Date.now() + latest.intervalMs);
    }
  }

  private async step(): Promise<ChannelDiff['kind']> {
    const [progress, loop] = await Promise.all([this.progress(), this.loop()]);
    const result = await getChannelDifference({ ...(await this.callInput()), pts: progress.pts, limit: loop.limit });
    await this.deliver(result.diff);
    // TooLong means the gap is bigger than one page can express. Telegram
    // hands back the current pts; anything in between must be re-checked by
    // id (see /check). The cursor jumps so the loop does not stall forever.
    const pts = result.diff.pts ?? progress.pts;
    await this.ctx.storage.put({
      progress: { pts, serverSalt: result.serverSalt, initialized: true } satisfies Progress,
      loop: {
        ...loop,
        ticks: loop.ticks + 1,
        failures: 0,
        lastRunAt: new Date().toISOString(),
        lastKind: result.diff.kind,
        lastError: undefined,
        lastResponseBytes: result.responseBytes,
      } satisfies Loop,
    });
    return result.diff.kind;
  }

  private async deliver(diff: ChannelDiff): Promise<void> {
    if (!this.env.WEBHOOK_URL) {
      console.log('channel-watcher diff', JSON.stringify(diff));
      return;
    }
    const body = JSON.stringify(diff);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Watcher-Timestamp': timestamp };
    if (this.env.WEBHOOK_SECRET) {
      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(this.env.WEBHOOK_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );
      const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${body}`)));
      headers['X-Watcher-Signature'] = Array.from(signature, (byte) => byte.toString(16).padStart(2, '0')).join('');
    }
    const response = await fetch(this.env.WEBHOOK_URL, { method: 'POST', headers, body });
    if (!response.ok) throw new Error(`webhook failed: ${response.status} ${(await response.text()).slice(0, 200)}`);
  }

  private async callInput() {
    const [config, progress] = await Promise.all([this.ctx.storage.get<Config>('config'), this.progress()]);
    if (!config) throw new Error('not bootstrapped');
    return {
      ...config,
      serverSalt: progress.serverSalt,
      initialized: progress.initialized,
      init: { apiId: Number(this.env.API_ID), deviceModel: 'Cloudflare Durable Object', appVersion: 'channel-watcher' },
    };
  }

  private async bootstrap(request: Request): Promise<Response> {
    const { MT_SESSION, CHANNEL_ID, ACCESS_HASH } = this.env;
    if (!MT_SESSION || !CHANNEL_ID || !ACCESS_HASH) return json({ error: 'bootstrap_secrets_missing' }, 503);
    const body = await request.json() as { pts?: number };
    if (!Number.isSafeInteger(body.pts) || (body.pts ?? 0) <= 0) return json({ error: 'invalid_pts' }, 400);
    const config: Config = { session: MT_SESSION, channelId: CHANNEL_ID, accessHash: ACCESS_HASH };
    const progress: Progress = { pts: body.pts!, initialized: false };
    await this.ctx.storage.put({ config, progress });
    return json({ bootstrapped: true, pts: body.pts });
  }

  private async start(request: Request): Promise<Response> {
    await this.progress();
    const body = await request.json().catch(() => ({})) as { intervalMs?: number; limit?: number };
    const current = await this.loop();
    const loop: Loop = {
      ...current,
      enabled: true,
      intervalMs: clampInteger(body.intervalMs, current.intervalMs, 60_000, 60 * 60_000),
      limit: clampInteger(body.limit, current.limit, 1, 100),
    };
    await this.ctx.storage.put('loop', loop);
    await this.ctx.storage.setAlarm(Date.now() + 1_000);
    return json(loop);
  }

  private async saveProgress(patch: Partial<Progress>): Promise<void> {
    await this.ctx.storage.put('progress', { ...(await this.progress()), ...patch });
  }

  private async loop(): Promise<Loop> {
    return (await this.ctx.storage.get<Loop>('loop')) ?? defaultLoop;
  }

  private async progress(): Promise<Progress> {
    const progress = await this.ctx.storage.get<Progress>('progress');
    if (!progress) throw new Error('not bootstrapped');
    return progress;
  }

  private async status(): Promise<Record<string, unknown>> {
    const [progress, loop, alarm] = await Promise.all([this.progress(), this.loop(), this.ctx.storage.getAlarm()]);
    return {
      pts: progress.pts,
      initialized: progress.initialized,
      bootstrapSecretPresent: Boolean(this.env.MT_SESSION),
      nextAlarmAt: alarm ? new Date(alarm).toISOString() : null,
      loop,
    };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.headers.get('authorization') !== `Bearer ${env.ADMIN_SECRET}`) return json({ error: 'not_found' }, 404);
    const url = new URL(request.url);
    const stub = env.WATCHER.getByName(objectName);
    return stub.fetch(new Request(`https://watcher.internal${url.pathname}${url.search}`, request));
  },
} satisfies ExportedHandler<Env>;

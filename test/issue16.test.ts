import { createRequire } from 'node:module';
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite');
import { readFileSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import rooms from '../src/api/rooms';
import account from '../src/api/account';
import federation from '../src/api/federation';
import rtc from '../src/api/rtc';
import login from '../src/api/login';
import { hashPassword, hashToken } from '../src/utils/crypto';

// Execute production SQL against SQLite; only the D1/KV transport is substituted.
// Requires Node 22.13+ (node:sqlite).
let sql: InstanceType<typeof DatabaseSync>;
let env: any;
let app: Hono<any>;
const userId = '@alice:example.test';
const roomId = '!room:example.test';
const auth = { Authorization: 'Bearer test-session' };

class TestStatement {
  args: any[] = [];
  constructor(private query: string) {}
  bind(...args: any[]) { this.args = args; return this; }
  async first(column?: string) {
    const row = sql.prepare(this.query).get(...this.args);
    return row ? (column ? row[column] : row) : null;
  }
  async all() { return { results: sql.prepare(this.query).all(...this.args), success: true }; }
  async run() { return { meta: sql.prepare(this.query).run(...this.args), success: true }; }
}

beforeEach(async () => {
  sql = new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('../migrations/schema.sql', import.meta.url), 'utf8'));
  const values = new Map<string, string>();
  const cache = {
    async get(key: string, type?: string) {
      const value = values.get(key);
      return value === undefined ? null : type === 'json' ? JSON.parse(value) : value;
    },
    async put(key: string, value: string) { values.set(key, value); },
    async delete(key: string) { values.delete(key); },
  };
  env = {
    SERVER_NAME: 'example.test',
    DB: { prepare: (query: string) => new TestStatement(query) },
    CACHE: cache,
    SESSIONS: { ...cache, get: async () => null },
    LIVEKIT_URL: 'wss://sfu.example.test',
    LIVEKIT_API_KEY: 'test-key',
    LIVEKIT_API_SECRET: 'test-secret',
  };
  sql.prepare('INSERT INTO users (user_id, localpart, password_hash) VALUES (?, ?, ?)')
    .run(userId, 'alice', await hashPassword('test-password'));
  sql.prepare('INSERT INTO devices (user_id, device_id, created_at) VALUES (?, ?, ?)')
    .run(userId, 'DEVICE', Date.now());
  sql.prepare('INSERT INTO access_tokens (token_id, token_hash, user_id, device_id, created_at) VALUES (?, ?, ?, ?, ?)')
    .run('session', await hashToken('test-session'), userId, 'DEVICE', Date.now());
  sql.prepare('INSERT INTO rooms (room_id, room_version, creator_id) VALUES (?, ?, ?)')
    .run(roomId, '10', userId);
  sql.prepare('INSERT INTO room_memberships (room_id, user_id, membership, event_id) VALUES (?, ?, ?, ?)')
    .run(roomId, userId, 'join', '$join');
  app = new Hono();
  app.route('/', login);
  app.route('/', rooms);
  app.route('/', account);
  app.route('/', rtc);
  app.route('/', federation);
});

afterEach(() => sql.close());

async function issueToken() {
  const response = await app.request(`/_matrix/client/v3/user/${encodeURIComponent(userId)}/openid/request_token`, {
    method: 'POST', headers: auth, body: '{}',
  }, env);
  expect(response.status).toBe(200);
  return response.json();
}

function call(body: unknown, path = '/livekit/get_token/sfu/get') {
  return app.request(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, env);
}

function decodeAndVerifyJwt(jwt: string) {
  const [header, payload, signature] = jwt.split('.');
  expect(signature).toBe(createHmac('sha256', env.LIVEKIT_API_SECRET).update(`${header}.${payload}`).digest('base64url'));
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

const rtcHash = (parts: string[]) => createHash('sha256').update(JSON.stringify(parts)).digest('base64').replace(/=+$/, '');

describe('event context (#16)', () => {
  function event(id: string, time: number, type: string, content: unknown, stateKey: string | null = null) {
    sql.prepare(`INSERT INTO events
      (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, depth, auth_events, prev_events, stream_ordering)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?)`)
      .run(id, roomId, userId, type, stateKey, JSON.stringify(content), time, time, time);
  }

  it('formats the parsed target and raw neighboring events without double parsing', async () => {
    event('$before', 1, 'm.room.message', { body: 'before' });
    event('$target', 2, 'm.room.encrypted', { algorithm: 'm.megolm.v1.aes-sha2', ciphertext: 'encrypted-media' });
    event('$after', 3, 'm.room.message', { body: 'after' });
    event('$state', 0, 'm.room.name', { name: 'Test room' }, '');
    sql.prepare('INSERT INTO room_state (room_id, event_type, state_key, event_id) VALUES (?, ?, ?, ?)')
      .run(roomId, 'm.room.name', '', '$state');
    const response = await app.request(`/_matrix/client/v3/rooms/${roomId}/context/$target?limit=2`, { headers: auth }, env);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.event).toMatchObject({ event_id: '$target', type: 'm.room.encrypted', content: { ciphertext: 'encrypted-media' } });
    expect(body.events_before.map((e: any) => e.event_id)).toEqual(['$before']);
    expect(body.events_after[0]).toMatchObject({ type: 'm.room.message', content: { body: 'after' } });
    expect(body.state[0]).toMatchObject({ type: 'm.room.name', state_key: '', content: { name: 'Test room' } });
  });

  it('does not return event context to non-members or for a different room', async () => {
    event('$target', 2, 'm.room.encrypted', { ciphertext: 'secret' });
    const path = `/_matrix/client/v3/rooms/${roomId}/context/$target`;
    expect((await app.request(path, {}, env)).status).toBe(401);
    sql.prepare('UPDATE room_memberships SET membership = ?').run('leave');
    expect((await app.request(path, { headers: auth }, env)).status).toBe(403);
    sql.prepare('UPDATE room_memberships SET membership = ?').run('join');
    sql.prepare('INSERT INTO rooms (room_id, room_version) VALUES (?, ?)').run('!other:example.test', '10');
    sql.prepare('UPDATE events SET room_id = ?').run('!other:example.test');
    expect((await app.request(path, { headers: auth }, env)).status).toBe(404);
  });
});

describe('OpenID round trip', () => {
  it('validates an issued token without X-Matrix authentication', async () => {
    const token = await issueToken();
    const response = await app.request(`/_matrix/federation/v1/openid/userinfo?access_token=${token.access_token}`, {}, env);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toEqual({ sub: userId });
    const stored = await env.CACHE.get(`openid_token:${token.access_token}`, 'json');
    expect(stored.device_id).toBe('DEVICE');
  });

  it('rejects invalid/expired tokens while other federation routes still require signatures', async () => {
    const token = await issueToken();
    await env.CACHE.put(`openid_token:${token.access_token}`, JSON.stringify({ user_id: userId, expires_at: Date.now() - 1 }));
    for (const value of ['unknown', token.access_token, 'test-session']) {
      expect((await app.request(`/_matrix/federation/v1/openid/userinfo?access_token=${value}`, {}, env)).status).toBe(401);
    }
    expect((await app.request('/_matrix/federation/v1/openid/userinfo', {}, env)).status).toBe(400);
    expect((await app.request('/_matrix/federation/v1/event/$target', {}, env)).status).toBe(401);
  });
});

describe('MatrixRTC token exchange', () => {
  it.each(['/livekit/get_token', '/livekit/get_token/sfu/get'])('accepts OpenID body auth on %s and uses the legacy user:device identity', async (path) => {
    const token = await issueToken();
    const response = await call({ room: roomId, device_id: 'DEVICE', openid_token: token }, path);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.url).toBe(env.LIVEKIT_URL);
    const claims = decodeAndVerifyJwt(body.jwt);
    expect(claims.sub).toBe(`${userId}:DEVICE`);
    expect(claims.video).toMatchObject({ roomJoin: true, room: rtcHash([roomId, 'm.call#ROOM']) });
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(body.jwt).not.toContain(token.access_token);
  });

  it('uses the member-based identity and slot-specific room alias for newer clients', async () => {
    const token = await issueToken();
    const response = await call({
      room_id: roomId, slot_id: 'm.call#ROOM', openid_token: token,
      member: { id: 'member-1', claimed_user_id: userId, claimed_device_id: 'DEVICE' },
    }, '/livekit/get_token/get_token');
    expect(response.status).toBe(200);
    const claims = decodeAndVerifyJwt((await response.json()).jwt);
    expect(claims.sub).toBe(rtcHash([userId, 'DEVICE', 'member-1']));
    expect(claims.video.room).toBe(rtcHash([roomId, 'm.call#ROOM']));
  });

  it.each(['unknown', 'expired', 'foreign', 'malformed-record'])('rejects %s OpenID credentials', async (kind) => {
    const token = await issueToken();
    if (kind === 'unknown') token.access_token = 'invented';
    if (kind === 'foreign') token.matrix_server_name = 'remote.invalid';
    if (kind === 'expired') await env.CACHE.put(`openid_token:${token.access_token}`, JSON.stringify({ user_id: userId, expires_at: Date.now() - 1 }));
    if (kind === 'malformed-record') await env.CACHE.put(`openid_token:${token.access_token}`, JSON.stringify({ user_id: userId }));
    const response = await call({ room: roomId, device_id: 'DEVICE', openid_token: token });
    expect(response.status).toBe(401);
    expect(await response.json()).not.toHaveProperty('jwt');
  });

  it.each(['leave', 'invite', 'ban'])('rejects a user with %s membership', async (membership) => {
    const token = await issueToken();
    sql.prepare('UPDATE room_memberships SET membership = ?').run(membership);
    expect((await call({ room: roomId, device_id: 'DEVICE', openid_token: token })).status).toBe(403);
  });

  it('rejects impersonation, mismatched devices, removed devices and deactivated users', async () => {
    const token = await issueToken();
    expect((await call({ room_id: roomId, slot_id: 'm.call#ROOM', openid_token: token,
      member: { id: '1', claimed_user_id: '@bob:example.test', claimed_device_id: 'DEVICE' },
    })).status).toBe(403);
    expect((await call({ room: roomId, device_id: 'OTHER', openid_token: token })).status).toBe(403);
    sql.prepare('UPDATE users SET is_deactivated = 1').run();
    expect((await call({ room: roomId, device_id: 'DEVICE', openid_token: token })).status).toBe(403);
    sql.prepare('UPDATE users SET is_deactivated = 0').run();
    sql.prepare('DELETE FROM devices').run();
    expect((await call({ room: roomId, device_id: 'DEVICE', openid_token: token })).status).toBe(403);
  });

  it.each([null, [], {}, { room: 1 }, { room: roomId, openid_token: 'invalid' }])('rejects malformed body %j', async (body) => {
    expect((await call(body)).status).toBe(400);
  });

  it('supports endpoint probes and refuses to mint tokens without SFU configuration', async () => {
    expect((await app.request('/livekit/get_token/sfu/get', {}, env)).status).toBe(405);
    expect((await app.request('/livekit/get_token/sfu/get', { method: 'OPTIONS' }, env)).status).toBe(204);
    delete env.LIVEKIT_API_SECRET;
    expect((await call({})).status).toBe(503);
  });
});

it('accepts the standard password login used by Matrix clients', async () => {
  const response = await app.request('/_matrix/client/v3/login', {
    method: 'POST', body: JSON.stringify({ type: 'm.login.password', identifier: { type: 'm.id.user', user: 'alice' }, password: 'test-password' }),
  }, env);
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ user_id: userId });
});

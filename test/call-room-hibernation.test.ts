import { describe, it, expect } from 'vitest';
import { CallRoomDurableObject } from '../src/durable-objects/call-room';
import type { Env } from '../src/types';

// Minimal stand-ins for the pieces of the DO runtime the hibernation path touches.
// Storage structured-clones values like real DO storage, so a Map smuggled into a
// stored participant would be caught by the round-trip assertions below.

class FakeStorage {
  map = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }

  async put(key: string, value: unknown): Promise<void> {
    this.map.set(key, structuredClone(value));
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  async deleteAll(): Promise<void> {
    this.map.clear();
  }

  async list<T>(options: { prefix: string }): Promise<Map<string, T>> {
    const out = new Map<string, T>();
    for (const [k, v] of [...this.map.entries()].sort()) {
      if (k.startsWith(options.prefix)) out.set(k, v as T);
    }
    return out;
  }
}

class FakeWebSocket {
  attachment: unknown = null;
  sent: string[] = [];
  closed: { code: number; reason: string } | null = null;

  serializeAttachment(value: unknown): void {
    this.attachment = structuredClone(value);
  }

  deserializeAttachment(): unknown {
    return this.attachment;
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(code: number, reason: string): void {
    this.closed = { code, reason };
  }
}

class FakeState {
  storage = new FakeStorage();
  sockets: FakeWebSocket[] = [];

  getWebSockets(): FakeWebSocket[] {
    return this.sockets;
  }

  acceptWebSocket(ws: FakeWebSocket): void {
    this.sockets.push(ws);
  }

  setWebSocketAutoResponse(): void {}

  blockConcurrencyWhile(cb: () => Promise<void>): Promise<void> {
    return cb();
  }
}

function makeRoom(state: FakeState): CallRoomDurableObject {
  return new CallRoomDurableObject(
    state as unknown as DurableObjectState,
    {} as Env
  );
}

// Storage-shaped participant; track-free variants avoid the SFU cleanup network path.
function storedParticipant(userId: string, deviceId: string, tracks: Record<string, object> = {}) {
  return {
    oderId: userId,
    deviceId,
    sessionId: `session-${userId}`,
    tracks,
    joinedAt: 1752900000000,
  };
}

const TRACK = { mid: '0', kind: 'audio', enabled: true };

describe('CallRoom hibernation: participant persistence', () => {
  it('persistParticipant stores a JSON-safe snapshot with tracks as a plain record', async () => {
    const state = new FakeState();
    const room = makeRoom(state) as any;

    await room.persistParticipant('u1|d1', {
      oderId: 'u1',
      deviceId: 'd1',
      sessionId: 'session-u1',
      tracks: new Map([['audio0', TRACK]]),
      joinedAt: 1752900000000,
    });

    const raw = state.storage.map.get('participant:u1|d1') as any;
    expect(raw.tracks instanceof Map).toBe(false);
    expect(raw.tracks.audio0).toEqual(TRACK);
    // Snapshot must survive serialization untouched
    expect(JSON.parse(JSON.stringify(raw))).toEqual(raw);
  });

  it('loadParticipants rehydrates the in-memory map after simulated eviction', async () => {
    const state = new FakeState();
    const writer = makeRoom(state) as any;
    await writer.persistParticipant('u1|d1', {
      oderId: 'u1',
      deviceId: 'd1',
      sessionId: 'session-u1',
      tracks: new Map([['audio0', TRACK]]),
      joinedAt: 1752900000000,
    });

    // "Eviction": a brand-new instance over the same storage
    const revived = makeRoom(state) as any;
    await revived.loadParticipants();

    expect(revived.participants.size).toBe(1);
    const p = revived.participants.get('u1|d1');
    expect(p.tracks instanceof Map).toBe(true);
    expect(p.tracks.get('audio0')).toEqual(TRACK);
    expect(p.sessionId).toBe('session-u1');
  });
});

describe('CallRoom hibernation: socket identity via attachments', () => {
  it('getParticipantBySocket resolves through the serialized attachment after rehydration', async () => {
    const state = new FakeState();
    await state.storage.put('participant:u1|d1', storedParticipant('u1', 'd1'));

    const ws = new FakeWebSocket();
    ws.serializeAttachment({ participantKey: 'u1|d1' });

    const room = makeRoom(state) as any;
    await room.loadParticipants();

    expect(room.getParticipantBySocket(ws)?.deviceId).toBe('d1');
    expect(room.getParticipantBySocket(new FakeWebSocket())).toBeNull();
  });

  it('broadcast reaches only attached sockets of live participants, honoring excludeKey', async () => {
    const state = new FakeState();
    await state.storage.put('participant:u1|d1', storedParticipant('u1', 'd1'));
    await state.storage.put('participant:u2|d2', storedParticipant('u2', 'd2'));

    const wsA = new FakeWebSocket();
    wsA.serializeAttachment({ participantKey: 'u1|d1' });
    const wsB = new FakeWebSocket();
    wsB.serializeAttachment({ participantKey: 'u2|d2' });
    const wsGhost = new FakeWebSocket(); // attachment points at a participant no longer stored
    wsGhost.serializeAttachment({ participantKey: 'u9|d9' });
    const wsBare = new FakeWebSocket(); // never went through join
    state.sockets = [wsA, wsB, wsGhost, wsBare];

    const room = makeRoom(state) as any;
    await room.loadParticipants();
    room.broadcast({ type: 'test' }, 'u1|d1');

    expect(wsA.sent).toHaveLength(0);
    expect(wsB.sent).toHaveLength(1);
    expect(JSON.parse(wsB.sent[0]).type).toBe('test');
    expect(wsGhost.sent).toHaveLength(0);
    expect(wsBare.sent).toHaveLength(0);
  });
});

describe('CallRoom hibernation: leave and close cleanup', () => {
  async function seedTwoParticipantRoom() {
    const state = new FakeState();
    await state.storage.put('participant:u1|d1', storedParticipant('u1', 'd1'));
    await state.storage.put('participant:u2|d2', storedParticipant('u2', 'd2'));
    const wsA = new FakeWebSocket();
    wsA.serializeAttachment({ participantKey: 'u1|d1' });
    const wsB = new FakeWebSocket();
    wsB.serializeAttachment({ participantKey: 'u2|d2' });
    state.sockets = [wsA, wsB];
    return { state, wsA, wsB, room: makeRoom(state) as any };
  }

  it('handleLeave removes the participant from memory and storage and notifies peers', async () => {
    const { state, wsA, wsB, room } = await seedTwoParticipantRoom();

    await room.handleLeave(wsA);

    expect(state.storage.map.has('participant:u1|d1')).toBe(false);
    expect(state.storage.map.has('participant:u2|d2')).toBe(true);
    expect(room.participants.size).toBe(1);
    expect(wsA.closed?.code).toBe(1000);
    const left = wsB.sent.map(s => JSON.parse(s)).find(m => m.type === 'participant_left');
    expect(left?.oderId).toBe('u1');
  });

  it('webSocketClose (ungraceful disconnect) triggers the same cleanup', async () => {
    const { state, wsA, room } = await seedTwoParticipantRoom();

    await room.webSocketClose(wsA, 1005, '');

    expect(state.storage.map.has('participant:u1|d1')).toBe(false);
    expect(room.participants.size).toBe(1);
  });

  it('handleEndCall closes every attached socket and wipes storage', async () => {
    const { state, wsA, wsB, room } = await seedTwoParticipantRoom();
    await state.storage.put('callId', 'call-1');

    const res = await room.handleEndCall();

    expect(res.status).toBe(200);
    expect(wsA.closed?.code).toBe(1000);
    expect(wsB.closed?.code).toBe(1000);
    expect(state.storage.map.size).toBe(0);
    expect(room.participants.size).toBe(0);
  });
});

describe('CallRoom hibernation: state endpoint', () => {
  it('handleGetState reflects storage-rehydrated participants', async () => {
    const state = new FakeState();
    await state.storage.put('callId', 'call-1');
    await state.storage.put('participant:u1|d1', storedParticipant('u1', 'd1', { audio0: TRACK }));
    await state.storage.put('participant:u2|d2', storedParticipant('u2', 'd2'));

    const room = makeRoom(state) as any;
    const res = await room.handleGetState();
    const body = await res.json();

    expect(body.callId).toBe('call-1');
    expect(body.participants).toHaveLength(2);
    const u1 = body.participants.find((p: any) => p.oderId === 'u1');
    expect(u1.tracks).toEqual([{ trackName: 'audio0', kind: 'audio', enabled: true }]);
  });
});

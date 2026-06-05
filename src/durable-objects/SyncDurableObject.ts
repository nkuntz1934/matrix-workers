// Sync Durable Object for user-specific sync state
// Handles both WebSocket-based traditional sync and HTTP-based sliding sync

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface SyncSession {
  userId: string;
  deviceId: string | null;
  lastSyncToken: string;
}

interface PendingEvent {
  event_id: string;
  room_id: string;
  type: string;
  timestamp: number;
}

// Sliding sync connection state (stored in DO storage, not KV)
interface SlidingSyncConnectionState {
  pos: number;
  lastAccess: number;
  roomStates: Record<string, {
    lastStreamOrdering: number;
    sentState: boolean;
  }>;
  listStates: Record<string, {
    roomIds: string[];
    count: number;
  }>;
  roomNotificationCounts?: Record<string, number>;
  roomFullyReadMarkers?: Record<string, string>;
  initialSyncComplete?: boolean;
  lastDeviceKeyChangePos?: number;
  deviceKeyPosBySyncPos?: Record<string, number>;
  roomSentAsRead?: Record<string, boolean>;
}

export class SyncDurableObject extends DurableObject<Env> {
  private sessions: Map<WebSocket, SyncSession> = new Map();
  private pendingEvents: PendingEvent[] = [];
  // In-memory cache for sliding sync state (persisted to storage on save)
  private slidingSyncStates: Map<string, SlidingSyncConnectionState> = new Map();
  // Waiting resolvers for long-polling requests
  private waitingResolvers: Array<(hasEvents: boolean) => void> = [];

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/websocket') {
      return this.handleWebSocket(request);
    }

    if (path === '/notify') {
      return this.handleNotify(request);
    }

    if (path === '/pending') {
      return this.handlePending(request);
    }

    // Sliding sync connection state endpoints
    if (path === '/sliding-sync/state') {
      if (request.method === 'GET') {
        return this.getSlidingSyncState(request);
      } else if (request.method === 'PUT') {
        return this.saveSlidingSyncState(request);
      }
    }

    // Wait for events endpoint (for long-polling)
    if (path === '/wait-for-events') {
      return this.handleWaitForEvents(request);
    }

    return new Response('Not found', { status: 404 });
  }

  // Get sliding sync connection state for a user/connection
  private async getSlidingSyncState(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const connId = url.searchParams.get('conn_id');

    if (!connId) {
      return new Response(JSON.stringify({ error: 'Missing conn_id' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const key = `sliding_sync:${connId}`;

    // Check in-memory cache first
    let state = this.slidingSyncStates.get(key);

    // If not in cache, load from storage
    if (!state) {
      state = await this.ctx.storage.get<SlidingSyncConnectionState>(key);
      if (state) {
        this.slidingSyncStates.set(key, state);
      }
    }

    return new Response(JSON.stringify(state || null), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Save sliding sync connection state
  private async saveSlidingSyncState(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const connId = url.searchParams.get('conn_id');

    if (!connId) {
      return new Response(JSON.stringify({ error: 'Missing conn_id' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      const state = await request.json() as SlidingSyncConnectionState;
      const key = `sliding_sync:${connId}`;

      // Update in-memory cache
      this.slidingSyncStates.set(key, state);

      // Persist to storage (DO storage has no rate limits like KV)
      await this.ctx.storage.put(key, state);

      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      console.error('[SyncDO] Failed to save sliding sync state:', error);
      return new Response(JSON.stringify({ error: 'Failed to save state' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  private async handleWebSocket(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected websocket upgrade', { status: 426 });
    }

    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');
    const deviceId = url.searchParams.get('device_id');
    const since = url.searchParams.get('since');

    if (!userId) {
      return new Response('Missing user_id', { status: 400 });
    }

    // Store userId for this DO instance (used via tags)

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    this.ctx.acceptWebSocket(server, [userId]);

    const session: SyncSession = {
      userId,
      deviceId,
      lastSyncToken: since || '0',
    };

    server.serializeAttachment(session);
    this.sessions.set(server, session);

    // Send any pending events immediately
    const pending = await this.getPendingEvents(parseInt(since || '0'));
    if (pending.length > 0) {
      server.send(JSON.stringify({
        type: 'sync',
        events: pending,
      }));
    }

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private async handleNotify(request: Request): Promise<Response> {
    const data = await request.json() as PendingEvent;
    console.log('[SyncDO] /notify received for event:', data.event_id, 'waiting resolvers:', this.waitingResolvers.length);

    // Store pending event
    const key = `event:${data.event_id}`;
    await this.ctx.storage.put(key, data);

    // Add to in-memory list
    this.pendingEvents.push(data);

    // Notify all connected WebSockets
    const message = JSON.stringify({
      type: 'event',
      event: data,
    });

    const webSockets = this.ctx.getWebSockets();
    for (const ws of webSockets) {
      try {
        ws.send(message);
      } catch (e) {
        // WebSocket may be closed
      }
    }

    // Wake up all waiting long-polling requests
    const numResolvers = this.waitingResolvers.length;
    const resolvers = this.waitingResolvers;
    this.waitingResolvers = [];
    for (const resolve of resolvers) {
      resolve(true);
    }
    if (numResolvers > 0) {
      console.log('[SyncDO] Woke up', numResolvers, 'waiting request(s)');
    }

    return new Response('OK');
  }

  // Wait for events (used by long-polling sliding sync)
  private async handleWaitForEvents(request: Request): Promise<Response> {
    try {
      const body = await request.json() as { timeout?: number; afterTimestamp?: number };
      const requestedTimeout = Number.isFinite(body.timeout) ? body.timeout! : 25000;
      const timeout = Math.min(Math.max(requestedTimeout, 0), 25000); // Cap at 25s
      const afterTimestamp = Number.isFinite(body.afterTimestamp) ? body.afterTimestamp : undefined;

      this.pendingEvents = this.pendingEvents.filter(event => event.timestamp >= Date.now() - 60000);

      if (afterTimestamp !== undefined && this.pendingEvents.some(event => event.timestamp >= afterTimestamp)) {
        console.log('[SyncDO] /wait-for-events found pending event after timestamp:', afterTimestamp);
        return new Response(JSON.stringify({ hasEvents: true }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }

      console.log('[SyncDO] /wait-for-events started, timeout:', timeout, 'current waiters:', this.waitingResolvers.length);

      let myResolver: ((hasEvents: boolean) => void) | null = null;

      // Create a promise that resolves when events arrive or timeout expires
      const eventPromise = new Promise<boolean>((resolve) => {
        myResolver = resolve;
        this.waitingResolvers.push(resolve);
      });

      const timeoutPromise = new Promise<boolean>((resolve) => {
        setTimeout(() => resolve(false), timeout);
      });

      // Wait for either events or timeout
      const hasEvents = await Promise.race([eventPromise, timeoutPromise]);

      // Clean up our resolver from the array if timeout won
      if (!hasEvents && myResolver) {
        const index = this.waitingResolvers.indexOf(myResolver);
        if (index !== -1) {
          this.waitingResolvers.splice(index, 1);
        }
      }

      console.log('[SyncDO] /wait-for-events completed, hasEvents:', hasEvents);

      return new Response(JSON.stringify({ hasEvents }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      console.error('[SyncDO] Error in wait-for-events:', error);
      return new Response(JSON.stringify({ hasEvents: false, error: 'Internal error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  private async handlePending(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const since = parseInt(url.searchParams.get('since') || '0');

    const pending = await this.getPendingEvents(since);

    return new Response(JSON.stringify({ events: pending }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private async getPendingEvents(since: number): Promise<PendingEvent[]> {
    const events: PendingEvent[] = [];
    const allKeys = await this.ctx.storage.list({ prefix: 'event:' });

    for (const [, value] of allKeys) {
      const event = value as PendingEvent;
      if (event.timestamp > since) {
        events.push(event);
      }
    }

    // Sort by timestamp
    events.sort((a, b) => a.timestamp - b.timestamp);

    return events;
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const session = ws.deserializeAttachment() as SyncSession | null;
    if (!session) return;

    try {
      const data = typeof message === 'string' ? JSON.parse(message) : null;
      if (!data) return;

      switch (data.type) {
        case 'ack':
          // Client acknowledged receipt of events up to this token
          session.lastSyncToken = data.token;
          ws.serializeAttachment(session);
          break;

        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;

        default:
          break;
      }
    } catch (e) {
      console.error('Error handling sync message:', e);
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    const session = ws.deserializeAttachment() as SyncSession | null;
    if (session) {
      this.sessions.delete(ws);
    }
    ws.close(code, reason);
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error('Sync WebSocket error:', error);
    const session = ws.deserializeAttachment() as SyncSession | null;
    if (session) {
      this.sessions.delete(ws);
    }
  }

  // Cleanup old events (run periodically via alarm)
  async alarm(): Promise<void> {
    const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago

    const allKeys = await this.ctx.storage.list({ prefix: 'event:' });
    for (const [key, value] of allKeys) {
      const event = value as PendingEvent;
      if (event.timestamp < cutoff) {
        await this.ctx.storage.delete(key);
      }
    }

    // Schedule next cleanup in 1 hour
    await this.ctx.storage.setAlarm(Date.now() + (60 * 60 * 1000));
  }
}

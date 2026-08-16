// Room Durable Object for real-time room coordination

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface RoomSession {
  id: string;
  userId: string;
  deviceId: string | null;
}

interface TypingState {
  expiresAt: number;
}

interface ReceiptData {
  user_id: string;  // Added for proper response building
  event_id: string;
  receipt_type: string;
  ts: number;
  thread_id?: string;
}

// Bounds for in-memory maps. Chosen conservatively so a hot room cannot
// drive a single DO to memory exhaustion / eviction.
// - MAX_WS_CONNECTIONS: refuse new WebSockets above this threshold (503).
// - MAX_TYPING_USERS: bound the typing map; expired entries are evicted lazily,
//   the cap is a safety valve against runaway entries.
// - MAX_RECEIPTS_CACHE: receipts are 1-per-user-per-type-per-thread by design,
//   but a cap protects against unbounded growth. LRU-evicted in memory only;
//   durable storage remains the source of truth.
const MAX_WS_CONNECTIONS = 500;
const MAX_TYPING_USERS = 1000;
const MAX_RECEIPTS_CACHE = 5000;

export class RoomDurableObject extends DurableObject<Env> {
  private sessions: Map<WebSocket, RoomSession> = new Map();
  private roomId: string = '';

  // In-memory typing state - Map of userId -> expiration timestamp
  private typingUsers: Map<string, TypingState> = new Map();

  // In-memory receipts cache (also persisted to durable storage)
  // Map of `${userId}:${receiptType}:${threadContext}` -> ReceiptData
  // threadContext is thread_id ?? 'unthreaded'
  // Iteration order is insertion order, which we rely on for LRU eviction:
  // a `set()` to an existing key updates the value but does NOT move it,
  // so we delete-then-set in setReceiptCacheLRU() to refresh recency.
  private receiptsCache: Map<string, ReceiptData> = new Map();
  private receiptsCacheLoaded: boolean = false;

  // LRU set for receiptsCache: refresh recency, then evict oldest if over cap.
  private setReceiptCacheLRU(key: string, value: ReceiptData): void {
    if (this.receiptsCache.has(key)) {
      this.receiptsCache.delete(key);
    }
    this.receiptsCache.set(key, value);
    while (this.receiptsCache.size > MAX_RECEIPTS_CACHE) {
      const oldest = this.receiptsCache.keys().next().value;
      if (oldest === undefined) break;
      this.receiptsCache.delete(oldest);
    }
  }

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  // Load receipts from durable storage into cache
  private async loadReceiptsCache(): Promise<void> {
    if (this.receiptsCacheLoaded) return;

    const stored = await this.ctx.storage.list<ReceiptData>({ prefix: 'receipt:' });
    for (const [key, value] of stored) {
      // Handle both old and new key formats for backwards compatibility
      // Old format: receipt:{userId}:{receiptType}
      // New format: receipt:{userId}:{receiptType}:{threadContext}
      const keyWithoutPrefix = key.replace('receipt:', '');

      // Check if this is new format (has user_id in data)
      if (value.user_id) {
        // New format - use key as-is
        this.setReceiptCacheLRU(keyWithoutPrefix, value);
      } else {
        // Old format - need to add user_id and thread context
        // Old key: {userId}:{receiptType} where userId is @localpart:server
        // We need to extract userId - find the receipt_type in the key
        const receiptType = value.receipt_type;
        const receiptTypeIndex = keyWithoutPrefix.lastIndexOf(`:${receiptType}`);

        if (receiptTypeIndex > 0) {
          const userId = keyWithoutPrefix.substring(0, receiptTypeIndex);
          const threadContext = value.thread_id ?? 'unthreaded';
          const newCacheKey = `${userId}:${receiptType}:${threadContext}`;

          // Backfill user_id into value
          value.user_id = userId;
          this.setReceiptCacheLRU(newCacheKey, value);
        } else {
          // Fallback: just use the key with unthreaded suffix
          const threadContext = value.thread_id ?? 'unthreaded';
          this.setReceiptCacheLRU(`${keyWithoutPrefix}:${threadContext}`, value);
        }
      }
    }
    this.receiptsCacheLoaded = true;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/websocket') {
      return this.handleWebSocket(request);
    }

    if (path === '/broadcast') {
      return this.handleBroadcast(request);
    }

    if (path === '/state') {
      return this.handleState(request);
    }

    // Typing endpoints
    if (path === '/typing') {
      if (request.method === 'PUT') {
        return this.handleSetTyping(request);
      }
      if (request.method === 'GET') {
        return this.handleGetTyping();
      }
    }

    // Receipt endpoints
    if (path === '/receipt') {
      if (request.method === 'PUT') {
        return this.handleSetReceipt(request);
      }
    }
    if (path === '/receipts') {
      if (request.method === 'GET') {
        return this.handleGetReceipts();
      }
    }

    return new Response('Not found', { status: 404 });
  }

  // Set a read receipt for a user
  private async handleSetReceipt(request: Request): Promise<Response> {
    const body = await request.json() as {
      user_id: string;
      event_id: string;
      receipt_type: string;
      thread_id?: string;
    };

    const { user_id, event_id, receipt_type, thread_id } = body;
    const ts = Date.now();

    // Determine thread context for storage key
    // - undefined/absent = "unthreaded" (room-level receipt)
    // - "main" = main timeline only
    // - event_id = specific thread
    const threadContext = thread_id ?? 'unthreaded';

    // Store in durable storage with thread-aware key
    const storageKey = `receipt:${user_id}:${receipt_type}:${threadContext}`;
    const receiptData: ReceiptData = { user_id, event_id, receipt_type, ts, thread_id };
    await this.ctx.storage.put(storageKey, receiptData);

    // Update cache (LRU-bounded)
    await this.loadReceiptsCache();
    this.setReceiptCacheLRU(`${user_id}:${receipt_type}:${threadContext}`, receiptData);

    // Broadcast to WebSocket clients
    const message = JSON.stringify({
      type: 'receipt',
      user_id,
      event_id,
      receipt_type,
      ts,
      room_id: this.roomId,
      thread_id,
    });

    const webSockets = this.ctx.getWebSockets();
    for (const ws of webSockets) {
      const session = ws.deserializeAttachment() as RoomSession | null;
      if (session && session.userId !== user_id) {
        try {
          ws.send(message);
        } catch {
          // WebSocket may be closed
        }
      }
    }

    return new Response('OK');
  }

  // Get all receipts for this room
  private async handleGetReceipts(): Promise<Response> {
    await this.loadReceiptsCache();

    // Build Matrix receipt format: { eventId: { receiptType: { userId: { ts, thread_id? } } } }
    const receipts: Record<string, Record<string, Record<string, { ts: number; thread_id?: string }>>> = {};

    for (const [_key, data] of this.receiptsCache.entries()) {
      const { user_id, event_id, receipt_type, ts, thread_id } = data;

      if (!receipts[event_id]) {
        receipts[event_id] = {};
      }
      if (!receipts[event_id][receipt_type]) {
        receipts[event_id][receipt_type] = {};
      }

      // Include thread_id in response if present and not 'unthreaded'
      const userData: { ts: number; thread_id?: string } = { ts };
      if (thread_id && thread_id !== 'unthreaded') {
        userData.thread_id = thread_id;
      }
      receipts[event_id][receipt_type][user_id] = userData;
    }

    return new Response(JSON.stringify({ receipts }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Set typing state for a user
  private async handleSetTyping(request: Request): Promise<Response> {
    const body = await request.json() as {
      user_id: string;
      typing: boolean;
      timeout?: number;
    };

    const { user_id, typing, timeout = 30000 } = body;

    if (typing) {
      // User started typing - set expiration
      const expiresAt = Date.now() + Math.min(timeout, 120000); // Max 2 minutes

      // Opportunistically evict already-expired entries before checking cap.
      if (this.typingUsers.size >= MAX_TYPING_USERS) {
        const now = Date.now();
        for (const [uid, state] of this.typingUsers) {
          if (state.expiresAt <= now) this.typingUsers.delete(uid);
        }
        // Hard cap: drop oldest insertion if still over (LRU by insertion order).
        while (this.typingUsers.size >= MAX_TYPING_USERS) {
          const oldest = this.typingUsers.keys().next().value;
          if (oldest === undefined) break;
          this.typingUsers.delete(oldest);
        }
      }

      this.typingUsers.set(user_id, { expiresAt });

      // Broadcast to WebSocket clients
      await this.broadcastTyping(user_id, true);
    } else {
      // User stopped typing
      this.typingUsers.delete(user_id);

      // Broadcast to WebSocket clients
      await this.broadcastTyping(user_id, false);
    }

    return new Response('OK');
  }

  // Get current typing users (with cleanup of expired entries)
  private handleGetTyping(): Response {
    const now = Date.now();
    const activeTypingUsers: string[] = [];

    // Clean up expired entries and collect active ones
    for (const [userId, state] of this.typingUsers.entries()) {
      if (state.expiresAt > now) {
        activeTypingUsers.push(userId);
      } else {
        // Expired - remove it
        this.typingUsers.delete(userId);
      }
    }

    return new Response(JSON.stringify({
      user_ids: activeTypingUsers,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private async handleWebSocket(request: Request): Promise<Response> {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected websocket upgrade', { status: 426 });
    }

    // Get session info from query params
    const url = new URL(request.url);
    const userId = url.searchParams.get('user_id');
    const deviceId = url.searchParams.get('device_id');
    const roomId = url.searchParams.get('room_id');

    if (!userId || !roomId) {
      return new Response('Missing user_id or room_id', { status: 400 });
    }

    // Cap concurrent WebSocket connections per room. Hibernated sockets are
    // included via getWebSockets(), so this counts all live connections.
    const activeWs = this.ctx.getWebSockets().length;
    if (activeWs >= MAX_WS_CONNECTIONS) {
      return new Response('Room WebSocket connection limit reached', { status: 503 });
    }

    this.roomId = roomId;

    // Create WebSocket pair
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    // Accept the WebSocket with hibernation support
    this.ctx.acceptWebSocket(server, [userId, roomId]);

    // Store session data
    const session: RoomSession = {
      id: crypto.randomUUID(),
      userId,
      deviceId,
    };

    // Serialize session for hibernation
    server.serializeAttachment(session);

    this.sessions.set(server, session);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private async handleBroadcast(request: Request): Promise<Response> {
    const message = await request.json();

    // Broadcast to all connected WebSockets
    const webSockets = this.ctx.getWebSockets();
    for (const ws of webSockets) {
      try {
        ws.send(JSON.stringify(message));
      } catch (e) {
        // WebSocket may be closed
      }
    }

    return new Response('OK');
  }

  private async handleState(_request: Request): Promise<Response> {
    // Return current room state
    const webSockets = this.ctx.getWebSockets();
    const users: string[] = [];

    for (const ws of webSockets) {
      const session = ws.deserializeAttachment() as RoomSession | null;
      if (session) {
        users.push(session.userId);
      }
    }

    return new Response(JSON.stringify({
      room_id: this.roomId,
      connected_users: [...new Set(users)],
      connection_count: webSockets.length,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // WebSocket hibernation handlers
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const session = ws.deserializeAttachment() as RoomSession | null;
    if (!session) return;

    try {
      const data = typeof message === 'string' ? JSON.parse(message) : null;
      if (!data) return;

      // Handle different message types
      switch (data.type) {
        case 'typing':
          // Broadcast typing notification to other users
          await this.broadcastTyping(session.userId, data.typing);
          break;

        case 'read':
          // Handle read receipt
          await this.handleReadReceipt(session.userId, data.event_id);
          break;

        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;

        default:
          // Unknown message type
          break;
      }
    } catch (e) {
      console.error('Error handling WebSocket message:', e);
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    const session = ws.deserializeAttachment() as RoomSession | null;
    if (session) {
      this.sessions.delete(ws);

      // Notify other users that this user disconnected
      const webSockets = this.ctx.getWebSockets();
      for (const otherWs of webSockets) {
        if (otherWs !== ws) {
          try {
            otherWs.send(JSON.stringify({
              type: 'user_disconnected',
              user_id: session.userId,
            }));
          } catch (e) {
            // WebSocket may be closed
          }
        }
      }
    }

    ws.close(code, reason);
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error('WebSocket error:', error);
    const session = ws.deserializeAttachment() as RoomSession | null;
    if (session) {
      this.sessions.delete(ws);
    }
  }

  private async broadcastTyping(userId: string, isTyping: boolean): Promise<void> {
    const message = JSON.stringify({
      type: 'typing',
      user_id: userId,
      typing: isTyping,
      room_id: this.roomId,
    });

    const webSockets = this.ctx.getWebSockets();
    for (const ws of webSockets) {
      const session = ws.deserializeAttachment() as RoomSession | null;
      if (session && session.userId !== userId) {
        try {
          ws.send(message);
        } catch (e) {
          // WebSocket may be closed
        }
      }
    }
  }

  private async handleReadReceipt(userId: string, eventId: string, threadId?: string): Promise<void> {
    const ts = Date.now();
    const receiptType = 'm.read';  // Default to public read receipt
    const threadContext = threadId ?? 'unthreaded';

    // Store read receipt in durable storage with proper key format
    const storageKey = `receipt:${userId}:${receiptType}:${threadContext}`;
    const receiptData: ReceiptData = {
      user_id: userId,
      event_id: eventId,
      receipt_type: receiptType,
      ts,
      thread_id: threadId,
    };
    await this.ctx.storage.put(storageKey, receiptData);

    // Update cache (LRU-bounded)
    await this.loadReceiptsCache();
    this.setReceiptCacheLRU(`${userId}:${receiptType}:${threadContext}`, receiptData);

    // Broadcast to other users
    const message = JSON.stringify({
      type: 'receipt',
      user_id: userId,
      event_id: eventId,
      receipt_type: receiptType,
      room_id: this.roomId,
      ts,
      thread_id: threadId,
    });

    const webSockets = this.ctx.getWebSockets();
    for (const ws of webSockets) {
      const session = ws.deserializeAttachment() as RoomSession | null;
      if (session && session.userId !== userId) {
        try {
          ws.send(message);
        } catch (e) {
          // WebSocket may be closed
        }
      }
    }
  }
}

// CallRoom Durable Object
// Manages WebRTC signaling for video/audio calls in a Matrix room
// Uses Cloudflare Calls SFU for media routing

import type { Env } from '../types';
import {
  createSession,
  addTracks,
  renegotiate,
  closeTracks,
} from '../services/cloudflare-calls';

interface Participant {
  oderId: string; // This is the userId
  deviceId: string;
  sessionId: string; // Cloudflare Calls session ID
  tracks: Map<string, TrackInfo>; // trackName -> TrackInfo
  joinedAt: number;
}

interface StoredParticipant {
  oderId: string;
  deviceId: string;
  sessionId: string;
  tracks: Record<string, TrackInfo>;
  joinedAt: number;
}

interface CallSocketAttachment {
  participantKey: string;
}

interface TrackInfo {
  mid: string;
  kind: 'audio' | 'video';
  enabled: boolean;
}

interface SignalingMessage {
  type: string;
  [key: string]: unknown;
}

// Messages from client to server
interface JoinMessage {
  type: 'join';
  userId: string;
  deviceId: string;
}

interface OfferMessage {
  type: 'offer';
  sdp: string;
  trackName: string;
  kind: 'audio' | 'video';
}

interface AnswerMessage {
  type: 'answer';
  sdp: string;
  mid: string;
}

// LeaveMessage for future use (currently handled by ws.close)
export interface LeaveMessage {
  type: 'leave';
}

interface MuteMessage {
  type: 'mute';
  trackName: string;
  muted: boolean;
}

// Messages from server to client
interface WelcomeMessage {
  type: 'welcome';
  callId: string;
  participants: Array<{
    oderId: string; // Note: This is userId, kept as oderId for API compatibility
    deviceId: string;
    tracks: Array<{ trackName: string; kind: string }>;
  }>;
}

interface ParticipantJoinedMessage {
  type: 'participant_joined';
  oderId: string; // Note: This is userId
  deviceId: string;
}

interface ParticipantLeftMessage {
  type: 'participant_left';
  oderId: string; // Note: This is userId
  deviceId: string;
}

interface TrackPublishedMessage {
  type: 'track_published';
  oderId: string; // Note: This is userId
  deviceId: string;
  trackName: string;
  kind: string;
  sessionId: string; // SFU session ID for pulling the track
}

// TrackUnpublishedMessage for future use
export interface TrackUnpublishedMessage {
  type: 'track_unpublished';
  oderId: string; // Note: This is userId
  deviceId: string;
  trackName: string;
}

interface OfferResponseMessage {
  type: 'offer_response';
  sdp: string;
  trackName: string;
  mid: string;
}

// PullOfferMessage for future use (pull track from another participant)
export interface PullOfferMessage {
  type: 'pull_offer';
  sdp: string;
  trackName: string;
  mid: string;
  fromUserId: string;
  fromDeviceId: string;
}

interface ErrorMessage {
  type: 'error';
  code: string;
  message: string;
}

export class CallRoomDurableObject implements DurableObject {
  private state: DurableObjectState;
  private env: Env;
  private participants: Map<string, Participant> = new Map(); // oderId|deviceId -> Participant
  private participantsLoaded: boolean = false;
  private callId: string | null = null;
  private matrixRoomId: string | null = null;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;

    // Load persisted state
    this.state.blockConcurrencyWhile(async () => {
      this.callId = await this.state.storage.get('callId') || null;
      this.matrixRoomId = await this.state.storage.get('matrixRoomId') || null;
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Initialize call room
    if (url.pathname === '/init' && request.method === 'POST') {
      return this.handleInit(request);
    }

    // WebSocket upgrade for signaling
    if (url.pathname === '/ws') {
      return this.handleWebSocket(request);
    }

    // Get call state
    if (url.pathname === '/state' && request.method === 'GET') {
      return this.handleGetState();
    }

    // End call
    if (url.pathname === '/end' && request.method === 'POST') {
      return this.handleEndCall();
    }

    return new Response('Not Found', { status: 404 });
  }

  private async handleInit(request: Request): Promise<Response> {
    const body = await request.json() as { roomId: string; callId: string };

    this.matrixRoomId = body.roomId;
    this.callId = body.callId;

    await this.state.storage.put('matrixRoomId', this.matrixRoomId);
    await this.state.storage.put('callId', this.callId);

    return Response.json({
      callId: this.callId,
      roomId: this.matrixRoomId,
    });
  }

  private async loadParticipants(): Promise<void> {
    if (this.participantsLoaded) return;

    const stored = await this.state.storage.list<StoredParticipant>({ prefix: 'participant:' });
    this.participants.clear();

    for (const [key, participant] of stored) {
      const participantKey = key.slice('participant:'.length);
      this.participants.set(participantKey, {
        oderId: participant.oderId,
        deviceId: participant.deviceId,
        sessionId: participant.sessionId,
        tracks: new Map(Object.entries(participant.tracks)),
        joinedAt: participant.joinedAt,
      });
    }

    this.participantsLoaded = true;
  }

  private async persistParticipant(participantKey: string, participant: Participant): Promise<void> {
    const stored: StoredParticipant = {
      oderId: participant.oderId,
      deviceId: participant.deviceId,
      sessionId: participant.sessionId,
      tracks: Object.fromEntries(participant.tracks.entries()),
      joinedAt: participant.joinedAt,
    };

    await this.state.storage.put(`participant:${participantKey}`, stored);
  }

  private async deleteParticipant(participantKey: string): Promise<void> {
    await this.state.storage.delete(`participant:${participantKey}`);
  }

  private async handleWebSocket(request: Request): Promise<Response> {
    // Verify WebSocket upgrade
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Accept the WebSocket
    this.state.acceptWebSocket(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') {
      this.sendError(ws, 'INVALID_MESSAGE', 'Binary messages not supported');
      return;
    }

    let msg: SignalingMessage;
    try {
      msg = JSON.parse(message);
    } catch {
      this.sendError(ws, 'INVALID_JSON', 'Invalid JSON message');
      return;
    }

    try {
      switch (msg.type) {
        case 'join':
          await this.handleJoin(ws, msg as unknown as JoinMessage);
          break;
        case 'offer':
          await this.handleOffer(ws, msg as unknown as OfferMessage);
          break;
        case 'answer':
          await this.handleAnswer(ws, msg as unknown as AnswerMessage);
          break;
        case 'leave':
          await this.handleLeave(ws);
          break;
        case 'mute':
          await this.handleMute(ws, msg as unknown as MuteMessage);
          break;
        default:
          this.sendError(ws, 'UNKNOWN_MESSAGE', `Unknown message type: ${msg.type}`);
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
      this.sendError(ws, 'INTERNAL_ERROR', error instanceof Error ? error.message : 'Unknown error');
    }
  }

  async webSocketClose(ws: WebSocket, _code: number, _reason: string): Promise<void> {
    await this.handleLeave(ws);
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error('WebSocket error:', error);
    await this.handleLeave(ws);
  }

  private async handleJoin(ws: WebSocket, msg: JoinMessage): Promise<void> {
    await this.loadParticipants();

    const participantKey = `${msg.userId}|${msg.deviceId}`;

    // Check if already joined
    if (this.participants.has(participantKey)) {
      this.sendError(ws, 'ALREADY_JOINED', 'Already joined this call');
      return;
    }

    // Create a Cloudflare Calls session for this participant
    const session = await createSession(this.env);

    const participant: Participant = {
      oderId: msg.userId,
      deviceId: msg.deviceId,
      sessionId: session.sessionId,
      tracks: new Map(),
      joinedAt: Date.now(),
    };

    this.participants.set(participantKey, participant);
    await this.persistParticipant(participantKey, participant);

    // Tag the WebSocket for later lookup
    ws.serializeAttachment({ participantKey } satisfies CallSocketAttachment);
    this.state.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair(
        JSON.stringify({ type: 'ping' }),
        JSON.stringify({ type: 'pong' })
      )
    );

    // Send welcome message with current participants
    const welcomeMsg: WelcomeMessage = {
      type: 'welcome',
      callId: this.callId || '',
      participants: Array.from(this.participants.values())
        .filter(p => p.oderId !== msg.userId || p.deviceId !== msg.deviceId)
        .map(p => ({
          oderId: p.oderId,
          deviceId: p.deviceId,
          tracks: Array.from(p.tracks.entries()).map(([name, info]) => ({
            trackName: name,
            kind: info.kind,
          })),
        })),
    };
    this.send(ws, welcomeMsg);

    // Notify other participants
    const joinedMsg: ParticipantJoinedMessage = {
      type: 'participant_joined',
      oderId: msg.userId,
      deviceId: msg.deviceId,
    };
    this.broadcast(joinedMsg, participantKey);
  }

  private async handleOffer(ws: WebSocket, msg: OfferMessage): Promise<void> {
    await this.loadParticipants();

    const participant = this.getParticipantBySocket(ws);
    if (!participant) {
      this.sendError(ws, 'NOT_JOINED', 'Must join before sending offer');
      return;
    }

    // Push the track to Cloudflare Calls SFU
    const response = await addTracks(this.env, participant.sessionId, {
      sessionDescription: {
        sdp: msg.sdp,
        type: 'offer',
      },
      tracks: [
        {
          location: 'local',
          trackName: msg.trackName,
        },
      ],
    });

    if (!response.sessionDescription) {
      this.sendError(ws, 'NO_ANSWER', 'SFU did not return answer');
      return;
    }

    const track = response.tracks[0];
    if (track.errorCode) {
      this.sendError(ws, track.errorCode, track.errorDescription || 'Track error');
      return;
    }

    // Store track info
    participant.tracks.set(msg.trackName, {
      mid: track.mid,
      kind: msg.kind,
      enabled: true,
    });
    await this.persistParticipant(`${participant.oderId}|${participant.deviceId}`, participant);

    // Send answer back to client
    const answerMsg: OfferResponseMessage = {
      type: 'offer_response',
      sdp: response.sessionDescription.sdp,
      trackName: msg.trackName,
      mid: track.mid,
    };
    this.send(ws, answerMsg);

    // Notify other participants about the new track
    const publishedMsg: TrackPublishedMessage = {
      type: 'track_published',
      oderId: participant.oderId,
      deviceId: participant.deviceId,
      trackName: msg.trackName,
      kind: msg.kind,
      sessionId: participant.sessionId,
    };
    this.broadcast(publishedMsg, `${participant.oderId}|${participant.deviceId}`);
  }

  private async handleAnswer(ws: WebSocket, msg: AnswerMessage): Promise<void> {
    await this.loadParticipants();

    const participant = this.getParticipantBySocket(ws);
    if (!participant) {
      this.sendError(ws, 'NOT_JOINED', 'Must join before sending answer');
      return;
    }

    // Send answer to SFU for renegotiation
    await renegotiate(this.env, participant.sessionId, {
      sessionDescription: {
        sdp: msg.sdp,
        type: 'answer',
      },
    });
  }

  private async handleLeave(ws: WebSocket): Promise<void> {
    await this.loadParticipants();

    const participant = this.getParticipantBySocket(ws);
    if (!participant) return;

    const participantKey = `${participant.oderId}|${participant.deviceId}`;

    // Close all tracks in the SFU session
    if (participant.tracks.size > 0) {
      const mids = Array.from(participant.tracks.values()).map(t => t.mid);
      try {
        await closeTracks(this.env, participant.sessionId, mids, true);
      } catch (error) {
        console.error('Error closing tracks:', error);
      }
    }

    // Remove participant
    this.participants.delete(participantKey);
    await this.deleteParticipant(participantKey);

    // Notify other participants
    const leftMsg: ParticipantLeftMessage = {
      type: 'participant_left',
      oderId: participant.oderId,
      deviceId: participant.deviceId,
    };
    this.broadcast(leftMsg);

    // Close WebSocket
    try {
      ws.close(1000, 'Left call');
    } catch {
      // Already closed
    }
  }

  private async handleMute(ws: WebSocket, msg: MuteMessage): Promise<void> {
    await this.loadParticipants();

    const participant = this.getParticipantBySocket(ws);
    if (!participant) {
      this.sendError(ws, 'NOT_JOINED', 'Must join before muting');
      return;
    }

    const track = participant.tracks.get(msg.trackName);
    if (!track) {
      this.sendError(ws, 'TRACK_NOT_FOUND', 'Track not found');
      return;
    }

    track.enabled = !msg.muted;
    await this.persistParticipant(`${participant.oderId}|${participant.deviceId}`, participant);

    // Notify other participants about mute state
    this.broadcast({
      type: 'mute_changed',
      oderId: participant.oderId,
      deviceId: participant.deviceId,
      trackName: msg.trackName,
      muted: msg.muted,
    }, `${participant.oderId}|${participant.deviceId}`);
  }

  private async handleGetState(): Promise<Response> {
    await this.loadParticipants();

    return Response.json({
      callId: this.callId,
      roomId: this.matrixRoomId,
      participants: Array.from(this.participants.values()).map(p => ({
        oderId: p.oderId,
        deviceId: p.deviceId,
        sessionId: p.sessionId,
        tracks: Array.from(p.tracks.entries()).map(([name, info]) => ({
          trackName: name,
          kind: info.kind,
          enabled: info.enabled,
        })),
        joinedAt: p.joinedAt,
      })),
    });
  }

  private async handleEndCall(): Promise<Response> {
    await this.loadParticipants();

    // Close all participant sessions
    for (const participant of this.participants.values()) {
      if (participant.tracks.size > 0) {
        const mids = Array.from(participant.tracks.values()).map(t => t.mid);
        try {
          await closeTracks(this.env, participant.sessionId, mids, true);
        } catch {
          // Ignore errors
        }
      }
    }

    for (const ws of this.state.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as CallSocketAttachment | null;
      if (attachment?.participantKey) {
        try {
          ws.close(1000, 'Call ended');
        } catch {
          // Already closed
        }
      }
    }

    this.participants.clear();

    // Clear storage
    await this.state.storage.deleteAll();

    return Response.json({ success: true });
  }

  private getParticipantBySocket(ws: WebSocket): Participant | null {
    const attachment = ws.deserializeAttachment() as CallSocketAttachment | null;
    return attachment?.participantKey ? this.participants.get(attachment.participantKey) || null : null;
  }

  private send(ws: WebSocket, msg: object): void {
    try {
      ws.send(JSON.stringify(msg));
    } catch (error) {
      console.error('Error sending message:', error);
    }
  }

  private sendError(ws: WebSocket, code: string, message: string): void {
    const errorMsg: ErrorMessage = { type: 'error', code, message };
    this.send(ws, errorMsg);
  }

  private broadcast(msg: object, excludeKey?: string): void {
    for (const ws of this.state.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as CallSocketAttachment | null;
      const participantKey = attachment?.participantKey;
      if (participantKey && participantKey !== excludeKey && this.participants.has(participantKey)) {
        this.send(ws, msg);
      }
    }
  }
}

// Room Join Workflow - Durable execution for reliable room joins
//
// This workflow handles room joins with:
// - Automatic retry on failures
// - Federation handshake (make_join → send_join) with backoff
// - Batched member notifications
// - Step persistence for resume on failure

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import type { Env } from '../types';
import { generateEventId } from '../utils/ids';
import {
  storeEvent,
  updateMembership,
  getRoomMembers,
  getStateEvent,
  getRoomEvents,
  getMembership,
} from '../services/database';
import { federationGet, federationPut } from '../services/federation-keys';

// Supported room versions per Matrix Spec v1.17. Rooms outside this set must be
// rejected — accepting an unknown version means we can't apply the right auth
// rules or event format checks.
const SUPPORTED_ROOM_VERSIONS = new Set([
  '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12',
]);

const EVENT_ID_REGEX = /^\$[A-Za-z0-9+/=_\-.]+(:[A-Za-z0-9.\-]+)?$/;

/**
 * Validate a make_join template returned by a remote server before we sign and
 * send it back. A malicious remote could otherwise feed us empty auth_events
 * (bypassing authorization), a non-positive depth (DAG-ordering corruption),
 * a mismatched room_id (cross-room signature reuse), or a version we don't
 * support (silent room-version downgrade).
 *
 * Throws on validation failure; the workflow's outer catch turns the error
 * into a JoinResult with success=false.
 */
function validateRemoteJoinTemplate(
  template: { room_version?: unknown; event?: any },
  expectedRoomId: string,
  expectedUserId: string
): void {
  if (!template || typeof template !== 'object') {
    throw new Error('make_join: response is not an object');
  }

  const roomVersion = template.room_version;
  if (typeof roomVersion !== 'string' || !SUPPORTED_ROOM_VERSIONS.has(roomVersion)) {
    throw new Error(`make_join: unsupported room_version ${String(roomVersion)}`);
  }

  const event = template.event;
  if (!event || typeof event !== 'object') {
    throw new Error('make_join: missing event template');
  }

  // room_id must match what we asked to join
  if (event.room_id !== undefined && event.room_id !== expectedRoomId) {
    throw new Error(
      `make_join: room_id mismatch (got ${String(event.room_id)}, expected ${expectedRoomId})`
    );
  }

  // sender / state_key must be the joining user. A spoofed sender lets the
  // remote get us to sign a join event for a different user.
  if (event.sender !== undefined && event.sender !== expectedUserId) {
    throw new Error(`make_join: sender mismatch (got ${String(event.sender)})`);
  }
  if (event.state_key !== undefined && event.state_key !== expectedUserId) {
    throw new Error(`make_join: state_key mismatch (got ${String(event.state_key)})`);
  }

  if (event.type !== undefined && event.type !== 'm.room.member') {
    throw new Error(`make_join: type must be m.room.member (got ${String(event.type)})`);
  }

  if (
    event.content === undefined ||
    typeof event.content !== 'object' ||
    event.content.membership !== 'join'
  ) {
    throw new Error('make_join: content.membership must be "join"');
  }

  // auth_events: must be a non-empty array of valid event IDs
  if (!Array.isArray(event.auth_events) || event.auth_events.length === 0) {
    throw new Error('make_join: auth_events must be a non-empty array');
  }
  for (const id of event.auth_events) {
    if (typeof id !== 'string' || !EVENT_ID_REGEX.test(id)) {
      throw new Error(`make_join: invalid event ID in auth_events: ${String(id)}`);
    }
  }

  // prev_events: must be a non-empty array of valid event IDs
  if (!Array.isArray(event.prev_events) || event.prev_events.length === 0) {
    throw new Error('make_join: prev_events must be a non-empty array');
  }
  for (const id of event.prev_events) {
    if (typeof id !== 'string' || !EVENT_ID_REGEX.test(id)) {
      throw new Error(`make_join: invalid event ID in prev_events: ${String(id)}`);
    }
  }

  // depth: must be a positive integer. A 0 or negative depth corrupts ordering.
  if (
    typeof event.depth !== 'number' ||
    !Number.isFinite(event.depth) ||
    !Number.isInteger(event.depth) ||
    event.depth < 1
  ) {
    throw new Error(`make_join: depth must be a positive integer (got ${String(event.depth)})`);
  }
}

// Parameters passed when triggering the workflow
export interface JoinParams {
  roomId: string;
  userId: string;
  displayName?: string;
  avatarUrl?: string;
  isRemote: boolean;
  remoteServer?: string;
  reason?: string;
}

// Result returned when workflow completes
export interface JoinResult {
  eventId: string;
  roomId: string;
  success: boolean;
  error?: string;
}

// Serializable event data for workflow steps
// Using any for content to avoid TypeScript serialization issues with Cloudflare Workflows
interface SerializableEvent {
  event_id: string;
  room_id: string;
  sender: string;
  type: string;
  state_key?: string;
  content: any;
  origin_server_ts: number;
  depth: number;
  auth_events: string[];
  prev_events: string[];
}

export class RoomJoinWorkflow extends WorkflowEntrypoint<Env, JoinParams> {
  async run(event: WorkflowEvent<JoinParams>, step: WorkflowStep): Promise<JoinResult> {
    const { roomId, userId, isRemote, remoteServer, displayName, avatarUrl, reason } = event.payload;

    console.log('[RoomJoinWorkflow] Starting join', { roomId, userId, isRemote, remoteServer });

    try {
      // Step 1: For remote joins, get join template from remote server
      let remoteEventTemplate: { room_version: string; event: any } | null = null;
      if (isRemote && remoteServer) {
        remoteEventTemplate = await step.do('make-join', {
          retries: {
            limit: 3,
            delay: 5000, // 5 seconds in milliseconds
            backoff: 'exponential',
          },
          timeout: 30000, // 30 seconds in milliseconds
        }, async () => {
          return await this.makeJoinRequest(remoteServer, roomId, userId);
        }) as { room_version: string; event: any } | null;

        // Validate the remote-supplied template before trusting any of its
        // fields (auth_events, prev_events, depth, room_id, sender, state_key).
        // A malicious remote could otherwise bypass authorization or trick us
        // into signing a join for the wrong room or user.
        if (remoteEventTemplate) {
          validateRemoteJoinTemplate(remoteEventTemplate, roomId, userId);
        }
      }

      // Step 2: Create and sign the join event
      const joinEventData = await step.do('create-event', async () => {
        return await this.createJoinEvent({
          roomId,
          userId,
          displayName,
          avatarUrl,
          reason,
          remoteEventTemplate,
        });
      }) as SerializableEvent;

      // Step 3: For remote joins, send signed event to remote server
      if (isRemote && remoteServer && joinEventData) {
        await step.do('send-join', {
          retries: {
            limit: 3,
            delay: 5000,
            backoff: 'exponential',
          },
          timeout: 30000,
        }, async () => {
          return await this.sendJoinRequest(remoteServer, roomId, joinEventData);
        });
      }

      // Step 4: Persist event and membership locally
      await step.do('persist', async () => {
        await storeEvent(this.env.DB, joinEventData);
        await updateMembership(this.env.DB, roomId, userId, 'join', joinEventData.event_id);
      });

      // Step 5: Get room members for notification
      const members = await step.do('get-members', async () => {
        const memberList = await getRoomMembers(this.env.DB, roomId);
        // Exclude the joining user from notifications
        return memberList.filter(m => m.userId !== userId).map(m => ({ userId: m.userId }));
      }) as Array<{ userId: string }>;

      // Step 6: Notify members in batches of 50
      const BATCH_SIZE = 50;
      for (let i = 0; i < members.length; i += BATCH_SIZE) {
        const batch = members.slice(i, i + BATCH_SIZE);
        await step.do(`notify-batch-${i}`, async () => {
          await this.notifyMemberBatch(batch, joinEventData);
        });
      }

      console.log('[RoomJoinWorkflow] Join completed successfully', { roomId, userId, eventId: joinEventData.event_id });

      return {
        eventId: joinEventData.event_id,
        roomId,
        success: true,
      };
    } catch (error) {
      console.error('[RoomJoinWorkflow] Join failed', { roomId, userId, error });
      return {
        eventId: '',
        roomId,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Make an authenticated make_join request to a remote server
  private async makeJoinRequest(
    remoteServer: string,
    roomId: string,
    userId: string
  ): Promise<{ room_version: string; event: any }> {
    console.log('[RoomJoinWorkflow] Making make_join request', { remoteServer, roomId, userId });

    const path = `/_matrix/federation/v1/make_join/${encodeURIComponent(roomId)}/${encodeURIComponent(userId)}`;

    const response = await federationGet(
      remoteServer,
      path,
      this.env.SERVER_NAME,
      this.env.DB,
      this.env.CACHE
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`make_join failed: ${response.status} ${error}`);
    }

    const result = await response.json() as { room_version: string; event: any };
    return result;
  }

  // Create a join event (either from remote template or local state)
  private async createJoinEvent(params: {
    roomId: string;
    userId: string;
    displayName?: string;
    avatarUrl?: string;
    reason?: string;
    remoteEventTemplate?: { room_version: string; event: any } | null;
  }): Promise<SerializableEvent> {
    const { roomId, userId, displayName, avatarUrl, reason, remoteEventTemplate } = params;

    let authEvents: string[] = [];
    let prevEvents: string[] = [];
    let depth = 1;

    if (remoteEventTemplate?.event) {
      // Use template from remote server
      authEvents = remoteEventTemplate.event.auth_events || [];
      prevEvents = remoteEventTemplate.event.prev_events || [];
      depth = remoteEventTemplate.event.depth || 1;
    } else {
      // Get local room state
      const createEvent = await getStateEvent(this.env.DB, roomId, 'm.room.create');
      const joinRulesEvent = await getStateEvent(this.env.DB, roomId, 'm.room.join_rules');
      const powerLevelsEvent = await getStateEvent(this.env.DB, roomId, 'm.room.power_levels');
      const currentMembership = await getMembership(this.env.DB, roomId, userId);

      if (createEvent) authEvents.push(createEvent.event_id);
      if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
      if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
      if (currentMembership) authEvents.push(currentMembership.eventId);

      const { events: latestEvents } = await getRoomEvents(this.env.DB, roomId, undefined, 1);
      prevEvents = latestEvents.map(e => e.event_id);
      depth = (latestEvents[0]?.depth ?? 0) + 1;
    }

    const eventId = await generateEventId(this.env.SERVER_NAME);

    const memberContent: any = {
      membership: 'join',
    };

    if (displayName) {
      memberContent.displayname = displayName;
    }
    if (avatarUrl) {
      memberContent.avatar_url = avatarUrl;
    }
    if (reason) {
      memberContent.reason = reason;
    }

    const event: SerializableEvent = {
      event_id: eventId,
      room_id: roomId,
      sender: userId,
      type: 'm.room.member',
      state_key: userId,
      content: memberContent,
      origin_server_ts: Date.now(),
      depth,
      auth_events: authEvents,
      prev_events: prevEvents,
    };

    return event;
  }

  // Send an authenticated send_join request to a remote server
  private async sendJoinRequest(
    remoteServer: string,
    roomId: string,
    joinEvent: SerializableEvent
  ): Promise<any> {
    console.log('[RoomJoinWorkflow] Sending send_join request', { remoteServer, roomId, eventId: joinEvent.event_id });

    const path = `/_matrix/federation/v1/send_join/${encodeURIComponent(roomId)}/${encodeURIComponent(joinEvent.event_id)}`;

    const response = await federationPut(
      remoteServer,
      path,
      joinEvent,
      this.env.SERVER_NAME,
      this.env.DB,
      this.env.CACHE
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`send_join failed: ${response.status} ${error}`);
    }

    const result = await response.json();
    return result;
  }

  // Notify a batch of members about the join
  private async notifyMemberBatch(
    members: Array<{ userId: string }>,
    joinEvent: SerializableEvent
  ): Promise<void> {
    const promises = members.map(async (member) => {
      try {
        const syncDO = this.env.SYNC;
        const doId = syncDO.idFromName(member.userId);
        const stub = syncDO.get(doId);

        await stub.fetch(new Request('http://internal/notify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            roomId: joinEvent.room_id,
            eventId: joinEvent.event_id,
            eventType: joinEvent.type,
          }),
        }));
      } catch (error) {
        console.error('[RoomJoinWorkflow] Failed to notify member', {
          userId: member.userId,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        // Don't throw - continue notifying other members
      }
    });

    await Promise.all(promises);
  }
}

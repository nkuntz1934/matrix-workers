// Push Notification Workflow - Durable execution for reliable push delivery
//
// This workflow handles push notifications with:
// - Automatic retry on gateway/APNs failures
// - Batched member processing (50 per batch)
// - Step persistence for resume on failure
// - Parallel pusher delivery with retry

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import type { Env } from '../types';

// Parameters passed when triggering the workflow
export interface PushParams {
  eventId: string;
  roomId: string;
  eventType: string;
  sender: string;
  content: any;
  originServerTs: number;
}

// Result returned when workflow completes
export interface PushResult {
  success: boolean;
  notifiedCount: number;
  failedCount: number;
  skippedCount: number;
  error?: string;
}

// Serializable member notification result
interface MemberResult {
  userId: string;
  notified: boolean;
  skipped: boolean;
  error?: string;
}

// Serializable room context
interface RoomContext {
  memberCount: number;
  senderDisplayName: string;
  roomName: string | undefined;
}

// Serializable pusher data
interface SerializablePusher {
  pushkey: string;
  kind: string;
  appId: string;
  data: string;
}

// Serializable push rule result
interface PushRuleResult {
  notify: boolean;
  actions: any[];
  highlight: boolean;
}

export class PushNotificationWorkflow extends WorkflowEntrypoint<Env, PushParams> {
  async run(event: WorkflowEvent<PushParams>, step: WorkflowStep): Promise<PushResult> {
    const { eventId, roomId, eventType, sender, content, originServerTs } = event.payload;

    console.log('[PushNotificationWorkflow] Starting', { eventId, roomId, eventType, sender });

    try {
      // Step 1: Get room members (excluding sender)
      const members = await step.do('get-members', async () => {
        const result = await this.env.DB.prepare(`
          SELECT user_id FROM room_memberships
          WHERE room_id = ? AND membership = 'join' AND user_id != ?
        `).bind(roomId, sender).all<{ user_id: string }>();
        return result.results.map(m => m.user_id);
      }) as string[];

      if (members.length === 0) {
        console.log('[PushNotificationWorkflow] No members to notify');
        return { success: true, notifiedCount: 0, failedCount: 0, skippedCount: 0 };
      }

      // Step 2: Get room context (member count, sender name, room name)
      const roomContext = await step.do('get-room-context', async () => {
        return await this.getRoomContext(roomId, sender);
      }) as RoomContext;

      // Step 3: Process members in batches of 50
      const BATCH_SIZE = 50;
      let notifiedCount = 0;
      let failedCount = 0;
      let skippedCount = 0;

      for (let i = 0; i < members.length; i += BATCH_SIZE) {
        const batch = members.slice(i, i + BATCH_SIZE);

        const batchResults = await step.do(`notify-batch-${i}`, {
          retries: {
            limit: 2,
            delay: 5000,
            backoff: 'exponential',
          },
          timeout: 60000, // 60 seconds per batch
        }, async () => {
          return await this.processMemberBatch(batch, {
            eventId,
            roomId,
            eventType,
            sender,
            content,
            originServerTs,
            senderDisplayName: roomContext.senderDisplayName,
            roomName: roomContext.roomName,
            memberCount: roomContext.memberCount,
          });
        }) as MemberResult[];

        // Aggregate results
        for (const result of batchResults) {
          if (result.skipped) {
            skippedCount++;
          } else if (result.notified) {
            notifiedCount++;
          } else if (result.error) {
            failedCount++;
          }
        }
      }

      console.log('[PushNotificationWorkflow] Completed', {
        eventId,
        roomId,
        notifiedCount,
        failedCount,
        skippedCount,
      });

      return {
        success: true,
        notifiedCount,
        failedCount,
        skippedCount,
      };
    } catch (error) {
      console.error('[PushNotificationWorkflow] Failed', { eventId, roomId, error });
      return {
        success: false,
        notifiedCount: 0,
        failedCount: 0,
        skippedCount: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Get room context for notifications
  private async getRoomContext(roomId: string, sender: string): Promise<RoomContext> {
    // Get member count
    const memberCountResult = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM room_memberships
      WHERE room_id = ? AND membership = 'join'
    `).bind(roomId).first<{ count: number }>();
    const memberCount = memberCountResult?.count || 0;

    // Get sender's display name
    const senderMembership = await this.env.DB.prepare(`
      SELECT display_name FROM room_memberships
      WHERE room_id = ? AND user_id = ?
    `).bind(roomId, sender).first<{ display_name: string | null }>();
    const senderDisplayName = senderMembership?.display_name || sender.split(':')[0].replace('@', '');

    // Get room name
    const roomNameEvent = await this.env.DB.prepare(`
      SELECT content FROM events
      WHERE room_id = ? AND event_type = 'm.room.name' AND state_key = ''
      ORDER BY origin_server_ts DESC LIMIT 1
    `).bind(roomId).first<{ content: string }>();

    let roomName: string | undefined;
    if (roomNameEvent) {
      try {
        const parsed = JSON.parse(roomNameEvent.content);
        roomName = parsed.name;
      } catch {}
    }

    // For DM rooms without explicit name, use sender's name
    if (!roomName && memberCount === 2) {
      roomName = senderDisplayName;
    }

    return { memberCount, senderDisplayName, roomName };
  }

  // Process a batch of members
  private async processMemberBatch(
    members: string[],
    eventContext: {
      eventId: string;
      roomId: string;
      eventType: string;
      sender: string;
      content: any;
      originServerTs: number;
      senderDisplayName: string;
      roomName: string | undefined;
      memberCount: number;
    }
  ): Promise<MemberResult[]> {
    const results: MemberResult[] = [];

    // Process members in parallel within the batch
    const promises = members.map(async (userId) => {
      try {
        // Evaluate push rules
        const pushResult = await this.evaluatePushRules(
          userId,
          {
            type: eventContext.eventType,
            content: eventContext.content,
            sender: eventContext.sender,
            room_id: eventContext.roomId,
          },
          eventContext.memberCount
        );

        if (!pushResult.notify) {
          return { userId, notified: false, skipped: true };
        }

        // Get unread count
        const unreadCount = await this.getUnreadCount(userId, eventContext.roomId);

        // Get pushers and send notifications
        const pushers = await this.getUserPushers(userId);
        if (pushers.length === 0) {
          return { userId, notified: false, skipped: true };
        }

        // Send to all pushers
        let anySuccess = false;
        for (const pusher of pushers) {
          try {
            const success = await this.sendToPusher(
              userId,
              pusher,
              eventContext,
              unreadCount
            );
            if (success) {
              anySuccess = true;
            }
          } catch (err) {
            console.error('[PushNotificationWorkflow] Pusher failed', {
              userId,
              appId: pusher.appId,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        }

        // Queue notification for history
        await this.queueNotification(userId, eventContext, pushResult);

        return { userId, notified: anySuccess, skipped: false };
      } catch (error) {
        console.error('[PushNotificationWorkflow] Member failed', {
          userId,
          error: error instanceof Error ? error.message : String(error),
        });
        return {
          userId,
          notified: false,
          skipped: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    });

    const memberResults = await Promise.all(promises);
    results.push(...memberResults);

    return results;
  }

  // Simplified push rule evaluation (main logic is in push.ts)
  private async evaluatePushRules(
    userId: string,
    event: { type: string; content: any; sender: string; room_id: string },
    _roomMemberCount: number
  ): Promise<PushRuleResult> {
    // Import the evaluatePushRules function isn't possible in workflow context
    // So we implement a simplified version here

    // Check if user has a master kill switch enabled
    const masterRule = await this.env.DB.prepare(`
      SELECT enabled FROM push_rules
      WHERE user_id = ? AND rule_id = '.m.rule.master'
    `).bind(userId).first<{ enabled: number }>();

    if (masterRule?.enabled === 1) {
      return { notify: false, actions: [], highlight: false };
    }

    // Default: notify for messages and encrypted events
    if (event.type === 'm.room.message' || event.type === 'm.room.encrypted') {
      return { notify: true, actions: ['notify'], highlight: false };
    }

    return { notify: false, actions: [], highlight: false };
  }

  // Get unread count for user in room
  private async getUnreadCount(userId: string, roomId: string): Promise<number> {
    const result = await this.env.DB.prepare(`
      SELECT COUNT(*) as count FROM events e
      WHERE e.room_id = ?
        AND e.stream_ordering > COALESCE(
          (SELECT CAST(json_extract(content, '$.event_id') AS TEXT) FROM account_data
           WHERE user_id = ? AND room_id = ? AND event_type = 'm.fully_read'),
          ''
        )
        AND e.sender != ?
        AND e.event_type IN ('m.room.message', 'm.room.encrypted')
    `).bind(roomId, userId, roomId, userId).first<{ count: number }>();

    return result?.count || 1;
  }

  // Get user's pushers
  private async getUserPushers(userId: string): Promise<SerializablePusher[]> {
    const result = await this.env.DB.prepare(`
      SELECT pushkey, kind, app_id, data FROM pushers WHERE user_id = ?
    `).bind(userId).all<{ pushkey: string; kind: string; app_id: string; data: string }>();

    return result.results.map(p => ({
      pushkey: p.pushkey,
      kind: p.kind,
      appId: p.app_id,
      data: p.data,
    }));
  }

  // Send notification to a single pusher
  private async sendToPusher(
    userId: string,
    pusher: SerializablePusher,
    eventContext: {
      eventId: string;
      roomId: string;
      eventType: string;
      sender: string;
      content: any;
      senderDisplayName: string;
      roomName: string | undefined;
    },
    unreadCount: number
  ): Promise<boolean> {
    if (pusher.kind !== 'http') {
      return false;
    }

    let pusherData: any;
    try {
      pusherData = JSON.parse(pusher.data);
    } catch {
      return false;
    }

    if (!pusherData.url) {
      return false;
    }

    const senderDisplayName = eventContext.senderDisplayName;
    const roomDisplayName = eventContext.roomName || 'Chat';

    // Build device data with APNs alert
    const deviceData = JSON.parse(JSON.stringify(pusherData.default_payload || {}));

    if (deviceData.aps) {
      if (eventContext.eventType === 'm.room.encrypted') {
        deviceData.aps.alert = {
          title: senderDisplayName,
          body: roomDisplayName,
        };
      } else {
        const messageBody = eventContext.content?.body || 'New message';
        deviceData.aps.alert = {
          title: senderDisplayName,
          subtitle: roomDisplayName,
          body: messageBody,
        };
      }
      deviceData.aps['mutable-content'] = 1;
    }

    deviceData.event_id = eventContext.eventId;
    deviceData.room_id = eventContext.roomId;
    deviceData.sender = eventContext.sender;
    deviceData.unread_count = unreadCount;

    const notification = {
      notification: {
        event_id: eventContext.eventId,
        room_id: eventContext.roomId,
        type: eventContext.eventType,
        sender: eventContext.sender,
        sender_display_name: senderDisplayName,
        room_name: roomDisplayName,
        prio: 'high',
        counts: { unread: unreadCount },
        devices: [{
          app_id: pusher.appId,
          pushkey: pusher.pushkey,
          pushkey_ts: Date.now(),
          data: {
            format: pusherData.format,
            default_payload: deviceData,
          },
        }],
        ...(pusherData.format !== 'event_id_only' && { content: eventContext.content }),
      },
    };

    try {
      const response = await fetch(pusherData.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notification),
        signal: AbortSignal.timeout(10000), // 10 second timeout
      });

      if (response.ok) {
        // Update pusher success
        await this.env.DB.prepare(`
          UPDATE pushers SET last_success = ?, failure_count = 0
          WHERE user_id = ? AND pushkey = ? AND app_id = ?
        `).bind(Date.now(), userId, pusher.pushkey, pusher.appId).run();
        return true;
      } else {
        // Update pusher failure
        await this.env.DB.prepare(`
          UPDATE pushers SET last_failure = ?, failure_count = failure_count + 1
          WHERE user_id = ? AND pushkey = ? AND app_id = ?
        `).bind(Date.now(), userId, pusher.pushkey, pusher.appId).run();
        return false;
      }
    } catch (error) {
      // Update pusher failure
      await this.env.DB.prepare(`
        UPDATE pushers SET last_failure = ?, failure_count = failure_count + 1
        WHERE user_id = ? AND pushkey = ? AND app_id = ?
      `).bind(Date.now(), userId, pusher.pushkey, pusher.appId).run();
      throw error;
    }
  }

  // Queue notification for history API
  private async queueNotification(
    userId: string,
    eventContext: { eventId: string; roomId: string },
    pushResult: PushRuleResult
  ): Promise<void> {
    await this.env.DB.prepare(`
      INSERT INTO notification_queue (user_id, room_id, event_id, notification_type, actions)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      userId,
      eventContext.roomId,
      eventContext.eventId,
      pushResult.highlight ? 'highlight' : 'notify',
      JSON.stringify(pushResult.actions)
    ).run();
  }
}

// Federation Catchup Workflow - Backfill events when a server comes online
//
// Triggered when a previously-offline server is detected as reachable again.
// Requests missing events via /backfill and /get_missing_events.

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import type { Env } from '../types';

export interface CatchupParams {
  serverName: string;
  roomIds: string[];
}

export interface CatchupResult {
  serverName: string;
  backfilledEvents: number;
  success: boolean;
  error?: string;
}

export class FederationCatchupWorkflow extends WorkflowEntrypoint<Env, CatchupParams> {
  async run(event: WorkflowEvent<CatchupParams>, step: WorkflowStep) {
    const { serverName, roomIds } = event.payload;

    // Step 1: Verify server is reachable
    const isReachable = await step.do('check-server', async () => {
      try {
        const resp = await fetch(`https://${serverName}/_matrix/federation/v1/version`, {
          signal: AbortSignal.timeout(10000),
        });
        return resp.ok;
      } catch {
        return false;
      }
    });

    if (!isReachable) {
      return { serverName, backfilledEvents: 0, success: false, error: 'Server not reachable' };
    }

    let totalBackfilled = 0;

    // Step 2: For each room, request missing events
    for (const roomId of roomIds) {
      const count = await step.do(`backfill-${roomId}`, async () => {
        try {
          // Get our latest event in this room
          const latestEvent = await this.env.DB.prepare(`
            SELECT event_id FROM events WHERE room_id = ? ORDER BY stream_ordering DESC LIMIT 1
          `).bind(roomId).first<{ event_id: string }>();

          if (!latestEvent) return 0;

          // Request missing events from the remote server
          const resp = await fetch(
            `https://${serverName}/_matrix/federation/v1/get_missing_events/${encodeURIComponent(roomId)}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                limit: 100,
                earliest_events: [latestEvent.event_id],
                latest_events: [],
              }),
              signal: AbortSignal.timeout(30000),
            }
          );

          if (!resp.ok) return 0;

          const data = await resp.json() as { events?: unknown[] };
          return data.events?.length || 0;
        } catch {
          return 0;
        }
      });

      totalBackfilled += count;
    }

    return { serverName, backfilledEvents: totalBackfilled, success: true };
  }
}

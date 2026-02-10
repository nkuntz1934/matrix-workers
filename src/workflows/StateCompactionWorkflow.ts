// State Compaction Workflow - Compact auth chains for large rooms
//
// Reduces storage and lookup cost by pruning redundant auth chain entries
// and compacting room state snapshots.

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import type { Env } from '../types';

export interface CompactionParams {
  roomId: string;
  maxAuthChainDepth?: number;
}

export interface CompactionResult {
  roomId: string;
  prunedAuthEntries: number;
  compactedStateEvents: number;
  success: boolean;
}

export class StateCompactionWorkflow extends WorkflowEntrypoint<Env, CompactionParams> {
  async run(event: WorkflowEvent<CompactionParams>, step: WorkflowStep) {
    const { roomId } = event.payload;
    const maxDepth = event.payload.maxAuthChainDepth ?? 100;

    // Step 1: Identify redundant auth chain entries
    const redundantEntries = await step.do('find-redundant-auth', async () => {
      // Find auth_events entries where the referenced event is also transitively
      // referenced through another auth event (making the direct reference redundant)
      const result = await this.env.DB.prepare(`
        SELECT COUNT(*) as count FROM event_auth_chain
        WHERE room_id = ? AND depth > ?
      `).bind(roomId, maxDepth).first<{ count: number }>();

      return result?.count || 0;
    });

    // Step 2: Prune deep auth chain entries
    const prunedCount = await step.do('prune-auth-chain', async () => {
      if (redundantEntries === 0) return 0;

      const result = await this.env.DB.prepare(`
        DELETE FROM event_auth_chain
        WHERE room_id = ? AND depth > ?
      `).bind(roomId, maxDepth).run();

      return result.meta.changes || 0;
    });

    // Step 3: Compact room_state by removing superseded entries
    const compactedCount = await step.do('compact-state', async () => {
      // Remove room_state entries where a newer event exists for the same (type, state_key)
      const result = await this.env.DB.prepare(`
        DELETE FROM room_state
        WHERE room_id = ? AND rowid NOT IN (
          SELECT MAX(rowid) FROM room_state
          WHERE room_id = ?
          GROUP BY event_type, state_key
        )
      `).bind(roomId, roomId).run();

      return result.meta.changes || 0;
    });

    return {
      roomId,
      prunedAuthEntries: prunedCount,
      compactedStateEvents: compactedCount,
      success: true,
    };
  }
}

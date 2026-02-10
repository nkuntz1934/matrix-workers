// Media Cleanup Workflow - Clean orphaned and expired media
//
// Runs periodically to remove media files that are no longer referenced
// or have exceeded retention policies.

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import type { Env } from '../types';

export interface CleanupParams {
  maxAgeDays?: number;
  dryRun?: boolean;
}

export interface CleanupResult {
  deletedCount: number;
  freedBytes: number;
  dryRun: boolean;
  success: boolean;
}

export class MediaCleanupWorkflow extends WorkflowEntrypoint<Env, CleanupParams> {
  async run(event: WorkflowEvent<CleanupParams>, step: WorkflowStep) {
    const maxAgeDays = event.payload.maxAgeDays ?? 90;
    const dryRun = event.payload.dryRun ?? false;
    const cutoff = Date.now() - (maxAgeDays * 24 * 60 * 60 * 1000);

    // Step 1: Find expired media entries
    const expiredMedia = await step.do('find-expired', async () => {
      const results = await this.env.DB.prepare(`
        SELECT media_id, content_type, file_size, created_at FROM media
        WHERE created_at < ? AND media_id NOT IN (
          SELECT DISTINCT json_extract(e.content, '$.url')
          FROM events e
          WHERE json_extract(e.content, '$.url') IS NOT NULL
            AND json_extract(e.content, '$.url') LIKE 'mxc://%'
        )
        LIMIT 500
      `).bind(cutoff).all<{
        media_id: string;
        content_type: string;
        file_size: number;
        created_at: number;
      }>();

      return results.results;
    });

    if (dryRun) {
      const freedBytes = expiredMedia.reduce((sum, m) => sum + (m.file_size || 0), 0);
      return { deletedCount: expiredMedia.length, freedBytes, dryRun: true, success: true };
    }

    // Step 2: Delete from R2 and D1
    let deletedCount = 0;
    let freedBytes = 0;

    for (const media of expiredMedia) {
      const deleted = await step.do(`delete-${media.media_id}`, async () => {
        try {
          await this.env.MEDIA.delete(media.media_id);
          await this.env.DB.prepare('DELETE FROM media WHERE media_id = ?')
            .bind(media.media_id).run();
          return true;
        } catch {
          return false;
        }
      });

      if (deleted) {
        deletedCount++;
        freedBytes += media.file_size || 0;
      }
    }

    return { deletedCount, freedBytes, dryRun: false, success: true };
  }
}

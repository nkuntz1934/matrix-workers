// Analytics middleware using Cloudflare Analytics Engine

import { createMiddleware } from 'hono/factory';
import type { AppEnv } from '../types';

export function analyticsMiddleware() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const start = Date.now();

    await next();

    // Write analytics data if Analytics Engine is available
    if (c.env.ANALYTICS) {
      try {
        const latency = Date.now() - start;
        const path = new URL(c.req.url).pathname;
        const method = c.req.method;
        const status = c.res.status;

        c.env.ANALYTICS.writeDataPoint({
          blobs: [
            path,              // blob1: request path
            method,            // blob2: HTTP method
            String(status),    // blob3: status code
          ],
          doubles: [
            latency,           // double1: latency in ms
          ],
          indexes: [
            path.split('/').slice(0, 5).join('/'), // index1: path prefix for grouping
          ],
        });
      } catch (err) {
        // Don't fail requests if analytics fails
      }
    }
  });
}

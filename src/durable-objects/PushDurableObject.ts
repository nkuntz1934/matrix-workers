// Push Durable Object for direct APNs delivery
// Bypasses Sygnal for full control over notification payload

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface APNsNotification {
  pushkey: string; // APNs device token
  topic: string; // Bundle ID (e.g., io.element.elementx)
  payload: APNsPayload;
  priority?: 5 | 10;
  expiration?: number;
  collapseId?: string;
}

interface APNsPayload {
  aps: {
    alert?: {
      title?: string;
      subtitle?: string;
      body?: string;
      'loc-key'?: string;
      'loc-args'?: string[];
    } | string;
    badge?: number;
    sound?: string | { critical?: number; name?: string; volume?: number };
    'thread-id'?: string;
    category?: string;
    'content-available'?: number;
    'mutable-content'?: number;
  };
  // Matrix-specific fields for NSE
  room_id?: string;
  event_id?: string;
  sender?: string;
  unread_count?: number;
  [key: string]: unknown;
}

interface PendingPush {
  id: string;
  notification: APNsNotification;
  attempts: number;
  lastAttempt?: number;
  error?: string;
}

// APNs JWT token cache
interface JWTCache {
  token: string;
  expiresAt: number;
}

export class PushDurableObject extends DurableObject<Env> {
  private jwtCache: JWTCache | null = null;
  private pendingPushes: Map<string, PendingPush> = new Map();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/send' && request.method === 'POST') {
      return this.handleSend(request);
    }

    if (path === '/send-batch' && request.method === 'POST') {
      return this.handleSendBatch(request);
    }

    if (path === '/status' && request.method === 'GET') {
      return this.handleStatus();
    }

    return new Response('Not found', { status: 404 });
  }

  // Send a single APNs notification
  private async handleSend(request: Request): Promise<Response> {
    try {
      const notification = await request.json() as APNsNotification;
      const result = await this.sendAPNs(notification);
      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      console.error('[PushDO] Send error:', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // Send batch of notifications
  private async handleSendBatch(request: Request): Promise<Response> {
    try {
      const { notifications } = await request.json() as { notifications: APNsNotification[] };
      const results = await Promise.all(
        notifications.map(n => this.sendAPNs(n))
      );
      return new Response(JSON.stringify({ results }), {
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (error) {
      console.error('[PushDO] Batch send error:', error);
      return new Response(JSON.stringify({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // Get status of push delivery
  private async handleStatus(): Promise<Response> {
    const pending = Array.from(this.pendingPushes.values());
    return new Response(JSON.stringify({
      pendingCount: pending.length,
      pending: pending.slice(0, 10), // Return first 10
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Send notification to APNs
  private async sendAPNs(notification: APNsNotification): Promise<{ success: boolean; apnsId?: string; error?: string; reason?: string }> {
    // Check for required secrets
    const keyId = this.env.APNS_KEY_ID;
    const teamId = this.env.APNS_TEAM_ID;
    const privateKey = this.env.APNS_PRIVATE_KEY;

    if (!keyId || !teamId || !privateKey) {
      console.log('[PushDO] APNs credentials not configured, falling back to Sygnal');
      return { success: false, error: 'APNs not configured' };
    }

    try {
      // Get or refresh JWT token
      const jwt = await this.getAPNsJWT(keyId, teamId, privateKey);

      // Determine APNs environment (production vs sandbox)
      const isProduction = this.env.APNS_ENVIRONMENT !== 'sandbox';
      const apnsHost = isProduction
        ? 'api.push.apple.com'
        : 'api.sandbox.push.apple.com';

      // Build APNs request
      const deviceToken = notification.pushkey.replace(/[<>\s]/g, '');
      const url = `https://${apnsHost}/3/device/${deviceToken}`;

      console.log('[PushDO] Sending to APNs:', url, 'topic:', notification.topic);
      console.log('[PushDO] Payload:', JSON.stringify(notification.payload));

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'authorization': `bearer ${jwt}`,
          'apns-topic': notification.topic,
          'apns-push-type': notification.payload.aps['content-available'] ? 'background' : 'alert',
          'apns-priority': String(notification.priority || 10),
          ...(notification.expiration && { 'apns-expiration': String(notification.expiration) }),
          ...(notification.collapseId && { 'apns-collapse-id': notification.collapseId }),
        },
        body: JSON.stringify(notification.payload),
      });

      const apnsId = response.headers.get('apns-id');

      if (response.ok) {
        console.log('[PushDO] APNs success, apns-id:', apnsId);
        return { success: true, apnsId: apnsId || undefined };
      }

      // Handle APNs error response
      const errorBody = await response.text();
      let reason = 'Unknown';
      try {
        const errorJson = JSON.parse(errorBody);
        reason = errorJson.reason || 'Unknown';
      } catch {
        reason = errorBody;
      }

      console.error('[PushDO] APNs error:', response.status, reason);
      return { success: false, error: `APNs ${response.status}`, reason };

    } catch (error) {
      console.error('[PushDO] APNs request failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Request failed'
      };
    }
  }

  // Get or generate APNs JWT token
  private async getAPNsJWT(keyId: string, teamId: string, privateKey: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    // Check cache (tokens valid for ~1 hour, refresh after 50 min)
    if (this.jwtCache && this.jwtCache.expiresAt > now) {
      return this.jwtCache.token;
    }

    // Generate new JWT using Web Crypto API
    const token = await this.generateAPNsJWT(keyId, teamId, privateKey);

    // Cache for 30 minutes (APNs accepts tokens up to 1 hour old).
    // 30 min provides a safe buffer for clock skew and key rotation.
    this.jwtCache = {
      token,
      expiresAt: now + (30 * 60),
    };

    return token;
  }

  // Generate APNs JWT using Web Crypto API (ES256)
  private async generateAPNsJWT(keyId: string, teamId: string, privateKey: string): Promise<string> {
    const header = {
      alg: 'ES256',
      kid: keyId,
    };

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: teamId,
      iat: now,
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Import the private key
    const key = await this.importPrivateKey(privateKey);

    // Sign using ES256
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      new TextEncoder().encode(signingInput)
    );

    // Convert signature from DER to raw format (r || s)
    const rawSignature = this.derToRaw(new Uint8Array(signature));
    const encodedSignature = this.base64UrlEncode(rawSignature);

    return `${signingInput}.${encodedSignature}`;
  }

  // Import PEM private key for Web Crypto
  private async importPrivateKey(pemKey: string): Promise<CryptoKey> {
    // Remove PEM headers and decode
    const pemContents = pemKey
      .replace(/-----BEGIN PRIVATE KEY-----/g, '')
      .replace(/-----END PRIVATE KEY-----/g, '')
      .replace(/-----BEGIN EC PRIVATE KEY-----/g, '')
      .replace(/-----END EC PRIVATE KEY-----/g, '')
      .replace(/\s/g, '');

    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

    return crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
  }

  // Base64URL encode
  private base64UrlEncode(input: string | Uint8Array): string {
    let base64: string;
    if (typeof input === 'string') {
      base64 = btoa(input);
    } else {
      base64 = btoa(String.fromCharCode(...input));
    }
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Convert DER signature to raw format (for ECDSA P-256)
  private derToRaw(der: Uint8Array): Uint8Array {
    // ECDSA signatures from Web Crypto are in IEEE P1363 format (r || s)
    // Each component is 32 bytes for P-256
    if (der.length === 64) {
      // Already in raw format
      return der;
    }

    // Parse DER format: 0x30 [total length] 0x02 [r length] [r] 0x02 [s length] [s]
    const raw = new Uint8Array(64);

    let offset = 2; // Skip 0x30 and total length

    // Parse r
    if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const rLen = der[offset++];
    let r = der.slice(offset, offset + rLen);
    offset += rLen;

    // Parse s
    if (der[offset] !== 0x02) throw new Error('Invalid DER signature');
    offset++;
    const sLen = der[offset++];
    let s = der.slice(offset, offset + sLen);

    // Remove leading zeros and pad to 32 bytes
    while (r.length > 32 && r[0] === 0) r = r.slice(1);
    while (s.length > 32 && s[0] === 0) s = s.slice(1);

    raw.set(r, 32 - r.length);
    raw.set(s, 64 - s.length);

    return raw;
  }

  // Retry failed notifications
  async alarm(): Promise<void> {
    const now = Date.now();
    const retryDelay = 60000; // 1 minute

    for (const [id, push] of this.pendingPushes) {
      if (push.attempts >= 3) {
        // Max retries exceeded, remove
        this.pendingPushes.delete(id);
        console.log('[PushDO] Giving up on push:', id, 'after', push.attempts, 'attempts');
        continue;
      }

      if (push.lastAttempt && (now - push.lastAttempt) < retryDelay) {
        continue; // Too soon to retry
      }

      // Retry
      push.attempts++;
      push.lastAttempt = now;

      const result = await this.sendAPNs(push.notification);
      if (result.success) {
        this.pendingPushes.delete(id);
      } else {
        push.error = result.error;
      }
    }

    // Schedule next retry if there are pending pushes
    if (this.pendingPushes.size > 0) {
      await this.ctx.storage.setAlarm(Date.now() + retryDelay);
    }
  }
}

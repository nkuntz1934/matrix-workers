// UserKeysDurableObject - Strongly consistent E2EE key storage
// Per the Cloudflare blog post: "Some operations can't tolerate eventual consistency"
// This DO provides single-threaded, atomic operations for device keys and cross-signing keys
// which is critical during the initial E2EE bootstrap flow.

import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

interface CrossSigningKeys {
  master?: any;
  self_signing?: any;
  user_signing?: any;
}

interface DeviceSignature {
  signer_user_id: string;
  signer_key_id: string;
  target_user_id: string;
  target_key_id: string;
  signature: string;
}

export class UserKeysDurableObject extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Account data endpoints (E2EE-related: m.secret_storage.*, m.cross_signing.*, etc.)
      if (path === '/account-data/get' && request.method === 'GET') {
        const eventType = url.searchParams.get('event_type');
        return this.getAccountData(eventType);
      }

      if (path === '/account-data/put' && request.method === 'POST') {
        const body = await request.json() as { event_type: string; content: any };
        return this.putAccountData(body.event_type, body.content);
      }

      // Device keys endpoints
      if (path === '/device-keys/get' && request.method === 'GET') {
        const deviceId = url.searchParams.get('device_id');
        return this.getDeviceKeys(deviceId);
      }

      if (path === '/device-keys/put' && request.method === 'POST') {
        const body = await request.json() as { device_id: string; keys: any };
        return this.putDeviceKeys(body.device_id, body.keys);
      }

      if (path === '/device-keys/list' && request.method === 'GET') {
        return this.listDeviceIds();
      }

      // Cross-signing keys endpoints
      if (path === '/cross-signing/get' && request.method === 'GET') {
        return this.getCrossSigningKeys();
      }

      if (path === '/cross-signing/put' && request.method === 'POST') {
        const body = await request.json() as Partial<CrossSigningKeys>;
        return this.putCrossSigningKeys(body);
      }

      if (path === '/cross-signing/delete' && request.method === 'POST') {
        return this.deleteCrossSigningKeys();
      }

      if (path === '/signatures/get' && request.method === 'GET') {
        const targetKeyId = url.searchParams.get('target_key_id');
        return this.getSignatures(targetKeyId);
      }

      if (path === '/signatures/put' && request.method === 'POST') {
        const sig = await request.json() as DeviceSignature;
        return this.putSignature(sig);
      }

      return new Response('Not found', { status: 404 });
    } catch (error) {
      // Log error internally but don't expose stack traces to clients
      console.error('[UserKeysDO] Error:', error);
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // ============================================
  // Account Data (E2EE-related) - strongly consistent
  // ============================================

  private async getAccountData(eventType: string | null): Promise<Response> {
    if (eventType) {
      const data = await this.ctx.storage.get<any>(`account_data:${eventType}`);
      return new Response(JSON.stringify(data || null), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get all account data for this user
    const allData: Record<string, any> = {};
    const eventTypes = await this.ctx.storage.get<string[]>('account_data_types') || [];
    for (const type of eventTypes) {
      const data = await this.ctx.storage.get<any>(`account_data:${type}`);
      if (data !== undefined) {
        allData[type] = data;
      }
    }
    return new Response(JSON.stringify(allData), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private async putAccountData(eventType: string, content: any): Promise<Response> {
    await this.ctx.storage.put(`account_data:${eventType}`, content);

    // Track event types
    const eventTypes = await this.ctx.storage.get<string[]>('account_data_types') || [];
    if (!eventTypes.includes(eventType)) {
      eventTypes.push(eventType);
      await this.ctx.storage.put('account_data_types', eventTypes);
    }

    console.log('[UserKeysDO] Stored account data:', eventType);
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ============================================
  // Device Keys - strongly consistent
  // ============================================

  private async getDeviceKeys(deviceId: string | null): Promise<Response> {
    if (deviceId) {
      const keys = await this.ctx.storage.get<any>(`device_keys:${deviceId}`);
      return new Response(JSON.stringify(keys || null), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get all device keys for this user
    const allKeys: Record<string, any> = {};
    const deviceIds = await this.ctx.storage.get<string[]>('device_ids') || [];
    for (const did of deviceIds) {
      const keys = await this.ctx.storage.get<any>(`device_keys:${did}`);
      if (keys) {
        allKeys[did] = keys;
      }
    }
    return new Response(JSON.stringify(allKeys), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private async putDeviceKeys(deviceId: string, keys: any): Promise<Response> {
    await this.ctx.storage.put(`device_keys:${deviceId}`, keys);

    // Track device IDs
    const deviceIds = await this.ctx.storage.get<string[]>('device_ids') || [];
    if (!deviceIds.includes(deviceId)) {
      deviceIds.push(deviceId);
      await this.ctx.storage.put('device_ids', deviceIds);
    }

    console.log('[UserKeysDO] Stored device keys for device:', deviceId);
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  private async listDeviceIds(): Promise<Response> {
    const deviceIds = await this.ctx.storage.get<string[]>('device_ids') || [];
    return new Response(JSON.stringify(deviceIds), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get cross-signing keys - strongly consistent read
  private async getCrossSigningKeys(): Promise<Response> {
    const keys = await this.ctx.storage.get<CrossSigningKeys>('cross_signing_keys');
    return new Response(JSON.stringify(keys || {}), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Put cross-signing keys - atomic write
  private async putCrossSigningKeys(newKeys: Partial<CrossSigningKeys>): Promise<Response> {
    // Get existing keys and merge
    const existing = await this.ctx.storage.get<CrossSigningKeys>('cross_signing_keys') || {};

    const merged: CrossSigningKeys = {
      ...existing,
      ...(newKeys.master && { master: newKeys.master }),
      ...(newKeys.self_signing && { self_signing: newKeys.self_signing }),
      ...(newKeys.user_signing && { user_signing: newKeys.user_signing }),
    };

    await this.ctx.storage.put('cross_signing_keys', merged);

    console.log('[UserKeysDO] Stored cross-signing keys:', Object.keys(merged));
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Delete cross-signing keys - for identity reset
  private async deleteCrossSigningKeys(): Promise<Response> {
    await this.ctx.storage.delete('cross_signing_keys');
    console.log('[UserKeysDO] Deleted all cross-signing keys');
    return new Response(JSON.stringify({ success: true, deleted: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Get signatures for a target key
  private async getSignatures(targetKeyId: string | null): Promise<Response> {
    const allSigs = await this.ctx.storage.get<DeviceSignature[]>('signatures') || [];

    if (targetKeyId) {
      const filtered = allSigs.filter(s => s.target_key_id === targetKeyId);
      return new Response(JSON.stringify(filtered), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify(allSigs), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Add a signature - atomic append
  private async putSignature(sig: DeviceSignature): Promise<Response> {
    const existing = await this.ctx.storage.get<DeviceSignature[]>('signatures') || [];

    // Check for duplicate
    const isDuplicate = existing.some(
      s => s.signer_key_id === sig.signer_key_id &&
           s.target_key_id === sig.target_key_id
    );

    if (!isDuplicate) {
      existing.push(sig);
      await this.ctx.storage.put('signatures', existing);
      console.log('[UserKeysDO] Stored signature:', sig.signer_key_id, '->', sig.target_key_id);
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

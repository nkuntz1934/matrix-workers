// Matrix ID generation utilities

import type { UserId, RoomId, EventId, RoomAlias, DeviceId } from '../types';

// Generate a random opaque ID using Web Crypto API
export async function generateOpaqueId(length: number = 18): Promise<string> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// Base64 URL-safe encoding
export function base64UrlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Base64 URL-safe decoding
export function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

// Generate a user ID
export function formatUserId(localpart: string, serverName: string): UserId {
  return `@${localpart}:${serverName}`;
}

// Parse a user ID into components
export function parseUserId(userId: UserId): { localpart: string; serverName: string } | null {
  const match = userId.match(/^@([^:]+):(.+)$/);
  if (!match) return null;
  return { localpart: match[1], serverName: match[2] };
}

// Generate a room ID
export async function generateRoomId(serverName: string): Promise<RoomId> {
  const opaque = await generateOpaqueId(18);
  return `!${opaque}:${serverName}`;
}

// Parse a room ID
export function parseRoomId(roomId: RoomId): { opaque: string; serverName: string } | null {
  const match = roomId.match(/^!([^:]+):(.+)$/);
  if (!match) return null;
  return { opaque: match[1], serverName: match[2] };
}

// Generate an event ID (room version 4+ format)
export async function generateEventId(_serverName: string): Promise<EventId> {
  const opaque = await generateOpaqueId(32);
  return `$${opaque}`;
}

// Generate a legacy event ID (room version 1-3)
export async function generateLegacyEventId(serverName: string): Promise<EventId> {
  const opaque = await generateOpaqueId(18);
  return `$${opaque}:${serverName}`;
}

// Format a room alias
export function formatRoomAlias(localpart: string, serverName: string): RoomAlias {
  return `#${localpart}:${serverName}`;
}

// Parse a room alias
export function parseRoomAlias(alias: RoomAlias): { localpart: string; serverName: string } | null {
  const match = alias.match(/^#([^:]+):(.+)$/);
  if (!match) return null;
  return { localpart: match[1], serverName: match[2] };
}

// Generate a device ID
export async function generateDeviceId(): Promise<DeviceId> {
  const opaque = await generateOpaqueId(10);
  return opaque.toUpperCase();
}

// Generate an access token
export async function generateAccessToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `syt_${base64UrlEncode(bytes)}`;
}

// Generate a transaction ID
export async function generateTransactionId(): Promise<string> {
  const timestamp = Date.now().toString(36);
  const random = await generateOpaqueId(8);
  return `${timestamp}_${random}`;
}

// Generate a login token (for QR code authentication)
export async function generateLoginToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `mlt_${base64UrlEncode(bytes)}`;
}

// Generate a refresh token (for token refresh flow)
export async function generateRefreshToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `syr_${base64UrlEncode(bytes)}`;
}

// Validate localpart (username)
export function isValidLocalpart(localpart: string): boolean {
  // Matrix spec: lowercase letters, digits, and the characters .-_=/
  // Must not be empty and should be reasonable length
  if (!localpart || localpart.length > 255) return false;
  return /^[a-z0-9._=/-]+$/.test(localpart);
}

// Validate server name
export function isValidServerName(serverName: string): boolean {
  // Can be domain or domain:port or IPv4 or [IPv6]:port
  if (!serverName || serverName.length > 255) return false;

  // Simple validation - domain with optional port
  const domainWithPort = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:\d+)?$/;
  const ipv4WithPort = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/;
  const ipv6WithPort = /^\[[\da-fA-F:]+\](:\d+)?$/;

  return domainWithPort.test(serverName) || ipv4WithPort.test(serverName) || ipv6WithPort.test(serverName);
}

// Check if server name is local
export function isLocalServerName(serverName: string, localServer: string): boolean {
  return serverName.toLowerCase() === localServer.toLowerCase();
}

// Extract server name from Matrix ID
export function getServerName(id: string): string | null {
  const match = id.match(/:([^:]+)$/);
  return match ? match[1] : null;
}

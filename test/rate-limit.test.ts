import { describe, it, expect } from 'vitest';

// Pure function extracted for testing — mirrors src/middleware/rate-limit.ts
function getRateLimitType(path: string, method: string): string {
  if (path.includes('/login') && method === 'POST') return 'login';
  if (path.includes('/register') && method === 'POST') return 'register';
  if (path.includes('/sync')) return 'sync';
  if (path.includes('/keys/')) return 'e2ee';
  if (path.includes('/media') || path.includes('/upload')) {
    return method === 'POST' || method === 'PUT' ? 'media_upload' : 'media_download';
  }
  if (path.includes('/search')) return 'search';
  if (path.includes('/_matrix/federation') || path.includes('/_matrix/key')) return 'federation';
  if (path.includes('/createRoom') && method === 'POST') return 'create_room';
  if (path.match(/\/rooms\/[^/]+\/send/) && method === 'PUT') return 'send_message';
  return 'default';
}

describe('getRateLimitType', () => {
  it('classifies login POST correctly', () => {
    expect(getRateLimitType('/_matrix/client/v3/login', 'POST')).toBe('login');
  });

  it('does not classify login GET as login', () => {
    expect(getRateLimitType('/_matrix/client/v3/login', 'GET')).toBe('default');
  });

  it('classifies register POST correctly', () => {
    expect(getRateLimitType('/_matrix/client/v3/register', 'POST')).toBe('register');
  });

  it('classifies sync endpoint', () => {
    expect(getRateLimitType('/_matrix/client/v3/sync', 'GET')).toBe('sync');
  });

  it('classifies e2ee key upload', () => {
    expect(getRateLimitType('/_matrix/client/v3/keys/upload', 'POST')).toBe('e2ee');
  });

  it('classifies media upload vs download', () => {
    expect(getRateLimitType('/_matrix/media/v3/upload', 'POST')).toBe('media_upload');
    expect(getRateLimitType('/_matrix/media/v3/download/server/media', 'GET')).toBe('media_download');
  });

  it('classifies search', () => {
    expect(getRateLimitType('/_matrix/client/v3/search', 'POST')).toBe('search');
  });

  it('classifies federation routes', () => {
    expect(getRateLimitType('/_matrix/federation/v1/send', 'PUT')).toBe('federation');
    expect(getRateLimitType('/_matrix/key/v2/server', 'GET')).toBe('federation');
  });

  it('classifies room creation', () => {
    expect(getRateLimitType('/_matrix/client/v3/createRoom', 'POST')).toBe('create_room');
  });

  it('classifies room message send', () => {
    expect(getRateLimitType('/_matrix/client/v3/rooms/!abc:example.com/send/m.room.message/1', 'PUT')).toBe('send_message');
  });

  it('falls back to default for unknown routes', () => {
    expect(getRateLimitType('/_matrix/client/v3/profile/@user:example.com', 'GET')).toBe('default');
  });
});

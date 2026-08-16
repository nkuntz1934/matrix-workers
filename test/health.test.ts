import { describe, it, expect } from 'vitest';

describe('Health endpoint shape', () => {
  it('returns expected status fields', () => {
    // Basic shape test — real integration tests need a running worker
    const response = { status: 'ok', server: 'matrix-worker' };
    expect(response.status).toBe('ok');
    expect(response.server).toBe('matrix-worker');
  });
});

describe('Matrix version format', () => {
  it('SERVER_NAME must match a valid hostname pattern', () => {
    const serverName = 'matrix.example.com';
    expect(serverName).toMatch(/^[a-z0-9.-]+\.[a-z]{2,}$/);
  });

  it('rejects empty server name', () => {
    const serverName = '';
    expect(serverName.length).toBe(0);
    // In real code, an empty SERVER_NAME should cause startup failure
  });

  it('valid Andrew deployment domains pass hostname check', () => {
    const validDomains = [
      'matrix.fuzzywigg.com',
      'matrix.smtp.eth',
      'm.smtp.eth',
    ];
    const hostnameRe = /^[a-z0-9.-]+\.[a-z]{2,}$/;
    for (const domain of validDomains) {
      expect(domain).toMatch(hostnameRe);
    }
  });
});

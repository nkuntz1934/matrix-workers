// URL Validator for SSRF Protection
// Prevents Server-Side Request Forgery by blocking requests to internal networks

// IPv4 private and reserved ranges
const BLOCKED_IPV4_RANGES = [
  // Loopback
  { start: '127.0.0.0', end: '127.255.255.255' },
  // Private networks (RFC 1918)
  { start: '10.0.0.0', end: '10.255.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' },
  // Link-local
  { start: '169.254.0.0', end: '169.254.255.255' },
  // AWS metadata service
  { start: '169.254.169.254', end: '169.254.169.254' },
  // Broadcast
  { start: '255.255.255.255', end: '255.255.255.255' },
  // Current network
  { start: '0.0.0.0', end: '0.255.255.255' },
];

// Blocked hostnames
const BLOCKED_HOSTNAMES = [
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  // Kubernetes internal
  'kubernetes.default',
  'kubernetes.default.svc',
  'kubernetes.default.svc.cluster.local',
  // Common internal service names
  'internal',
  'metadata',
  'metadata.google.internal',
];

/**
 * Convert an IPv4 address to a 32-bit integer for range comparison
 */
function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return -1;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Check if an IPv4 address is in a blocked range
 */
function isBlockedIPv4(ip: string): boolean {
  const ipInt = ipv4ToInt(ip);
  if (ipInt === -1) return false;

  for (const range of BLOCKED_IPV4_RANGES) {
    const startInt = ipv4ToInt(range.start);
    const endInt = ipv4ToInt(range.end);
    if (ipInt >= startInt && ipInt <= endInt) {
      return true;
    }
  }

  return false;
}

/**
 * Check if an IPv6 address is a blocked address
 */
function isBlockedIPv6(ip: string): boolean {
  // Normalize the address
  const normalized = ip.toLowerCase();

  // Loopback
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') {
    return true;
  }

  // Unspecified
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
  const ipv4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Mapped) {
    return isBlockedIPv4(ipv4Mapped[1]);
  }

  // Link-local (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // Unique local (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  return false;
}

/**
 * Check if a hostname is blocked
 */
function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();

  // Check exact matches
  if (BLOCKED_HOSTNAMES.includes(lower)) {
    return true;
  }

  // Check if it's a subdomain of a blocked hostname
  for (const blocked of BLOCKED_HOSTNAMES) {
    if (lower.endsWith('.' + blocked)) {
      return true;
    }
  }

  // Check for .local TLD (mDNS)
  if (lower.endsWith('.local')) {
    return true;
  }

  // Check for .internal domains
  if (lower.endsWith('.internal')) {
    return true;
  }

  return false;
}

/**
 * Check if a hostname appears to be an IP address and if so, whether it's blocked
 */
function isBlockedIPAddress(hostname: string): boolean {
  // IPv4 check
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return isBlockedIPv4(hostname);
  }

  // IPv6 check (with brackets removed if present)
  const ipv6 = hostname.replace(/^\[|\]$/g, '');
  if (ipv6.includes(':')) {
    return isBlockedIPv6(ipv6);
  }

  return false;
}

export interface URLValidationResult {
  valid: boolean;
  error?: string;
  sanitizedUrl?: string;
}

/**
 * Validate a URL for SSRF protection
 * Returns { valid: true, sanitizedUrl } if safe, { valid: false, error } if blocked
 */
export function validateUrl(url: string): URLValidationResult {
  try {
    const parsed = new URL(url);

    // Only allow http and https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check for blocked hostnames
    if (isBlockedHostname(hostname)) {
      return { valid: false, error: 'Access to internal hostnames is not allowed' };
    }

    // Check for blocked IP addresses
    if (isBlockedIPAddress(hostname)) {
      return { valid: false, error: 'Access to internal IP addresses is not allowed' };
    }

    // Check for non-standard ports that might indicate internal services
    const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;

    // Block common internal service ports
    const blockedPorts = [
      22, // SSH
      23, // Telnet
      25, // SMTP
      53, // DNS
      135, // RPC
      139, // NetBIOS
      445, // SMB
      1433, // MSSQL
      1521, // Oracle
      3306, // MySQL
      3389, // RDP
      5432, // PostgreSQL
      5900, // VNC
      6379, // Redis
      9200, // Elasticsearch
      27017, // MongoDB
    ];

    if (blockedPorts.includes(port)) {
      return { valid: false, error: `Access to port ${port} is not allowed` };
    }

    return { valid: true, sanitizedUrl: parsed.toString() };
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * Validate a URL for use in URL preview
 * More restrictive than general URL validation
 */
export function validateUrlForPreview(url: string): URLValidationResult {
  const result = validateUrl(url);
  if (!result.valid) {
    return result;
  }

  const parsed = new URL(url);

  // For previews, only allow standard HTTP ports
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  if (port !== 80 && port !== 443 && port !== 8080 && port !== 8443) {
    return { valid: false, error: 'Only standard HTTP ports (80, 443, 8080, 8443) are allowed for URL preview' };
  }

  return result;
}

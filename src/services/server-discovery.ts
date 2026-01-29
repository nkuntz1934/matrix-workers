// Matrix Server Discovery Service
// Implements Matrix spec server discovery with SRV record support via Cloudflare DoH
// Reference: https://spec.matrix.org/v1.12/server-server-api/#resolving-server-names

import { validateUrl } from '../utils/url-validator';

export interface ServerDiscoveryResult {
  host: string;
  port: number;
  tlsHostname: string; // For SNI/certificate verification
}

interface SRVRecord {
  priority: number;
  weight: number;
  port: number;
  target: string;
}

interface CloudflareDNSResponse {
  Status: number;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
}

// Cache key prefix for server discovery
const DISCOVERY_CACHE_PREFIX = 'discovery:';
const DISCOVERY_CACHE_TTL = 3600; // 1 hour

/**
 * Discover the actual Matrix server endpoint for a given server name.
 * Implements the full Matrix server discovery algorithm.
 */
export async function discoverServer(
  serverName: string,
  cache?: KVNamespace
): Promise<ServerDiscoveryResult> {
  // Check cache first if available
  if (cache) {
    const cached = await cache.get(`${DISCOVERY_CACHE_PREFIX}${serverName}`);
    if (cached) {
      return JSON.parse(cached);
    }
  }

  const result = await performDiscovery(serverName);

  // Cache the result if cache is available
  if (cache) {
    await cache.put(`${DISCOVERY_CACHE_PREFIX}${serverName}`, JSON.stringify(result), {
      expirationTtl: DISCOVERY_CACHE_TTL,
    });
  }

  return result;
}

/**
 * Perform the actual server discovery without caching
 */
async function performDiscovery(serverName: string): Promise<ServerDiscoveryResult> {
  // Step 1: Check if server name is an IP literal
  if (isIPLiteral(serverName)) {
    // IP literals use port 8448 by default
    return {
      host: serverName,
      port: 8448,
      tlsHostname: serverName,
    };
  }

  // Step 2: Check if server name includes an explicit port
  const portMatch = serverName.match(/^(.+):(\d+)$/);
  if (portMatch) {
    const [, host, portStr] = portMatch;
    return {
      host: host,
      port: parseInt(portStr, 10),
      tlsHostname: host,
    };
  }

  // Step 3: Try .well-known/matrix/server delegation
  const wellKnownResult = await tryWellKnown(serverName);
  if (wellKnownResult) {
    return wellKnownResult;
  }

  // Step 4: Try SRV record lookup (_matrix-fed._tcp, then _matrix._tcp)
  const srvResult = await trySRVRecords(serverName);
  if (srvResult) {
    return srvResult;
  }

  // Step 5: Default - use server name with port 8448
  return {
    host: serverName,
    port: 8448,
    tlsHostname: serverName,
  };
}

/**
 * Check if a string is an IP literal (IPv4 or IPv6)
 */
function isIPLiteral(hostname: string): boolean {
  // IPv4 pattern
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return true;
  }

  // IPv6 in brackets (e.g., [::1])
  if (/^\[.+\]$/.test(hostname)) {
    return true;
  }

  return false;
}

/**
 * Try to fetch .well-known/matrix/server for delegation
 */
async function tryWellKnown(serverName: string): Promise<ServerDiscoveryResult | null> {
  const wellKnownUrl = `https://${serverName}/.well-known/matrix/server`;

  // Validate URL to prevent SSRF
  const validation = validateUrl(wellKnownUrl);
  if (!validation.valid) {
    console.warn(`Invalid well-known URL for ${serverName}: ${validation.error}`);
    return null;
  }

  try {
    const response = await fetch(wellKnownUrl, {
      headers: { Accept: 'application/json' },
      cf: { cacheTtl: 3600, cacheEverything: true },
    });

    if (!response.ok) {
      return null;
    }

    const wellKnown = (await response.json()) as { 'm.server'?: string };
    const delegatedServer = wellKnown['m.server'];

    if (!delegatedServer || typeof delegatedServer !== 'string') {
      return null;
    }

    // Validate the delegated server isn't malicious
    const delegatedUrl = `https://${delegatedServer}/`;
    const delegatedValidation = validateUrl(delegatedUrl);
    if (!delegatedValidation.valid) {
      console.warn(`Invalid delegated server ${delegatedServer}: ${delegatedValidation.error}`);
      return null;
    }

    // Parse the delegated server for host:port
    const delegatedPortMatch = delegatedServer.match(/^(.+):(\d+)$/);
    if (delegatedPortMatch) {
      const [, host, portStr] = delegatedPortMatch;
      return {
        host: host,
        port: parseInt(portStr, 10),
        tlsHostname: host,
      };
    }

    // No port specified, continue discovery on the delegated name
    // Check SRV records for the delegated server
    const srvResult = await trySRVRecords(delegatedServer);
    if (srvResult) {
      return srvResult;
    }

    // Default to port 8448
    return {
      host: delegatedServer,
      port: 8448,
      tlsHostname: delegatedServer,
    };
  } catch (error) {
    // Well-known not available or invalid
    console.debug(`Well-known lookup failed for ${serverName}:`, error);
    return null;
  }
}

/**
 * Try SRV record lookups via Cloudflare DNS-over-HTTPS
 * First tries _matrix-fed._tcp (Matrix 1.8+), then _matrix._tcp (legacy)
 */
async function trySRVRecords(serverName: string): Promise<ServerDiscoveryResult | null> {
  // Try the new _matrix-fed._tcp record first (Matrix 1.8+)
  const fedSrvRecords = await lookupSRVRecords(serverName, '_matrix-fed._tcp');
  if (fedSrvRecords.length > 0) {
    const selected = selectSRVRecord(fedSrvRecords);
    return {
      host: selected.target,
      port: selected.port,
      tlsHostname: serverName, // Use original server name for TLS verification
    };
  }

  // Fall back to legacy _matrix._tcp record
  const legacySrvRecords = await lookupSRVRecords(serverName, '_matrix._tcp');
  if (legacySrvRecords.length > 0) {
    const selected = selectSRVRecord(legacySrvRecords);
    return {
      host: selected.target,
      port: selected.port,
      tlsHostname: serverName, // Use original server name for TLS verification
    };
  }

  return null;
}

/**
 * Look up SRV records via Cloudflare DNS-over-HTTPS
 */
async function lookupSRVRecords(serverName: string, recordName: string): Promise<SRVRecord[]> {
  const queryName = `${recordName}.${serverName}`;

  try {
    // Use Cloudflare's DNS-over-HTTPS API
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(queryName)}&type=SRV`,
      {
        headers: {
          Accept: 'application/dns-json',
        },
        cf: { cacheTtl: 300, cacheEverything: true },
      }
    );

    if (!response.ok) {
      return [];
    }

    const dnsResponse: CloudflareDNSResponse = await response.json();

    if (dnsResponse.Status !== 0 || !dnsResponse.Answer) {
      return [];
    }

    const srvRecords: SRVRecord[] = [];

    for (const answer of dnsResponse.Answer) {
      // SRV records have type 33
      if (answer.type !== 33) continue;

      // Parse SRV record data: "priority weight port target"
      const parts = answer.data.split(/\s+/);
      if (parts.length !== 4) continue;

      const [priority, weight, port, target] = parts;

      // Skip if target is "." (no service available)
      if (target === '.') continue;

      // Remove trailing dot from target if present
      const cleanTarget = target.endsWith('.') ? target.slice(0, -1) : target;

      // Validate the target isn't a private/internal address
      const targetUrl = `https://${cleanTarget}/`;
      const validation = validateUrl(targetUrl);
      if (!validation.valid) {
        console.warn(`Skipping SRV record with invalid target ${cleanTarget}: ${validation.error}`);
        continue;
      }

      srvRecords.push({
        priority: parseInt(priority, 10),
        weight: parseInt(weight, 10),
        port: parseInt(port, 10),
        target: cleanTarget,
      });
    }

    return srvRecords;
  } catch (error) {
    console.debug(`SRV lookup failed for ${queryName}:`, error);
    return [];
  }
}

/**
 * Select the best SRV record based on priority and weight
 * Lower priority values are preferred; weight is used for load balancing among same-priority records
 */
function selectSRVRecord(records: SRVRecord[]): SRVRecord {
  if (records.length === 1) {
    return records[0];
  }

  // Sort by priority (ascending)
  const sorted = [...records].sort((a, b) => a.priority - b.priority);

  // Get all records with the lowest priority
  const lowestPriority = sorted[0].priority;
  const lowestPriorityRecords = sorted.filter((r) => r.priority === lowestPriority);

  if (lowestPriorityRecords.length === 1) {
    return lowestPriorityRecords[0];
  }

  // Weight-based selection among same-priority records
  // Sum of all weights
  const totalWeight = lowestPriorityRecords.reduce((sum, r) => sum + r.weight, 0);

  if (totalWeight === 0) {
    // All weights are 0, pick randomly
    return lowestPriorityRecords[Math.floor(Math.random() * lowestPriorityRecords.length)];
  }

  // Random selection weighted by weight values
  let random = Math.random() * totalWeight;
  for (const record of lowestPriorityRecords) {
    random -= record.weight;
    if (random <= 0) {
      return record;
    }
  }

  // Fallback (shouldn't happen)
  return lowestPriorityRecords[0];
}

/**
 * Build the full URL for a Matrix server endpoint
 */
export function buildServerUrl(discovery: ServerDiscoveryResult): string {
  // Use the discovered host and port
  const portSuffix = discovery.port === 443 ? '' : `:${discovery.port}`;
  return `https://${discovery.host}${portSuffix}`;
}

/**
 * Clear the discovery cache for a specific server
 */
export async function clearDiscoveryCache(
  serverName: string,
  cache: KVNamespace
): Promise<void> {
  await cache.delete(`${DISCOVERY_CACHE_PREFIX}${serverName}`);
}

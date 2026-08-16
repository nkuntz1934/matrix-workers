// Cloudflare Workers Environment Types

export interface Env {
  // D1 Database
  DB: D1Database;

  // KV Namespaces
  SESSIONS: KVNamespace;
  DEVICE_KEYS: KVNamespace;
  CACHE: KVNamespace;
  CROSS_SIGNING_KEYS: KVNamespace;
  ACCOUNT_DATA: KVNamespace;
  ONE_TIME_KEYS: KVNamespace;

  // R2 Bucket
  MEDIA: R2Bucket;

  // Durable Objects
  ROOMS: DurableObjectNamespace;
  SYNC: DurableObjectNamespace;
  FEDERATION: DurableObjectNamespace;
  ADMIN: DurableObjectNamespace;
  USER_KEYS: DurableObjectNamespace;
  PUSH: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;

  // Environment variables
  SERVER_NAME: string;
  SERVER_VERSION: string;

  // Rate-limit IP source trust.
  // - On Cloudflare, CF-Connecting-IP is set by the edge and is authoritative.
  // - Set TRUST_FORWARDED_FOR="true" only when the worker sits behind a
  //   different trusted proxy that authenticates and rewrites X-Forwarded-For.
  //   Otherwise the header is client-spoofable and must NOT be trusted.
  TRUST_FORWARDED_FOR?: string;

  // Support contact info (optional)
  ADMIN_CONTACT_EMAIL?: string;
  ADMIN_CONTACT_MXID?: string;
  SUPPORT_PAGE_URL?: string;

  // Secrets (to be configured)
  SIGNING_KEY?: string;

  // Maximum staleness (in ms) past a federation key's valid_until_ts before
  // the key is rejected for signature verification. Default 7 days.
  FEDERATION_KEY_MAX_STALENESS_MS?: string;

  // OIDC encryption key for client secrets (32 random bytes, base64 encoded)
  // Generate with: openssl rand -base64 32
  // Set with: npx wrangler secret put OIDC_ENCRYPTION_KEY
  OIDC_ENCRYPTION_KEY?: string;

  // Cloudflare TURN Server Configuration
  TURN_KEY_ID?: string;
  TURN_API_TOKEN?: string;

  // Cloudflare Calls Configuration (native video calling)
  CALLS_APP_ID?: string;      // Cloudflare Calls App ID
  CALLS_APP_SECRET?: string;  // Cloudflare Calls App Secret

  // Durable Object for call signaling
  CALL_ROOMS?: DurableObjectNamespace;

  // Workers VPC Service binding for LiveKit
  LIVEKIT_API: Fetcher;

  // LiveKit Configuration for MatrixRTC
  LIVEKIT_API_KEY?: string;      // LiveKit API Key (e.g., "devkey")
  LIVEKIT_API_SECRET?: string;   // LiveKit API Secret
  LIVEKIT_URL?: string;          // LiveKit WebSocket URL for clients (e.g., "wss://livekit.example.com")

  // APNs Direct Push Configuration (optional - bypasses Sygnal)
  APNS_KEY_ID?: string;          // Key ID from Apple Developer Portal
  APNS_TEAM_ID?: string;         // Apple Developer Team ID
  APNS_PRIVATE_KEY?: string;     // Contents of the .p8 private key file
  APNS_ENVIRONMENT?: string;     // "production" or "sandbox" (default: production)

  // Cloudflare Workflows for durable multi-step operations
  ROOM_JOIN_WORKFLOW: Workflow;
  PUSH_NOTIFICATION_WORKFLOW: Workflow;

  // Email Service Configuration (Cloudflare Email Service)
  EMAIL?: SendEmail;         // Cloudflare Email Service binding
  EMAIL_FROM?: string;       // From address for verification emails (e.g., "noreply@m.example.com")

  // Browser Rendering (for URL previews of JS-rendered pages)
  BROWSER?: Fetcher;

  // Analytics Engine (for server metrics)
  ANALYTICS?: AnalyticsEngineDataset;

  // Workers AI (for embeddings and content moderation)
  AI?: Ai;
}

// Variables set by middleware and available via c.get()
export type Variables = {
  userId: string;
  deviceId: string | null;
  accessToken: string;
  auth: {
    userId: string;
    deviceId: string | null;
    accessToken: string;
  };
};

// Combined Hono app type with bindings and variables
export type AppEnv = {
  Bindings: Env;
  Variables: Variables;
};

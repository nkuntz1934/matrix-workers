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

  // Environment variables
  SERVER_NAME: string;
  SERVER_VERSION: string;

  // Secrets (to be configured)
  SIGNING_KEY?: string;

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

  // Federation signature enforcement: 'log' (warn only) or 'enforce' (reject invalid)
  SIGNATURE_ENFORCEMENT?: string;
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

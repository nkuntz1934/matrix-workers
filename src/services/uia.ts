// User-Interactive Authentication (UIA) Service
// Implements: https://spec.matrix.org/v1.12/client-server-api/#user-interactive-authentication-api
//
// Manages UIA sessions with proper persistence, stage tracking, and validation.

import { generateOpaqueId } from '../utils/ids';

/**
 * UIA session stored in KV
 */
export interface UiaSession {
  /** Session ID */
  session_id: string;
  /** User ID (optional - may not be known until auth completes) */
  user_id?: string;
  /** Type of operation this session is for */
  type: UiaOperationType;
  /** Available authentication flows */
  flows: UiaFlow[];
  /** Stages that have been completed */
  completed_stages: string[];
  /** Parameters for each auth type */
  params: Record<string, unknown>;
  /** When the session was created (ms since epoch) */
  created_at: number;
  /** Additional context data for the operation */
  context?: Record<string, unknown>;
}

/**
 * Authentication flow - a sequence of stages
 */
export interface UiaFlow {
  stages: string[];
}

/**
 * Types of operations that require UIA
 */
export type UiaOperationType =
  | 'registration'
  | 'password_change'
  | 'account_deactivation'
  | 'device_deletion'
  | 'threepid_add'
  | 'device_signing_upload';

/**
 * Result of validating a UIA stage
 */
export interface UiaValidationResult {
  /** Whether validation succeeded */
  valid: boolean;
  /** Error message if validation failed */
  error?: string;
  /** Error code if validation failed */
  errcode?: string;
  /** Updated session after validation */
  session?: UiaSession;
}

/**
 * UIA response to return to client (HTTP 401)
 */
export interface UiaResponse {
  flows: UiaFlow[];
  params: Record<string, unknown>;
  session: string;
  completed?: string[];
}

// Session TTL in seconds (5 minutes)
const SESSION_TTL = 300;

// KV key prefix for UIA sessions
const SESSION_PREFIX = 'uia_session:';

/**
 * Create a new UIA session
 */
export async function createUiaSession(
  cache: KVNamespace,
  type: UiaOperationType,
  flows: UiaFlow[],
  params: Record<string, unknown> = {},
  userId?: string,
  context?: Record<string, unknown>
): Promise<UiaSession> {
  const sessionId = await generateOpaqueId(16);

  const session: UiaSession = {
    session_id: sessionId,
    user_id: userId,
    type,
    flows,
    completed_stages: [],
    params,
    created_at: Date.now(),
    context,
  };

  await cache.put(
    `${SESSION_PREFIX}${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: SESSION_TTL }
  );

  return session;
}

/**
 * Get a UIA session by ID
 */
export async function getUiaSession(
  cache: KVNamespace,
  sessionId: string
): Promise<UiaSession | null> {
  const json = await cache.get(`${SESSION_PREFIX}${sessionId}`);
  if (!json) {
    return null;
  }

  try {
    return JSON.parse(json) as UiaSession;
  } catch {
    return null;
  }
}

/**
 * Update a UIA session
 */
export async function updateUiaSession(
  cache: KVNamespace,
  session: UiaSession
): Promise<void> {
  await cache.put(
    `${SESSION_PREFIX}${session.session_id}`,
    JSON.stringify(session),
    { expirationTtl: SESSION_TTL }
  );
}

/**
 * Delete a UIA session
 */
export async function deleteUiaSession(
  cache: KVNamespace,
  sessionId: string
): Promise<void> {
  await cache.delete(`${SESSION_PREFIX}${sessionId}`);
}

/**
 * Mark a stage as completed in the session
 */
export async function completeUiaStage(
  cache: KVNamespace,
  sessionId: string,
  stage: string
): Promise<UiaSession | null> {
  const session = await getUiaSession(cache, sessionId);
  if (!session) {
    return null;
  }

  if (!session.completed_stages.includes(stage)) {
    session.completed_stages.push(stage);
  }

  await updateUiaSession(cache, session);
  return session;
}

/**
 * Check if all required stages for any flow are completed
 */
export function isUiaComplete(session: UiaSession): boolean {
  // Check if any flow has all its stages completed
  return session.flows.some(flow =>
    flow.stages.every(stage => session.completed_stages.includes(stage))
  );
}

/**
 * Get the UIA response to send to the client (HTTP 401)
 */
export function buildUiaResponse(session: UiaSession): UiaResponse {
  const response: UiaResponse = {
    flows: session.flows,
    params: session.params,
    session: session.session_id,
  };

  // Include completed stages if any
  if (session.completed_stages.length > 0) {
    response.completed = session.completed_stages;
  }

  return response;
}

/**
 * Validate that a session exists and matches expected criteria
 */
export async function validateUiaSession(
  cache: KVNamespace,
  sessionId: string | undefined,
  expectedType?: UiaOperationType,
  expectedUserId?: string
): Promise<UiaValidationResult> {
  if (!sessionId) {
    return {
      valid: false,
      error: 'Missing session ID',
      errcode: 'M_MISSING_PARAM',
    };
  }

  const session = await getUiaSession(cache, sessionId);
  if (!session) {
    return {
      valid: false,
      error: 'UIA session not found or expired',
      errcode: 'M_UNKNOWN',
    };
  }

  if (expectedType && session.type !== expectedType) {
    return {
      valid: false,
      error: 'Session type mismatch',
      errcode: 'M_FORBIDDEN',
    };
  }

  if (expectedUserId && session.user_id && session.user_id !== expectedUserId) {
    return {
      valid: false,
      error: 'Session user mismatch',
      errcode: 'M_FORBIDDEN',
    };
  }

  return {
    valid: true,
    session,
  };
}

/**
 * Standard flows for different operations
 * Returns mutable copies to avoid readonly type issues
 */
export const StandardFlows = {
  /** Registration flow - just dummy auth */
  get registration(): UiaFlow[] {
    return [{ stages: ['m.login.dummy'] }];
  },

  /** Password-protected operations */
  get passwordRequired(): UiaFlow[] {
    return [{ stages: ['m.login.password'] }];
  },

  /** Dummy-only flow (for testing/simple auth) */
  get dummyOnly(): UiaFlow[] {
    return [{ stages: ['m.login.dummy'] }];
  },
};

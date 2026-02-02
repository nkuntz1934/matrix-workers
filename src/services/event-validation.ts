// Event field validation per Matrix spec
// https://spec.matrix.org/v1.12/server-server-api/#pdus
// https://spec.matrix.org/v1.12/client-server-api/#room-events

import type { Membership } from '../types/matrix';

/**
 * Result of event validation
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
  errcode?: 'M_BAD_JSON' | 'M_INVALID_PARAM';
}

const VALID_RESULT: ValidationResult = { valid: true };

/**
 * Regex patterns for Matrix identifiers
 */
const PATTERNS = {
  // User ID: @localpart:domain
  userId: /^@[a-z0-9._=\-/+]+:[a-zA-Z0-9.\-]+(:[0-9]+)?$/,
  // Room ID: !opaque_id:domain
  roomId: /^![a-zA-Z0-9._~\-/+]+:[a-zA-Z0-9.\-]+(:[0-9]+)?$/,
  // Event ID: $opaque_id (room v4+) or $base64:domain (older)
  eventId: /^\$[a-zA-Z0-9._~\-/+=]+$/,
};

/**
 * Validate a Matrix user ID format
 */
export function isValidUserId(userId: unknown): userId is string {
  return typeof userId === 'string' && PATTERNS.userId.test(userId);
}

/**
 * Validate a Matrix room ID format
 */
export function isValidRoomId(roomId: unknown): roomId is string {
  return typeof roomId === 'string' && PATTERNS.roomId.test(roomId);
}

/**
 * Validate a Matrix event ID format
 */
export function isValidEventId(eventId: unknown): eventId is string {
  return typeof eventId === 'string' && PATTERNS.eventId.test(eventId);
}

/**
 * Extract server name from a Matrix user ID
 */
export function extractServerName(userId: string): string | null {
  const match = userId.match(/^@[^:]+:(.+)$/);
  return match ? match[1] : null;
}

/**
 * Validate common event fields (client-server events)
 */
export function validateEventFields(event: Record<string, unknown>): ValidationResult {
  // type - must be non-empty string
  if (typeof event.type !== 'string' || event.type.length === 0) {
    return {
      valid: false,
      error: 'Event must have a non-empty "type" field',
      errcode: 'M_BAD_JSON',
    };
  }

  // sender - must be valid user ID
  if (!isValidUserId(event.sender)) {
    return {
      valid: false,
      error: 'Event must have a valid "sender" user ID',
      errcode: 'M_BAD_JSON',
    };
  }

  // room_id - must be valid room ID
  if (!isValidRoomId(event.room_id)) {
    return {
      valid: false,
      error: 'Event must have a valid "room_id"',
      errcode: 'M_BAD_JSON',
    };
  }

  // origin_server_ts - must be positive integer
  if (typeof event.origin_server_ts !== 'number' ||
      !Number.isInteger(event.origin_server_ts) ||
      event.origin_server_ts < 0) {
    return {
      valid: false,
      error: 'Event must have a valid "origin_server_ts" (positive integer)',
      errcode: 'M_BAD_JSON',
    };
  }

  // content - must be an object
  if (typeof event.content !== 'object' || event.content === null || Array.isArray(event.content)) {
    return {
      valid: false,
      error: 'Event must have a "content" object',
      errcode: 'M_BAD_JSON',
    };
  }

  return VALID_RESULT;
}

/**
 * Validate PDU-specific fields (federation events)
 */
export function validatePduFields(pdu: Record<string, unknown>): ValidationResult {
  // First validate common event fields
  const baseResult = validateEventFields(pdu);
  if (!baseResult.valid) {
    return baseResult;
  }

  // event_id - must be valid event ID
  if (!isValidEventId(pdu.event_id)) {
    return {
      valid: false,
      error: 'PDU must have a valid "event_id"',
      errcode: 'M_BAD_JSON',
    };
  }

  // depth - must be non-negative integer
  if (typeof pdu.depth !== 'number' || !Number.isInteger(pdu.depth) || pdu.depth < 0) {
    return {
      valid: false,
      error: 'PDU must have a valid "depth" (non-negative integer)',
      errcode: 'M_BAD_JSON',
    };
  }

  // auth_events - must be array of valid event IDs
  if (!Array.isArray(pdu.auth_events)) {
    return {
      valid: false,
      error: 'PDU must have an "auth_events" array',
      errcode: 'M_BAD_JSON',
    };
  }
  for (const authEventId of pdu.auth_events) {
    if (!isValidEventId(authEventId)) {
      return {
        valid: false,
        error: `Invalid event ID in auth_events: ${authEventId}`,
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // prev_events - must be array of valid event IDs
  if (!Array.isArray(pdu.prev_events)) {
    return {
      valid: false,
      error: 'PDU must have a "prev_events" array',
      errcode: 'M_BAD_JSON',
    };
  }
  for (const prevEventId of pdu.prev_events) {
    if (!isValidEventId(prevEventId)) {
      return {
        valid: false,
        error: `Invalid event ID in prev_events: ${prevEventId}`,
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // origin - if present, should be a valid server name
  if (pdu.origin !== undefined) {
    if (typeof pdu.origin !== 'string' || pdu.origin.length === 0) {
      return {
        valid: false,
        error: 'PDU "origin" must be a non-empty string',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  return VALID_RESULT;
}

/**
 * Validate state event fields
 */
export function validateStateEventFields(event: Record<string, unknown>): ValidationResult {
  // state_key must be present and be a string (can be empty)
  if (typeof event.state_key !== 'string') {
    return {
      valid: false,
      error: 'State event must have a "state_key" string field',
      errcode: 'M_BAD_JSON',
    };
  }

  return VALID_RESULT;
}

/**
 * Validate m.room.message event content
 */
export function validateMessageContent(content: Record<string, unknown>): ValidationResult {
  // msgtype - must be non-empty string
  if (typeof content.msgtype !== 'string' || content.msgtype.length === 0) {
    return {
      valid: false,
      error: 'm.room.message must have a non-empty "msgtype" field',
      errcode: 'M_BAD_JSON',
    };
  }

  // body - must be a string (can be empty for some message types)
  if (typeof content.body !== 'string') {
    return {
      valid: false,
      error: 'm.room.message must have a "body" string field',
      errcode: 'M_BAD_JSON',
    };
  }

  return VALID_RESULT;
}

/**
 * Validate m.room.member event content
 */
export function validateMemberContent(content: Record<string, unknown>): ValidationResult {
  const validMemberships: Membership[] = ['invite', 'join', 'leave', 'ban', 'knock'];

  // membership - must be valid value
  if (typeof content.membership !== 'string') {
    return {
      valid: false,
      error: 'm.room.member must have a "membership" field',
      errcode: 'M_BAD_JSON',
    };
  }

  if (!validMemberships.includes(content.membership as Membership)) {
    return {
      valid: false,
      error: `Invalid membership value: "${content.membership}". Must be one of: ${validMemberships.join(', ')}`,
      errcode: 'M_INVALID_PARAM',
    };
  }

  // avatar_url - if present, should be a valid mxc:// URL
  if (content.avatar_url !== undefined && content.avatar_url !== null) {
    if (typeof content.avatar_url !== 'string') {
      return {
        valid: false,
        error: 'avatar_url must be a string',
        errcode: 'M_BAD_JSON',
      };
    }
    if (content.avatar_url.length > 0 && !content.avatar_url.startsWith('mxc://')) {
      return {
        valid: false,
        error: 'avatar_url must be an mxc:// URL',
        errcode: 'M_INVALID_PARAM',
      };
    }
  }

  // displayname - if present, should be a string
  if (content.displayname !== undefined && content.displayname !== null) {
    if (typeof content.displayname !== 'string') {
      return {
        valid: false,
        error: 'displayname must be a string',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // reason - if present, should be a string (used for kicks, bans, etc.)
  if (content.reason !== undefined && content.reason !== null) {
    if (typeof content.reason !== 'string') {
      return {
        valid: false,
        error: 'reason must be a string',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // join_authorised_via_users_server - if present, must be valid user ID
  // Used when joining via restricted join rules
  if (content.join_authorised_via_users_server !== undefined) {
    if (!isValidUserId(content.join_authorised_via_users_server)) {
      return {
        valid: false,
        error: 'join_authorised_via_users_server must be a valid user ID',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // third_party_invite - if present, validate structure
  // Used for invites via third party identifiers (email, phone)
  if (content.third_party_invite !== undefined) {
    const result = validateThirdPartyInvite(content.third_party_invite);
    if (!result.valid) {
      return result;
    }
  }

  return VALID_RESULT;
}

/**
 * Validate third_party_invite structure in m.room.member content
 * https://spec.matrix.org/v1.12/client-server-api/#mroommember
 */
function validateThirdPartyInvite(invite: unknown): ValidationResult {
  if (typeof invite !== 'object' || invite === null || Array.isArray(invite)) {
    return {
      valid: false,
      error: 'third_party_invite must be an object',
      errcode: 'M_BAD_JSON',
    };
  }

  const inv = invite as Record<string, unknown>;

  // display_name - required string
  if (typeof inv.display_name !== 'string') {
    return {
      valid: false,
      error: 'third_party_invite must have a "display_name" string',
      errcode: 'M_BAD_JSON',
    };
  }

  // signed - required object
  if (typeof inv.signed !== 'object' || inv.signed === null || Array.isArray(inv.signed)) {
    return {
      valid: false,
      error: 'third_party_invite must have a "signed" object',
      errcode: 'M_BAD_JSON',
    };
  }

  const signed = inv.signed as Record<string, unknown>;

  // signed.mxid - required valid user ID
  if (!isValidUserId(signed.mxid)) {
    return {
      valid: false,
      error: 'third_party_invite.signed.mxid must be a valid user ID',
      errcode: 'M_BAD_JSON',
    };
  }

  // signed.token - required string
  if (typeof signed.token !== 'string' || signed.token.length === 0) {
    return {
      valid: false,
      error: 'third_party_invite.signed.token must be a non-empty string',
      errcode: 'M_BAD_JSON',
    };
  }

  // signed.signatures - required object (server signatures)
  if (typeof signed.signatures !== 'object' || signed.signatures === null || Array.isArray(signed.signatures)) {
    return {
      valid: false,
      error: 'third_party_invite.signed.signatures must be an object',
      errcode: 'M_BAD_JSON',
    };
  }

  // Validate signatures structure: { "server_name": { "key_id": "signature" } }
  for (const [serverName, keys] of Object.entries(signed.signatures as Record<string, unknown>)) {
    if (typeof serverName !== 'string' || serverName.length === 0) {
      return {
        valid: false,
        error: 'third_party_invite signature server name must be a non-empty string',
        errcode: 'M_BAD_JSON',
      };
    }
    if (typeof keys !== 'object' || keys === null || Array.isArray(keys)) {
      return {
        valid: false,
        error: `third_party_invite signatures for "${serverName}" must be an object`,
        errcode: 'M_BAD_JSON',
      };
    }
    for (const [keyId, sig] of Object.entries(keys as Record<string, unknown>)) {
      if (typeof keyId !== 'string' || keyId.length === 0) {
        return {
          valid: false,
          error: 'third_party_invite signature key ID must be a non-empty string',
          errcode: 'M_BAD_JSON',
        };
      }
      if (typeof sig !== 'string' || sig.length === 0) {
        return {
          valid: false,
          error: `third_party_invite signature for "${keyId}" must be a non-empty string`,
          errcode: 'M_BAD_JSON',
        };
      }
    }
  }

  return VALID_RESULT;
}

/**
 * Validate m.room.power_levels event content
 */
export function validatePowerLevelsContent(content: Record<string, unknown>): ValidationResult {
  // Validate numeric fields
  const numericFields = [
    'ban',
    'events_default',
    'invite',
    'kick',
    'redact',
    'state_default',
    'users_default',
  ];

  for (const field of numericFields) {
    if (content[field] !== undefined) {
      if (typeof content[field] !== 'number' || !Number.isInteger(content[field])) {
        return {
          valid: false,
          error: `m.room.power_levels "${field}" must be an integer`,
          errcode: 'M_BAD_JSON',
        };
      }
    }
  }

  // Validate users object
  if (content.users !== undefined) {
    if (typeof content.users !== 'object' || content.users === null || Array.isArray(content.users)) {
      return {
        valid: false,
        error: 'm.room.power_levels "users" must be an object',
        errcode: 'M_BAD_JSON',
      };
    }
    for (const [userId, level] of Object.entries(content.users as Record<string, unknown>)) {
      if (!isValidUserId(userId)) {
        return {
          valid: false,
          error: `Invalid user ID in power_levels.users: "${userId}"`,
          errcode: 'M_BAD_JSON',
        };
      }
      if (typeof level !== 'number' || !Number.isInteger(level)) {
        return {
          valid: false,
          error: `Power level for "${userId}" must be an integer`,
          errcode: 'M_BAD_JSON',
        };
      }
    }
  }

  // Validate events object
  if (content.events !== undefined) {
    if (typeof content.events !== 'object' || content.events === null || Array.isArray(content.events)) {
      return {
        valid: false,
        error: 'm.room.power_levels "events" must be an object',
        errcode: 'M_BAD_JSON',
      };
    }
    for (const [eventType, level] of Object.entries(content.events as Record<string, unknown>)) {
      if (typeof eventType !== 'string' || eventType.length === 0) {
        return {
          valid: false,
          error: 'Event types in power_levels.events must be non-empty strings',
          errcode: 'M_BAD_JSON',
        };
      }
      if (typeof level !== 'number' || !Number.isInteger(level)) {
        return {
          valid: false,
          error: `Power level for event type "${eventType}" must be an integer`,
          errcode: 'M_BAD_JSON',
        };
      }
    }
  }

  return VALID_RESULT;
}

/**
 * Validate m.room.create event content
 */
export function validateCreateContent(content: Record<string, unknown>): ValidationResult {
  // room_version - if present, must be a string
  if (content.room_version !== undefined) {
    if (typeof content.room_version !== 'string') {
      return {
        valid: false,
        error: 'm.room.create "room_version" must be a string',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  // creator - if present (room versions < 11), must be valid user ID
  if (content.creator !== undefined) {
    if (!isValidUserId(content.creator)) {
      return {
        valid: false,
        error: 'm.room.create "creator" must be a valid user ID',
        errcode: 'M_BAD_JSON',
      };
    }
  }

  return VALID_RESULT;
}

/**
 * Validate m.room.join_rules event content
 */
export function validateJoinRulesContent(content: Record<string, unknown>): ValidationResult {
  const validJoinRules = ['public', 'invite', 'knock', 'restricted', 'knock_restricted', 'private'];

  if (typeof content.join_rule !== 'string') {
    return {
      valid: false,
      error: 'm.room.join_rules must have a "join_rule" field',
      errcode: 'M_BAD_JSON',
    };
  }

  if (!validJoinRules.includes(content.join_rule)) {
    return {
      valid: false,
      error: `Invalid join_rule: "${content.join_rule}". Must be one of: ${validJoinRules.join(', ')}`,
      errcode: 'M_INVALID_PARAM',
    };
  }

  // For restricted/knock_restricted, validate allow list if present
  if ((content.join_rule === 'restricted' || content.join_rule === 'knock_restricted') && content.allow !== undefined) {
    if (!Array.isArray(content.allow)) {
      return {
        valid: false,
        error: '"allow" must be an array for restricted join rules',
        errcode: 'M_BAD_JSON',
      };
    }
    for (const condition of content.allow) {
      if (typeof condition !== 'object' || condition === null) {
        return {
          valid: false,
          error: 'Each allow condition must be an object',
          errcode: 'M_BAD_JSON',
        };
      }
      const cond = condition as Record<string, unknown>;
      if (cond.type === 'm.room_membership') {
        if (!isValidRoomId(cond.room_id)) {
          return {
            valid: false,
            error: 'Allow condition room_id must be a valid room ID',
            errcode: 'M_BAD_JSON',
          };
        }
      }
    }
  }

  return VALID_RESULT;
}

/**
 * Validate event content based on event type
 */
export function validateEventContent(type: string, content: Record<string, unknown>): ValidationResult {
  switch (type) {
    case 'm.room.message':
      return validateMessageContent(content);
    case 'm.room.member':
      return validateMemberContent(content);
    case 'm.room.power_levels':
      return validatePowerLevelsContent(content);
    case 'm.room.create':
      return validateCreateContent(content);
    case 'm.room.join_rules':
      return validateJoinRulesContent(content);
    default:
      // Unknown event types pass content validation
      return VALID_RESULT;
  }
}

/**
 * Full validation for a PDU (federation event)
 */
export function validatePdu(pdu: Record<string, unknown>): ValidationResult {
  // Validate PDU structure
  const pduResult = validatePduFields(pdu);
  if (!pduResult.valid) {
    return pduResult;
  }

  // Validate state event fields if applicable
  if (pdu.state_key !== undefined) {
    const stateResult = validateStateEventFields(pdu);
    if (!stateResult.valid) {
      return stateResult;
    }
  }

  // Validate content based on event type
  const contentResult = validateEventContent(
    pdu.type as string,
    pdu.content as Record<string, unknown>
  );
  if (!contentResult.valid) {
    return contentResult;
  }

  return VALID_RESULT;
}

/**
 * Full validation for a client event (non-PDU)
 */
export function validateClientEvent(
  event: Record<string, unknown>,
  isStateEvent: boolean = false
): ValidationResult {
  // Validate common fields
  const baseResult = validateEventFields(event);
  if (!baseResult.valid) {
    return baseResult;
  }

  // Validate state event fields if applicable
  if (isStateEvent) {
    const stateResult = validateStateEventFields(event);
    if (!stateResult.valid) {
      return stateResult;
    }
  }

  // Validate content based on event type
  const contentResult = validateEventContent(
    event.type as string,
    event.content as Record<string, unknown>
  );
  if (!contentResult.valid) {
    return contentResult;
  }

  return VALID_RESULT;
}

// Room Version Registry
// Maps each Matrix room version to its specific behaviors per the spec

export type StateResolutionAlgorithm = 'v1' | 'v2';
export type EventIdFormat = 'v1' | 'v3' | 'v4';
export type RedactionAlgorithm = 'v1' | 'v11';

export interface RoomVersionBehavior {
  /** Room version string */
  version: string;
  /** State resolution algorithm: v1 for room v1, v2 for room v2+ */
  stateResolution: StateResolutionAlgorithm;
  /** Event ID format: v1 ($opaque:domain), v3 (URL-safe base64 of SHA-256), v4 (URL-safe base64 of SHA-256 with $ prefix) */
  eventIdFormat: EventIdFormat;
  /** Redaction algorithm variant */
  redactionAlgorithm: RedactionAlgorithm;
  /** Whether knocking is supported (v7+) */
  knockingSupported: boolean;
  /** Whether restricted joins are supported (v8+) */
  restrictedJoinsSupported: boolean;
  /** Whether power levels must be integers (v10+) */
  integerPowerLevels: boolean;
  /** Whether the updated redaction algorithm is used (v11+) */
  updatedRedactionRules: boolean;
  /** Auth rule variant: determines which auth checks apply */
  authRuleVariant: 'v1' | 'v8' | 'v10';
  /** Whether knock_restricted join rule is supported (v10+) */
  knockRestrictedSupported: boolean;
  /** Stability status */
  stable: boolean;
}

const ROOM_VERSIONS: Record<string, RoomVersionBehavior> = {
  '1': {
    version: '1',
    stateResolution: 'v1',
    eventIdFormat: 'v1',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '2': {
    version: '2',
    stateResolution: 'v2',
    eventIdFormat: 'v1',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '3': {
    version: '3',
    stateResolution: 'v2',
    eventIdFormat: 'v3',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '4': {
    version: '4',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '5': {
    version: '5',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '6': {
    version: '6',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: false,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '7': {
    version: '7',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: true,
    restrictedJoinsSupported: false,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v1',
    knockRestrictedSupported: false,
    stable: true,
  },
  '8': {
    version: '8',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: true,
    restrictedJoinsSupported: true,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v8',
    knockRestrictedSupported: false,
    stable: true,
  },
  '9': {
    version: '9',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: true,
    restrictedJoinsSupported: true,
    integerPowerLevels: false,
    updatedRedactionRules: false,
    authRuleVariant: 'v8',
    knockRestrictedSupported: false,
    stable: true,
  },
  '10': {
    version: '10',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v1',
    knockingSupported: true,
    restrictedJoinsSupported: true,
    integerPowerLevels: true,
    updatedRedactionRules: false,
    authRuleVariant: 'v10',
    knockRestrictedSupported: true,
    stable: true,
  },
  '11': {
    version: '11',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v11',
    knockingSupported: true,
    restrictedJoinsSupported: true,
    integerPowerLevels: true,
    updatedRedactionRules: true,
    authRuleVariant: 'v10',
    knockRestrictedSupported: true,
    stable: true,
  },
  '12': {
    version: '12',
    stateResolution: 'v2',
    eventIdFormat: 'v4',
    redactionAlgorithm: 'v11',
    knockingSupported: true,
    restrictedJoinsSupported: true,
    integerPowerLevels: true,
    updatedRedactionRules: true,
    authRuleVariant: 'v10',
    knockRestrictedSupported: true,
    stable: true,
  },
};

/** Get room version behavior. Returns null for unsupported versions. */
export function getRoomVersion(version: string): RoomVersionBehavior | null {
  return ROOM_VERSIONS[version] ?? null;
}

/** Check if a room version is supported */
export function isRoomVersionSupported(version: string): boolean {
  return version in ROOM_VERSIONS;
}

/** Get the default room version */
export function getDefaultRoomVersion(): string {
  return '10';
}

/** Get all supported room versions */
export function getSupportedRoomVersions(): Record<string, 'stable' | 'unstable'> {
  const result: Record<string, 'stable' | 'unstable'> = {};
  for (const [version, behavior] of Object.entries(ROOM_VERSIONS)) {
    result[version] = behavior.stable ? 'stable' : 'unstable';
  }
  return result;
}

/** Keys to preserve during redaction, per spec. Version-dependent. */
export function getRedactionAllowedKeys(
  eventType: string,
  roomVersion: RoomVersionBehavior
): string[] {
  // Keys always preserved for all event types
  const baseKeys = [
    'event_id', 'type', 'room_id', 'sender', 'state_key',
    'hashes', 'signatures', 'depth', 'prev_events', 'auth_events',
    'origin_server_ts',
  ];

  // Content keys preserved per event type
  const contentKeys: Record<string, string[]> = {
    'm.room.member': ['membership', 'join_authorised_via_users_server'],
    'm.room.create': ['creator'],
    'm.room.join_rules': ['join_rule', 'allow'],
    'm.room.power_levels': [
      'ban', 'events', 'events_default', 'invite', 'kick',
      'redact', 'state_default', 'users', 'users_default',
    ],
    'm.room.history_visibility': ['history_visibility'],
  };

  if (roomVersion.updatedRedactionRules) {
    // v11+ preserves additional keys
    contentKeys['m.room.member'] = [
      'membership', 'join_authorised_via_users_server', 'third_party_invite',
    ];
    contentKeys['m.room.create'] = ['creator', 'room_version'];
    contentKeys['m.room.power_levels'] = [
      'ban', 'events', 'events_default', 'invite', 'kick',
      'redact', 'state_default', 'users', 'users_default', 'notifications',
    ];
    contentKeys['m.room.redaction'] = ['redacts'];
  }

  return [...baseKeys, ...(contentKeys[eventType] || [])];
}

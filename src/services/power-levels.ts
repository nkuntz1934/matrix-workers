// Power level checking for Matrix rooms
// https://spec.matrix.org/v1.12/client-server-api/#mroompower_levels

import type { RoomPowerLevelsContent, RoomCreateContent } from '../types/matrix';
import { getStateEvent } from './database';

/**
 * Result of a power level check
 */
export interface PowerLevelCheckResult {
  allowed: boolean;
  userLevel: number;
  requiredLevel: number;
  reason?: string;
}

/**
 * Get a user's power level in a room
 */
export async function getUserPowerLevel(
  db: D1Database,
  roomId: string,
  userId: string
): Promise<number> {
  // Get the power levels event
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  if (!powerLevelsEvent) {
    // No power levels event - use defaults
    // Room creator has 100, others have 0
    const createEvent = await getStateEvent(db, roomId, 'm.room.create');
    if (createEvent) {
      const content = createEvent.content as RoomCreateContent;
      // In room versions < 11, creator is in content
      // In room versions >= 11, creator is the sender
      const creator = content.creator || createEvent.sender;
      if (creator === userId) {
        return 100;
      }
    }
    return 0;
  }

  const content = powerLevelsEvent.content as RoomPowerLevelsContent;
  return content.users?.[userId] ?? content.users_default ?? 0;
}

/**
 * Get the required power level to send a specific event type
 */
export async function getRequiredPowerLevel(
  db: D1Database,
  roomId: string,
  eventType: string,
  isStateEvent: boolean
): Promise<number> {
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  if (!powerLevelsEvent) {
    // Default power levels per spec
    // State events require 50, message events require 0
    return isStateEvent ? 50 : 0;
  }

  const content = powerLevelsEvent.content as RoomPowerLevelsContent;

  // Check event-specific power level
  if (content.events && content.events[eventType] !== undefined) {
    return content.events[eventType];
  }

  // State events use state_default, message events use events_default
  if (isStateEvent) {
    return content.state_default ?? 50;
  }

  return content.events_default ?? 0;
}

/**
 * Check if a user can send a state event
 */
export async function canSendStateEvent(
  db: D1Database,
  roomId: string,
  userId: string,
  eventType: string,
  stateKey: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const requiredLevel = await getRequiredPowerLevel(db, roomId, eventType, true);

  // Special case: m.room.member events for self
  // Users can always set their own membership to 'leave'
  if (eventType === 'm.room.member' && stateKey === userId) {
    return {
      allowed: true,
      userLevel,
      requiredLevel: 0,
    };
  }

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

/**
 * Check if a user can send a message event
 */
export async function canSendMessageEvent(
  db: D1Database,
  roomId: string,
  userId: string,
  eventType: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const requiredLevel = await getRequiredPowerLevel(db, roomId, eventType, false);

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

/**
 * Check if a user can modify power levels
 * This has additional restrictions beyond normal state events
 */
export async function canModifyPowerLevels(
  db: D1Database,
  roomId: string,
  userId: string,
  newContent: RoomPowerLevelsContent
): Promise<PowerLevelCheckResult> {
  // First check if user can send m.room.power_levels at all
  const basicCheck = await canSendStateEvent(db, roomId, userId, 'm.room.power_levels', '');
  if (!basicCheck.allowed) {
    return basicCheck;
  }

  const userLevel = basicCheck.userLevel;
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');
  const currentContent = powerLevelsEvent?.content as RoomPowerLevelsContent | undefined;

  // Check user power level changes
  if (newContent.users) {
    for (const [targetUserId, newLevel] of Object.entries(newContent.users)) {
      const currentLevel = currentContent?.users?.[targetUserId] ?? currentContent?.users_default ?? 0;

      // Cannot set power level higher than own
      if (newLevel > userLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: newLevel,
          reason: `Cannot set power level higher than own (${userLevel}) for ${targetUserId}`,
        };
      }

      // Cannot change power level of user with equal or higher power (unless it's self)
      if (targetUserId !== userId && currentLevel >= userLevel && newLevel !== currentLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: currentLevel,
          reason: `Cannot change power level of ${targetUserId} who has equal or higher power`,
        };
      }
    }
  }

  // Check changes to default levels and action levels
  const numericFields: (keyof RoomPowerLevelsContent)[] = [
    'ban',
    'events_default',
    'invite',
    'kick',
    'redact',
    'state_default',
    'users_default',
  ];

  for (const field of numericFields) {
    const newValue = newContent[field] as number | undefined;
    const currentValue = currentContent?.[field] as number | undefined;

    if (newValue !== undefined && newValue !== currentValue) {
      // Cannot set a level higher than own power
      if (newValue > userLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: newValue,
          reason: `Cannot set ${field} to ${newValue}, which is higher than own power level (${userLevel})`,
        };
      }

      // Cannot change if current value is >= own power level
      if (currentValue !== undefined && currentValue >= userLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: currentValue,
          reason: `Cannot change ${field} from ${currentValue}, which is >= own power level (${userLevel})`,
        };
      }
    }
  }

  // Check changes to event-specific power levels
  if (newContent.events) {
    for (const [eventType, newLevel] of Object.entries(newContent.events)) {
      const currentLevel = currentContent?.events?.[eventType];

      // Cannot set higher than own power
      if (newLevel > userLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: newLevel,
          reason: `Cannot set power level for ${eventType} to ${newLevel}, which is higher than own power level (${userLevel})`,
        };
      }

      // Cannot change if current level is >= own power level
      if (currentLevel !== undefined && currentLevel >= userLevel && newLevel !== currentLevel) {
        return {
          allowed: false,
          userLevel,
          requiredLevel: currentLevel,
          reason: `Cannot change power level for ${eventType} from ${currentLevel}, which is >= own power level (${userLevel})`,
        };
      }
    }
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel: basicCheck.requiredLevel,
  };
}

/**
 * Check if a user can invite to a room
 */
export async function canInvite(
  db: D1Database,
  roomId: string,
  userId: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  let requiredLevel = 0; // Default invite level
  if (powerLevelsEvent) {
    const content = powerLevelsEvent.content as RoomPowerLevelsContent;
    requiredLevel = content.invite ?? 0;
  }

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level to invite: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

/**
 * Check if a user can kick from a room
 */
export async function canKick(
  db: D1Database,
  roomId: string,
  userId: string,
  targetUserId: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const targetLevel = await getUserPowerLevel(db, roomId, targetUserId);
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  let requiredLevel = 50; // Default kick level
  if (powerLevelsEvent) {
    const content = powerLevelsEvent.content as RoomPowerLevelsContent;
    requiredLevel = content.kick ?? 50;
  }

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level to kick: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  if (userLevel <= targetLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel: targetLevel + 1,
      reason: `Cannot kick user with equal or higher power level`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

/**
 * Check if a user can ban from a room
 */
export async function canBan(
  db: D1Database,
  roomId: string,
  userId: string,
  targetUserId: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const targetLevel = await getUserPowerLevel(db, roomId, targetUserId);
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  let requiredLevel = 50; // Default ban level
  if (powerLevelsEvent) {
    const content = powerLevelsEvent.content as RoomPowerLevelsContent;
    requiredLevel = content.ban ?? 50;
  }

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level to ban: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  if (userLevel <= targetLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel: targetLevel + 1,
      reason: `Cannot ban user with equal or higher power level`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

/**
 * Check if a user can redact events
 */
export async function canRedact(
  db: D1Database,
  roomId: string,
  userId: string,
  eventSenderId?: string
): Promise<PowerLevelCheckResult> {
  const userLevel = await getUserPowerLevel(db, roomId, userId);
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  // Users can always redact their own events
  if (eventSenderId === userId) {
    return {
      allowed: true,
      userLevel,
      requiredLevel: 0,
    };
  }

  let requiredLevel = 50; // Default redact level
  if (powerLevelsEvent) {
    const content = powerLevelsEvent.content as RoomPowerLevelsContent;
    requiredLevel = content.redact ?? 50;
  }

  if (userLevel < requiredLevel) {
    return {
      allowed: false,
      userLevel,
      requiredLevel,
      reason: `Insufficient power level to redact: have ${userLevel}, need ${requiredLevel}`,
    };
  }

  return {
    allowed: true,
    userLevel,
    requiredLevel,
  };
}

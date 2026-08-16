// Matrix error handling utilities

import { ErrorCodes, type ErrorCode, type MatrixError } from '../types';

export class MatrixApiError extends Error {
  public readonly errcode: ErrorCode;
  public readonly status: number;
  public readonly retryAfterMs?: number;

  constructor(errcode: ErrorCode, message: string, status: number = 400, retryAfterMs?: number) {
    super(message);
    this.name = 'MatrixApiError';
    this.errcode = errcode;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }

  toJSON(): MatrixError {
    const error: MatrixError = {
      errcode: this.errcode,
      error: this.message,
    };
    if (this.retryAfterMs) {
      error.retry_after_ms = this.retryAfterMs;
    }
    return error;
  }

  toResponse(): Response {
    return new Response(JSON.stringify(this.toJSON()), {
      status: this.status,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Common error factories
export const Errors = {
  forbidden(message: string = 'Forbidden'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_FORBIDDEN, message, 403);
  },

  unknownToken(message: string = 'Unknown token'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_UNKNOWN_TOKEN, message, 401);
  },

  missingToken(message: string = 'Missing access token'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_MISSING_TOKEN, message, 401);
  },

  badJson(message: string = 'Could not parse request body as JSON'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_BAD_JSON, message, 400);
  },

  notJson(message: string = 'Content-Type must be application/json'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_NOT_JSON, message, 400);
  },

  notFound(message: string = 'Not found'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_NOT_FOUND, message, 404);
  },

  limitExceeded(message: string = 'Rate limit exceeded', retryAfterMs?: number): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_LIMIT_EXCEEDED, message, 429, retryAfterMs);
  },

  unknown(message: string = 'An unknown error occurred'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_UNKNOWN, message, 500);
  },

  unrecognized(message: string = 'Unrecognized request'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_UNRECOGNIZED, message, 400);
  },

  unauthorized(message: string = 'Unauthorized'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_UNAUTHORIZED, message, 401);
  },

  userDeactivated(message: string = 'User account has been deactivated'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_USER_DEACTIVATED, message, 403);
  },

  userInUse(message: string = 'User ID already taken'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_USER_IN_USE, message, 400);
  },

  invalidUsername(message: string = 'Invalid username'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_INVALID_USERNAME, message, 400);
  },

  roomInUse(message: string = 'Room alias already taken'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_ROOM_IN_USE, message, 400);
  },

  invalidRoomState(message: string = 'Invalid room state'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_INVALID_ROOM_STATE, message, 400);
  },

  unsupportedRoomVersion(message: string = 'Unsupported room version'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_UNSUPPORTED_ROOM_VERSION, message, 400);
  },

  guestAccessForbidden(message: string = 'Guest access forbidden'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_GUEST_ACCESS_FORBIDDEN, message, 403);
  },

  missingParam(param: string): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_MISSING_PARAM, `Missing required parameter: ${param}`, 400);
  },

  invalidParam(param: string, message?: string): MatrixApiError {
    return new MatrixApiError(
      ErrorCodes.M_INVALID_PARAM,
      message || `Invalid parameter: ${param}`,
      400
    );
  },

  tooLarge(message: string = 'Request too large'): MatrixApiError {
    return new MatrixApiError(ErrorCodes.M_TOO_LARGE, message, 413);
  },

  conflict(message: string = 'State changed concurrently; retry the operation'): MatrixApiError {
    // 409 Conflict — the auth basis for the request was invalidated by a
    // concurrent state change. Standard Matrix has no errcode for this case
    // (see issue 009), so we use a non-standard M_CONFLICT and document it.
    return new MatrixApiError(ErrorCodes.M_CONFLICT, message, 409);
  },
};

// Wrap an async handler with error handling
export function withErrorHandler<T>(
  handler: () => Promise<T>
): Promise<T | Response> {
  return handler().catch((error) => {
    if (error instanceof MatrixApiError) {
      return error.toResponse();
    }

    console.error('Unexpected error:', error);
    return Errors.unknown().toResponse();
  });
}

// JSON response helper
export function jsonResponse(data: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Empty response helper
export function emptyResponse(status: number = 200): Response {
  return new Response(JSON.stringify({}), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

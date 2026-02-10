// Application Service API
// Implements: https://spec.matrix.org/v1.12/application-service-api/

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { getAppServiceByToken } from '../services/appservice';
import { getUserById } from '../services/database';

const app = new Hono<AppEnv>();

// Middleware to authenticate requests from application services
async function requireAppServiceAuth(c: any, next: () => Promise<void>): Promise<Response | void> {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return Errors.missingToken('Missing AS token').toResponse();
  }

  const token = authHeader.slice(7);
  const appservice = await getAppServiceByToken(c.env.DB, token);
  if (!appservice) {
    return Errors.unknownToken('Invalid AS token').toResponse();
  }

  c.set('appservice', appservice);
  return next();
}

// GET /_matrix/app/v1/users/:userId - Query if a user exists (AS → HS direction)
app.get('/_matrix/app/v1/users/:userId', requireAppServiceAuth, async (c) => {
  const userId = c.req.param('userId');
  const user = await getUserById(c.env.DB, userId);

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  return c.json({});
});

// GET /_matrix/app/v1/rooms/:roomAlias - Query if a room alias exists
app.get('/_matrix/app/v1/rooms/:roomAlias', requireAppServiceAuth, async (c) => {
  const roomAlias = c.req.param('roomAlias');

  const result = await c.env.DB.prepare(
    `SELECT room_id FROM room_aliases WHERE alias = ?`
  ).bind(roomAlias).first<{ room_id: string }>();

  if (!result) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  return c.json({});
});

// GET /_matrix/app/v1/thirdparty/protocol/:protocol - Get third party protocol info
app.get('/_matrix/app/v1/thirdparty/protocol/:protocol', requireAppServiceAuth, async (c) => {
  // Stub - return empty protocol info
  return c.json({
    user_fields: [],
    location_fields: [],
    field_types: {},
    instances: [],
  });
});

// GET /_matrix/app/v1/thirdparty/user/:protocol - Lookup third party users
app.get('/_matrix/app/v1/thirdparty/user/:protocol', requireAppServiceAuth, async (c) => {
  return c.json([]);
});

// GET /_matrix/app/v1/thirdparty/location/:protocol - Lookup third party locations
app.get('/_matrix/app/v1/thirdparty/location/:protocol', requireAppServiceAuth, async (c) => {
  return c.json([]);
});

export default app;

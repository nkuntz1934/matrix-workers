// Application Service management

export interface AppServiceRegistration {
  id: string;
  url: string;
  as_token: string;
  hs_token: string;
  sender_localpart: string;
  rate_limited: boolean;
  protocols: string[];
  namespaces: {
    users: Array<{ exclusive: boolean; regex: string }>;
    rooms: Array<{ exclusive: boolean; regex: string }>;
    aliases: Array<{ exclusive: boolean; regex: string }>;
  };
}

/** Get all registered application services */
export async function getAppServices(db: D1Database): Promise<AppServiceRegistration[]> {
  const result = await db.prepare(
    `SELECT id, url, as_token, hs_token, sender_localpart, rate_limited, protocols, namespaces
     FROM appservice_registrations`
  ).all<{
    id: string;
    url: string;
    as_token: string;
    hs_token: string;
    sender_localpart: string;
    rate_limited: number;
    protocols: string | null;
    namespaces: string;
  }>();

  return result.results.map(r => ({
    id: r.id,
    url: r.url,
    as_token: r.as_token,
    hs_token: r.hs_token,
    sender_localpart: r.sender_localpart,
    rate_limited: r.rate_limited === 1,
    protocols: r.protocols ? JSON.parse(r.protocols) : [],
    namespaces: JSON.parse(r.namespaces),
  }));
}

/** Find app service by AS token */
export async function getAppServiceByToken(db: D1Database, asToken: string): Promise<AppServiceRegistration | null> {
  const result = await db.prepare(
    `SELECT id, url, as_token, hs_token, sender_localpart, rate_limited, protocols, namespaces
     FROM appservice_registrations WHERE as_token = ?`
  ).bind(asToken).first<{
    id: string;
    url: string;
    as_token: string;
    hs_token: string;
    sender_localpart: string;
    rate_limited: number;
    protocols: string | null;
    namespaces: string;
  }>();

  if (!result) return null;

  return {
    id: result.id,
    url: result.url,
    as_token: result.as_token,
    hs_token: result.hs_token,
    sender_localpart: result.sender_localpart,
    rate_limited: result.rate_limited === 1,
    protocols: result.protocols ? JSON.parse(result.protocols) : [],
    namespaces: JSON.parse(result.namespaces),
  };
}

/** Check if a user ID matches any exclusive AS namespace */
export function isExclusiveAppServiceUser(
  appservices: AppServiceRegistration[],
  userId: string,
  excludeAsId?: string
): AppServiceRegistration | null {
  for (const as of appservices) {
    if (excludeAsId && as.id === excludeAsId) continue;
    for (const ns of as.namespaces.users) {
      if (ns.exclusive && new RegExp(ns.regex).test(userId)) {
        return as;
      }
    }
  }
  return null;
}

/** Check if a room alias matches any exclusive AS namespace */
export function isExclusiveAppServiceAlias(
  appservices: AppServiceRegistration[],
  alias: string,
  excludeAsId?: string
): AppServiceRegistration | null {
  for (const as of appservices) {
    if (excludeAsId && as.id === excludeAsId) continue;
    for (const ns of as.namespaces.aliases) {
      if (ns.exclusive && new RegExp(ns.regex).test(alias)) {
        return as;
      }
    }
  }
  return null;
}

/** Check if an event interests any app service */
export function getInterestedAppServices(
  appservices: AppServiceRegistration[],
  event: { room_id: string; sender: string; state_key?: string; type: string }
): AppServiceRegistration[] {
  const interested: AppServiceRegistration[] = [];

  for (const as of appservices) {
    let isInterested = false;

    // Check user namespace matches (sender or state_key for membership events)
    for (const ns of as.namespaces.users) {
      if (new RegExp(ns.regex).test(event.sender)) {
        isInterested = true;
        break;
      }
      if (event.state_key && new RegExp(ns.regex).test(event.state_key)) {
        isInterested = true;
        break;
      }
    }

    // Check room namespace matches
    if (!isInterested) {
      for (const ns of as.namespaces.rooms) {
        if (new RegExp(ns.regex).test(event.room_id)) {
          isInterested = true;
          break;
        }
      }
    }

    if (isInterested) {
      interested.push(as);
    }
  }

  return interested;
}

/** Send transaction to an app service */
export async function sendAppServiceTransaction(
  db: D1Database,
  appservice: AppServiceRegistration,
  events: Record<string, unknown>[]
): Promise<boolean> {
  // Store the transaction
  const txnResult = await db.prepare(
    `INSERT INTO appservice_transactions (appservice_id, events, created_at)
     VALUES (?, ?, ?)`
  ).bind(appservice.id, JSON.stringify(events), Date.now()).run();

  const txnId = txnResult.meta.last_row_id;

  try {
    const response = await fetch(`${appservice.url}/_matrix/app/v1/transactions/${txnId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${appservice.hs_token}`,
      },
      body: JSON.stringify({ events }),
    });

    if (response.ok) {
      await db.prepare(
        `UPDATE appservice_transactions SET sent_at = ? WHERE txn_id = ?`
      ).bind(Date.now(), txnId).run();
      return true;
    }
  } catch (err) {
    console.warn(`[appservice] Failed to send transaction to ${appservice.id}:`, err);
  }

  // Increment retry
  await db.prepare(
    `UPDATE appservice_transactions SET retry_count = retry_count + 1 WHERE txn_id = ?`
  ).bind(txnId).run();

  return false;
}

// Federation Queue Consumer
// Processes outbound federation transactions via Cloudflare Queues

import type { Env } from '../types';
import { signJson } from '../utils/crypto';

interface FederationQueueMessage {
  destination: string;
  pdu?: Record<string, unknown>;
  edu?: { edu_type: string; content: Record<string, unknown> };
  timestamp: number;
}

interface FederationBatch {
  pdus: Record<string, unknown>[];
  edus: Array<{ edu_type: string; content: Record<string, unknown> }>;
}

export async function handleFederationQueue(
  batch: MessageBatch<FederationQueueMessage>,
  env: Env
): Promise<void> {
  // Group messages by destination
  const byDestination = new Map<string, FederationBatch>();

  for (const message of batch.messages) {
    const { destination, pdu, edu } = message.body;
    if (!byDestination.has(destination)) {
      byDestination.set(destination, { pdus: [], edus: [] });
    }
    const group = byDestination.get(destination)!;
    if (pdu) group.pdus.push(pdu);
    if (edu) group.edus.push(edu);
  }

  // Send transactions to each destination
  const results = await Promise.allSettled(
    Array.from(byDestination.entries()).map(async ([destination, data]) => {
      return sendFederationTransaction(env, destination, data);
    })
  );

  // Retry failed messages
  for (let i = 0; i < batch.messages.length; i++) {
    const msg = batch.messages[i];
    const destination = msg.body.destination;

    // Check if this destination's send succeeded
    const entries = Array.from(byDestination.keys());
    const destIndex = entries.indexOf(destination);
    const result = results[destIndex];

    if (result.status === 'rejected' || (result.status === 'fulfilled' && !result.value)) {
      // Retry with exponential backoff
      if (msg.attempts < 5) {
        msg.retry({ delaySeconds: Math.pow(2, msg.attempts) * 60 });
      } else {
        // Give up after 5 attempts - message goes to DLQ if configured
        msg.ack();
      }
    } else {
      msg.ack();
    }
  }
}

async function sendFederationTransaction(
  env: Env,
  destination: string,
  data: FederationBatch
): Promise<boolean> {
  const txnId = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

  // Get signing key
  const signingKey = await env.DB.prepare(
    `SELECT key_id, private_key_jwk FROM server_keys WHERE is_current = 1 AND key_version = 2`
  ).first<{ key_id: string; private_key_jwk: string | null }>();

  let body: Record<string, unknown> = {
    pdus: data.pdus,
    edus: data.edus,
    origin: env.SERVER_NAME,
    origin_server_ts: Date.now(),
  };

  // Sign the transaction if we have a key
  if (signingKey?.private_key_jwk) {
    body = await signJson(
      body,
      env.SERVER_NAME,
      signingKey.key_id,
      JSON.parse(signingKey.private_key_jwk)
    );
  }

  try {
    const response = await fetch(
      `https://${destination}/_matrix/federation/v1/send/${txnId}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return response.ok;
  } catch (err) {
    console.error(`[federation-consumer] Failed to send to ${destination}:`, err);
    return false;
  }
}

// Email Service using Resend API
// Used for 3PID email verification

import type { Env } from '../types/env';

interface ResendEmailResponse {
  id?: string;
  error?: string;
  message?: string;
}

/**
 * Generate a 6-digit verification code
 */
export function generateVerificationToken(): string {
  // Generate a secure random 6-digit code
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  // Ensure 6 digits (100000-999999)
  const code = (array[0] % 900000) + 100000;
  return code.toString();
}

/**
 * Generate a unique session ID for email verification
 */
export async function generateSessionId(): Promise<string> {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Send a verification email with a 6-digit code via Resend API
 */
export async function sendVerificationEmail(
  env: Env,
  toEmail: string,
  token: string,
  serverName: string
): Promise<{ success: boolean; error?: string }> {
  const apiKey = env.RESEND_API_KEY;
  const fromEmail = env.EMAIL_FROM || `noreply@${serverName}`;

  if (!apiKey) {
    console.error('RESEND_API_KEY is not configured');
    return { success: false, error: 'Email service not configured' };
  }

  const subject = `Your ${serverName} verification code`;
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 20px 0; }
    .footer { margin-top: 30px; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Email Verification</h2>
    <p>Your verification code for ${serverName} is:</p>
    <div class="code">${token}</div>
    <p>Enter this code in your Matrix client to verify your email address.</p>
    <p>This code will expire in 24 hours.</p>
    <div class="footer">
      <p>If you didn't request this code, you can safely ignore this email.</p>
      <p>This email was sent from ${serverName}</p>
    </div>
  </div>
</body>
</html>
`;

  const textContent = `
Email Verification

Your verification code for ${serverName} is: ${token}

Enter this code in your Matrix client to verify your email address.

This code will expire in 24 hours.

If you didn't request this code, you can safely ignore this email.

This email was sent from ${serverName}
`;

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [toEmail],
        subject,
        html: htmlContent,
        text: textContent,
      }),
    });

    const result = await response.json() as ResendEmailResponse;

    if (!response.ok) {
      console.error('Resend API error:', result);
      return {
        success: false,
        error: result.message || result.error || 'Failed to send email'
      };
    }

    console.log(`Verification email sent to ${toEmail}, message id: ${result.id}`);
    return { success: true };
  } catch (error) {
    console.error('Error sending verification email:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to send email'
    };
  }
}

/**
 * Store an email verification session
 */
export async function createVerificationSession(
  db: D1Database,
  email: string,
  clientSecret: string,
  sendAttempt: number,
  userId?: string
): Promise<{ sessionId: string; token: string } | { error: string }> {
  const sessionId = await generateSessionId();
  const token = generateVerificationToken();
  const now = Date.now();
  const expiresAt = now + 24 * 60 * 60 * 1000; // 24 hours

  try {
    // Check if there's an existing session for this email/client_secret combo
    const existing = await db.prepare(`
      SELECT session_id, send_attempt, validated
      FROM email_verification_sessions
      WHERE email = ? AND client_secret = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(email, clientSecret).first<{
      session_id: string;
      send_attempt: number;
      validated: number;
    }>();

    if (existing) {
      // If already validated, reject
      if (existing.validated) {
        return { error: 'Email already validated for this session' };
      }

      // If send_attempt is same or lower, it's a retry - return existing session
      if (sendAttempt <= existing.send_attempt) {
        // Return existing session without sending new email
        return {
          sessionId: existing.session_id,
          token: '' // Don't return token on retry
        };
      }

      // Delete old session for new attempt
      await db.prepare(`
        DELETE FROM email_verification_sessions WHERE session_id = ?
      `).bind(existing.session_id).run();
    }

    // Create new session
    await db.prepare(`
      INSERT INTO email_verification_sessions
      (session_id, email, user_id, client_secret, token, send_attempt, validated, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).bind(
      sessionId,
      email,
      userId || null,
      clientSecret,
      token,
      sendAttempt,
      now,
      expiresAt
    ).run();

    return { sessionId, token };
  } catch (error) {
    console.error('Error creating verification session:', error);
    return { error: 'Failed to create verification session' };
  }
}

/**
 * Validate an email verification token
 */
export async function validateEmailToken(
  db: D1Database,
  sessionId: string,
  clientSecret: string,
  token: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const session = await db.prepare(`
      SELECT session_id, email, client_secret, token, validated, expires_at
      FROM email_verification_sessions
      WHERE session_id = ?
    `).bind(sessionId).first<{
      session_id: string;
      email: string;
      client_secret: string;
      token: string;
      validated: number;
      expires_at: number;
    }>();

    if (!session) {
      return { success: false, error: 'Session not found' };
    }

    // Check if already validated
    if (session.validated) {
      return { success: true };
    }

    // Check expiry
    if (Date.now() > session.expires_at) {
      return { success: false, error: 'Session expired' };
    }

    // Verify client_secret matches
    if (session.client_secret !== clientSecret) {
      return { success: false, error: 'Invalid client_secret' };
    }

    // Verify token
    if (session.token !== token) {
      return { success: false, error: 'Invalid token' };
    }

    // Mark as validated
    await db.prepare(`
      UPDATE email_verification_sessions
      SET validated = 1, validated_at = ?
      WHERE session_id = ?
    `).bind(Date.now(), sessionId).run();

    return { success: true };
  } catch (error) {
    console.error('Error validating email token:', error);
    return { success: false, error: 'Validation failed' };
  }
}

/**
 * Get a validated session
 */
export async function getValidatedSession(
  db: D1Database,
  sessionId: string,
  clientSecret: string
): Promise<{ email: string; userId?: string } | null> {
  const session = await db.prepare(`
    SELECT email, user_id, client_secret, validated
    FROM email_verification_sessions
    WHERE session_id = ? AND validated = 1
  `).bind(sessionId).first<{
    email: string;
    user_id: string | null;
    client_secret: string;
    validated: number;
  }>();

  if (!session || session.client_secret !== clientSecret) {
    return null;
  }

  return {
    email: session.email,
    userId: session.user_id || undefined,
  };
}

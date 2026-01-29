-- Identity Provider (IdP) configuration for OIDC SSO
-- Allows users to authenticate via external identity providers

-- IdP Provider configurations
CREATE TABLE IF NOT EXISTS idp_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,                          -- Display name (e.g., "Google", "Okta")
    issuer_url TEXT NOT NULL,                    -- OIDC issuer URL (e.g., https://accounts.google.com)
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,       -- Encrypted client secret
    scopes TEXT NOT NULL DEFAULT 'openid profile email',
    enabled INTEGER NOT NULL DEFAULT 1,
    auto_create_users INTEGER NOT NULL DEFAULT 1,
    username_claim TEXT NOT NULL DEFAULT 'email', -- Claim to derive username from (email, preferred_username, sub)
    display_order INTEGER NOT NULL DEFAULT 0,    -- Order to display on login page
    icon_url TEXT,                               -- Optional icon URL
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE INDEX IF NOT EXISTS idx_idp_providers_enabled ON idp_providers(enabled);

-- Link external IdP identities to Matrix users
CREATE TABLE IF NOT EXISTS idp_user_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    external_id TEXT NOT NULL,                   -- The 'sub' claim from the IdP
    user_id TEXT NOT NULL,                       -- Matrix user ID
    external_email TEXT,                         -- Email from IdP (for reference)
    external_name TEXT,                          -- Display name from IdP (for reference)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    last_login_at INTEGER,
    FOREIGN KEY (provider_id) REFERENCES idp_providers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE (provider_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_idp_user_links_provider ON idp_user_links(provider_id);
CREATE INDEX IF NOT EXISTS idx_idp_user_links_user ON idp_user_links(user_id);
CREATE INDEX IF NOT EXISTS idx_idp_user_links_external ON idp_user_links(provider_id, external_id);

# Deployment Guide

Complete guide to deploying your own Matrix homeserver on Cloudflare Workers.

## Table of Contents

- [Deploy Button (Quick Start)](#deploy-button-quick-start)
- [Manual Deployment](#manual-deployment)
  - [Prerequisites](#prerequisites)
  - [Step 1: Clone and Install](#step-1-clone-and-install)
  - [Step 2: Create Cloudflare Resources](#step-2-create-cloudflare-resources)
  - [Step 3: Configure wrangler.jsonc](#step-3-configure-wranglerjsonc)
  - [Step 4: Run Database Migrations](#step-4-run-database-migrations)
  - [Step 5: Deploy](#step-5-deploy)
  - [Step 6: Configure Your Domain](#step-6-configure-your-domain)
  - [Step 7: Verify Deployment](#step-7-verify-deployment)
- [Optional Features](#optional-features)
- [Troubleshooting](#troubleshooting)

---

## Deploy Button (Quick Start)

The fastest way to deploy is using the Deploy to Cloudflare button:

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nkuntz1934/matrix-workers)

### What the Deploy Button Does

When you click the button, Cloudflare will:

1. **Fork the repository** to your GitHub/GitLab account
2. **Provision resources automatically**:
   - D1 database
   - All KV namespaces (SESSIONS, DEVICE_KEYS, CACHE, etc.)
   - R2 bucket for media storage
   - Durable Objects
   - Workflows
3. **Deploy the Worker** to your Cloudflare account
4. **Set up Workers Builds** for continuous deployment from your forked repo

### After Using the Deploy Button

You still need to complete these steps manually:

#### 1. Update SERVER_NAME

The `SERVER_NAME` environment variable must match your domain. Update it in your Cloudflare dashboard:

1. Go to [Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages)
2. Select your deployed Worker
3. Go to **Settings** → **Variables and Secrets**
4. Edit `SERVER_NAME` to your domain (e.g., `matrix.yourdomain.com`)
5. Click **Deploy** to apply changes

**Important:** `SERVER_NAME` cannot be changed after users register. Choose carefully.

#### 2. Run Database Migrations

The D1 database is created but empty. You must run all migrations:

1. Find your D1 database name in the Worker settings (under **D1 Database Bindings**)
2. Run each migration (replace `YOUR_DB_NAME` with your actual database name):

```bash
# Clone your forked repository locally
git clone https://github.com/YOUR_USERNAME/matrix-workers
cd matrix-workers

# Authenticate wrangler
npx wrangler login

# Run all migrations in order
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/schema.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/002_phase1_e2ee.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/003_account_management.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/004_reports_and_notices.sql
# Note: Two migrations share the 005 prefix (both must be run)
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/005_server_config.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/005_idp_providers.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/006_query_optimization.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/007_secure_server_keys.sql
npx wrangler d1 execute YOUR_DB_NAME --remote --file=migrations/008_federation_transactions.sql
```

#### 3. Configure Custom Domain

Your Worker is deployed at `*.workers.dev` but Matrix federation requires a proper domain:

1. Go to your Worker in the dashboard
2. Navigate to **Settings** → **Domains & Routes**
3. Click **Add** → **Custom Domain**
4. Enter your domain (e.g., `matrix.yourdomain.com`)
5. Cloudflare automatically configures DNS if your domain is on Cloudflare

#### 4. Verify Deployment

Test your deployment:

```bash
# Replace with your domain
curl https://matrix.yourdomain.com/_matrix/client/versions

# Check federation
curl https://matrix.yourdomain.com/_matrix/federation/v1/version
```

Run the [Federation Tester](https://federationtester.matrix.org) with your server name.

#### 5. Register Your First User

```bash
curl -X POST "https://matrix.yourdomain.com/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password",
    "auth": {"type": "m.login.dummy"}
  }'
```

---

## Manual Deployment

For more control, deploy manually using the steps below.

## Prerequisites

### Required

1. **Cloudflare Account** with Workers Paid plan ($5/month)
   - Required for Durable Objects, which are essential for real-time sync
   - Sign up at [cloudflare.com](https://cloudflare.com)

2. **Node.js 18+**
   ```bash
   node --version  # Should be v18.0.0 or higher
   ```

3. **Wrangler CLI**
   ```bash
   npm install -g wrangler
   wrangler --version
   ```

4. **Authenticate Wrangler**
   ```bash
   npx wrangler login
   ```
   This opens a browser to authenticate with your Cloudflare account.

5. **A Domain** managed by Cloudflare (for federation to work)
   - Matrix federation requires a proper domain name
   - The domain's DNS must be managed by Cloudflare

---

## Step 1: Clone and Install

```bash
git clone https://github.com/nkuntz1934/matrix-workers
cd matrix-workers
npm install
```

---

## Step 2: Create Cloudflare Resources

Run these commands and **save the output** - you'll need the IDs for configuration.

### 2.1 Get Your Account ID

```bash
npx wrangler whoami
```

Note your Account ID from the output.

### 2.2 Create D1 Database

```bash
npx wrangler d1 create my-matrix-db
```

Output will include:
```
Created D1 database 'my-matrix-db'
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Save the `database_id`.**

### 2.3 Create KV Namespaces

Create all 6 required KV namespaces:

```bash
npx wrangler kv namespace create SESSIONS
npx wrangler kv namespace create DEVICE_KEYS
npx wrangler kv namespace create CACHE
npx wrangler kv namespace create CROSS_SIGNING_KEYS
npx wrangler kv namespace create ACCOUNT_DATA
npx wrangler kv namespace create ONE_TIME_KEYS
```

Each command outputs an ID. **Save all 6 IDs.**

Example output:
```
Add the following to your wrangler configuration file:
kv_namespaces = [
  { binding = "SESSIONS", id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
]
```

### 2.4 Create R2 Bucket

```bash
npx wrangler r2 bucket create my-matrix-media
```

**Save the bucket name** (you chose it, so just remember it).

---

## Step 3: Configure wrangler.jsonc

Open `wrangler.jsonc` and replace all placeholder values with your actual IDs.

### 3.1 Basic Configuration

```jsonc
{
  "name": "my-matrix-server",           // Your worker name
  "account_id": "YOUR_ACCOUNT_ID",      // From npx wrangler whoami

  // ... rest of config
}
```

### 3.2 D1 Database

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "my-matrix-db",           // Name you chose
    "database_id": "YOUR_DATABASE_ID"          // From d1 create output
  }
]
```

### 3.3 KV Namespaces

```jsonc
"kv_namespaces": [
  { "binding": "SESSIONS", "id": "YOUR_SESSIONS_KV_ID" },
  { "binding": "DEVICE_KEYS", "id": "YOUR_DEVICE_KEYS_KV_ID" },
  { "binding": "CACHE", "id": "YOUR_CACHE_KV_ID" },
  { "binding": "CROSS_SIGNING_KEYS", "id": "YOUR_CROSS_SIGNING_KEYS_KV_ID" },
  { "binding": "ACCOUNT_DATA", "id": "YOUR_ACCOUNT_DATA_KV_ID" },
  { "binding": "ONE_TIME_KEYS", "id": "YOUR_ONE_TIME_KEYS_KV_ID" }
]
```

### 3.4 R2 Bucket

```jsonc
"r2_buckets": [
  {
    "binding": "MEDIA",
    "bucket_name": "my-matrix-media"    // Name you chose
  }
]
```

### 3.5 Environment Variables

```jsonc
"vars": {
  "SERVER_NAME": "matrix.yourdomain.com",   // Your Matrix server domain
  "SERVER_VERSION": "0.1.0"
}
```

**Important:** `SERVER_NAME` must match the domain you'll use for Matrix. This cannot be changed after users register.

### 3.6 Custom Domain (Optional but Recommended)

```jsonc
"routes": [
  {
    "pattern": "matrix.yourdomain.com",
    "custom_domain": true
  }
]
```

### 3.7 Remove Optional Features (If Not Using)

If you're not using LiveKit for video calls, remove or comment out:

```jsonc
// Remove these sections if not using LiveKit:
"vpc_services": [ ... ],
"vars": {
  // Remove these:
  "LIVEKIT_API_KEY": "...",
  "LIVEKIT_URL": "..."
}
```

---

## Step 4: Run Database Migrations

Apply all migrations to your D1 database:

```bash
# Replace 'my-matrix-db' with your actual database name

npx wrangler d1 execute my-matrix-db --remote --file=migrations/schema.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/002_phase1_e2ee.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/003_account_management.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/004_reports_and_notices.sql
# Note: Two migrations share the 005 prefix (both must be run)
npx wrangler d1 execute my-matrix-db --remote --file=migrations/005_server_config.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/005_idp_providers.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/006_query_optimization.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/007_secure_server_keys.sql
npx wrangler d1 execute my-matrix-db --remote --file=migrations/008_federation_transactions.sql
```

Each migration should complete with "success": true.

---

## Step 5: Deploy

```bash
npm run deploy
```

Or directly:

```bash
npx wrangler deploy
```

The output will show your worker URL (e.g., `my-matrix-server.your-subdomain.workers.dev`).

---

## Step 6: Configure Your Domain

### Option A: Cloudflare Custom Domain (Recommended)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **Workers & Pages** → Your Worker → **Settings** → **Domains & Routes**
3. Click **Add** → **Custom Domain**
4. Enter your domain (e.g., `matrix.yourdomain.com`)
5. Cloudflare automatically configures DNS

### Option B: Manual DNS Setup

If using manual DNS, add these records:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| CNAME | matrix | your-worker.workers.dev | Proxied |

### Required: .well-known Endpoints

Matrix clients and servers need `.well-known` endpoints. These are automatically served by the worker at:

- `https://matrix.yourdomain.com/.well-known/matrix/server`
- `https://matrix.yourdomain.com/.well-known/matrix/client`

### Federation DNS (For Server-to-Server Communication)

For full federation support, ensure your domain resolves correctly. The worker handles the `.well-known` responses automatically.

---

## Step 7: Verify Deployment

### 7.1 Check Basic Endpoints

```bash
# Replace with your domain
export MATRIX_SERVER="https://matrix.yourdomain.com"

# Check server is responding
curl -s "$MATRIX_SERVER/_matrix/client/versions" | jq .

# Check well-known endpoints
curl -s "$MATRIX_SERVER/.well-known/matrix/server" | jq .
curl -s "$MATRIX_SERVER/.well-known/matrix/client" | jq .

# Check federation keys
curl -s "$MATRIX_SERVER/_matrix/key/v2/server" | jq .

# Check federation version
curl -s "$MATRIX_SERVER/_matrix/federation/v1/version" | jq .
```

### 7.2 Run Federation Tester

Visit the Matrix Federation Tester:

```
https://federationtester.matrix.org/api/report?server_name=matrix.yourdomain.com
```

Look for `"FederationOK": true` in the response.

### 7.3 Register Your First User

```bash
curl -X POST "$MATRIX_SERVER/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-secure-password",
    "auth": {
      "type": "m.login.dummy"
    }
  }'
```

### 7.4 Test with Element

1. Open [Element Web](https://app.element.io)
2. Click **Sign In** → **Edit** homeserver
3. Enter your server URL: `https://matrix.yourdomain.com`
4. Sign in with your registered user

---

## Optional Features

### TURN Server (For Voice/Video Calls)

Cloudflare provides TURN servers. To enable:

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **Calls** → **TURN**
2. Create a TURN key
3. Add to `wrangler.jsonc`:
   ```jsonc
   "vars": {
     "TURN_KEY_ID": "your-turn-key-id"
   }
   ```
4. Set the secret:
   ```bash
   npx wrangler secret put TURN_API_TOKEN
   # Paste your TURN API token when prompted
   ```

### LiveKit (For MatrixRTC Video Calls)

If you have a LiveKit server:

1. Add to `wrangler.jsonc`:
   ```jsonc
   "vars": {
     "LIVEKIT_API_KEY": "your-api-key",
     "LIVEKIT_URL": "wss://your-livekit-server.com"
   }
   ```
2. Set the secret:
   ```bash
   npx wrangler secret put LIVEKIT_API_SECRET
   ```

### APNs Push Notifications (iOS)

For direct Apple Push Notification support:

```bash
npx wrangler secret put APNS_KEY_ID      # From Apple Developer Portal
npx wrangler secret put APNS_TEAM_ID     # Your Apple Team ID
npx wrangler secret put APNS_PRIVATE_KEY # Contents of .p8 file
```

### OIDC Authentication

For OpenID Connect login:

```bash
npx wrangler secret put OIDC_ENCRYPTION_KEY
# Generate with: openssl rand -base64 32
```

---

## Troubleshooting

### "Workers Paid plan required"

Durable Objects require the Workers Paid plan ($5/month). Upgrade at:
Cloudflare Dashboard → Workers & Pages → Plans

### "Database not found"

Ensure you've run all migrations and the database name in `wrangler.jsonc` matches what you created.

### Federation Test Fails

1. Verify your domain's DNS is managed by Cloudflare
2. Check `.well-known/matrix/server` returns correct content
3. Ensure the worker is deployed and responding
4. Check the signing key is generated (first request auto-generates it)

### "M_UNKNOWN" Errors

Check Cloudflare Workers logs:
```bash
npx wrangler tail
```

### Registration Disabled

Registration is enabled by default. If you've disabled it and need to create an admin:

```bash
# Connect to D1 directly
npx wrangler d1 execute my-matrix-db --remote --command "SELECT * FROM users LIMIT 5"
```

### Rate Limited

The server has rate limiting. Default limits:
- Login: 10 requests/minute
- Register: 5 requests/minute
- General API: 100 requests/minute

---

## Updating

To update your deployment:

```bash
git pull
npm install
npm run deploy
```

If there are new migrations, run them before deploying:

```bash
npx wrangler d1 execute my-matrix-db --remote --file=migrations/NEW_MIGRATION.sql
```

---

## Architecture Overview

Your deployed Matrix server uses:

| Component | Cloudflare Service | Purpose |
|-----------|-------------------|---------|
| API & Routing | Workers | HTTP request handling |
| Database | D1 | Users, rooms, events, messages |
| Sessions | KV | Access tokens, fast lookups |
| E2EE Keys | KV | Device keys, cross-signing |
| Media | R2 | Images, files, avatars |
| Real-time Sync | Durable Objects | Live updates, typing indicators |
| Federation | Durable Objects | Server-to-server communication |
| Background Jobs | Workflows | Room joins, push notifications |

---

## Support

- **Issues**: [GitHub Issues](https://github.com/nkuntz1934/matrix-workers/issues)
- **Matrix Spec**: [spec.matrix.org](https://spec.matrix.org)
- **Cloudflare Docs**: [developers.cloudflare.com](https://developers.cloudflare.com)

# Deploying Your Own Tuwunel Matrix Homeserver

This guide covers deploying a personal Matrix homeserver to your own Cloudflare account using this fork.

## Prerequisites

- Cloudflare account (free tier works for small personal deployments)
- Wrangler CLI: `npm install -g wrangler && wrangler login`
- Domain with Cloudflare DNS (e.g., `matrix.fuzzywigg.com`)
- Node.js 20+

## Step 1: Clone and Install

```bash
git clone https://github.com/fuzzywigg/matrix-workers
cd matrix-workers
npm install
```

## Step 2: Create Cloudflare Resources

You can run `bash scripts/setup.sh` to create these interactively, or run each command manually and save the IDs:

```bash
# D1 database
wrangler d1 create matrix-db
# → save the database_id

# KV namespaces (run each, save the id from output)
wrangler kv namespace create SESSIONS
wrangler kv namespace create DEVICE_KEYS
wrangler kv namespace create CACHE
wrangler kv namespace create CROSS_SIGNING_KEYS
wrangler kv namespace create ACCOUNT_DATA
wrangler kv namespace create ONE_TIME_KEYS

# R2 bucket for media
wrangler r2 bucket create matrix-media
```

## Step 3: Update wrangler.jsonc

`wrangler.jsonc` in this repo is checked in with the live `matrix.fuzzywigg.com` resource IDs. If you are deploying to a **different** Cloudflare account, replace these values with your own IDs from Step 2:

| Field | Replace with |
|---|---|
| `d1_databases[0].database_id` | D1 `database_id` from Step 2 |
| `kv_namespaces[*].id` | The matching namespace id for each of the six bindings (`SESSIONS`, `DEVICE_KEYS`, `CACHE`, `CROSS_SIGNING_KEYS`, `ACCOUNT_DATA`, `ONE_TIME_KEYS`) |
| `vars.SERVER_NAME` | Your domain (e.g. `matrix.example.com`) |
| `routes[0].pattern` | Your domain (or delete `routes` and configure a custom domain via the dashboard) |

Leave `d1_databases[0].database_name` as `matrix-db` — the `db:migrate` npm scripts target that name.

**Durable Objects**: all eight DO classes are already declared in the `migrations` array using `new_sqlite_classes` (tags `v1`–`v6`). This is required — every DO class must appear in a `new_sqlite_classes` migration entry. If you add a new DO later, add a **new** migration tag for it; never use `new_classes` (legacy KV-backed DOs, unavailable on the free plan) and never edit already-deployed tags.

## Step 4: Run Database Migrations

```bash
npm run db:migrate
```

This applies `migrations/schema.sql` (the base schema) to your remote D1 database. The numbered migration files (`migrations/002_*.sql` … `migrations/019_*.sql`) are **not** applied by this script — apply them in order afterwards:

```bash
for f in $(ls migrations/0*.sql | sort); do
  npx wrangler d1 execute matrix-db --remote --file="$f"
done
```

(Note: two files share the `005` prefix and two share `017` — the loop above runs all of them.)

## Step 5: Set Required Secrets

```bash
wrangler secret put SIGNING_KEY
# Generate with: openssl rand -base64 32

wrangler secret put OIDC_ENCRYPTION_KEY
# Generate with: openssl rand -base64 32
```

Optional secrets (for TURN/LiveKit/email):
```bash
wrangler secret put TURN_API_TOKEN
wrangler secret put LIVEKIT_API_SECRET
wrangler secret put EMAIL_FROM        # e.g. "noreply@matrix.fuzzywigg.com"
```

## Step 6: Deploy

```bash
wrangler deploy
```

## Step 7: Configure DNS

In your Cloudflare DNS dashboard, add:
- **Type**: CNAME
- **Name**: `matrix` (for `matrix.fuzzywigg.com`)
- **Target**: `matrix-worker.<your-subdomain>.workers.dev`
- **Proxied**: Yes

Or use Cloudflare dashboard → Workers & Pages → your worker → Custom Domains → Add.

## Step 8: Test Your Deployment

```bash
# Health check
curl https://matrix.fuzzywigg.com/health

# Matrix version endpoint
curl https://matrix.fuzzywigg.com/_matrix/client/versions

# Check federation
curl https://matrix.fuzzywigg.com/_matrix/federation/v1/version
```

## Step 9: Optional — Federation Setup

To allow other Matrix servers to federate with you, add a `.well-known` record at your root domain.

For `fuzzywigg.com/.well-known/matrix/server`:
```json
{"m.server": "matrix.fuzzywigg.com:443"}
```

For `smtp.eth` — this requires an ENS text record or an HTTP gateway that serves the JSON.

## Cost Estimate

| Resource | Free Tier | Paid ($5/mo plan) |
|---|---|---|
| Workers | 100K req/day | 10M req/day |
| D1 reads | 5M/day | 25M+/day |
| D1 writes | 100K/day | 50M+/day |
| KV reads | 100K/day | 10M/day |
| KV writes | 1K/day | 1M/day |
| R2 storage | 10GB | 10GB + $0.015/GB |
| R2 reads | 1M/month | 10M/month |

**Verdict**: Free tier is suitable for personal/family use with a few active users. Upgrade to $5/mo Workers Paid if you plan to run a small community.

## Recommended Domains for Andrew

- `matrix.fuzzywigg.com` — simplest, direct CNAME possible
- `matrix.smtp.eth` — requires ENS + HTTP gateway (more complex)
- `m.smtp.eth` — same as above

Start with `matrix.fuzzywigg.com` for the first deployment.

#!/bin/bash
# Tuwunel setup helper - creates required Cloudflare resources
# Run: bash scripts/setup.sh

set -euo pipefail

echo "=== Tuwunel Cloudflare Resource Setup ==="
echo ""
echo "This script creates the D1 database, KV namespaces, and R2 bucket"
echo "needed to deploy your own Matrix homeserver."
echo ""

read -r -p "Enter your Matrix server name (e.g. matrix.fuzzywigg.com): " SERVER_NAME

if [[ -z "$SERVER_NAME" ]]; then
  echo "Error: SERVER_NAME cannot be empty."
  exit 1
fi

echo ""
echo "Creating D1 database (matrix-db)..."
D1_OUTPUT=$(wrangler d1 create matrix-db 2>&1)
echo "$D1_OUTPUT"
D1_ID=$(echo "$D1_OUTPUT" | grep -o '"[a-f0-9-]\{36\}"' | head -1 | tr -d '"')

echo ""
echo "Creating KV namespaces..."
declare -A KV_IDS
for NS in SESSIONS DEVICE_KEYS CACHE CROSS_SIGNING_KEYS ACCOUNT_DATA ONE_TIME_KEYS; do
  echo "  Creating $NS..."
  NS_OUT=$(wrangler kv namespace create "$NS" 2>&1)
  KV_ID=$(echo "$NS_OUT" | grep -o '"id": "[^"]*"' | head -1 | sed 's/"id": "//;s/"//')
  KV_IDS["$NS"]="$KV_ID"
  echo "    $NS id: $KV_ID"
done

echo ""
echo "Creating R2 bucket (matrix-media)..."
wrangler r2 bucket create matrix-media

echo ""
echo "========================================"
echo "=== Setup complete! Resource IDs:    ==="
echo "========================================"
echo ""
echo "SERVER_NAME: $SERVER_NAME"
echo ""
echo "D1 database_id: $D1_ID"
echo ""
echo "KV namespace IDs:"
for NS in SESSIONS DEVICE_KEYS CACHE CROSS_SIGNING_KEYS ACCOUNT_DATA ONE_TIME_KEYS; do
  echo "  $NS: ${KV_IDS[$NS]}"
done
echo ""
echo "R2 bucket: matrix-media"
echo ""
echo "Next steps:"
echo "  1. Copy the IDs above into wrangler.jsonc"
echo "  2. Set SERVER_NAME to: $SERVER_NAME"
echo "  3. npm run db:migrate"
echo "  4. wrangler secret put SIGNING_KEY    # openssl rand -base64 32"
echo "  5. wrangler secret put OIDC_ENCRYPTION_KEY"
echo "  6. wrangler deploy"
echo ""
echo "See DEPLOY.md for full instructions."

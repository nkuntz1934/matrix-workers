# AGENTS.md — matrix-workers (Tuwunel)

parent_governance: github.com/fuzzywigg/agents-governance

## Classification

- **Tier**: A (Active Strategic)
- **Autonomy**: L1 (Bounded)
- **Stack**: TypeScript, Cloudflare Workers, D1, KV, R2, Durable Objects
- **Owner**: fuzzywigg (Andrew Pappas)
- **Purpose**: Personal Matrix homeserver for smtp.eth ecosystem

## Context

This is a fork of nkuntz1934/matrix-workers (Tuwunel), a Matrix Spec v1.17 homeserver running
entirely on Cloudflare's edge infrastructure. The live instance for this fork is
`matrix.fuzzywigg.com` (see `DEPLOY.md` and committed `wrangler.jsonc`).

Read `DEPLOY.md` before any deployment-related work.

## Agent Instructions

- `wrangler.jsonc` is checked in with the live `matrix.fuzzywigg.com` D1/KV resource IDs and `SERVER_NAME` (same fact as `DEPLOY.md`). Changing those IDs, bindings, or server name is HITL — do not invent, strip, or replace them
- **Never hardcode** credentials or secrets into source or docs; do not print live Cloudflare resource IDs in new documentation
- **Never modify existing migration files** — add a new numbered file instead
- When touching `src/services/database.ts` or `src/middleware/auth.ts`, flag for human review
- When touching `migrations/`, flag for human review before merging
- PRs that change federation key handling require human review
- Keep migration numbers strictly sequential — check existing files before numbering a new one

## Safe Agent Actions (L1 — no human required)

- Add or update tests in `test/`
- Update documentation (`README.md`, `DEPLOY.md`, `CLAUDE.md`, `AGENTS.md`)
- Add new migration files (never modify existing ones)
- Update CI/CD workflows in `.github/workflows/`
- Add TypeScript type definitions
- Performance improvements accompanied by benchmarks
- Dependency updates (devDependencies only) with no behavior changes
- Fix lint/type errors that don't change logic

## Escalate to Human (L0 — HITL required)

- Any migration schema changes (ALTER TABLE, DROP, data transforms)
- Auth middleware changes (`src/middleware/auth.ts`)
- Federation key handling changes
- Secrets, credentials, or encryption key handling
- Deploy to production (`wrangler deploy`)
- Any change that affects how sessions, tokens, or passwords are stored
- Wrangler config changes that affect resource bindings

## Deployment Notes

- Target CF account: Andrew's personal account (not nkuntz1934's `870e8509c92b6115e64a0cd8bb95ea97`)
- Preferred domain: `matrix.fuzzywigg.com`
- Run `bash scripts/setup.sh` to create CF resources interactively
- Full deploy guide: `DEPLOY.md`

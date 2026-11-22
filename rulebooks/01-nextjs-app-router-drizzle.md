# Next.js App Router + Drizzle ORM + PostgreSQL Guardrails

## Architecture Invariants
- Default to **React Server Components (RSC)**. Only add `"use client"` at leaf interactive islands.
- Never import database clients, secret environment variables, or service keys inside `"use client"` files.
- Validate 100% of Route Handler inputs and Server Action payloads with explicit schemas before touching Drizzle.
- Enforce **authorization (session + tenant/ownership check)** inside every Server Action and API route — middleware is defense-in-depth, never the sole auth check.

## Database & Migration Discipline
- Never edit an already-applied SQL migration file; always generate an additive forward migration.
- Wrap multi-table financial/state transitions in `db.transaction(async (tx) => { ... })` with explicit row locks or idempotency keys.
- Use indexed queries with explicit column projections; reject unbounded `SELECT *` on user-facing endpoints.

## Zero-Regression Verification Gate
Before marking any task done: run `tsc --noEmit`, linter, unit/integration tests, and confirm no accidental diffs in unrelated files.

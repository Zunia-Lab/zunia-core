# ADR-0001: Record architecture decisions

- Status: Accepted
- Date: 2026-08-31

## Context

Pre-development audit (`PRE-DEVELOPMENT.md`) lists irreversible product and crypto choices. Without written ADRs, teams implement divergent assumptions across extension, mobile, and dashboard.

## Decision

Use Markdown ADRs in `docs/adr/` (this repo for kernel/custody; product ADRs may also live in `zunia-docs/docs/adr/`).

## Consequences

No production crypto or social-login code merges until relevant ADRs are Accepted or Explicitly Deferred with an owner.

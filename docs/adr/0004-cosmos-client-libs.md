# ADR-0004: Cosmos client libraries

- Status: Proposed
- Date: 2026-08-31

## Context

Protobuf registry drift causes signing bugs. Candidates: CosmJS, cosmes, telescope-generated clients.

## Decision

**Pending.** Pin one stack in this ADR before Phase 1 signing code. Prefer CosmJS for Amino/Direct familiarity unless telescope codegen is adopted for registry sync.

## Consequences

`zunia-core` signing module depends on this choice; changelogs must note registry/proto version pins.

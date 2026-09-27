# Status

## KCF-SDK-P continuation — 2026-09-25

- Implemented pre-issuance rejection of reserved provider budgets/credentials, multiple completions and explicit provider storage.
- Fixed borrowed HTTPX transport lifetime across per-request clients; cookie isolation preserved.
- 79 focused tests pass locally, including the original 60.
- Native Rust conformance remains BLOCKED (zero native cases); full current-main suite, Ruff and Python-version matrix are not run.
- Both new APIs remain opt-in; legacy v1 migration and all remaining issue #1 work stay open. No release, main/pin change, CI dispatch or deployment.

- [x] Add a high-level app integration helper mirroring the Rust SDK wrapper
- [x] Document env-driven app setup and relay support in the README
- [x] Add an executable example and targeted tests
- [x] Validate locally, then commit and push

## KCF-SDK-P / issue #1 — first implementation slice, 2026-09-25

- [x] Add opt-in immutable prepare / authorize / send APIs, separate from legacy v1.
- [x] Implement request-bound envelope v2 using the inspected gateway protocol.
- [x] Run 60 focused synthetic tests, including two real loopback HTTP round trips.
- [x] Document supported numeric/message subset and limits in docs/PREPARED_V2.md.
- [ ] Native Rust interoperability, full current-main package and Ruff qualification.
- [ ] Supported-Python-version matrix and remaining issue #1 acceptance criteria.
- [ ] Migration of legacy GatewayClient / integration wrapper (still v1).

No CI was enabled, no provider/hardware call or deployment performed, no real
payment finality, blinded issuance, TEE or healthcare approval claimed. This is a
partial implementation; issue #1 remains open and the PR must remain draft.

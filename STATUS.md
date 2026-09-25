# Status

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

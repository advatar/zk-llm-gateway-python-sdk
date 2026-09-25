# Prepared inference and envelope v2 — KCF-SDK-P first slice

Status: implemented, opt-in, draft qualification. Not a production or healthcare approval.

## Why a separate API

The inspected gateway main `e4b31b449211906f31f1d529c4257388627ba5aa`
requires envelope **v2**: request ID, 32-byte client nonce, ephemeral key and
gateway key bind both the HKDF and AEAD transcripts. Python main
`30e3e7db316b02a934ad358a145676263e280130` still emits v1 through `GatewayClient`.
That legacy API is deliberately unchanged in this slice; it is not compatible
with the inspected v2 gateway. Do not silently fall back to it.

Import the new APIs from `zk_llm_gateway_sdk.prepared` and
`zk_llm_gateway_sdk.prepared_transport`. Do not route a prepared request through
`GatewayClient.infer_json_with_ticket`, which generates another request ID.

## Lifecycle

Prepare final content -> authorize that exact commitment -> send unchanged.
The prepared object stores detached immutable bytes. Returned dictionaries are
copies. Defaults, local retrieval, minimization and optional redaction must happen
before preparation. Ticket binding and payload size are rechecked before sending.

```python
from typing import Awaitable, Callable
from zk_llm_gateway_sdk.prepared import PreparedInference
from zk_llm_gateway_sdk.prepared_transport import PreparedClient, PreparedEndpoint

async def infer(endpoint: PreparedEndpoint,
                request: dict,
                issue: Callable[[PreparedInference], Awaitable[dict]]) -> dict:
    prepared = PreparedInference.prepare("c2048", request)
    authorized = await prepared.authorize_async(issue)
    return await PreparedClient(endpoint).send_prepared(authorized)
```

`issue` is supplied by the application's approved Actum integration. This SDK
has **no real issuer**, finality verifier, clinical authority or confidential
workload attestation verifier. Local ticket binding is not finality verification.
The canonical gateway verifier must still verify the evidence. The public key
and exact endpoint must be obtained over the deployment's authenticated channel.
Never log real patient content or enumerable request commitments in public logs.

`PreparedSyncClient` provides the same `send_prepared` operation for synchronous
applications. The async path bounds the full exchange (including body reads);
the sync path uses HTTPX phase/inactivity timeouts, not a hard wall-clock deadline.
An injected HTTPX transport is trusted application code and must enforce the host's
network policy; this slice does not itself integrate Kline's SurfaceIOBoundary.

## Supported subset and limits

Text messages only; null/missing content normalizes to the empty string as in Rust.
JSON options accept null, boolean, string, list, object and safe integers. Generic
floating-point options are refused. Temperature accepts null or 0, 0.5, 1, 1.5, 2;
these are exact binary32 values with an unambiguous tested JSON representation.
This is an intentionally narrow compatibility subset, not full OpenAI compatibility.
Streaming, multimodal content and other numeric settings remain unsupported.

The domain-separated 48-byte SHAKE256 commitment mirrors the gateway's ticket-free
projection, including nested `provider_options` and explicit optional nulls.
Native Rust conformance must pass before claiming cross-language qualification.
All five token-class budgets follow gateway `common/src/token.rs`; the entire
payload including evidence must fit. Byte budgets are not exact tokenizer counts.

## Transport and failure behavior

HTTPS is required except explicitly opted-in numeric loopback HTTP for local tests.
Only `/v1/infer` and `/relay` are accepted. No URL credentials/query/fragment,
redirects, environment proxies, automatic retries or per-client cookie persistence.
A new ephemeral key/client nonce/AEAD nonce is used for each send. The response must
match the request ID, class, ephemeral key and client nonce, authenticate, fit its
class, and contain the matching response fields. Model labels are correlation
checks, not proof of the model actually executed. No fallback to v1 or compatibility
inference exists in this API.

Errors are categorical and exclude upstream response bodies. A transport failure
or invalid response after submission is `dispatched_unknown`: do not automatically
buy another ticket or issue a new request. `gateway_reported_error` is an authenticated
error report, not proof that no provider work occurred. Cancellation propagates;
already transmitted content cannot be recalled. Cross-process spend durability
and safe retries remain gateway/issuer responsibilities.

Encryption terminates at the configured gateway, not a verified TEE. The gateway
and upstream may see plaintext. Padding does not remove context/timing linkability.
No new protected task store, hospital deployment, blind issuance or clinical approval
is provided by this SDK slice.

## Verification record — 25 September 2026

- 60 focused Python tests passed locally on Python 3.13, cryptography 46.0.4,
  HTTPX 0.28.1. Two tests use actual loopback HTTP servers (sync and async).
- Test-owned reference gateway independently transcribes the Rust envelope formulas;
  payment evidence and upstream answers are explicitly synthetic. Its counters are
  observed fixture calls/effects, not production payment or clinical evidence.
- Tests cover mutation, class/commitment substitution, v1 rejection, nonce/key/ID
  substitution, ciphertext tamper/replay across contexts, reserved fields, unsafe
  numbers, size limits, redirects, cookies, body timeout and pre-send refusal.
- Native Rust interoperability, full current-main package regression, Ruff,
  Python 3.10/3.11/3.12 matrix and hosted-provider runs were NOT run here.
  This container lacks Cargo and direct network access. Focused tests exercise the
  new standalone modules; legacy files used for package import came from the
  attached SDK snapshot, not a complete new checkout of current main.
- Existing CI is manually triggered to conserve credits; it was not re-enabled.

```bash
python3 -m pytest -q tests/test_prepared.py
```

Follow-up: run the native gateway bridge against these exact SDK files, broaden
canonical numeric support only with shared vectors, migrate legacy high-level APIs
explicitly, and qualify the other three SDKs. Issue #1 remains open.

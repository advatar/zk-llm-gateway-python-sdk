# ZK LLM Gateway SDK (Python)

Python SDK for the **ZK LLM Gateway**: **end-to-end encrypted envelopes**, **token-class padding**, and **ZK-ready usage tickets** for metered LLM inference.

This SDK is designed for calling a **hosted commercial gateway** (or a self-hosted gateway that implements the same wire format).
It helps you avoid identity-linked per-user API keys by supporting **unlinkable “ticket” spends** (nullifier-based anti-replay),
while also reducing metadata leakage via fixed-size padding.

> ⚠️ Privacy note (important):
> - This SDK protects prompts/responses from **relays/intermediaries** (ciphertext only) and reduces size fingerprinting.
> - It **does not** magically prevent the upstream LLM provider from correlating requests via the **content you send** or timing.
> - For long personal-agent chats, keep long-term memory local and send minimized context.

## Features

- **Envelope encryption**: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (client → gateway)
- **Token classes**: coarse buckets (`c256`, `c512`, `c1024`, `c2048`, `c4096`) that map to fixed padded byte sizes
- **ZK-ready tickets**: pluggable ticket source (`DummyTicketSource`, `FileTicketSource`, or your own)
- **Optional redaction helpers**: redact obvious identifiers (emails, phone numbers, ETH addresses, API keys) before sending prompts

## Install

From source (GitHub):

```bash
pip install "zk-llm-gateway-sdk @ git+https://github.com/your-org/zk-llm-gateway-python-sdk"
```

Or editable local dev:

```bash
pip install -e ".[dev]"
```

## Quickstart (Chat Completions)

Set environment variables:

- `GATEWAY_URL` – e.g. `https://api.gateway.example.com`
- `GATEWAY_PUBLIC_KEY_B64` – base64 X25519 public key for the gateway
- *(optional)* `MODEL` – e.g. `gpt-4o-mini`

```python
import os
import asyncio

from zk_llm_gateway_sdk import (
    GatewayClient,
    GatewayPublicKey,
    TokenClass,
    DummyTicketSource,
    ChatCompletionsRequest,
    ChatMessage,
)

async def main() -> None:
    endpoint = os.environ.get("GATEWAY_URL", "https://api.gateway.example.com")
    pk_b64 = os.environ["GATEWAY_PUBLIC_KEY_B64"]

    gateway_pk = GatewayPublicKey.from_base64(pk_b64)
    tickets = DummyTicketSource()

    client = GatewayClient(endpoint, gateway_pk, tickets)

    req = ChatCompletionsRequest(
        model=os.environ.get("MODEL", "gpt-4o-mini"),
        messages=[
            ChatMessage.system("You are a helpful assistant."),
            ChatMessage.user("Write a haiku about privacy-preserving payments."),
        ],
        temperature=0.2,
    )

    resp = await client.chat_completions(TokenClass.C2048, req)
    print(resp.first_text() or "")

asyncio.run(main())
```

## Drop-in app wrapper

If your Python app wants an env-driven integration layer instead of wiring
`GatewayClient` manually, use `AppGatewayConfig`.

Environment variables:

- `GATEWAY_BASE_URL` or `GATEWAY_URL` - base URL for the gateway or relay host
- `GATEWAY_PUBLIC_KEY_B64` - base64 X25519 gateway public key
- `GATEWAY_TICKETS_JSON` or `TICKETS_JSON` - JSON file containing pre-issued tickets
- `GATEWAY_USE_DUMMY_TICKETS=true` - development-only fallback
- `GATEWAY_INFER_PATH=/relay` or `GATEWAY_USE_RELAY=true` - send ciphertext through the relay
- `GATEWAY_MODEL` or `MODEL` - default model name, defaults to `gpt-4o-mini`
- `GATEWAY_TOKEN_CLASS` or `TOKEN_CLASS` - defaults to `c2048`
- `GATEWAY_TEMPERATURE` - optional default temperature
- `GATEWAY_TIMEOUT_SECS` - optional request timeout, defaults to `60`
- `GATEWAY_AUTH_BEARER` - optional bearer token

```python
import asyncio

from zk_llm_gateway_sdk import AppGatewayConfig


async def main() -> None:
    gateway = AppGatewayConfig.from_env().build()
    try:
        answer = await gateway.ask_with_system(
            "You are a helpful assistant.",
            "Summarize our privacy model.",
        )
        print(answer)
    finally:
        await gateway.aclose()


asyncio.run(main())
```

For a complete executable example, see `examples/app_gateway.py`.

## Ticket sources

### Dummy tickets (dev only)

```python
tickets = DummyTicketSource()
```

### Ticket pack file (JSON array)

```python
from zk_llm_gateway_sdk import FileTicketSource

tickets = FileTicketSource.from_path("./tickets.json")
```

File format:

```json
[
  {
    "commitment_root": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "nullifier": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    "token_class": "c2048",
    "proof": ""
  }
]
```

## Wire format (high level)

The SDK sends:

1. A plaintext JSON payload:
   ```json
   {
     "request_id": "6f0f8bc0-87de-4a8c-bad2-5f4f08c6c3d9",
     "model": "gpt-4o-mini",
     "messages": [{ "role": "user", "content": "hello" }],
     "max_tokens": 256,
     "temperature": 0.2,
     "token_class": "c2048",
     "ticket": {
       "commitment_root": "...",
       "nullifier": "...",
       "token_class": "c2048",
       "proof": "..."
     }
   }
   ```

2. Pads it to a fixed size for the chosen token class.

3. Encrypts it into an **Envelope**:
   ```json
   {
     "v": 1,
     "token_class": "c2048",
     "eph_pubkey_b64": "...",
     "nonce_b64": "...",
     "ciphertext_b64": "..."
   }
   ```

The gateway returns an encrypted envelope response (and typically echoes the same `eph_pubkey_b64`).

## Redaction helpers

Redaction is optional but useful to prevent accidental leakage of obvious identifiers.

```python
from zk_llm_gateway_sdk import Redactor, RedactionMode

redactor = Redactor(mode=RedactionMode.STABLE_PER_VALUE)
res = redactor.redact_text("Email me at alice@example.com (sk-verysecret...)")
print(res.redacted)
restored = redactor.rehydrate_text(res.redacted, res.map)
```

## Examples

See the `examples/` directory:

- `basic_chat.py`
- `app_gateway.py`
- `ticket_file.py`
- `redaction.py`

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

## License

Apache-2.0

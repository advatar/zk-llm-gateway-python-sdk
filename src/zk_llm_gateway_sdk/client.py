from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx

from .crypto import Envelope, GatewayPublicKey, SealState, open_json, seal_json
from .errors import GatewayError, HttpError, ProtocolError
from .openai_types import ChatCompletionsRequest, ChatCompletionsResponse
from .tickets import TicketSource, ZkTicket
from .token_class import TokenClass


@dataclass
class GatewayClientConfig:
    """HTTP and protocol configuration."""

    infer_path: str = "/v1/infer"
    auth_bearer: Optional[str] = None
    timeout_seconds: float = 60.0
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Sensible defaults (can be overridden).
        self.headers.setdefault("accept", "application/json")
        self.headers.setdefault("content-type", "application/json")
        self.headers.setdefault("user-agent", "zk-llm-gateway-python-sdk/0.1")

    def with_auth_bearer(self, bearer: str) -> "GatewayClientConfig":
        self.auth_bearer = bearer
        return self


def _join_url(base: str, path: str) -> str:
    b = base if base.endswith("/") else base + "/"
    p = path.lstrip("/")
    return urljoin(b, p)


class GatewayClient:
    """Async client for the encrypted /v1/infer endpoint."""

    def __init__(
        self,
        endpoint: str,
        gateway_pk: GatewayPublicKey,
        tickets: TicketSource,
        config: Optional[GatewayClientConfig] = None,
        http: Optional[httpx.AsyncClient] = None,
    ):
        self.endpoint = endpoint
        self.gateway_pk = gateway_pk
        self.tickets = tickets
        self.config = config or GatewayClientConfig()

        self.infer_url = _join_url(endpoint, self.config.infer_path)

        self._owns_http = http is None
        self.http = http or httpx.AsyncClient(timeout=self.config.timeout_seconds, headers=self.config.headers)

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    async def infer_json(self, token_class: TokenClass, upstream: Any) -> Any:
        ticket = await self.tickets.next_ticket_async(token_class)
        return await self.infer_json_with_ticket(token_class, ticket, upstream)

    async def infer_json_with_ticket(
        self,
        token_class: TokenClass,
        ticket: ZkTicket,
        upstream: Any,
    ) -> Any:
        payload = {
            "token_class": token_class.value,
            "ticket": ticket.to_dict(),
            "upstream": upstream,
        }

        env, st = seal_json(self.gateway_pk, token_class, payload)

        headers = dict(self.config.headers)
        if self.config.auth_bearer:
            headers["authorization"] = f"Bearer {self.config.auth_bearer}"

        resp = await self.http.post(self.infer_url, json=env.to_dict(), headers=headers)
        status = resp.status_code

        try:
            resp_env = Envelope.from_dict(resp.json())
        except Exception as e:  # noqa: BLE001
            snippet = resp.text[:500] if resp.text else ""
            raise ProtocolError(f"failed to parse envelope (HTTP {status}): {snippet}") from e

        decrypted = open_json(resp_env, st)

        # Encrypted error payload (preferred)
        if isinstance(decrypted, dict) and "error" in decrypted:
            err = decrypted.get("error") or {}
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        # For non-2xx, allow encrypted errors above; otherwise raise.
        if status < 200 or status >= 300:
            raise HttpError(status_code=status, message=f"gateway returned HTTP {status}")

        if not isinstance(decrypted, dict) or "upstream" not in decrypted:
            raise ProtocolError("missing 'upstream' field in decrypted gateway response")

        return decrypted["upstream"]

    async def chat_completions(
        self,
        token_class: TokenClass,
        req: ChatCompletionsRequest,
    ) -> ChatCompletionsResponse:
        if req.max_tokens is None:
            req.max_tokens = token_class.max_output_tokens_hint()

        upstream = {
            "path": "/v1/chat/completions",
            "method": "POST",
            "body": req.to_dict(),
        }

        resp_json = await self.infer_json(token_class, upstream)

        # Gateways may wrap upstream responses as { "body": <openai_json>, ... }.
        if isinstance(resp_json, dict) and "body" in resp_json:
            body = resp_json.get("body")
        else:
            body = resp_json

        if not isinstance(body, dict):
            raise ProtocolError("unexpected upstream response type")

        return ChatCompletionsResponse.from_dict(body)


class GatewaySyncClient:
    """Sync client for the encrypted /v1/infer endpoint."""

    def __init__(
        self,
        endpoint: str,
        gateway_pk: GatewayPublicKey,
        tickets: TicketSource,
        config: Optional[GatewayClientConfig] = None,
        http: Optional[httpx.Client] = None,
    ):
        self.endpoint = endpoint
        self.gateway_pk = gateway_pk
        self.tickets = tickets
        self.config = config or GatewayClientConfig()

        self.infer_url = _join_url(endpoint, self.config.infer_path)

        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=self.config.timeout_seconds, headers=self.config.headers)

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def infer_json(self, token_class: TokenClass, upstream: Any) -> Any:
        ticket = self.tickets.next_ticket(token_class)
        return self.infer_json_with_ticket(token_class, ticket, upstream)

    def infer_json_with_ticket(
        self,
        token_class: TokenClass,
        ticket: ZkTicket,
        upstream: Any,
    ) -> Any:
        payload = {
            "token_class": token_class.value,
            "ticket": ticket.to_dict(),
            "upstream": upstream,
        }

        env, st = seal_json(self.gateway_pk, token_class, payload)

        headers = dict(self.config.headers)
        if self.config.auth_bearer:
            headers["authorization"] = f"Bearer {self.config.auth_bearer}"

        resp = self.http.post(self.infer_url, json=env.to_dict(), headers=headers)
        status = resp.status_code

        try:
            resp_env = Envelope.from_dict(resp.json())
        except Exception as e:  # noqa: BLE001
            snippet = resp.text[:500] if resp.text else ""
            raise ProtocolError(f"failed to parse envelope (HTTP {status}): {snippet}") from e

        decrypted = open_json(resp_env, st)

        if isinstance(decrypted, dict) and "error" in decrypted:
            err = decrypted.get("error") or {}
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        if status < 200 or status >= 300:
            raise HttpError(status_code=status, message=f"gateway returned HTTP {status}")

        if not isinstance(decrypted, dict) or "upstream" not in decrypted:
            raise ProtocolError("missing 'upstream' field in decrypted gateway response")

        return decrypted["upstream"]

    def chat_completions(
        self,
        token_class: TokenClass,
        req: ChatCompletionsRequest,
    ) -> ChatCompletionsResponse:
        if req.max_tokens is None:
            req.max_tokens = token_class.max_output_tokens_hint()

        upstream = {
            "path": "/v1/chat/completions",
            "method": "POST",
            "body": req.to_dict(),
        }

        resp_json = self.infer_json(token_class, upstream)

        if isinstance(resp_json, dict) and "body" in resp_json:
            body = resp_json.get("body")
        else:
            body = resp_json

        if not isinstance(body, dict):
            raise ProtocolError("unexpected upstream response type")

        return ChatCompletionsResponse.from_dict(body)

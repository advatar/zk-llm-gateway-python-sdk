from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx

from .crypto import Envelope, GatewayPublicKey, open_json, seal_json
from .errors import GatewayError, HttpError, ProtocolError
from .openai_types import ChatCompletionsRequest, ChatCompletionsResponse, ChatMessage
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


def _parse_chat_request(upstream: Any) -> ChatCompletionsRequest:
    if isinstance(upstream, ChatCompletionsRequest):
        return upstream

    if isinstance(upstream, dict) and "model" in upstream and "messages" in upstream:
        try:
            return ChatCompletionsRequest(
                model=str(upstream["model"]),
                messages=[
                    ChatMessage.from_dict(m)
                    for m in list(upstream.get("messages") or [])
                    if isinstance(m, dict)
                ],
                temperature=upstream.get("temperature"),
                max_tokens=upstream.get("max_tokens"),
                stream=upstream.get("stream"),
                extra={
                    k: v
                    for k, v in upstream.items()
                    if k not in {"model", "messages", "temperature", "max_tokens", "stream"}
                },
            )
        except Exception as e:  # noqa: BLE001
            raise ProtocolError(f"invalid chat request payload: {e}") from e

    if isinstance(upstream, dict) and upstream.get("path") == "/v1/chat/completions":
        body = upstream.get("body")
        if not isinstance(body, dict):
            raise ProtocolError("missing or invalid 'body' in upstream wrapper")
        return _parse_chat_request(body)

    raise ProtocolError(
        "unsupported infer_json payload; expected chat request body or {path:'/v1/chat/completions', body:{...}}"
    )


def _build_inference_request(
    token_class: TokenClass,
    ticket: ZkTicket,
    chat_req: ChatCompletionsRequest,
) -> Dict[str, Any]:
    if chat_req.stream is True:
        raise ProtocolError("stream=true is not supported on /v1/infer")

    payload = chat_req.to_dict()
    payload["request_id"] = str(uuid.uuid4())
    payload["token_class"] = token_class.value
    payload["ticket"] = ticket.to_dict()
    return payload


class GatewayClient:
    """Async client for encrypted `/v1/infer` using canonical InferenceRequest."""

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
        self.http = http or httpx.AsyncClient(
            timeout=self.config.timeout_seconds,
            headers=self.config.headers,
        )

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
        if ticket.token_class != token_class:
            raise ProtocolError("ticket token_class must match requested token_class")

        chat_req = _parse_chat_request(upstream)

        payload = _build_inference_request(token_class, ticket, chat_req)

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

        # Canonical gateway payload.
        if isinstance(decrypted, dict) and decrypted.get("kind") in {"ok", "err"}:
            kind = str(decrypted.get("kind"))
            if kind == "ok":
                response = decrypted.get("response")
                if not isinstance(response, dict):
                    raise ProtocolError("missing 'response' field in gateway payload")
                return response

            err = decrypted.get("error")
            if not isinstance(err, dict):
                raise GatewayError(code="gateway_error", message="unknown error")
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        # Legacy SDK payload shape fallback.
        if isinstance(decrypted, dict) and "error" in decrypted:
            err = decrypted.get("error") or {}
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        if status < 200 or status >= 300:
            raise HttpError(status_code=status, message=f"gateway returned HTTP {status}")

        if isinstance(decrypted, dict) and "upstream" in decrypted:
            return decrypted["upstream"]

        raise ProtocolError("missing response payload in decrypted gateway response")

    async def chat_completions(
        self,
        token_class: TokenClass,
        req: ChatCompletionsRequest,
    ) -> ChatCompletionsResponse:
        if req.max_tokens is None:
            req.max_tokens = token_class.max_output_tokens_hint()

        resp_json = await self.infer_json(token_class, req.to_dict())

        # Canonical gateway response.
        if isinstance(resp_json, dict) and "output" in resp_json and "request_id" in resp_json:
            upstream = resp_json.get("upstream")
            if isinstance(upstream, dict):
                body = upstream.get("body") if isinstance(upstream.get("body"), dict) else upstream
                response = ChatCompletionsResponse.from_dict(body)
                response.extra["billed_token_class"] = resp_json.get("billed_token_class")
                response.id = response.id or str(resp_json.get("request_id"))
                response.model = response.model or str(resp_json.get("model") or req.model)
                return response

            data = {
                "id": str(resp_json.get("request_id")),
                "model": str(resp_json.get("model") or req.model),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": str(resp_json.get("output") or "")},
                        "finish_reason": "stop",
                    }
                ],
                "billed_token_class": resp_json.get("billed_token_class"),
            }
            return ChatCompletionsResponse.from_dict(data)

        # Backward-compatible parsing for SDK-proxy response.
        body = resp_json.get("body") if isinstance(resp_json, dict) and "body" in resp_json else resp_json

        if not isinstance(body, dict):
            raise ProtocolError("unexpected upstream response type")

        return ChatCompletionsResponse.from_dict(body)


class GatewaySyncClient:
    """Sync client for encrypted `/v1/infer` using canonical InferenceRequest."""

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
        self.http = http or httpx.Client(
            timeout=self.config.timeout_seconds,
            headers=self.config.headers,
        )

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
        if ticket.token_class != token_class:
            raise ProtocolError("ticket token_class must match requested token_class")

        chat_req = _parse_chat_request(upstream)

        payload = _build_inference_request(token_class, ticket, chat_req)

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

        if isinstance(decrypted, dict) and decrypted.get("kind") in {"ok", "err"}:
            kind = str(decrypted.get("kind"))
            if kind == "ok":
                response = decrypted.get("response")
                if not isinstance(response, dict):
                    raise ProtocolError("missing 'response' field in gateway payload")
                return response

            err = decrypted.get("error")
            if not isinstance(err, dict):
                raise GatewayError(code="gateway_error", message="unknown error")
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        if isinstance(decrypted, dict) and "error" in decrypted:
            err = decrypted.get("error") or {}
            code = str(err.get("code") or "gateway_error")
            msg = str(err.get("message") or "unknown error")
            raise GatewayError(code=code, message=msg)

        if status < 200 or status >= 300:
            raise HttpError(status_code=status, message=f"gateway returned HTTP {status}")

        if isinstance(decrypted, dict) and "upstream" in decrypted:
            return decrypted["upstream"]

        raise ProtocolError("missing response payload in decrypted gateway response")

    def chat_completions(
        self,
        token_class: TokenClass,
        req: ChatCompletionsRequest,
    ) -> ChatCompletionsResponse:
        if req.max_tokens is None:
            req.max_tokens = token_class.max_output_tokens_hint()

        resp_json = self.infer_json(token_class, req.to_dict())

        if isinstance(resp_json, dict) and "output" in resp_json and "request_id" in resp_json:
            upstream = resp_json.get("upstream")
            if isinstance(upstream, dict):
                body = upstream.get("body") if isinstance(upstream.get("body"), dict) else upstream
                response = ChatCompletionsResponse.from_dict(body)
                response.extra["billed_token_class"] = resp_json.get("billed_token_class")
                response.id = response.id or str(resp_json.get("request_id"))
                response.model = response.model or str(resp_json.get("model") or req.model)
                return response

            data = {
                "id": str(resp_json.get("request_id")),
                "model": str(resp_json.get("model") or req.model),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": str(resp_json.get("output") or "")},
                        "finish_reason": "stop",
                    }
                ],
                "billed_token_class": resp_json.get("billed_token_class"),
            }
            return ChatCompletionsResponse.from_dict(data)

        body = resp_json.get("body") if isinstance(resp_json, dict) and "body" in resp_json else resp_json

        if not isinstance(body, dict):
            raise ProtocolError("unexpected upstream response type")

        return ChatCompletionsResponse.from_dict(body)

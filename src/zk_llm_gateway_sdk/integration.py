from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from .client import GatewayClient, GatewayClientConfig, GatewaySyncClient
from .crypto import GatewayPublicKey
from .errors import ProtocolError
from .openai_types import ChatCompletionsRequest, ChatCompletionsResponse, ChatMessage
from .tickets import DummyTicketSource, FileTicketSource, TicketSource
from .token_class import TokenClass

GATEWAY_INFER_PATH = "/v1/infer"
RELAY_INFER_PATH = "/relay"


@dataclass(frozen=True)
class TicketSourceConfig:
    kind: str
    path: Optional[Path] = None

    @classmethod
    def dummy(cls) -> "TicketSourceConfig":
        return cls(kind="dummy")

    @classmethod
    def file(cls, path: str | Path) -> "TicketSourceConfig":
        return cls(kind="file", path=Path(path))

    def load(self) -> TicketSource:
        if self.kind == "dummy":
            return DummyTicketSource()
        if self.kind == "file" and self.path is not None:
            return FileTicketSource.from_path(self.path)
        raise ProtocolError("ticket source config must be dummy or file(path)")


@dataclass(frozen=True)
class AppGatewayConfig:
    endpoint: str
    gateway_public_key: GatewayPublicKey
    tickets: TicketSourceConfig
    model: str
    token_class: TokenClass
    infer_path: str = GATEWAY_INFER_PATH
    auth_bearer: Optional[str] = None
    temperature: Optional[float] = None
    timeout_seconds: float = 60.0

    @classmethod
    def from_env(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "AppGatewayConfig":
        source = env or os.environ

        endpoint = _required_env(source, "GATEWAY_BASE_URL", "GATEWAY_URL")
        pk_b64 = _required_env(source, "GATEWAY_PUBLIC_KEY_B64")
        gateway_public_key = GatewayPublicKey.from_base64(pk_b64)

        use_relay = _parse_bool(source.get("GATEWAY_USE_RELAY", "false"), "GATEWAY_USE_RELAY")
        infer_path = source.get("GATEWAY_INFER_PATH") or (
            RELAY_INFER_PATH if use_relay else GATEWAY_INFER_PATH
        )

        tickets_json = source.get("GATEWAY_TICKETS_JSON") or source.get("TICKETS_JSON")
        if tickets_json:
            tickets = TicketSourceConfig.file(tickets_json)
        elif "GATEWAY_USE_DUMMY_TICKETS" in source:
            if _parse_bool(
                source["GATEWAY_USE_DUMMY_TICKETS"],
                "GATEWAY_USE_DUMMY_TICKETS",
            ):
                tickets = TicketSourceConfig.dummy()
            else:
                raise ProtocolError(
                    "set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true"
                )
        else:
            raise ProtocolError(
                "set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true"
            )

        model = source.get("GATEWAY_MODEL") or source.get("MODEL") or "gpt-4o-mini"

        token_class_raw = source.get("GATEWAY_TOKEN_CLASS") or source.get("TOKEN_CLASS")
        token_class = (
            TokenClass.parse(token_class_raw) if token_class_raw is not None else TokenClass.C2048
        )

        temperature_raw = source.get("GATEWAY_TEMPERATURE")
        temperature = (
            _parse_float(temperature_raw, "GATEWAY_TEMPERATURE")
            if temperature_raw is not None
            else None
        )

        timeout_raw = source.get("GATEWAY_TIMEOUT_SECS")
        timeout_seconds = (
            _parse_float(timeout_raw, "GATEWAY_TIMEOUT_SECS")
            if timeout_raw is not None
            else 60.0
        )

        return cls(
            endpoint=endpoint,
            infer_path=infer_path,
            gateway_public_key=gateway_public_key,
            auth_bearer=source.get("GATEWAY_AUTH_BEARER"),
            tickets=tickets,
            model=model,
            token_class=token_class,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
        )

    def build(self) -> "AppGateway":
        client_config = GatewayClientConfig(
            infer_path=self.infer_path,
            auth_bearer=self.auth_bearer,
            timeout_seconds=self.timeout_seconds,
        )
        client = GatewayClient(
            self.endpoint,
            self.gateway_public_key,
            self.tickets.load(),
            config=client_config,
        )
        return AppGateway(
            client=client,
            default_model=self.model,
            default_token_class=self.token_class,
            default_temperature=self.temperature,
        )

    def build_sync(self) -> "AppGatewaySync":
        client_config = GatewayClientConfig(
            infer_path=self.infer_path,
            auth_bearer=self.auth_bearer,
            timeout_seconds=self.timeout_seconds,
        )
        client = GatewaySyncClient(
            self.endpoint,
            self.gateway_public_key,
            self.tickets.load(),
            config=client_config,
        )
        return AppGatewaySync(
            client=client,
            default_model=self.model,
            default_token_class=self.token_class,
            default_temperature=self.temperature,
        )


@dataclass(frozen=True)
class AppChatRequest:
    messages: list[ChatMessage]
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    token_class: Optional[TokenClass] = None
    temperature: Optional[float] = None

    @classmethod
    def from_user_prompt(cls, user_prompt: str) -> "AppChatRequest":
        return cls(messages=[ChatMessage.user(user_prompt)])

    def with_system_prompt(self, system_prompt: str) -> "AppChatRequest":
        return self._replace(system_prompt=system_prompt)

    def with_model(self, model: str) -> "AppChatRequest":
        return self._replace(model=model)

    def with_token_class(self, token_class: TokenClass) -> "AppChatRequest":
        return self._replace(token_class=token_class)

    def with_temperature(self, temperature: float) -> "AppChatRequest":
        return self._replace(temperature=temperature)

    def _replace(self, **changes: object) -> "AppChatRequest":
        payload = {
            "messages": self.messages,
            "system_prompt": self.system_prompt,
            "model": self.model,
            "token_class": self.token_class,
            "temperature": self.temperature,
        }
        payload.update(changes)
        return AppChatRequest(**payload)


@dataclass
class AppGateway:
    client: GatewayClient
    default_model: str
    default_token_class: TokenClass
    default_temperature: Optional[float] = None

    async def aclose(self) -> None:
        await self.client.aclose()

    async def ask(self, user_prompt: str) -> str:
        response = await self.chat(AppChatRequest.from_user_prompt(user_prompt))
        return response.first_text() or ""

    async def ask_with_system(self, system_prompt: str, user_prompt: str) -> str:
        request = AppChatRequest.from_user_prompt(user_prompt).with_system_prompt(system_prompt)
        response = await self.chat(request)
        return response.first_text() or ""

    async def chat(self, request: AppChatRequest) -> ChatCompletionsResponse:
        if not request.messages:
            raise ProtocolError("chat request must include at least one message")

        token_class = request.token_class or self.default_token_class
        model = request.model or self.default_model
        temperature = request.temperature
        if temperature is None:
            temperature = self.default_temperature

        messages = []
        if request.system_prompt is not None:
            messages.append(ChatMessage.system(request.system_prompt))
        messages.extend(request.messages)

        return await self.client.chat_completions(
            token_class,
            ChatCompletionsRequest(
                model=model,
                messages=messages,
                temperature=temperature,
                stream=False,
            ),
        )


@dataclass
class AppGatewaySync:
    client: GatewaySyncClient
    default_model: str
    default_token_class: TokenClass
    default_temperature: Optional[float] = None

    def close(self) -> None:
        self.client.close()

    def ask(self, user_prompt: str) -> str:
        response = self.chat(AppChatRequest.from_user_prompt(user_prompt))
        return response.first_text() or ""

    def ask_with_system(self, system_prompt: str, user_prompt: str) -> str:
        request = AppChatRequest.from_user_prompt(user_prompt).with_system_prompt(system_prompt)
        response = self.chat(request)
        return response.first_text() or ""

    def chat(self, request: AppChatRequest) -> ChatCompletionsResponse:
        if not request.messages:
            raise ProtocolError("chat request must include at least one message")

        token_class = request.token_class or self.default_token_class
        model = request.model or self.default_model
        temperature = request.temperature
        if temperature is None:
            temperature = self.default_temperature

        messages = []
        if request.system_prompt is not None:
            messages.append(ChatMessage.system(request.system_prompt))
        messages.extend(request.messages)

        return self.client.chat_completions(
            token_class,
            ChatCompletionsRequest(
                model=model,
                messages=messages,
                temperature=temperature,
                stream=False,
            ),
        )


def _required_env(env: Mapping[str, str], *keys: str) -> str:
    for key in keys:
        value = env.get(key)
        if value is not None and value.strip():
            return value
    raise ProtocolError(f"missing environment variable; set one of {', '.join(keys)}")


def _parse_bool(raw: str, key: str) -> bool:
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ProtocolError(f"{key} must be one of true/false/1/0/yes/no/on/off")


def _parse_float(raw: str, key: str) -> float:
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ProtocolError(f"{key} must be numeric") from exc

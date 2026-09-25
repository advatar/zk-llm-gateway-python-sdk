"""Immutable preparation for the gateway's Actum v1 authorization contract.

This bounded first slice admits text messages, JSON integer options, and exactly
representable half-step temperatures. Other floating-point values are refused
until cross-language canonicalization is qualified. No issuance or authority is
created here; the gateway remains responsible for verification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

DOMAIN = b"ACTIVECHAIN-ZEROK-INFERENCE-AUTHORIZATION-V1\0"
# id, prompt bytes, request bytes, response bytes: gateway/common/src/token.rs.
CLASSES = {
    "c256": (1, 2048, 8192, 8192),
    "c512": (2, 4096, 12288, 16384),
    "c1024": (3, 8192, 20480, 32768),
    "c2048": (4, 16384, 36864, 65536),
    "c4096": (5, 32768, 69632, 131072),
}
RESERVED = {"request_id", "token_class", "ticket", "provider_options"}
CORE = {"model", "messages", "max_tokens", "temperature", "stream"}


class PreparedError(ValueError):
    """Categorical, data-free failure; never includes upstream response text."""

    def __init__(self, code: str, outcome: str = "not_dispatched") -> None:
        self.code = code
        self.outcome = outcome
        super().__init__(f"{code} ({outcome})")


def encode_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise PreparedError("invalid_json_value") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreparedError("duplicate_json_key")
        result[key] = value
    return result


def decode_json(raw: bytes) -> Any:
    def bad_constant(_: str) -> None:
        raise PreparedError("non_finite_json")
    try:
        return json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise PreparedError("invalid_json") from None


def _check_json(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise PreparedError("json_depth_exceeded")
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int:
        if abs(value) > (2**53 - 1):
            raise PreparedError("integer_outside_portable_range")
        return
    if type(value) is list:
        for item in value:
            _check_json(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise PreparedError("non_string_json_key")
            _check_json(item, depth + 1)
        return
    raise PreparedError("unsupported_json_value_or_float")


def decode_b64(value: Any, *, length: int | None = None,
               maximum: int = 2 * 1024 * 1024) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise PreparedError("invalid_base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise PreparedError("invalid_base64") from None
    if len(raw) > maximum or (length is not None and len(raw) != length):
        raise PreparedError("invalid_base64_length")
    if base64.b64encode(raw).decode("ascii") != value:
        raise PreparedError("noncanonical_base64")
    return raw


@dataclass(frozen=True, repr=False)
class PreparedInference:
    """Detached immutable byte snapshot. This object confers no release authority."""

    _wire: bytes
    _projection: bytes

    @classmethod
    def prepare(cls, token_class: str, request: Mapping[str, Any], *,
                request_id: str | None = None) -> PreparedInference:
        if token_class not in CLASSES:
            raise PreparedError("unsupported_token_class")
        # Require ordinary JSON containers; never call user-defined serializers.
        if type(request) is not dict or any(type(k) is not str for k in request):
            raise PreparedError("request_must_be_json_object")
        if RESERVED.intersection(request):
            raise PreparedError("reserved_request_field")
        if type(request.get("model")) is not str or not request["model"]:
            raise PreparedError("model_required")
        messages = request.get("messages")
        if type(messages) is not list or not messages:
            raise PreparedError("messages_required")
        normalized = []
        for message in messages:
            if type(message) is not dict or type(message.get("role")) is not str:
                raise PreparedError("invalid_message")
            item = dict(message)
            if item.get("content") is None:
                item["content"] = ""  # matches Rust's message deserializer
            if type(item["content"]) is not str:
                raise PreparedError("nontext_message_not_qualified")
            _check_json(item)
            normalized.append(item)
        options = {k: v for k, v in request.items() if k not in CORE}
        _check_json(options)
        maximum = request.get("max_tokens")
        if maximum is not None and (type(maximum) is not int or not 0 <= maximum <= 2**32-1):
            raise PreparedError("invalid_max_tokens")
        stream = request.get("stream")
        if stream is not None and stream is not False:
            raise PreparedError("streaming_not_supported")
        temperature = request.get("temperature")
        if temperature is not None:
            if type(temperature) not in (int, float) or temperature not in (0, .5, 1, 1.5, 2):
                raise PreparedError("temperature_not_portably_qualified")
            temperature = float(temperature)
            if temperature == 0:
                temperature = 0.0  # canonicalize negative zero before binding
        try:
            rid = str(uuid.UUID(request_id)) if request_id is not None else str(uuid.uuid4())
        except (ValueError, TypeError, AttributeError):
            raise PreparedError("invalid_request_id") from None
        if len(encode_json(normalized)) > CLASSES[token_class][1]:
            raise PreparedError("prompt_exceeds_class")
        projection = {
            "request_id": rid, "model": request["model"], "messages": normalized,
            "max_tokens": maximum, "temperature": temperature, "stream": stream,
            "token_class": token_class, "provider_options": options,
        }
        wire = {k: v for k, v in projection.items() if k != "provider_options"}
        wire.update(options)
        wire_bytes = encode_json(wire)
        if len(wire_bytes) > CLASSES[token_class][2]:
            raise PreparedError("request_exceeds_class")
        return cls(wire_bytes, encode_json(projection))

    @property
    def request_id(self) -> str:
        return decode_json(self._wire)["request_id"]

    @property
    def token_class(self) -> str:
        return decode_json(self._wire)["token_class"]

    @property
    def model(self) -> str:
        return decode_json(self._wire)["model"]

    @property
    def commitment(self) -> bytes:
        return hashlib.shake_256(DOMAIN + len(self._projection).to_bytes(8, "big")
                               + self._projection).digest(48)

    @property
    def commitment_b64(self) -> str:
        return base64.b64encode(self.commitment).decode("ascii")

    def to_request(self) -> dict[str, Any]:
        """Returns a detached copy, not a mutable reference to prepared state."""
        return decode_json(self._wire)

    def bind(self, ticket: Mapping[str, Any]) -> AuthorizedInference:
        if type(ticket) is not dict or set(ticket) != {
                "commitment_root", "nullifier", "token_class", "proof"}:
            raise PreparedError("invalid_ticket_shape")
        if ticket["token_class"] != self.token_class:
            raise PreparedError("ticket_class_mismatch")
        if decode_b64(ticket["commitment_root"], length=48) != self.commitment:
            raise PreparedError("authorization_commitment_mismatch")
        if not decode_b64(ticket["nullifier"]) or not decode_b64(ticket["proof"]):
            raise PreparedError("empty_authorization_evidence")
        payload = self.to_request()
        payload["ticket"] = decode_json(encode_json(ticket))
        raw = encode_json(payload)
        if len(raw) > CLASSES[self.token_class][2]:
            raise PreparedError("authorized_payload_exceeds_class")
        return AuthorizedInference(self, raw)

    def authorize(self, issue: Callable[[PreparedInference], Mapping[str, Any]]) -> AuthorizedInference:
        return self.bind(issue(self))

    async def authorize_async(self, issue: Callable[[PreparedInference], Awaitable[Mapping[str, Any]]]) -> AuthorizedInference:
        return self.bind(await issue(self))

    def __repr__(self) -> str:
        return "PreparedInference(<private>)"


@dataclass(frozen=True, repr=False)
class AuthorizedInference:
    """Locally bound payment evidence; NOT verified finality or data authority."""

    prepared: PreparedInference
    _payload: bytes

    def validate(self) -> None:
        # Recheck structure even for directly constructed public dataclass objects.
        wire = self.prepared.to_request()
        rid = wire.pop("request_id", None)
        token_class = wire.pop("token_class", None)
        rebuilt = PreparedInference.prepare(token_class, wire, request_id=rid)
        if rebuilt != self.prepared:
            raise PreparedError("invalid_prepared_snapshot")
        value = decode_json(self._payload)
        if type(value) is not dict:
            raise PreparedError("invalid_authorized_payload")
        ticket = value.pop("ticket", None)
        if encode_json(value) != self.prepared._wire:
            raise PreparedError("prepared_payload_mutated")
        checked = self.prepared.bind(ticket)
        if checked._payload != self._payload:
            raise PreparedError("noncanonical_authorized_payload")

    def __repr__(self) -> str:
        return "AuthorizedInference(<private>)"

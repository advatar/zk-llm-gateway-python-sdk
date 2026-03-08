from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ChatMessage:
    role: str
    content: str
    extra: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def system(content: str) -> "ChatMessage":
        return ChatMessage(role="system", content=content)

    @staticmethod
    def user(content: str) -> "ChatMessage":
        return ChatMessage(role="user", content=content)

    @staticmethod
    def assistant(content: str) -> "ChatMessage":
        return ChatMessage(role="assistant", content=content)

    def to_dict(self) -> Dict[str, Any]:
        out = {"role": self.role, "content": self.content}
        out.update(self.extra)
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChatMessage":
        extra = dict(d)
        role = str(extra.pop("role"))
        content = extra.pop("content", "")
        return cls(
            role=role,
            content="" if content is None else str(content),
            extra=extra,
        )


@dataclass
class ChatCompletionsRequest:
    model: str
    messages: List[ChatMessage]

    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = None

    # Extra parameters forwarded to the upstream provider.
    # `stream=True` is rejected on `/v1/infer`, which remains non-streaming today.
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "model": self.model,
            "messages": [m.to_dict() for m in self.messages],
        }
        if self.temperature is not None:
            out["temperature"] = self.temperature
        if self.max_tokens is not None:
            out["max_tokens"] = self.max_tokens
        if self.stream is not None:
            out["stream"] = self.stream
        out.update(self.extra)
        return out


@dataclass
class Usage:
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Usage":
        return cls(
            prompt_tokens=d.get("prompt_tokens"),
            completion_tokens=d.get("completion_tokens"),
            total_tokens=d.get("total_tokens"),
        )


@dataclass
class ChatChoice:
    index: int
    message: Optional[ChatMessage] = None
    finish_reason: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChatChoice":
        extra = dict(d)
        idx = int(extra.pop("index", 0))
        msg = extra.pop("message", None)
        finish = extra.pop("finish_reason", None)
        return cls(
            index=idx,
            message=ChatMessage.from_dict(msg) if isinstance(msg, dict) else None,
            finish_reason=str(finish) if finish is not None else None,
            extra=extra,
        )


@dataclass
class ChatCompletionsResponse:
    id: Optional[str]
    model: Optional[str]
    choices: List[ChatChoice]
    usage: Optional[Usage] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ChatCompletionsResponse":
        extra = dict(d)
        rid = extra.pop("id", None)
        model = extra.pop("model", None)
        choices_raw = extra.pop("choices", []) or []
        usage_raw = extra.pop("usage", None)
        choices = [
            ChatChoice.from_dict(c) for c in choices_raw if isinstance(c, dict)
        ]
        usage = Usage.from_dict(usage_raw) if isinstance(usage_raw, dict) else None
        return cls(
            id=str(rid) if rid is not None else None,
            model=str(model) if model is not None else None,
            choices=choices,
            usage=usage,
            extra=extra,
        )

    def first_text(self) -> Optional[str]:
        for c in self.choices:
            if c.message is not None:
                return c.message.content
        return None

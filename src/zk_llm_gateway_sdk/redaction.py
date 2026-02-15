from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Tuple


class RedactionMode(str, Enum):
    """How placeholders are generated."""

    STABLE_PER_VALUE = "stable_per_value"
    EPHEMERAL = "ephemeral"


@dataclass
class RedactionResult:
    redacted: str
    # placeholder -> original
    map: Dict[str, str]


class RedactionKind(Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ETH = "ETH"
    APIKEY = "APIKEY"
    PRIVKEY = "PRIVKEY"

    @property
    def label(self) -> str:
        return self.value


class Redactor:
    """Regex-based redaction helpers.

    These utilities can reduce accidental leakage of obvious identifiers (emails, phones, ETH addresses,
    API keys, private key blocks) before sending prompts to a remote model.

    They do not provide perfect privacy: writing style, unique context, and metadata can still identify a user.
    """

    def __init__(self, mode: RedactionMode = RedactionMode.STABLE_PER_VALUE):
        self.mode = mode
        self.salt = os.urandom(16)
        self.custom_terms: List[str] = []

        # Pragmatic patterns. Tune for your product.
        email = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
        phone = re.compile(r"\b\+?[0-9][0-9() \-]{7,}[0-9]\b")
        eth = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
        apikey = re.compile(r"\b(sk-[A-Za-z0-9]{16,})\b")
        privkey = re.compile(
            r"-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----"
        )

        self.patterns: List[Tuple[RedactionKind, re.Pattern[str]]] = [
            (RedactionKind.PRIVKEY, privkey),
            (RedactionKind.APIKEY, apikey),
            (RedactionKind.ETH, eth),
            (RedactionKind.EMAIL, email),
            (RedactionKind.PHONE, phone),
        ]

    def add_custom_term(self, term: str) -> None:
        t = term.strip()
        if t:
            self.custom_terms.append(t)

    def redact_text(self, input_text: str) -> RedactionResult:
        out = input_text
        mapping: Dict[str, str] = {}
        counter = 0

        # Custom terms first (exact match).
        for term in self.custom_terms:
            if term in out:
                ph = self._placeholder("TERM", term, counter)
                out = out.replace(term, ph)
                mapping[ph] = term
                counter += 1

        # Regex replacements (iterative).
        for kind, rx in self.patterns:
            while True:
                m = rx.search(out)
                if not m:
                    break
                s = m.group(0)
                ph = self._placeholder(kind.label, s, counter)
                out = out[: m.start()] + ph + out[m.end() :]
                mapping[ph] = s
                counter += 1

        return RedactionResult(redacted=out, map=mapping)

    def redact_json(self, value: Any) -> tuple[Any, Dict[str, str]]:
        mapping: Dict[str, str] = {}
        redacted = self._redact_json_inner(value, mapping)
        return redacted, mapping

    def _redact_json_inner(self, value: Any, mapping: Dict[str, str]) -> Any:
        if isinstance(value, str):
            res = self.redact_text(value)
            mapping.update(res.map)
            return res.redacted
        if isinstance(value, list):
            return [self._redact_json_inner(v, mapping) for v in value]
        if isinstance(value, dict):
            return {k: self._redact_json_inner(v, mapping) for k, v in value.items()}
        return value

    def rehydrate_text(self, input_text: str, mapping: Dict[str, str]) -> str:
        out = input_text
        keys = sorted(mapping.keys(), key=len, reverse=True)
        for k in keys:
            out = out.replace(k, mapping[k])
        return out

    def rehydrate_json(self, value: Any, mapping: Dict[str, str]) -> Any:
        if isinstance(value, str):
            return self.rehydrate_text(value, mapping)
        if isinstance(value, list):
            return [self.rehydrate_json(v, mapping) for v in value]
        if isinstance(value, dict):
            return {k: self.rehydrate_json(v, mapping) for k, v in value.items()}
        return value

    def _placeholder(self, label: str, original: str, counter: int) -> str:
        h = hashlib.sha256()
        h.update(self.salt)
        h.update(label.encode("utf-8"))

        if self.mode == RedactionMode.STABLE_PER_VALUE:
            h.update(original.encode("utf-8"))
        else:
            h.update(counter.to_bytes(8, "little"))
            h.update(original.encode("utf-8"))

        digest = h.digest()
        short = digest[:6].hex()
        return f"<{label}_{short}>"

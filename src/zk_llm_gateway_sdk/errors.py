from __future__ import annotations

from dataclasses import dataclass


class GatewaySdkError(Exception):
    """Base class for SDK errors."""


class Base64Error(GatewaySdkError):
    pass


class InvalidGatewayPublicKey(GatewaySdkError):
    pass


class InvalidTokenClass(GatewaySdkError):
    pass


@dataclass
class PayloadTooLarge(GatewaySdkError):
    actual: int
    limit: int

    def __str__(self) -> str:
        return f"payload too large: {self.actual} bytes (limit {self.limit} bytes)"


class InvalidPadding(GatewaySdkError):
    pass


class CryptoError(GatewaySdkError):
    pass


class ProtocolError(GatewaySdkError):
    pass


class TicketExhausted(GatewaySdkError):
    pass


@dataclass
class GatewayError(GatewaySdkError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"gateway error ({self.code}): {self.message}"


@dataclass
class HttpError(GatewaySdkError):
    status_code: int
    message: str

    def __str__(self) -> str:
        return f"http error {self.status_code}: {self.message}"

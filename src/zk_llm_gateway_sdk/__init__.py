"""ZK LLM Gateway SDK (Python).

This SDK implements the client-side envelope encryption + padding protocol used by
the ZK LLM Gateway, along with ticket abstractions and a small OpenAI-style schema.

High level:
- Build the gateway's canonical `InferenceRequest` payload
- Pad to a fixed size for the token class
- Encrypt into an Envelope using X25519 + HKDF + ChaCha20-Poly1305
- POST envelope JSON to the gateway (/v1/infer)
- Decrypt the response envelope and parse `GatewayEnvelopePayload`

See README.md for usage and examples.
"""

from .client import GatewayClient, GatewayClientConfig, GatewaySyncClient
from .crypto import Envelope, GatewayPublicKey
from .errors import (
    GatewaySdkError,
    GatewayError,
    TicketExhausted,
    InvalidTokenClass,
    InvalidGatewayPublicKey,
)
from .integration import (
    AppChatRequest,
    AppGateway,
    AppGatewayConfig,
    AppGatewaySync,
    GATEWAY_INFER_PATH,
    RELAY_INFER_PATH,
    TicketSourceConfig,
)
from .openai_types import (
    ChatMessage,
    ChatCompletionsRequest,
    ChatCompletionsResponse,
)
from .redaction import RedactionMode, Redactor, RedactionResult
from .tickets import (
    ZkTicket,
    TicketSource,
    DummyTicketSource,
    FileTicketSource,
)
from .token_class import TokenClass

__all__ = [
    "GatewayClient",
    "GatewaySyncClient",
    "GatewayClientConfig",
    "GatewayPublicKey",
    "Envelope",
    "AppGateway",
    "AppGatewaySync",
    "AppGatewayConfig",
    "AppChatRequest",
    "TicketSourceConfig",
    "GATEWAY_INFER_PATH",
    "RELAY_INFER_PATH",
    "TokenClass",
    "ZkTicket",
    "TicketSource",
    "DummyTicketSource",
    "FileTicketSource",
    "ChatMessage",
    "ChatCompletionsRequest",
    "ChatCompletionsResponse",
    "Redactor",
    "RedactionMode",
    "RedactionResult",
    "GatewaySdkError",
    "GatewayError",
    "TicketExhausted",
    "InvalidTokenClass",
    "InvalidGatewayPublicKey",
]

__version__ = "0.1.0"

import asyncio

from zk_llm_gateway_sdk import (
    AppChatRequest,
    AppGateway,
    AppGatewayConfig,
    ChatCompletionsResponse,
    ChatMessage,
    TicketSourceConfig,
    TokenClass,
)


def test_app_gateway_config_from_env_dummy() -> None:
    config = AppGatewayConfig.from_env(
        {
            "GATEWAY_URL": "https://proxy.example.com",
            "GATEWAY_PUBLIC_KEY_B64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "GATEWAY_USE_DUMMY_TICKETS": "true",
            "GATEWAY_USE_RELAY": "true",
            "MODEL": "gpt-4o-mini",
            "TOKEN_CLASS": "c1024",
            "GATEWAY_TEMPERATURE": "0.2",
            "GATEWAY_TIMEOUT_SECS": "30",
        }
    )

    assert config.endpoint == "https://proxy.example.com"
    assert config.infer_path == "/relay"
    assert config.model == "gpt-4o-mini"
    assert config.token_class == TokenClass.C1024
    assert config.temperature == 0.2
    assert config.timeout_seconds == 30.0
    assert config.tickets == TicketSourceConfig.dummy()


def test_app_chat_request_builder() -> None:
    request = (
        AppChatRequest.from_user_prompt("hello")
        .with_system_prompt("system")
        .with_model("gpt-4o-mini")
        .with_token_class(TokenClass.C512)
        .with_temperature(0.1)
    )

    assert len(request.messages) == 1
    assert request.messages[0].role == "user"
    assert request.system_prompt == "system"
    assert request.model == "gpt-4o-mini"
    assert request.token_class == TokenClass.C512
    assert request.temperature == 0.1


def test_app_gateway_chat_applies_defaults_and_system_prompt() -> None:
    captured = {}

    class StubClient:
        async def chat_completions(self, token_class, request):  # type: ignore[no-untyped-def]
            captured["token_class"] = token_class
            captured["request"] = request
            return ChatCompletionsResponse.from_dict(
                {
                    "id": "resp-1",
                    "model": request.model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hello from stub"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            )

    gateway = AppGateway(
        client=StubClient(),  # type: ignore[arg-type]
        default_model="gpt-4o-mini",
        default_token_class=TokenClass.C2048,
        default_temperature=0.2,
    )

    answer = asyncio.run(gateway.ask_with_system("system", "hello"))

    assert answer == "hello from stub"
    assert captured["token_class"] == TokenClass.C2048
    assert captured["request"].model == "gpt-4o-mini"
    assert captured["request"].temperature == 0.2
    assert captured["request"].messages == [
        ChatMessage.system("system"),
        ChatMessage.user("hello"),
    ]

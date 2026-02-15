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
    pk_b64 = os.environ.get("GATEWAY_PUBLIC_KEY_B64", "REPLACE_ME")

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

    await client.aclose()

if __name__ == "__main__":
    asyncio.run(main())

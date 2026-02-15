import os
import asyncio

from zk_llm_gateway_sdk import (
    GatewayClient,
    GatewayPublicKey,
    TokenClass,
    FileTicketSource,
    ChatCompletionsRequest,
    ChatMessage,
)

async def main() -> None:
    endpoint = os.environ["GATEWAY_URL"]
    pk_b64 = os.environ["GATEWAY_PUBLIC_KEY_B64"]
    tickets_path = os.environ["TICKETS_JSON"]

    gateway_pk = GatewayPublicKey.from_base64(pk_b64)
    tickets = FileTicketSource.from_path(tickets_path)

    client = GatewayClient(endpoint, gateway_pk, tickets)

    req = ChatCompletionsRequest(
        model=os.environ.get("MODEL", "gpt-4o-mini"),
        messages=[
            ChatMessage.system("You are a helpful assistant."),
            ChatMessage.user("Summarize the goal of ZK usage credits in one sentence."),
        ],
        temperature=0.2,
    )

    resp = await client.chat_completions(TokenClass.C2048, req)
    print(resp.first_text() or "")

    await client.aclose()

if __name__ == "__main__":
    asyncio.run(main())

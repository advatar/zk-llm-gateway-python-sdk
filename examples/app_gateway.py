import asyncio
import os

from zk_llm_gateway_sdk import AppGatewayConfig


async def main() -> None:
    prompt = (
        os.environ.get("PROMPT")
        or "Explain how token classes reduce request-size leakage."
    )
    system_prompt = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")

    gateway = AppGatewayConfig.from_env().build()
    try:
        answer = await gateway.ask_with_system(system_prompt, prompt)
        print(answer)
    finally:
        await gateway.aclose()


if __name__ == "__main__":
    asyncio.run(main())

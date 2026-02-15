from zk_llm_gateway_sdk import Redactor, RedactionMode

def main() -> None:
    redactor = Redactor(mode=RedactionMode.STABLE_PER_VALUE)
    redactor.add_custom_term("ACME_INTERNAL_PROJECT")

    input_text = (
        "Email me at alice@example.com. "
        "My ETH is 0x0123456789aBCDEF0123456789abcdef01234567. "
        "sk-verysecretapikey"
    )

    res = redactor.redact_text(input_text)
    print("Original:", input_text)
    print("Redacted:", res.redacted)

    restored = redactor.rehydrate_text(res.redacted, res.map)
    print("Restored:", restored)

if __name__ == "__main__":
    main()

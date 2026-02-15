from zk_llm_gateway_sdk.redaction import RedactionMode, Redactor


def test_redaction_stable_mapping() -> None:
    r = Redactor(mode=RedactionMode.STABLE_PER_VALUE)
    text = "alice@example.com alice@example.com"
    res = r.redact_text(text)
    assert res.redacted.count("<EMAIL_") == 2
    # Both occurrences should map to the same placeholder.
    placeholders = list(res.map.keys())
    assert len(placeholders) == 1
    restored = r.rehydrate_text(res.redacted, res.map)
    assert restored == text

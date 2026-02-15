from zk_llm_gateway_sdk.padding import pad_payload, unpad_payload


def test_pad_roundtrip() -> None:
    msg = b"hello"
    padded = pad_payload(msg, 64)
    assert len(padded) == 64
    assert unpad_payload(padded) == msg

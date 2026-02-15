import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zk_llm_gateway_sdk.crypto import Envelope, GatewayPublicKey, seal_json, open_json
from zk_llm_gateway_sdk.padding import pad_payload, unpad_payload
from zk_llm_gateway_sdk.token_class import TokenClass


def _aad(v: int, token_class: TokenClass, eph_pubkey: bytes) -> bytes:
    return bytes([v]) + token_class.value.encode("ascii") + b"|" + eph_pubkey


def _derive_key(shared_secret: bytes, v: int, token_class: TokenClass) -> bytes:
    info = f"zk-llm-gateway|v{v}|{token_class.value}".encode("ascii")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)


def test_encrypt_decrypt_roundtrip() -> None:
    # Simulate a gateway static keypair.
    gw_sk = X25519PrivateKey.generate()
    gw_pk = gw_sk.public_key()
    try:
        gw_pk_bytes = gw_pk.public_bytes_raw()
    except AttributeError:
        from cryptography.hazmat.primitives import serialization

        gw_pk_bytes = gw_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    gateway_pk = GatewayPublicKey(gw_pk_bytes)

    payload = {"hello": "world", "n": 123}
    token_class = TokenClass.C2048

    env, st = seal_json(gateway_pk, token_class, payload)

    # Gateway side decrypt request.
    eph_pub = base64.b64decode(env.eph_pubkey_b64)
    nonce = base64.b64decode(env.nonce_b64)
    ct = base64.b64decode(env.ciphertext_b64)

    eph_pk = X25519PublicKey.from_public_bytes(eph_pub)
    shared = gw_sk.exchange(eph_pk)
    key = _derive_key(shared, env.v, token_class)

    # Client and gateway must derive same key.
    assert key == st.key

    cipher = ChaCha20Poly1305(key)
    padded = cipher.decrypt(nonce, ct, _aad(env.v, token_class, eph_pub))
    raw = unpad_payload(padded)
    assert json.loads(raw.decode("utf-8")) == payload

    # Gateway side encrypt response with same key and eph_pubkey.
    resp_payload = {"upstream": {"ok": True}}
    raw_resp = json.dumps(resp_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    padded_resp = pad_payload(raw_resp, token_class.response_padded_len())
    nonce2 = os.urandom(12)
    ct2 = cipher.encrypt(nonce2, padded_resp, _aad(env.v, token_class, eph_pub))

    resp_env = Envelope(
        v=env.v,
        token_class=token_class,
        eph_pubkey_b64=env.eph_pubkey_b64,
        nonce_b64=base64.b64encode(nonce2).decode("ascii"),
        ciphertext_b64=base64.b64encode(ct2).decode("ascii"),
    )

    decrypted = open_json(resp_env, st)
    assert decrypted == resp_payload

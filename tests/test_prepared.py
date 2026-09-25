"""Executable, synthetic reference-server tests; no real payment/TEE assertions."""
import asyncio
import base64
import copy
import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zk_llm_gateway_sdk.prepared import (
    CLASSES, AuthorizedInference, PreparedError, PreparedInference, encode_json,
)
from zk_llm_gateway_sdk.prepared_transport import (
    PreparedClient, PreparedEndpoint, PreparedSyncClient, open_response, seal_request,
)

RID = '12345678-1234-4234-9234-123456789abc'
REQ = {'model': 'synthetic-model', 'messages': [{'role': 'user', 'content': 'Ålder ok?'}]}


def b64(value):
    return base64.b64encode(value).decode('ascii')


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def prepare(**kwargs):
    return PreparedInference.prepare('c256', copy.deepcopy(REQ), request_id=RID, **kwargs)


def ticket(prepared):
    return {'commitment_root': prepared.commitment_b64, 'nullifier': b64(b'fixture-id'),
            'token_class': prepared.token_class, 'proof': b64(b'NOT-REAL-FINALITY')}


class ReferenceGateway:
    """Independent formula transcription from Rust, not the SDK crypto helpers."""
    def __init__(self, reply_mutator=None):
        self.sk = X25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.pk = public(self.sk)
        self.calls = 0
        self.effects = 0
        self.requests = []
        self.seen = set()
        self.reply_mutator = reply_mutator

    def respond(self, env):
        self.calls += 1
        assert env['v'] == 2
        cls = env['token_class']
        cid, _, req_len, resp_len = CLASSES[cls]
        eph = base64.b64decode(env['eph_pubkey_b64'])
        cn = base64.b64decode(env['client_nonce_b64'])
        suffix = bytes([2, cid]) + env['request_id'].encode() + cn + eph + self.pk
        salt = hashlib.sha256(b'zk-llm-gateway-envelope-kdf-v2' + suffix).digest()
        shared = self.sk.exchange(X25519PublicKey.from_public_bytes(eph))
        def key(direction):
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                        info=b'zk-llm-gateway-envelope-v2/' + direction + bytes([cid])).derive(shared)
        aad = b'zk-llm-gateway-envelope-aad-v2' + suffix
        raw = ChaCha20Poly1305(key(b'req')).decrypt(base64.b64decode(env['nonce_b64']),
              base64.b64decode(env['ciphertext_b64']), aad + b'\x01')
        assert len(raw) == req_len
        payload = json.loads(raw.rstrip(b'\0'))
        assert payload['request_id'] == env['request_id']
        self.requests.append(payload)
        t = payload['ticket']
        projection = {k: payload[k] for k in ('request_id', 'model', 'messages', 'max_tokens',
                                              'temperature', 'stream', 'token_class')}
        projection['provider_options'] = {k: v for k, v in payload.items() if k not in projection and k != 'ticket'}
        canonical = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        digest = hashlib.shake_256(b'ACTIVECHAIN-ZEROK-INFERENCE-AUTHORIZATION-V1\0'
                                  + len(canonical).to_bytes(8, 'big') + canonical).digest(48)
        assert b64(digest) == t['commitment_root']
        if t['nullifier'] in self.seen:
            body = {'kind': 'err', 'error': {'request_id': RID, 'code': 'canary-secret', 'message': 'private-error'}}
        else:
            self.seen.add(t['nullifier'])
            self.effects += 1
            body = {'kind': 'ok', 'response': {'request_id': RID, 'model': payload['model'],
                    'billed_token_class': cls, 'output': 'synthetic answer'}}
        if self.reply_mutator:
            self.reply_mutator(body)
        nonce = bytes([8])*12
        ct = ChaCha20Poly1305(key(b'resp')).encrypt(nonce, encode_json(body).ljust(resp_len, b'\0'), aad+b'\x02')
        return {**env, 'nonce_b64': b64(nonce), 'ciphertext_b64': b64(ct)}

    def http(self, request):
        return httpx.Response(200, headers={"content-type": "application/json"},
                              stream=httpx.ByteStream(encode_json(self.respond(json.loads(request.content)))))


def endpoint(server):
    return PreparedEndpoint('https://test.example/v1/infer', server.pk)


def test_snapshot_and_views_detached():
    source = copy.deepcopy(REQ)
    source['tools'] = [{'function': {'name': 'read'}}]
    p = PreparedInference.prepare('c256', source, request_id=RID)
    original = p.commitment
    source['messages'][0]['content'] = 'changed'
    source['tools'][0]['function']['name'] = 'write'
    p.to_request()['messages'][0]['content'] = 'changed again'
    assert p.commitment == original
    assert p.to_request()['tools'][0]['function']['name'] == 'read'
    with pytest.raises(FrozenInstanceError):
        p._wire = b'{}'
    assert 'Ålder' not in repr(p)


@pytest.mark.parametrize('field,value', [('temperature', .2), ('temperature', float('nan')),
    ('temperature', True), ('top_p', .9), ('seed', 2**53), ('stream', True), ('stream', 0),
    ('max_tokens', True), ('ticket', {}), ('provider_options', {}), ('request_id', RID)])
def test_unsupported_values_fail_closed(field, value):
    with pytest.raises(PreparedError):
        PreparedInference.prepare('c256', {**REQ, field: value})


@pytest.mark.parametrize('temperature', [None, 0, .5, 1, 1.5, 2])
def test_temperatures_and_nulls(temperature):
    request = copy.deepcopy(REQ)
    request['temperature'] = temperature
    p = PreparedInference.prepare('c256', request, request_id=RID)
    assert len(p.commitment) == 48
    assert p.to_request()['max_tokens'] is None
    assert p.to_request()['stream'] is None


def test_null_message_normalizes_like_gateway():
    p = PreparedInference.prepare('c256', {'model': 'synthetic-model', 'messages': [{'role': 'assistant', 'content': None}]})
    assert p.to_request()['messages'][0]['content'] == ''


def test_ticket_snapshot_and_mismatch():
    p = prepare()
    t = ticket(p)
    a = p.bind(t)
    t['proof'] = b64(b'mutated')
    assert b'mutated' not in a._payload
    assert 'NOT-REAL' not in repr(a)
    with pytest.raises(PreparedError, match='commitment_mismatch'):
        p.bind({**ticket(p), 'commitment_root': b64(bytes(48))})
    with pytest.raises(PreparedError, match='class_mismatch'):
        p.bind({**ticket(p), 'token_class': 'c512'})


@pytest.mark.parametrize('cls', list(CLASSES))
def test_independent_envelope_reference(cls):
    p = PreparedInference.prepare(cls, copy.deepcopy(REQ), request_id=RID)
    server = ReferenceGateway()
    env, ctx = seal_request(p.bind(ticket(p)), server.pk)
    assert len(base64.b64decode(env['ciphertext_b64'])) == CLASSES[cls][2] + 16
    assert open_response(server.respond(env), ctx)['output'] == 'synthetic answer'
    assert server.calls == server.effects == 1


@pytest.mark.parametrize('field,value', [('v', 1), ('v', True), ('request_id', str(__import__('uuid').uuid4())),
    ('client_nonce_b64', b64(bytes(32))), ('eph_pubkey_b64', b64(bytes(32))), ('token_class', 'c512')])
def test_response_header_substitution(field, value):
    server = ReferenceGateway()
    p = prepare()
    env, ctx = seal_request(p.bind(ticket(p)), server.pk)
    resp = server.respond(env)
    resp[field] = value
    with pytest.raises(PreparedError) as error:
        open_response(resp, ctx)
    assert error.value.outcome == 'dispatched_unknown'


def test_tamper_and_cross_request_replay():
    server = ReferenceGateway()
    p = prepare()
    env, ctx = seal_request(p.bind(ticket(p)), server.pk)
    response = server.respond(env)
    _, other = seal_request(p.bind(ticket(p)), server.pk)
    with pytest.raises(PreparedError):
        open_response(response, other)
    response['ciphertext_b64'] = b64(bytes(CLASSES['c256'][3]+16))
    with pytest.raises(PreparedError):
        open_response(response, ctx)


@pytest.mark.parametrize('field,value', [('request_id', 'wrong'), ('model', 'other'), ('billed_token_class', 'c512'), ('output', {})])
def test_decrypted_response_binding(field, value):
    server = ReferenceGateway(lambda body: body['response'].update({field: value}))
    p = prepare()
    env, ctx = seal_request(p.bind(ticket(p)), server.pk)
    with pytest.raises(PreparedError):
        open_response(server.respond(env), ctx)


@pytest.mark.parametrize('asynchronous', [False, True])
def test_sync_async_complete_roundtrip_and_replay(asynchronous):
    server = ReferenceGateway()
    p = prepare()
    a = p.authorize(ticket)
    cls = PreparedClient if asynchronous else PreparedSyncClient
    client = cls(endpoint(server), transport=httpx.MockTransport(server.http))
    call = lambda: asyncio.run(client.send_prepared(a)) if asynchronous else client.send_prepared(a)
    assert call()['output'] == 'synthetic answer'
    with pytest.raises(PreparedError) as error:
        call()
    assert error.value.code == 'gateway_rejected'
    assert 'private-error' not in str(error.value)
    assert server.calls == 2 and server.effects == 1


def test_async_authorization_callback():
    p = prepare()
    async def issue(prepared):
        return ticket(prepared)
    assert asyncio.run(p.authorize_async(issue)).prepared == p


def test_reject_mutation_before_transport():
    server = ReferenceGateway()
    p = prepare()
    a = p.bind(ticket(p))
    modified = json.loads(a._payload)
    modified['model'] = 'other'
    forged = AuthorizedInference(p, encode_json(modified))
    client = PreparedSyncClient(endpoint(server), transport=httpx.MockTransport(server.http))
    with pytest.raises(PreparedError) as error:
        client.send_prepared(forged)
    assert error.value.outcome == 'not_dispatched'
    assert server.calls == 0


@pytest.mark.parametrize('url', ['http://evil.example/v1/infer', 'http://localhost/v1/infer',
    'https://user:pw@a.example/v1/infer', 'https://a.example/v1/infer?q=1',
    'https://a.example/v1/chat/completions', 'https://a.example/v1/infer#x'])
def test_endpoint_restrictions(url):
    with pytest.raises(PreparedError):
        PreparedEndpoint(url, bytes(32), allow_http_loopback=True)


def test_numeric_loopback_explicit_only():
    with pytest.raises(PreparedError):
        PreparedEndpoint('http://127.0.0.1:8080/v1/infer', bytes(32))
    PreparedEndpoint('http://127.0.0.1:8080/v1/infer', bytes(32), allow_http_loopback=True)


@pytest.mark.parametrize('status,headers', [(307, {'location': 'https://other.example/v1/infer'}),
    (500, {}), (200, {'content-length': '999999999'}), (200, {'content-encoding': 'gzip'})])
def test_no_redirect_retry_or_raw_errors(status, headers):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers=headers, content=b'patient-secret')
    server = ReferenceGateway()
    client = PreparedSyncClient(endpoint(server), transport=httpx.MockTransport(handler))
    with pytest.raises(PreparedError) as error:
        client.send_prepared(prepare().bind(ticket(prepare())))
    assert len(calls) == 1
    assert 'patient-secret' not in str(error.value)


def test_cookies_not_carried_to_next_call():
    server = ReferenceGateway()
    seen = []
    def handler(request):
        seen.append(request.headers.get('cookie'))
        response = server.http(request)
        response.headers['set-cookie'] = 'tracking=secret; Path=/'
        return response
    client = PreparedSyncClient(endpoint(server), transport=httpx.MockTransport(handler))
    a = prepare().bind(ticket(prepare()))
    client.send_prepared(a)
    with pytest.raises(PreparedError):
        client.send_prepared(a)
    assert seen == [None, None]


def test_async_body_timeout_no_retry():
    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(1)
            yield b'{}'
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=Slow())
    server = ReferenceGateway()
    client = PreparedClient(replace(endpoint(server), timeout_seconds=.02), transport=httpx.MockTransport(handler))
    with pytest.raises(PreparedError) as error:
        asyncio.run(client.send_prepared(prepare().bind(ticket(prepare()))))
    assert error.value.outcome == 'dispatched_unknown' and len(calls) == 1


def test_no_low_order_key_release():
    with pytest.raises(PreparedError):
        seal_request(prepare().bind(ticket(prepare())), bytes(32))


def test_total_ticket_size_accounted():
    p = prepare()
    with pytest.raises(PreparedError, match='exceeds_class'):
        p.bind({**ticket(p), 'proof': b64(bytes(9000))})


@pytest.mark.parametrize('asynchronous', [False, True])
def test_real_loopback_http_roundtrip(asynchronous):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    reference = ReferenceGateway()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_POST(self):
            assert self.path == '/v1/infer'
            env = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            data = encode_json(reference.respond(env))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ep = PreparedEndpoint(f'http://127.0.0.1:{server.server_port}/v1/infer', reference.pk,
                          allow_http_loopback=True)
    p = prepare()
    try:
        if asynchronous:
            answer = asyncio.run(PreparedClient(ep).send_prepared(p.bind(ticket(p))))
        else:
            answer = PreparedSyncClient(ep).send_prepared(p.bind(ticket(p)))
        assert answer['output'] == 'synthetic answer'
        assert reference.calls == reference.effects == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_forged_projection_is_rejected_before_transport():
    p = replace(prepare(), _projection=b'{}')
    a = p.bind(ticket(p))
    with pytest.raises(PreparedError, match='invalid_prepared_snapshot'):
        a.validate()


def test_duplicate_response_json_rejected():
    from zk_llm_gateway_sdk.prepared import decode_json
    with pytest.raises(PreparedError):
        decode_json(b'{"a":1,"a":2}')


def test_oversized_stream_without_content_length():
    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(b'x'*20000))
    server = ReferenceGateway()
    client = PreparedSyncClient(endpoint(server), transport=httpx.MockTransport(handler))
    with pytest.raises(PreparedError, match='response_too_large'):
        client.send_prepared(prepare().bind(ticket(prepare())))

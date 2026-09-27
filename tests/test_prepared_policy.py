"""Additional pre-issuance policy and borrowed transport ownership regressions."""
import asyncio
import base64
import copy

import httpx
import pytest

from zk_llm_gateway_sdk.prepared import PreparedError, PreparedInference
from zk_llm_gateway_sdk.prepared_transport import PreparedClient, PreparedSyncClient
from test_prepared import ReferenceGateway, endpoint, ticket, REQ, RID


@pytest.mark.parametrize('option,value', [
    ('max_completion_tokens', 100000), ('max_output_tokens', 100000),
    ('api_key', 'SECRET-CREDENTIAL-CANARY'), ('authorization', 'SECRET-CREDENTIAL-CANARY'),
    ('n', 2), ('n', 0), ('n', True), ('n', '1'), ('n', None),
    ('store', True), ('store', 0), ('store', 'false'), ('store', None),
])
def test_unsafe_provider_options_refused_before_issuance(option, value):
    issued = []
    request = {**copy.deepcopy(REQ), option: value}
    with pytest.raises(PreparedError) as error:
        prepared = PreparedInference.prepare('c256', request, request_id=RID)
        prepared.authorize(lambda p: issued.append(p) or ticket(p))
    assert issued == []
    assert error.value.outcome == 'not_dispatched'
    assert 'SECRET-CREDENTIAL-CANARY' not in str(error.value)


@pytest.mark.parametrize('asynchronous', [False, True])
def test_one_completion_no_storage_passes_to_upstream(asynchronous):
    reference = ReferenceGateway()
    prepared = PreparedInference.prepare('c256', {**REQ, 'n': 1, 'store': False}, request_id=RID)
    cls = PreparedClient if asynchronous else PreparedSyncClient
    client = cls(endpoint(reference), transport=httpx.MockTransport(reference.http))
    authorized = prepared.bind(ticket(prepared))
    result = asyncio.run(client.send_prepared(authorized)) if asynchronous else client.send_prepared(authorized)
    assert result['output'] == 'synthetic answer'
    assert reference.requests[0]['n'] == 1
    assert reference.requests[0]['store'] is False
    assert reference.effects == 1


class OwnedSync(httpx.BaseTransport):
    def __init__(self, reference):
        self.reference = reference
        self.closed = False
        self.close_count = 0
        self.cookies = []

    def handle_request(self, request):
        assert not self.closed
        self.cookies.append(request.headers.get('cookie'))
        response = self.reference.http(request)
        response.headers['set-cookie'] = 'tracking=CANARY; Path=/'
        return response

    def close(self):
        self.closed = True
        self.close_count += 1


class OwnedAsync(httpx.AsyncBaseTransport):
    def __init__(self, reference):
        self.reference = reference
        self.closed = False
        self.close_count = 0
        self.cookies = []

    async def handle_async_request(self, request):
        assert not self.closed
        self.cookies.append(request.headers.get('cookie'))
        response = self.reference.http(request)
        response.headers['set-cookie'] = 'tracking=CANARY; Path=/'
        return response

    async def aclose(self):
        self.closed = True
        self.close_count += 1


@pytest.mark.parametrize('asynchronous', [False, True])
def test_borrowed_transport_stays_open_across_fresh_clients(asynchronous):
    reference = ReferenceGateway()
    transport = OwnedAsync(reference) if asynchronous else OwnedSync(reference)
    cls = PreparedClient if asynchronous else PreparedSyncClient
    client = cls(endpoint(reference), transport=transport)
    prepared = PreparedInference.prepare('c256', REQ, request_id=RID)
    for i in range(2):
        auth = ticket(prepared)
        auth['nullifier'] = base64.b64encode(bytes([i+1])).decode()
        bound = prepared.bind(auth)
        result = asyncio.run(client.send_prepared(bound)) if asynchronous else client.send_prepared(bound)
        assert result['output'] == 'synthetic answer'
    assert reference.effects == 2
    assert transport.cookies == [None, None]
    assert not transport.closed and transport.close_count == 0
    if asynchronous:
        asyncio.run(transport.aclose())
    else:
        transport.close()
    assert transport.close_count == 1


@pytest.mark.parametrize('asynchronous', [False, True])
def test_denied_local_binding_does_not_touch_caller_transport(asynchronous):
    reference = ReferenceGateway()
    transport = OwnedAsync(reference) if asynchronous else OwnedSync(reference)
    prepared = PreparedInference.prepare('c256', REQ, request_id=RID)
    auth = ticket(prepared)
    auth['commitment_root'] = base64.b64encode(bytes(48)).decode()
    with pytest.raises(PreparedError):
        prepared.bind(auth)
    assert not transport.closed and reference.calls == 0

"""Runs inside the isolated container. Never accepts a real credential."""
import http.client
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import uuid

HOST = 'litellm.ccviaghcp.test'
GATEWAY = 'sk-offline-only-sentinel'
OAUTH = 'gho_' + 'x' * 36
assert os.getuid() == 1000
context = ssl.create_default_context(cafile='/etc/lab/ca.crt')


class TLS(http.client.HTTPSConnection):
    def connect(self):
        self.sock = self._context.wrap_socket(socket.create_connection(('127.0.0.1', 4000), timeout=15), server_hostname=HOST)


def call(body=None, headers=None, path='/v1/messages', auth='x-api-key'):
    c = TLS(HOST, 4000, context=context, timeout=30)
    h = {'content-type': 'application/json', 'anthropic-version': '2023-06-01', 'x-claude-code-request-class': 'main'}
    if auth == 'authorization':
        h['authorization'] = 'Bearer ' + GATEWAY
    elif auth:
        h[auth] = GATEWAY
    h.update(headers or {})
    h = {k: v for k, v in h.items() if v is not None}
    c.request('POST' if body is not None else 'GET', path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse()
    status, content = r.status, r.read()
    c.close()
    return status, content


def wires():
    p = Path('/tmp/wire.jsonl')
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


for path in ('/health/liveliness', '/health/readiness'):
    assert call(path=path, auth=None)[0] == 200, path
for path in ('/v1/models', '/health', '/health?model=sonnet'):
    status, content = call(path=path)
    if path == '/health?model=sonnet':
        # A targeted, disabled health check reports no healthy endpoint, without inference.
        assert status == 503 and json.loads(content) == {
            'healthy_endpoints': [], 'unhealthy_endpoints': [], 'healthy_count': 0, 'unhealthy_count': 0}
    else:
        assert status == 200, path
assert not wires(), 'Health/model-list checks must not call the provider'
payload = {'model': 'sonnet', 'max_tokens': 64, 'messages': [{'role': 'user', 'content': 'synthetic-human-fixture'}]}
for auth in (None, 'x-api-key'):
    before = len(wires())
    status, error = call(payload, {'x-api-key': 'wrong'} if auth else {}, auth=auth)
    assert status in (401, 403) or (auth and status == 400 and json.loads(error)['error']['message'] == 'No connected db.'), status
    assert len(wires()) == before
for auth in ('x-api-key', 'authorization'):
    status, content = call(payload, {'anthropic-beta': 'synthetic-beta-2099-01-01',
        'x-claude-code-session-id': 'synthetic-session', 'x-arbitrary-client-header': 'synthetic-header'}, auth=auth)
    assert status == 200, (status, content)
    assert json.loads(content)['type'] == 'message'
    assert wires()[-1]['headers']['anthropic-beta'] == 'synthetic-beta-2099-01-01'
    assert wires()[-1]['headers']['x-initiator'] == 'user'
    assert 'x-claude-code-session-id' not in wires()[-1]['headers']
    assert 'x-arbitrary-client-header' not in wires()[-1]['headers']
    for path, body, expected in (
            ('/v1/messages/count_tokens', {'model': 'sonnet', 'messages': payload['messages']}, 200),
            ('/v1/responses', {'model': 'sonnet', 'input': 'synthetic-audit-input'}, 400),
            ('/anthropic/v1/messages', payload, 401),
            ('/v1/embeddings', {'model': 'sonnet', 'input': 'synthetic-audit-input'}, 400),
            ('/model/new', {'model_name': 'synthetic-audit-only', 'litellm_params': {
                'model': 'openai/claude-sonnet-5.5', 'api_base': 'https://api.enterprise.githubcopilot.com',
                'api_key': 'synthetic-invalid'}}, 500),
            ('/key/generate', {'models': ['sonnet']}, 500)):
        before = len(wires())
        status, content = call(body, path=path, auth=auth)  # POST for each exact route/payload.
        assert status == expected, (path, auth, status)
        if path == '/v1/messages/count_tokens':
            assert type(json.loads(content)['input_tokens']) is int
        assert len(wires()) == before, (path, auth)
# Admin 500s above are pinned no-database behavior, NOT authorization proof.
assert Path('/tmp/production-redirects-checked').read_text() == 'false'
status, content = call(payload | {'stream': True})
assert status == 200 and b'"type": "message_stop"' in content, (status, content)
tool = {'name': 'get_probe_value', 'description': 'Synthetic probe.', 'input_schema': {'type': 'object', 'properties': {'id': {'type': 'string'}}}}
status, content = call(payload | {'tools': [tool],
                                'thinking': {'type': 'adaptive'}, 'system': [{'type': 'text', 'text': 'fixture', 'cache_control': {'type': 'ephemeral'}}]})
assert status == 200, (status, content)
assert json.loads(content)['content'][0]['type'] == 'tool_use'
assert wires()[-1]['body']['tools'] == [tool]
assert wires()[-1]['body']['thinking'] == {'type': 'adaptive'}
assert wires()[-1]['body']['system'][0]['cache_control'] == {'type': 'ephemeral'}
assert call(payload | {'stream': True, 'tools': [tool]})[0] == 200
assert wires()[-1]['body']['tools'] == [tool] and wires()[-1]['body']['stream'] is True
assert call(payload | {'system': [{'type': 'text', 'text': 'fixture', 'cache_control': {'type': 'ephemeral', 'ttl': '1h'}}]})[0] == 200
assert wires()[-1]['body']['system'][0]['cache_control'] == {'type': 'ephemeral'}, 'Unverified cache TTL opt-in'
# Reissue an AUTO tool call so the next continuation uses its native tool_use response.
status, content = call(payload | {'tools': [tool]})
nonce = uuid.uuid4().hex
continuation = payload | {'messages': payload['messages'] + [{'role': 'assistant', 'content': json.loads(content)['content']},
                 {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'tool_offline', 'content': nonce}]}]}
status, content = call(continuation)
assert status == 200 and nonce in json.loads(content)['content'][0]['text']
assert wires()[-1]['headers']['x-initiator'] == 'agent'
assert wires()[-1]['body']['messages'][-1] == continuation['messages'][-1]
tool_result = continuation['messages'][-1]['content'][0]
for blocks, headers, expected in (
        ([{'type': 'text', 'text': 'synthetic-new-human-input'}], {}, 'user'),
        ([tool_result], {}, 'agent'),
        ([tool_result, {'type': 'text', 'text': 'synthetic-new-human-input'}], {}, 'user'),
        ([tool_result, {'type': 'text', 'text': 'synthetic-new-human-input'}],
         {'x-claude-code-prev-tool-durations': 'Bash=7'}, 'agent')):
    mixed = continuation | {'messages': continuation['messages'][:-1] + [{'role': 'user', 'content': blocks}]}
    assert call(mixed, headers)[0] == 200
    assert wires()[-1]['headers']['x-initiator'] == expected
    system_context = mixed | {'messages': mixed['messages'] + [{'role': 'system', 'content': 'synthetic trailing context'}]}
    assert call(system_context, headers)[0] == 200
    assert wires()[-1]['headers']['x-initiator'] == expected
    assert wires()[-1]['body']['messages'][-1] == system_context['messages'][-1]
for kind in ('subagent', 'auxiliary', 'workflow', 'compaction'):
    assert call(payload, {'x-claude-code-request-class': kind, 'x-initiator': 'user'})[0] == 200
    assert wires()[-1]['headers']['x-initiator'] == 'agent'
for headers in ({'x-claude-code-agent-id': 'synthetic-agent'}, {'x-claude-code-compaction': 'auto'}):
    assert call(payload, headers)[0] == 200
    assert wires()[-1]['headers']['x-initiator'] == 'agent'
assert call(payload, {'x-initiator': 'agent', 'openai-intent': 'spoofed', 'authorization': 'Bearer ' + GATEWAY})[0] == 200
assert wires()[-1]['headers']['x-initiator'] == 'user'
for override in ({'api_base': 'https://attacker.invalid'}, {'base_url': 'https://attacker.invalid'},
                 {'api_key': 'attacker-secret'}, {'headers': {'authorization': 'Bearer attacker-secret'}},
                 {'extra_headers': {'x-api-key': 'attacker-secret'}}, {'extra_body': {'api_base': 'https://attacker.invalid'}},
                 {'model': 'openai/claude-sonnet-5.5'}, {'model': 'github_copilot/claude-sonnet-5.5'},
                 {'model': 'unlisted'}, {'model_info': {'supported_endpoints': ['/chat/completions']}},
                 {'litellm_params': {'api_base': 'https://attacker.invalid'}}, {'max_tokens': 8193}):
    before = len(wires())
    status, _ = call(payload | override)
    assert status in (400, 401, 403, 404), (override.keys(), status)
    assert len(wires()) == before, override.keys()
for headers in ({'x-pass-authorization': 'Bearer attacker-secret'}, {'x-pass-x-api-key': 'attacker-secret'},
                {'x-claude-code-request-class': 'unknown'}, {'x-claude-code-request-class': None},
                {'anthropic-version': '2099-01-01'}):
    before = len(wires())
    assert call(payload, headers)[0] in (400, 403)
    assert len(wires()) == before
before = len(wires())
assert call(payload, path='/v1/chat/completions')[0] in (400, 403)
assert len(wires()) == before
for wire in wires():
    assert wire['url'] == 'https://api.enterprise.githubcopilot.com/v1/messages', wire['url']
    assert wire['body']['model'] in ('claude-sonnet-5.5', 'claude-opus-5.5', 'claude-haiku-5.5')
    h = wire['headers']
    assert h['authorization'] == 'Bearer ' + OAUTH
    assert 'x-api-key' not in h
    assert GATEWAY not in json.dumps(wire)
    assert h['user-agent'] == 'ccviaghcp-LiteLLM/1.106.0'
    assert h['x-github-api-version'] == '2026-08-01'
    assert h['openai-intent'] == 'conversation-edits' and h['x-interaction-type'] == 'conversation-agent'
    uuid.UUID(h['x-interaction-id'])
assert not Path('/var/run/copilot-cache').exists()
from gateway_policy import upstream_headers
assistant_turn = payload | {'messages': [{'role': 'assistant', 'content': 'synthetic-continuation'}],
    'proxy_server_request': {'url': 'https://' + HOST + '/v1/messages', 'headers': {'x-claude-code-request-class': 'main'}}}
assert upstream_headers(assistant_turn)['x-initiator'] == 'agent'
from fastapi import HTTPException
for invalid in ([], ['invalid-message-shape'], [{'role': 'system', 'content': 'no conversational turn'}]):
    try:
        upstream_headers(assistant_turn | {'messages': invalid})
        raise AssertionError('Invalid message shape accepted')
    except HTTPException as error:
        assert error.status_code == 400
# Run the shipped smoke implementation too, with only writable synthetic inputs.
import smoke
smoke.LOCAL = Path('/tmp/smoke-fixture')
smoke.LOCAL.mkdir(mode=0o700, exist_ok=True)
(smoke.LOCAL / 'ca.crt').write_bytes(Path('/etc/lab/ca.crt').read_bytes())
(smoke.LOCAL / 'gateway-key').write_text(GATEWAY)
with contextlib.redirect_stdout(io.StringIO()) as output:
    smoke.run('127.0.0.1', 4000)
assert 'PASS native tool_use/tool_result round trip' in output.getvalue()
# Distinct real-format model aliases avoid a preceding 307 putting the next test
# into Router cooldown before it can exercise the streaming transport.
for alias, stream in (('sonnet', False), ('haiku', True)):
    before = len(wires())
    status, content = call(payload | {'model': alias, 'stream': stream, 'messages': [{'role': 'user', 'content': 'redirect-fixture'}]})
    assert status != 200 or b'error' in content
    redirected = wires()[before:]
    assert redirected and all(w['url'] == 'https://api.enterprise.githubcopilot.com/v1/messages' for w in redirected), 'Redirect followed'
    assert all(w['headers']['authorization'] == 'Bearer ' + OAUTH and 'x-api-key' not in w['headers'] for w in redirected)
print('PASS synthetic native wire assertions')

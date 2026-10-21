"""Explicit live native-Messages test. Prints assertions only, never credentials or bodies."""
import argparse
import http.client
import json
import secrets
import socket
import ssl
import sys

from common import HOST, LOCAL, SafeError, read_private


class LabHTTPS(http.client.HTTPSConnection):
    def __init__(self, connect_host, port, context):
        super().__init__(HOST, port, timeout=180, context=context)
        self.connect_host = connect_host

    def connect(self):
        raw = socket.create_connection((self.connect_host, self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=HOST)


def sse(response):
    events = []
    for line in response:
        if line.startswith(b'data: '):
            value = line[6:].strip()
            if value and value != b'[DONE]':
                events.append(json.loads(value))
    return events


def run(host, port, count_tokens=False):
    context = ssl.create_default_context(cafile=str(LOCAL / 'ca.crt'))
    key = read_private(LOCAL / 'gateway-key').strip()

    def call(payload, auth=key, path='/v1/messages'):
        connection = LabHTTPS(host, port, context)
        headers = {'Content-Type': 'application/json', 'anthropic-version': '2023-06-01',
                   'x-claude-code-request-class': 'main'}
        if auth is not None:
            headers['x-api-key'] = auth
        try:
            connection.request('POST', path, json.dumps(payload), headers)
            response = connection.getresponse()
            if response.status != 200:
                try:
                    error = json.load(response)
                except (ValueError, UnicodeError):
                    error = None
                return response.status, error
            if payload.get('stream'):
                if not response.getheader('content-type', '').startswith('text/event-stream'):
                    raise SafeError('Native SSE content type mismatch')
                return response.status, sse(response)
            return response.status, json.load(response)
        finally:
            connection.close()

    payload = {'model': 'sonnet', 'max_tokens': 128, 'messages': [{'role': 'user', 'content': 'Reply with OK.'}]}
    for auth in (None, 'sk-deliberately-wrong-key'):
        status, error = call(payload, auth)
        # Pinned no-database proxy returns 400 (No connected db) for unknown keys.
        if not (status in (401, 403) or (auth is not None and status == 400
                and isinstance(error, dict) and error.get('error', {}).get('message') == 'No connected db.')):
            raise SafeError('Authentication rejection mismatch')
    print('PASS missing/wrong gateway authentication')
    status, plain = call(payload)
    if not (status == 200 and plain['type'] == 'message' and plain['role'] == 'assistant'
            and any(block['type'] == 'text' for block in plain['content'])):
        raise SafeError('Native Messages JSON check failed')
    print('PASS native Messages JSON')
    status, events = call(payload | {'stream': True})
    if not (status == 200 and events and events[0]['type'] == 'message_start'
            and events[-1]['type'] == 'message_stop' and any(e['type'] == 'content_block_delta' for e in events)
            and not any(e['type'] == 'error' for e in events)):
        raise SafeError('Native Messages SSE check failed')
    print('PASS native Messages SSE')
    tool = {'name': 'get_probe_value', 'description': 'Get the opaque probe value. Do not guess it.',
            'input_schema': {'type': 'object', 'properties': {'id': {'type': 'string', 'enum': ['probe']}}, 'required': ['id']}}
    request = payload | {'max_tokens': 512, 'messages': [{'role': 'user', 'content':
        'Call get_probe_value with id probe. After receiving its result, reply with exactly that value.'}], 'tools': [tool]}
    status, result = call(request)
    if not (status == 200 and result['stop_reason'] == 'tool_use'):
        raise SafeError('Native tool_use check failed')
    use = next((block for block in result['content'] if block['type'] == 'tool_use'), None)
    if not (use and use['name'] == 'get_probe_value' and use['input']['id'] == 'probe'):
        raise SafeError('Native tool_use probe mismatch')
    nonce = secrets.token_hex(24)
    messages = request['messages'] + [{'role': 'assistant', 'content': result['content']},
        {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': use['id'], 'content': nonce}]}]
    status, final = call(payload | {'messages': messages, 'tools': [tool]})
    if not (status == 200 and final['stop_reason'] == 'end_turn'
            and nonce in ''.join(block.get('text', '') for block in final['content'] if block['type'] == 'text')):
        raise SafeError('Native tool_result round trip failed')
    print('PASS native tool_use/tool_result round trip')
    if count_tokens:
        status, result = call({'model': 'sonnet', 'messages': payload['messages']}, path='/v1/messages/count_tokens')
        if not (status == 200 and type(result['input_tokens']) is int):
            raise SafeError('Optional local count_tokens estimate check failed')
        print('PASS optional LOCAL count_tokens estimate (not provider-side billing accuracy)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private', action='store_true', help='Use private DNS:443 instead of loopback:4000; requires VNet access')
    parser.add_argument('--count-tokens', action='store_true')
    args = parser.parse_args()
    try:
        run(HOST if args.private else '127.0.0.1', 443 if args.private else 4000, args.count_tokens)
    except (Exception, KeyboardInterrupt) as error:
        print('FAIL native smoke: ' + (str(error) if isinstance(error, SafeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)

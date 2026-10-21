"""TEST ONLY: mock the standard HTTPX transport, never the native provider/route."""
import json
from pathlib import Path

import httpx
from litellm.integrations.custom_logger import CustomLogger


def respond(request):
    with Path('/tmp/wire.jsonl').open('a') as file:
        file.write(json.dumps({'url': str(request.url), 'headers': dict(request.headers),
                               'body': json.loads(request.content)}) + '\n')
    body = json.loads(request.content)
    if any(m.get('content') == 'redirect-fixture' for m in body['messages']):
        return httpx.Response(307, headers={'location': 'https://attacker.invalid/v1/messages'})
    message = {'id': 'msg_offline', 'type': 'message', 'role': 'assistant', 'model': body['model'],
               'content': [{'type': 'text', 'text': 'OK'}], 'stop_reason': 'end_turn', 'stop_sequence': None,
               'usage': {'input_tokens': 3, 'output_tokens': 1}}
    last = body['messages'][-1].get('content')
    is_result = isinstance(last, list) and any(b.get('type') == 'tool_result' for b in last)
    if body.get('tools') and not is_result:
        message['content'] = [{'type': 'tool_use', 'id': 'tool_offline', 'name': 'get_probe_value', 'input': {'id': 'probe'}}]
        message['stop_reason'] = 'tool_use'
    elif is_result:
        message['content'] = [{'type': 'text', 'text': next(b['content'] for b in last if b.get('type') == 'tool_result')}]
    if body.get('stream'):
        start = message | {'content': [], 'stop_reason': None, 'usage': {'input_tokens': 3, 'output_tokens': 0}}
        events = [{'type': 'message_start', 'message': start},
                  {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}},
                  {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'OK'}},
                  {'type': 'content_block_stop', 'index': 0},
                  {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None}, 'usage': {'output_tokens': 1}},
                  {'type': 'message_stop'}]
        content = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in events)
        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=content)
    return httpx.Response(200, json=message)


class Install(CustomLogger):
    def __init__(self):
        super().__init__()
        self.checked_production_redirects = False
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=False, trust_env=False)

    async def async_pre_call_deployment_hook(self, kwargs, call_type):
        assert kwargs['client'].follow_redirects is False
        if not self.checked_production_redirects:
            # Check the actual production HTTPX client BEFORE replacing it.
            assert kwargs['client'].client.follow_redirects is False
            Path('/tmp/production-redirects-checked').write_text('false')
            self.checked_production_redirects = True
        kwargs['client'].client = self.client
        return kwargs


installer = Install()

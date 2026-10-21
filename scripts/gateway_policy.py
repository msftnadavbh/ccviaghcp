"""LiteLLM's existing request/deployment hooks, not an API adapter.

Only native Messages go to the pinned host. No client-controlled transport,
provider credentials, routing fallbacks or billing-classification headers.
"""
import json
import os
import sys
from urllib.parse import urlsplit
import uuid

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger
from litellm.llms.custom_httpx.http_handler import AsyncHTTPHandler

from common import OUTPUT, UPSTREAM

BLOCKED = {'api_key', 'api_base', 'base_url', 'extra_headers', 'extra_body', 'litellm_params',
           'model_info', 'custom_llm_provider', 'client', 'user_config',
           'fallbacks', 'context_window_fallbacks', 'content_policy_fallbacks', 'router_settings_override'}


def reject(reason):
    raise HTTPException(status_code=400, detail='Pinned native Messages boundary: ' + reason)


def upstream_headers(data):
    request = data.get('proxy_server_request') or {}
    if urlsplit(request.get('url', '')).path != '/v1/messages':
        reject('path')
    if BLOCKED.intersection(data) or request.get('credential_fields'):
        reject('client override')
    if data.get('model') not in ('sonnet', 'opus', 'haiku'):
        reject('model alias')
    maximum = data.get('max_tokens')
    if type(maximum) is not int or not 1 <= maximum <= OUTPUT:
        reject('output cap')
    headers = {k.lower(): v for k, v in request.get('headers', {}).items()}
    if any(k.startswith('x-pass-') for k in headers):
        reject('passthrough header')
    kind = headers.get('x-claude-code-request-class')
    if kind not in ('main', 'subagent', 'workflow', 'compaction', 'auxiliary'):
        reject('gateway hint')  # Actual Claude 2.1.284 launcher enables documented gateway hints.
    messages = data.get('messages')
    if not isinstance(messages, list) or not messages:
        reject('messages')
    last = None
    # Claude Code appends system context after the actual conversational turn.
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get('role') not in ('user', 'assistant', 'system'):
            reject('messages')
        if message['role'] != 'system':
            last = message
            break
    if last is None:
        reject('messages')
    content = last.get('content', [])
    tool_result = (isinstance(content, list) and bool(content)
                   and all(isinstance(b, dict) and b.get('type') == 'tool_result' for b in content))
    automated = (kind != 'main' or last.get('role') != 'user' or tool_result
                  or 'x-claude-code-prev-tool-durations' in headers
                  or headers.get('x-claude-code-agent-id') or headers.get('x-claude-code-compaction'))
    result = {'user-agent': 'ccviaghcp-LiteLLM/1.106.0', 'x-github-api-version': '2026-08-01',
              'anthropic-version': '2023-06-01', 'openai-intent': 'conversation-edits',
              'x-interaction-type': 'conversation-agent', 'x-interaction-id': str(uuid.uuid4()),
              'x-initiator': 'agent' if automated else 'user'}
    if 'anthropic-version' in headers and headers['anthropic-version'] != '2023-06-01':
        reject('API version')
    if 'anthropic-beta' in headers:
        result['anthropic-beta'] = headers['anthropic-beta']
    return result


class LabBoundary(CustomLogger):
    def __init__(self):
        super().__init__()
        self.client = AsyncHTTPHandler(follow_redirects=False)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if call_type != 'anthropic_messages':
            reject('call type')
        # credential_fields snapshots body `headers` BEFORE automatic forwarding.
        # Rebuild cleaned HTTP headers so the caller cannot choose auth/initiator.
        data['headers'] = upstream_headers(data)
        data['provider_specific_header'] = []
        kind = {k.lower(): v for k, v in data['proxy_server_request']['headers'].items()}['x-claude-code-request-class']
        # Fixed-vocabulary audit only: never emit caller headers, content or credentials.
        print(json.dumps({'class': kind, 'initiator': data['headers']['x-initiator']}, separators=(',', ':')), file=sys.stderr, flush=True)
        return data

    async def async_pre_call_deployment_hook(self, kwargs, call_type):
        if (kwargs.get('api_base') != UPSTREAM
                or not str(kwargs.get('model', '')).startswith('openai/claude-')
                or kwargs.get('api_key') != os.environ.get('COPILOT_OAUTH_TOKEN')):
            reject('deployment')
        # Standard LiteLLM HTTP handler; disable redirects for streaming AND JSON.
        kwargs['client'] = self.client
        return kwargs


policy = LabBoundary()

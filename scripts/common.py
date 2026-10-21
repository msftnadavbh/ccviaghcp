"""Explicit deployment scope and protected local I/O; standard library only."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local'
REGION = 'swedencentral'
RG = 'ccviaghcp-rg'
IMAGE = 'ghcr.io/berriai/litellm@sha256:2e4c0371f3a8c28e4da131d77abaa8341cd3b0c2fcc4d34d7c5900431af7b9d0'
HOST = 'litellm.ccviaghcp.test'
UPSTREAM = 'https://api.enterprise.githubcopilot.com'
WINDOW = 200000
OUTPUT = 8192


class SafeError(ValueError):
    """Only deliberately authored, value-free messages may cross a CLI boundary."""


def protect_dir(path=LOCAL):
    if path.is_symlink():
        raise SafeError('Refusing symlink directory')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_private(path, data):
    """Exclusive creation: reruns never rotate or clobber an existing secret."""
    protect_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)


def read_private(path):
    if path.parent.is_symlink():
        raise SafeError('Refusing symlink directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid():
            raise SafeError('Expected owned regular file')
        os.fchmod(f.fileno(), 0o600)
        return f.read()


def token(value):
    value = value.strip()
    if not re.fullmatch(r'[A-Za-z0-9_]{20,512}', value):
        raise SafeError('Invalid or empty access token')
    return value


def safe_endpoint(value):
    if value != UPSTREAM:
        raise SafeError('Unapproved Copilot endpoint')
    return value


def azure_target(required=True):
    """Resolve only on demand; local-only preparation permits BOTH settings absent."""
    names = ('CCVIAGHCP_SUBSCRIPTION_ID', 'CCVIAGHCP_TENANT_ID')
    if not required and all(name not in os.environ for name in names):
        return None
    values = []
    for name in names:
        try:
            value = uuid.UUID(os.environ[name].strip())
            if not value.int:
                raise ValueError()
        except (KeyError, ValueError):
            raise SafeError(name + ' must be set to a non-nil UUID') from None
        values.append(str(value))
    return tuple(values)


def check_account(account, subscription, tenant):
    if account.get('id') != subscription or account.get('tenantId') != tenant or account.get('state') != 'Enabled':
        raise SafeError('Azure tenant/subscription/state mismatch')


def az(*args, input=None, timeout=None):
    subscription, tenant = azure_target()
    # REST bodies/errors can contain credentials. Disable only child CLI logging/telemetry, not guest auditing.
    env = None
    if args[:1] == ('rest',):
        env = os.environ | {'AZURE_LOGGING_ENABLE_LOG_FILE': 'false', 'AZURE_CORE_COLLECT_TELEMETRY': 'false'}
    # Check actual context before EVERY command, including after an operator login change.
    account = subprocess.check_output(['az', 'account', 'show', '--subscription', subscription, '--only-show-errors', '-o', 'json'],
                                      stderr=subprocess.PIPE, timeout=timeout, env=env)
    check_account(json.loads(account), subscription, tenant)
    return subprocess.check_output(['az', *args, '--subscription', subscription, '--only-show-errors', '-o', 'json'],
                                   stderr=subprocess.PIPE, input=input, timeout=timeout, env=env)


def model_config(catalog, selection):
    if not catalog.get('verified_at') or not safe_endpoint(catalog.get('endpoint', '')):
        raise SafeError('Live discovery evidence is required')
    if set(selection) != {'sonnet', 'opus', 'haiku'}:
        raise SafeError('Select exactly sonnet, opus and haiku (reuse entitled IDs if needed)')
    available = {m['id']: m for m in catalog['response']['data']}
    models = []
    for alias, model_id in selection.items():
        if not isinstance(model_id, str) or not re.fullmatch(r'claude-[A-Za-z0-9_.-]+', model_id):
            raise SafeError('Only explicit discovered Claude IDs are allowed')
        if model_id not in available:
            raise SafeError('Selected model is not in the live catalog')
        entry = available[model_id]
        if entry.get('policy', {}).get('state') != 'enabled':
            raise SafeError('Selected model policy is not enabled')
        if '/v1/messages' not in entry.get('supported_endpoints', []):
            raise SafeError('Model does not advertise native /v1/messages')
        capabilities = entry.get('capabilities')
        if not isinstance(capabilities, dict):
            raise SafeError('Missing live model capabilities')
        limits = capabilities.get('limits')
        if not isinstance(limits, dict):
            raise SafeError('Live model limits must support fixed input 200000 and output 8192 caps')
        supports = capabilities.get('supports', {})
        if any(supports.get(key) is not True for key in ('streaming', 'tool_calls', 'adaptive_thinking')):
            raise SafeError('Native streaming/tool/adaptive capability evidence required')
        inputs, outputs = limits.get('max_prompt_tokens'), limits.get('max_output_tokens')
        if type(inputs) is not int or inputs < WINDOW:
            raise SafeError('Live model max_prompt_tokens must be an integer at least 200000')
        if type(outputs) is not int or outputs < OUTPUT:
            raise SafeError('Live model max_output_tokens must be an integer at least 8192')
        models.append({'model_name': alias,
                       'litellm_params': {'model': 'openai/' + model_id, 'api_base': UPSTREAM,
                                          'api_key': 'os.environ/COPILOT_OAUTH_TOKEN',
                                          'max_tokens': OUTPUT},
                       'model_info': {'mode': 'anthropic_messages', 'supported_endpoints': ['/v1/messages'],
                                      'disable_background_health_check': True,
                                      'supports_adaptive_thinking': True, 'supports_reasoning': True,
                                      'supports_function_calling': True,
                                      'max_tokens': WINDOW, 'max_input_tokens': WINDOW,
                                      'max_output_tokens': OUTPUT}})
    return {'model_list': models,
            'general_settings': {'master_key': 'os.environ/LITELLM_MASTER_KEY', 'disable_spend_logs': True,
                                 'health_check_skip_disabled_background_models': True,
                                 'allow_client_side_credentials': False,
                                 'forward_client_headers_to_llm_api': True,
                                 'forward_llm_provider_auth_headers': False},
            'router_settings': {'num_retries': 0},
            'litellm_settings': {'drop_params': False, 'turn_off_message_logging': True,
                                 'set_verbose': False, 'callbacks': ['gateway_policy.policy']}}

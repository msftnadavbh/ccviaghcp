"""Runs as the main process; never initiates device authorization."""
import json
import os
from pathlib import Path
import sys

from common import OUTPUT, SafeError, safe_endpoint, token


def main():
    os.umask(0o077)
    access = Path('/var/run/copilot-secret/access-token')
    os.environ['COPILOT_OAUTH_TOKEN'] = token(access.read_text())
    config = json.loads(Path('/etc/lab/config.json').read_text())
    settings = config['general_settings']
    if (settings.get('allow_client_side_credentials') is not False
            or settings.get('forward_llm_provider_auth_headers') is not False
            or settings.get('forward_client_headers_to_llm_api') is not True
            or settings.get('health_check_skip_disabled_background_models') is not True
            or 'gateway_policy.policy' not in config['litellm_settings'].get('callbacks', [])
            or {m['model_name'] for m in config['model_list']} != {'sonnet', 'opus', 'haiku'}):
        raise SafeError('Missing native Messages security boundary')
    for model in config['model_list']:
        params = model['litellm_params']
        safe_endpoint(params['api_base'])
        if (not params['model'].startswith('openai/claude-')
                or params['api_key'] != 'os.environ/COPILOT_OAUTH_TOKEN'
                or set(params) != {'model', 'api_base', 'api_key', 'max_tokens'}
                or not 1 <= params['max_tokens'] <= OUTPUT
                or model['model_info'].get('disable_background_health_check') is not True
                or model['model_info']['supported_endpoints'] != ['/v1/messages']):
            raise SafeError('Unapproved native Messages deployment')
    os.environ['HOME'] = '/tmp'
    os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
    os.environ['LITELLM_LOG'] = 'CRITICAL'
    os.environ['LITELLM_DISABLE_REDACT_SECRETS'] = 'false'
    os.environ['PYTHONPATH'] = '/etc/lab'
    os.execvp('litellm', ['litellm', '--config', '/etc/lab/config.json', '--host', '0.0.0.0',
                        '--port', '4000', '--num_workers', '1',
                        '--ssl_keyfile_path', '/var/run/lab-tls/tls.key',
                        '--ssl_certfile_path', '/var/run/lab-tls/tls.crt'])


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('Gateway startup refused: ' + (str(error) if isinstance(error, SafeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)

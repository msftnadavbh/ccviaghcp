"""Pinned TLS proxy + HTTPX mock wire, network=none, synthetic credentials ONLY."""
import json
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common
import lab
from test_kit import fixture_catalog


def docker(*args, timeout=120):
    return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT, timeout=timeout)


def check_container(command, name):
    created = False
    checked = False
    container = name
    try:
        identifier = docker(*command)
        created = True
        candidate = identifier.decode('ascii').strip()
        if len(candidate) == 64 and all(c in '0123456789abcdef' for c in candidate):
            container = candidate
        for cycle in range(2):
            if cycle:
                docker('restart', container)
            for attempt in range(45):
                try:
                    docker('exec', container, 'python', '-c', "import socket; socket.create_connection(('127.0.0.1',4000),timeout=2).close()")
                    break
                except subprocess.CalledProcessError:
                    if json.loads(docker('inspect', container))[0]['State']['Status'] != 'running':
                        raise AssertionError('Proxy exited before readiness') from None
                    time.sleep(2)
            else:
                raise AssertionError('Proxy startup timed out')
            result = docker('exec', container, 'python', '/etc/lab/native_assertions.py')
            assert result.strip() == b'PASS synthetic native wire assertions'
            logs = docker('logs', container, timeout=30)
            for secret in (b'gho_' + b'x' * 36, b'sk-offline-only-sentinel'):
                assert secret not in logs, 'Secret leaked in runtime log'
            audit = [line for line in logs.splitlines() if line.startswith(b'{"class":')]
            assert audit, 'Missing bounded classification audit'
            for line in audit:
                entry = json.loads(line)
                assert len(line) <= 96 and set(entry) == {'class', 'initiator'}
                assert entry['class'] in ('main', 'subagent', 'workflow', 'compaction', 'auxiliary')
                assert entry['initiator'] in ('user', 'agent')
            assert {json.loads(line)['initiator'] for line in audit} == {'user', 'agent'}
            print('CHECK pinned non-root native TLS + synthetic wire/negative suite, start ' + str(cycle + 1))
        checked = True
    except BaseException as error:
        # Retrieval and exclusive owner-only diagnostic creation must not mask the first error.
        diagnostic = getattr(error, 'output', b'') or b''
        if created:
            try:
                diagnostic += docker('logs', container, timeout=30)
            except BaseException:
                pass
        try:
            with tempfile.NamedTemporaryFile(prefix='ccviaghcp-offline-', suffix='-diagnostics.log', delete=False) as file:
                file.write(diagnostic)
                path = file.name
            print('Synthetic diagnostics: ' + path, file=sys.stderr)
        except BaseException:
            print('WARNING synthetic diagnostics unavailable.', file=sys.stderr)
        raise
    finally:
        if created:
            try:
                docker('rm', '-f', container, timeout=30)
            except BaseException:
                if checked:
                    raise
                print('WARNING offline container cleanup failed; primary failure preserved.', file=sys.stderr)
    print('PASS pinned offline suite and container cleanup')


def main():
    os.umask(0o077)
    assert os.getuid() == 1000 and os.getgid() == 1000
    with tempfile.TemporaryDirectory(prefix='ccviaghcp-offline-') as directory:
        local = Path(directory)
        with patch('lab.LOCAL', local), patch.dict(os.environ):
            for setting in ('CCVIAGHCP_SUBSCRIPTION_ID', 'CCVIAGHCP_TENANT_ID'):
                os.environ.pop(setting, None)
            lab.prepare(types.SimpleNamespace(operator_object_id='00000000-0000-0000-0000-000000000001', operator_ip='8.8.8.8'))
        catalog = fixture_catalog()
        selection = {alias: 'claude-' + alias + '-5.5' for alias in ('sonnet', 'opus', 'haiku')}
        entry = catalog['response']['data'][0]
        catalog['response']['data'] = [copy.deepcopy(entry) | {'id': model} for model in selection.values()]
        config = common.model_config(catalog, selection)
        config['litellm_settings']['callbacks'].append('native_transport.installer')
        common.write_private(local / 'config.json', json.dumps(config))
        common.write_private(local / 'access-token', 'gho_' + 'x' * 36)
        name = 'ccviaghcp-offline-' + str(os.getpid())
        command = ['run', '-d', '--name', name, '--pull', 'never', '--network', 'none', '--user', '1000:1000', '--read-only',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=128m',
                   '-e', 'LITELLM_LOCAL_MODEL_COST_MAP=True', '-e', 'LITELLM_LOG=CRITICAL',
                   '-e', 'LITELLM_MASTER_KEY=sk-offline-only-sentinel']
        mounts = {local / 'config.json': '/etc/lab/config.json', local / 'access-token': '/var/run/copilot-secret/access-token',
                  local / 'tls.key': '/var/run/lab-tls/tls.key', local / 'tls.crt': '/var/run/lab-tls/tls.crt',
                  local / 'ca.crt': '/etc/lab/ca.crt'}
        for file in ('common.py', 'start_gateway.py', 'gateway_policy.py', 'smoke.py'):
            mounts[common.ROOT / 'scripts' / file] = '/etc/lab/' + file
        for file in ('native_transport.py', 'native_assertions.py'):
            mounts[common.ROOT / 'tests' / file] = '/etc/lab/' + file
        for source, target in mounts.items():
            command.extend(['--mount', f'type=bind,src={source},dst={target},readonly'])
        command.extend(['--entrypoint', 'python', common.IMAGE, '/etc/lab/start_gateway.py'])
        check_container(command, name)


if __name__ == '__main__':
    main()

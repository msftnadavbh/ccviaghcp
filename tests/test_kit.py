"""Offline fixtures only: synthetic identities/tokens and public DNS test addresses."""
import copy
import base64
import io
import ipaddress
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import common
import copilot_auth
import lab
import smoke
import start_gateway

SUBSCRIPTION = '11111111-1111-4111-8111-111111111111'
TENANT = '22222222-2222-4222-8222-222222222222'
TARGET_ENV = {'CCVIAGHCP_SUBSCRIPTION_ID': SUBSCRIPTION, 'CCVIAGHCP_TENANT_ID': TENANT}
BINDING = {'expectedSubscriptionId': SUBSCRIPTION, 'expectedTenantId': TENANT}


def fixture_catalog():
    # Synthetic discovery/limits and model-shaped public IDs, not entitlement proof.
    return {'verified_at': '2099-01-01T00:00:00Z', 'endpoint': common.UPSTREAM,
            'response': {'data': [{'id': 'claude-sonnet-5.5', 'policy': {'state': 'enabled'}, 'supported_endpoints': ['/v1/messages'],
                'capabilities': {'supports': {'streaming': True, 'tool_calls': True, 'adaptive_thinking': True},
                                 'limits': {'max_prompt_tokens': 200000, 'max_output_tokens': 8192}}}]}}


class KitTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in TARGET_ENV:
            os.environ.pop(name, None)

    def test_imports_do_not_resolve_azure_target(self):
        for settings in ({}, dict.fromkeys(TARGET_ENV, 'malformed-unused-setting')):
            result = subprocess.run([sys.executable, '-c',
                'import common, lab, copilot_auth, smoke, start_gateway'],
                env=os.environ | settings | {'PYTHONPATH': str(common.ROOT / 'scripts')},
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')

    def test_target_validation_before_subprocess_or_prepare_writes(self):
        cases = [({}, 'CCVIAGHCP_SUBSCRIPTION_ID')]
        for name in TARGET_ENV:
            cases.append(({k: v for k, v in TARGET_ENV.items() if k != name}, name))
            for value in ('', 'malformed-sensitive-setting', '00000000-0000-0000-0000-000000000000'):
                cases.append((TARGET_ENV | {name: value}, name))
        for settings, name in cases:
            with self.subTest(settings=list(settings), invalid=name), patch.dict(os.environ, settings), \
                    patch('common.subprocess.check_output') as cli, patch('lab.subprocess.run') as run, \
                    patch('lab.write_private') as write, patch('lab.protect_dir') as protect:
                with self.assertRaisesRegex(ValueError, name) as caught:
                    common.az('vm', 'list')
                self.assertNotIn('malformed-sensitive-setting', str(caught.exception))
                with self.assertRaisesRegex(ValueError, name):
                    lab.prepare(types.SimpleNamespace(operator_object_id=None, operator_ip='8.8.8.8'))
                if settings:
                    with self.assertRaisesRegex(ValueError, name):
                        lab.prepare(types.SimpleNamespace(operator_object_id='00000000-0000-0000-0000-000000000001', operator_ip='8.8.8.8'))
                cli.assert_not_called()
                run.assert_not_called()
                write.assert_not_called()
                protect.assert_not_called()
        with patch.dict(os.environ, {'CCVIAGHCP_SUBSCRIPTION_ID': ' {AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA} ',
                                    'CCVIAGHCP_TENANT_ID': TENANT.replace('-', '')}):
            self.assertEqual(common.azure_target(), ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', TENANT))

    def test_account_scope(self):
        good = {'id': SUBSCRIPTION, 'tenantId': TENANT, 'state': 'Enabled'}
        common.check_account(good, SUBSCRIPTION, TENANT)
        with patch.dict(os.environ, TARGET_ENV):
            for field, value in (('id', TENANT), ('tenantId', SUBSCRIPTION), ('state', 'Disabled'), ('state', 'enabled')):
                with patch('common.subprocess.check_output', return_value=json.dumps(good | {field: value}).encode()) as call:
                    with self.assertRaises(ValueError):
                        common.az('vm', 'list')
                    self.assertEqual(call.call_count, 1)
            commands = [('vm', 'list'), ('account', 'show'), ('account', 'get-access-token'),
                        ('deployment', 'sub', 'validate'), ('aks', 'get-credentials'), ('aks', 'show'),
                        ('rest', '--method', 'get', '--url', 'https://management.azure.com/')]
            with patch('common.subprocess.check_output', return_value=json.dumps(good).encode()) as call:
                for command in commands:
                    common.az(*command)
                self.assertEqual(call.call_count, 2 * len(commands))
                for index, invocation in enumerate(call.call_args_list):
                    args = invocation.args[0]
                    self.assertEqual(args.count('--subscription'), 1)
                    self.assertEqual(args[args.index('--subscription') + 1], SUBSCRIPTION)
                    if index % 2 == 0:
                        self.assertEqual(args, ['az', 'account', 'show', '--subscription', SUBSCRIPTION, '--only-show-errors', '-o', 'json'])
                    self.assertEqual(invocation.kwargs['stderr'], subprocess.PIPE)
                for invocation in call.call_args_list[-2:]:
                    self.assertEqual(invocation.kwargs['env']['AZURE_LOGGING_ENABLE_LOG_FILE'], 'false')
                    self.assertEqual(invocation.kwargs['env']['AZURE_CORE_COLLECT_TELEMETRY'], 'false')
                for invocation in call.call_args_list[:-2]:
                    self.assertIsNone(invocation.kwargs['env'])
            with patch('common.subprocess.check_output', side_effect=[json.dumps(good).encode(), b'{}', b'{}']) as call:
                common.az('vm', 'list')
                with self.assertRaises(ValueError):
                    common.az('vm', 'list')
                self.assertEqual(call.call_count, 3)

    def test_endpoint_and_token_validation(self):
        self.assertEqual(common.safe_endpoint(common.UPSTREAM), common.UPSTREAM)
        for url in ('http://api.githubcopilot.com', 'https://githubcopilot.com.evil.test',
                    'https://githubcopilot.com@evil.test', 'https://user@api.githubcopilot.com',
                    'https://api.githubcopilot.com:444', 'https://api.githubcopilot.com/a',
                    'https://api.githubcopilot.com?x=secret', 'https://169.254.169.254',
                    'https://api.individual.githubcopilot.com', common.UPSTREAM + '/'):
            with self.assertRaises(ValueError):
                common.safe_endpoint(url)
        for value in (None, 'https://api..githubcopilot.com', 'https://api.githubcopilot.com\n'):
            with self.assertRaises(ValueError):
                common.safe_endpoint(value)
        for value in ('', 'short', 'x' * 20 + '\nInjected: header', 'x y' * 20):
            with self.assertRaises(ValueError) as caught:
                common.token(value)
            self.assertNotIn('Injected', str(caught.exception))
        self.assertEqual(common.token('gho_' + 'a' * 36 + '\n'), 'gho_' + 'a' * 36)

    @patch.dict(os.environ, TARGET_ENV)
    def test_operator_oid_discovery_scoped_claims_and_redaction(self):
        account = {'id': SUBSCRIPTION, 'tenantId': TENANT, 'state': 'Enabled', 'user': {'type': 'user'}}
        oid = '00000000-0000-0000-0000-000000000001'
        def access(claims):
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
            return 'e30.' + payload + '.synthetic-secret-sentinel'
        good = access({'tid': TENANT, 'oid': oid})
        with patch('common.subprocess.check_output', side_effect=[json.dumps(account).encode(), json.dumps(account).encode(),
                json.dumps(account).encode(), json.dumps({'accessToken': good}).encode()]) as cli, \
                patch('sys.stdout', new_callable=io.StringIO) as stdout, patch('sys.stderr', new_callable=io.StringIO) as stderr:
            self.assertEqual(lab.operator_object_id(), oid)
            for invocation in cli.call_args_list:
                args = invocation.args[0]
                self.assertEqual(args[args.index('--subscription') + 1], SUBSCRIPTION)
                self.assertNotIn('ad', args)
                self.assertNotIn(good, args)
            self.assertIn('https://management.azure.com/', cli.call_args_list[-1].args[0])
            self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
        bad_tokens = [access({'tid': SUBSCRIPTION, 'oid': oid}), access({'tid': TENANT, 'oid': 'not-a-uuid'}),
                      access({'tid': TENANT}), 'synthetic-malformed', 'e30.bad.fake']
        for bad in bad_tokens:
            with patch('lab.az', side_effect=[json.dumps(account).encode(), json.dumps({'accessToken': bad}).encode()]):
                with self.assertRaises(ValueError) as caught:
                    lab.operator_object_id()
                self.assertNotIn(bad, str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
        with patch('lab.az', return_value=json.dumps(account | {'user': {'type': 'servicePrincipal'}}).encode()) as cli:
            with self.assertRaises(ValueError):
                lab.operator_object_id()
            self.assertEqual(cli.call_count, 1)

    def test_private_files_exclusive_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'secret'
            common.write_private(path, 'sentinel')
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                common.write_private(path, 'changed')
            path.chmod(0o644)
            self.assertEqual(common.read_private(path), 'sentinel')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            (root / 'link').symlink_to(path)
            with self.assertRaises(OSError):
                common.read_private(root / 'link')
            (root / 'linked-directory').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink directory'):
                common.read_private(root / 'linked-directory' / 'secret')

    def test_prepare_rerun_and_secure_parameters(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch.dict(os.environ, TARGET_ENV):
            args = types.SimpleNamespace(operator_object_id='00000000-0000-0000-0000-000000000001', operator_ip='8.8.8.8')
            with patch('sys.stdout', new_callable=io.StringIO) as output:
                lab.prepare(args)
                password = common.read_private(lab.LOCAL / 'admin-password')
                key = common.read_private(lab.LOCAL / 'gateway-key')
                ca = common.read_private(lab.LOCAL / 'ca.key')
                lab.prepare(args)
            self.assertEqual(common.read_private(lab.LOCAL / 'admin-password'), password)
            self.assertEqual(common.read_private(lab.LOCAL / 'gateway-key'), key)
            self.assertEqual(common.read_private(lab.LOCAL / 'ca.key'), ca)
            self.assertNotIn(password, output.getvalue())
            params = json.loads(lab.parameters('foundation').read_text())
            self.assertEqual(params['parameters']['adminPassword']['value'], password)
            for name, value in BINDING.items():
                self.assertEqual(params['parameters'][name]['value'], value)
            inputs = common.read_private(lab.LOCAL / 'deployment-inputs.json')
            with patch.dict(os.environ, {'CCVIAGHCP_TENANT_ID': SUBSCRIPTION}):
                with self.assertRaisesRegex(ValueError, 'target inputs changed'):
                    lab.prepare(args)
            self.assertEqual(common.read_private(lab.LOCAL / 'deployment-inputs.json'), inputs)
            self.assertEqual(common.read_private(lab.LOCAL / 'gateway-key'), key)
            for file in lab.LOCAL.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            args.operator_ip = '8.8.4.4'
            with self.assertRaises(ValueError):
                lab.prepare(args)

    def test_explicit_oid_local_prepare_stays_unbound(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), \
                patch('lab.operator_object_id') as discover, patch('lab.az') as cli, \
                patch('sys.stdout', new_callable=io.StringIO):
            args = types.SimpleNamespace(operator_object_id='00000000-0000-0000-0000-000000000001', operator_ip='8.8.8.8')
            lab.prepare(args)
            inputs = common.read_private(lab.LOCAL / 'deployment-inputs.json')
            self.assertEqual(set(json.loads(inputs)), {'operatorObjectId', 'operatorCidr'})
            lab.prepare(args)
            with patch.dict(os.environ, TARGET_ENV):
                with self.assertRaisesRegex(ValueError, 'unbound'):
                    lab.prepare(args)
                with self.assertRaisesRegex(ValueError, 'unbound'):
                    lab.parameters('foundation')
                with patch('lab.render') as render:
                    with self.assertRaisesRegex(ValueError, 'unbound'):
                        lab.apply()
                    render.assert_not_called()
            self.assertEqual(common.read_private(lab.LOCAL / 'deployment-inputs.json'), inputs)
            discover.assert_not_called()
            cli.assert_not_called()

    def test_bound_target_guard_precedes_parameters_deploy_and_apply_side_effects(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)):
            inputs = {'operatorObjectId': '00000000-0000-0000-0000-000000000001', 'operatorCidr': '8.8.8.8/32'}
            for gate in ('local-smoke', 'review', 'claude'):
                common.write_private(lab.LOCAL / ('gate-' + gate + '.txt'), 'synthetic-only')
            invalid = [({}, BINDING), ({'CCVIAGHCP_SUBSCRIPTION_ID': SUBSCRIPTION}, BINDING),
                       (TARGET_ENV | {'CCVIAGHCP_TENANT_ID': SUBSCRIPTION}, BINDING),
                       (TARGET_ENV | {'CCVIAGHCP_SUBSCRIPTION_ID': TENANT}, BINDING),
                       (TARGET_ENV, {}), (TARGET_ENV, {'expectedTenantId': TENANT}),
                       (TARGET_ENV, BINDING | {'expectedTenantId': 'not-a-uuid'}),
                       (TARGET_ENV, BINDING | {'expectedSubscriptionId': '00000000-0000-0000-0000-000000000000'})]
            for settings, binding in invalid:
                path = lab.LOCAL / 'deployment-inputs.json'
                path.write_text(json.dumps(inputs | binding))
                before = path.read_bytes()
                with patch.dict(os.environ, settings), patch('lab.az') as cli, patch('lab.kubectl') as kube, \
                        patch('lab.render') as render, patch('lab.subprocess.run') as run, patch('lab.write_private') as write:
                    for phase in ('foundation', 'aks'):
                        with self.assertRaises(ValueError):
                            lab.parameters(phase)
                        for action in ('validate', 'what-if', 'create'):
                            with self.assertRaises(ValueError):
                                lab.deploy(types.SimpleNamespace(action=action, phase=phase))
                    with self.assertRaises(ValueError):
                        lab.apply()
                    for mocked in (cli, kube, render, run, write):
                        mocked.assert_not_called()
                self.assertEqual(path.read_bytes(), before)

    def test_default_prepare_and_ca_name_constraint(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch.dict(os.environ, TARGET_ENV), \
                patch('lab.operator_object_id', return_value='00000000-0000-0000-0000-000000000001') as discover:
            with patch('sys.stdout', new_callable=io.StringIO):
                lab.prepare(types.SimpleNamespace(operator_object_id=None, operator_ip='8.8.8.8'))
            discover.assert_called_once_with()
            extension = subprocess.check_output(['openssl', 'x509', '-in', str(lab.LOCAL / 'ca.crt'), '-noout', '-ext', 'nameConstraints'])
            self.assertIn(b'critical', extension)
            self.assertIn(('DNS:' + common.HOST).encode(), extension)
            common.write_private(lab.LOCAL / 'bad.ext', 'subjectAltName=DNS:unrelated.example\n')
            lab.openssl('x509', '-req', '-in', lab.LOCAL / 'tls.csr', '-CA', lab.LOCAL / 'ca.crt', '-CAkey', lab.LOCAL / 'ca.key',
                        '-set_serial', '2', '-days', '1', '-extfile', lab.LOCAL / 'bad.ext', '-out', lab.LOCAL / 'bad.crt')
            verified = subprocess.run(['openssl', 'verify', '-CAfile', str(lab.LOCAL / 'ca.crt'), str(lab.LOCAL / 'bad.crt')], capture_output=True)
            self.assertNotEqual(verified.returncode, 0)
            self.assertIn(b'permitted subtree violation', verified.stdout + verified.stderr)
            existing_ca = (lab.LOCAL / 'ca.crt').read_bytes()
            with patch('lab.subprocess.check_output', return_value='No extensions'), \
                    patch('sys.stdout', new_callable=io.StringIO):
                with self.assertRaisesRegex(ValueError, 'private DNS constraint'):
                    lab.prepare(types.SimpleNamespace(operator_object_id=None, operator_ip='8.8.8.8'))
            self.assertEqual((lab.LOCAL / 'ca.crt').read_bytes(), existing_ca)

    def test_interrupted_tls_preparation_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)):
            args = types.SimpleNamespace(operator_object_id='00000000-0000-0000-0000-000000000001', operator_ip='8.8.8.8')
            def interrupted(*args):
                common.write_private(lab.LOCAL / 'ca.key', 'synthetic-interrupted-TLS-key')
                raise subprocess.CalledProcessError(1, ['openssl'])
            with patch('lab.openssl', side_effect=interrupted):
                with self.assertRaises(subprocess.CalledProcessError):
                    lab.prepare(args)
            before = {p.name: p.read_bytes() for p in lab.LOCAL.iterdir()}
            with patch('lab.openssl') as openssl:
                with self.assertRaisesRegex(common.SafeError, 'Incomplete existing TLS material'):
                    lab.prepare(args)
                openssl.assert_not_called()
            self.assertEqual({p.name: p.read_bytes() for p in lab.LOCAL.iterdir()}, before)

    def test_live_model_config_no_fallback(self):
        catalog = fixture_catalog()
        selection = dict.fromkeys(('sonnet', 'opus', 'haiku'), 'claude-sonnet-5.5')
        config = common.model_config(catalog, selection)
        self.assertEqual(len(config['model_list']), 3)
        self.assertNotIn('*', json.dumps(config))
        self.assertTrue(all(m['litellm_params']['model'].startswith('openai/') for m in config['model_list']))
        self.assertTrue(all(m['litellm_params']['api_base'] == common.UPSTREAM for m in config['model_list']))
        self.assertTrue(all(m['model_info']['supported_endpoints'] == ['/v1/messages'] for m in config['model_list']))
        self.assertFalse(config['general_settings']['forward_llm_provider_auth_headers'])
        self.assertTrue(config['general_settings']['health_check_skip_disabled_background_models'])
        self.assertTrue(all(m['model_info']['disable_background_health_check'] for m in config['model_list']))
        for mutation in ('unsupported', 'badlimits', 'unverified', 'disabled', 'missing-policy', 'unknown'):
            changed = copy.deepcopy(catalog)
            selected = selection.copy()
            if mutation == 'unsupported':
                changed['response']['data'][0]['supported_endpoints'] = []
            elif mutation == 'badlimits':
                changed['response']['data'][0]['capabilities']['limits']['max_output_tokens'] = 0
            elif mutation == 'unverified':
                changed['verified_at'] = ''
            elif mutation == 'disabled':
                changed['response']['data'][0]['policy']['state'] = 'disabled'
            elif mutation == 'missing-policy':
                del changed['response']['data'][0]['policy']
            else:
                selected['sonnet'] = 'claude-not-discovered'
            with self.assertRaises((ValueError, KeyError)):
                common.model_config(changed, selected)

    def test_model_caps_independent_exact_integer_contract(self):
        selection = dict.fromkeys(('sonnet', 'opus', 'haiku'), 'claude-sonnet-5.5')
        for field, cap in (('max_prompt_tokens', common.WINDOW), ('max_output_tokens', common.OUTPUT)):
            for value in (cap - 1, cap, cap + 1, True, False, None, 'sentinel-limit', str(cap), float(cap), 'missing'):
                with self.subTest(field=field, value=value):
                    catalog = fixture_catalog()
                    limits = catalog['response']['data'][0]['capabilities']['limits']
                    if value == 'missing':
                        del limits[field]
                    else:
                        limits[field] = value
                    if type(value) is int and value >= cap:
                        for model in common.model_config(catalog, selection)['model_list']:
                            self.assertEqual(model['litellm_params']['max_tokens'], common.OUTPUT)
                            self.assertEqual(model['model_info']['max_input_tokens'], common.WINDOW)
                            self.assertEqual(model['model_info']['max_tokens'], common.WINDOW)
                            self.assertEqual(model['model_info']['max_output_tokens'], common.OUTPUT)
                    else:
                        with self.assertRaisesRegex(common.SafeError, field) as caught:
                            common.model_config(catalog, selection)
                        self.assertNotIn('sentinel-limit', str(caught.exception))
        for limits in (None, [], 'sentinel-limit'):
            catalog = fixture_catalog()
            catalog['response']['data'][0]['capabilities']['limits'] = limits
            with self.assertRaises(common.SafeError):
                common.model_config(catalog, selection)
        catalog = fixture_catalog()
        entry = catalog['response']['data'][0]
        bad = copy.deepcopy(entry)
        bad['id'] = 'claude-haiku-synthetic'
        bad['capabilities']['limits']['max_prompt_tokens'] = common.WINDOW - 1
        catalog['response']['data'].append(bad)
        with self.assertRaises(common.SafeError):
            common.model_config(catalog, selection | {'haiku': bad['id']})

    def test_render_changed_config_refuses_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), \
                patch('sys.stdout', new_callable=io.StringIO):
            catalog = fixture_catalog()
            common.write_private(lab.LOCAL / 'catalog.json', json.dumps(catalog))
            common.write_private(lab.LOCAL / 'selection.json', json.dumps(dict.fromkeys(('sonnet', 'opus', 'haiku'), 'claude-sonnet-5.5')))
            lab.render()
            before = (lab.LOCAL / 'config.json').read_bytes()
            catalog['response']['data'][0]['capabilities']['limits']['max_output_tokens'] = common.OUTPUT - 1
            (lab.LOCAL / 'catalog.json').write_text(json.dumps(catalog))
            with self.assertRaisesRegex(common.SafeError, 'max_output_tokens'):
                lab.render()
            self.assertEqual((lab.LOCAL / 'config.json').read_bytes(), before)
            catalog['response']['data'][0]['capabilities']['limits']['max_output_tokens'] = common.OUTPUT
            (lab.LOCAL / 'catalog.json').write_text(json.dumps(catalog))
            (lab.LOCAL / 'config.json').write_text('{}')
            with self.assertRaisesRegex(common.SafeError, 'Derived config changed'):
                lab.render()
            self.assertEqual((lab.LOCAL / 'config.json').read_text(), '{}')

    def test_cli_boundaries_only_expose_authored_safe_errors_or_class(self):
        errors = [common.SafeError('Fixed public validation message'), ValueError('sentinel-value'),
                  ipaddress.AddressValueError('sentinel-ip'),
                  json.JSONDecodeError('sentinel-json', 'sentinel-document', 0),
                  AssertionError('sentinel-assert'), KeyboardInterrupt('sentinel-interrupt'),
                  subprocess.CalledProcessError(1, ['sentinel-command'], output=b'sentinel-stdout', stderr=b'sentinel-stderr')]
        for script, args in (('lab', types.SimpleNamespace(command='render')),
                             ('copilot_auth', types.SimpleNamespace(action='finish')),
                             ('start_gateway', None),
                             ('smoke', types.SimpleNamespace(private=False, count_tokens=False))):
            for error in errors:
                with self.subTest(script=script, exception=type(error).__name__), tempfile.TemporaryDirectory() as directory, \
                        patch('common.LOCAL', Path(directory)), patch('common.protect_dir'), \
                        patch('common.read_private', side_effect=error), \
                        patch('pathlib.Path.read_text', side_effect=error), \
                        patch('ssl.create_default_context'), \
                        patch('argparse.ArgumentParser.parse_args', return_value=args), \
                        patch('sys.stdout', new_callable=io.StringIO) as out, \
                        patch('sys.stderr', new_callable=io.StringIO) as err:
                    with self.assertRaises(SystemExit) as caught:
                        runpy.run_path(str(common.ROOT / 'scripts' / (script + '.py')), run_name='__main__')
                    self.assertEqual(caught.exception.code, 1)
                    output = out.getvalue() + err.getvalue()
                    self.assertNotIn('sentinel-', output)
                    self.assertIn(str(error) if isinstance(error, common.SafeError) else type(error).__name__, output)
        with patch('lab.write_private') as write:
            for ip, oid, message in (('sentinel-ip', '00000000-0000-0000-0000-000000000001', 'operator-ip'),
                                     ('8.8.8.8', 'sentinel-uuid', 'operator-object-id')):
                with self.assertRaisesRegex(common.SafeError, message) as caught:
                    lab.prepare(types.SimpleNamespace(operator_object_id=oid, operator_ip=ip))
                self.assertNotIn('sentinel-', str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
            write.assert_not_called()

    @patch.dict(os.environ, TARGET_ENV)
    def test_az_warning_stderr_does_not_contaminate_json(self):
        account = {'id': SUBSCRIPTION, 'tenantId': TENANT, 'state': 'Enabled'}
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'az'
            executable.write_text('#!/bin/sh\nprintf "sentinel-warning\\n" >&2\nprintf \'%s\' \'' + json.dumps(account) + '\'\n')
            executable.chmod(0o700)
            with patch.dict(os.environ, {'PATH': directory}), patch('sys.stdout', new_callable=io.StringIO) as out, \
                    patch('sys.stderr', new_callable=io.StringIO) as err:
                self.assertEqual(json.loads(common.az('aks', 'show')), account)
                self.assertEqual(out.getvalue() + err.getvalue(), '')

    def test_auth_poll_pending_slowdown_expiry_denial(self):
        clock = [0]
        intervals = []
        def sleep(seconds):
            clock[0] += seconds
            intervals.append(seconds)
        results = iter([{'error': 'authorization_pending'}, {'error': 'slow_down'}, {'access_token': 'gho_' + 'a' * 36}])
        state = {'interval': 5, 'deadline': 60, 'device_code': 'fixture-only'}
        value = copilot_auth.poll(state, call=lambda *a: next(results), now=lambda: clock[0], sleep=sleep)
        self.assertTrue(value.startswith('gho_'))
        self.assertEqual(intervals, [5, 5, 10])
        for result in ({'error': 'access_denied', 'error_description': 'sentinel-secret'}, {'access_token': ''}):
            with self.assertRaises(ValueError) as caught:
                copilot_auth.poll(state, call=lambda *a: result, now=lambda: 0, sleep=lambda _: None)
            self.assertNotIn('sentinel-secret', str(caught.exception))
        with self.assertRaises(ValueError):
            copilot_auth.poll(state, call=lambda *a: self.fail('Expired flow must not poll'), now=lambda: 61)

    def test_device_start_finish_split_and_invalid_verification_url(self):
        response = {'device_code': 'private-device-sentinel', 'user_code': 'ABCD-EFGH',
                    'verification_uri': 'https://github.com/login/device', 'interval': 5, 'expires_in': 900}
        with tempfile.TemporaryDirectory() as directory, patch('copilot_auth.LOCAL', Path(directory)):
            with patch('copilot_auth.request', return_value=response | {'verification_uri': 'https://evil.test'}), \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                with self.assertRaises(ValueError):
                    copilot_auth.start()
                self.assertEqual(output.getvalue(), '')
            with patch('copilot_auth.request', return_value=response) as request, \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                copilot_auth.start()
                self.assertEqual(request.call_count, 1)  # Start never polls.
                self.assertIn('ABCD-EFGH', output.getvalue())
                self.assertNotIn('private-device-sentinel', output.getvalue())
                with self.assertRaises(ValueError):
                    copilot_auth.start()
            with patch('copilot_auth.poll', return_value='gho_' + 'a' * 36), \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                copilot_auth.finish()
                self.assertNotIn('gho_', output.getvalue())
            self.assertFalse((copilot_auth.LOCAL / 'device-state.json').exists())
            self.assertEqual(stat.S_IMODE((copilot_auth.LOCAL / 'access-token').stat().st_mode), 0o600)

    def test_http_errors_redacted_and_redirects_refused(self):
        with patch('copilot_auth.urllib.request.build_opener', side_effect=RuntimeError('sentinel-secret')):
            with self.assertRaises(ValueError) as caught:
                copilot_auth.request('https://github.com/login/device/code')
            self.assertNotIn('sentinel-secret', str(caught.exception))
        with self.assertRaises(ValueError):
            copilot_auth.NoRedirect().redirect_request(None, None, 302, None, None, 'https://evil.test')

    def test_discovery_uses_direct_designated_oauth_without_exchange(self):
        with tempfile.TemporaryDirectory() as directory, patch('copilot_auth.LOCAL', Path(directory)):
            access = 'gho_' + 'a' * 36
            common.write_private(copilot_auth.LOCAL / 'access-token', access)
            with patch('copilot_auth.request', side_effect=[{'chat_enabled': True, 'endpoints': {'api': common.UPSTREAM}}, fixture_catalog()['response']]) as request, \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                copilot_auth.discover()
                self.assertEqual([c.args[0] for c in request.call_args_list],
                    ['https://api.github.com/copilot_internal/user', common.UPSTREAM + '/models'])
                self.assertNotIn(access, output.getvalue())
                self.assertEqual(request.call_args_list[0].kwargs['headers']['X-GitHub-Api-Version'], '2025-04-01')
                self.assertEqual(copilot_auth.HEADERS['X-GitHub-Api-Version'], '2026-08-01')
            catalog = json.loads(common.read_private(copilot_auth.LOCAL / 'catalog.json'))
            self.assertEqual(catalog['endpoint'], common.UPSTREAM)
            self.assertTrue(catalog['verified_at'])
            for endpoint in (None, 'https://api.individual.githubcopilot.com', 'https://attacker.invalid'):
                with patch('copilot_auth.request', return_value={'chat_enabled': True, 'endpoints': {'api': endpoint}}) as request:
                    with self.assertRaises(ValueError):
                        copilot_auth.discover()
                    self.assertEqual(request.call_count, 1)

    def test_empty_startup_token_never_imports_or_execs(self):
        with patch('start_gateway.Path.read_text', return_value=''), patch('start_gateway.os.execvp') as execute:
            with self.assertRaises(ValueError):
                start_gateway.main()
            execute.assert_not_called()

    def test_startup_requires_both_health_skip_flags(self):
        original = common.model_config(fixture_catalog(), dict.fromkeys(('sonnet', 'opus', 'haiku'), 'claude-sonnet-5.5'))
        for flag in ('general', 'model'):
            config = copy.deepcopy(original)
            if flag == 'general':
                config['general_settings'].pop('health_check_skip_disabled_background_models')
            else:
                config['model_list'][0]['model_info'].pop('disable_background_health_check')
            with patch('start_gateway.Path.read_text', side_effect=['gho_' + 'x' * 36, json.dumps(config)]), \
                    patch.dict('start_gateway.os.environ', {}, clear=True), patch('start_gateway.os.execvp') as execute:
                with self.assertRaises(ValueError):
                    start_gateway.main()
                execute.assert_not_called()

    def test_sse_parser(self):
        events = smoke.sse([b'event: message_start\n', b'data: {"type":"message_start"}\n', b'\n',
                            b'data: {"type":"message_stop"}\n'])
        self.assertEqual([e['type'] for e in events], ['message_start', 'message_stop'])

    def test_smoke_fixed_stage_failures(self):
        plain = {'type': 'message', 'role': 'assistant', 'content': [{'type': 'text', 'text': 'OK'}]}
        tool = {'stop_reason': 'tool_use', 'content': [{'type': 'tool_use', 'name': 'get_probe_value',
                'id': 'synthetic-tool', 'input': {'id': 'probe'}}]}
        final = {'stop_reason': 'end_turn', 'content': [{'type': 'text', 'text': 'synthetic-nonce'}]}
        events = b''.join(b'data: ' + json.dumps({'type': kind}).encode() + b'\n\n'
                          for kind in ('message_start', 'content_block_delta', 'message_stop'))
        for index, status, body, content_type, message in (
                (0, 200, {}, '', 'Authentication rejection mismatch'),
                (2, 502, {}, '', 'Native Messages JSON check failed'),
                (3, 502, {}, '', 'Native Messages SSE check failed'),
                (3, 200, {}, 'application/json', 'Native SSE content type mismatch'),
                (4, 200, {'stop_reason': 'end_turn'}, '', 'Native tool_use check failed'),
                (4, 200, {'stop_reason': 'tool_use', 'content': []}, '', 'Native tool_use probe mismatch'),
                (5, 200, {'stop_reason': 'end_turn', 'content': []}, '', 'Native tool_result round trip failed'),
                (6, 200, {'input_tokens': True}, '', 'Optional local count_tokens estimate check failed')):
            replies = [(401, {}, ''), (401, {}, ''), (200, plain, ''),
                       (200, events, 'text/event-stream'), (200, tool, ''), (200, final, ''), (200, {'input_tokens': 1}, '')]
            replies[index] = status, body, content_type
            responses = []
            for status, body, content_type in replies:
                response = io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode())
                response.status = status
                response.getheader = lambda name, default='', value=content_type: value
                responses.append(response)
            with self.subTest(stage=message), patch('smoke.ssl.create_default_context'), \
                    patch('smoke.read_private', return_value='synthetic-key'), \
                    patch('smoke.secrets.token_hex', return_value='synthetic-nonce'), \
                    patch('smoke.LabHTTPS') as connection, patch('sys.stdout', new_callable=io.StringIO):
                connection.return_value.getresponse.side_effect = responses
                with self.assertRaises(common.SafeError) as caught:
                    smoke.run('127.0.0.1', 4000, count_tokens=True)
                self.assertEqual(str(caught.exception), message)

    def test_deployment_gates_before_azure(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch('lab.az') as az:
            gates = ('local-smoke', 'review', 'claude')
            for absent in gates:
                for gate in gates:
                    (lab.LOCAL / ('gate-' + gate + '.txt')).write_text('synthetic-only')
                path = lab.LOCAL / ('gate-' + absent + '.txt')
                path.unlink()
                for missing in (True, False):
                    if not missing:
                        path.write_text('')
                    for phase in ('foundation', 'aks'):
                        with self.assertRaisesRegex(ValueError, 'gate-' + absent):
                            lab.deploy(types.SimpleNamespace(action='create', phase=phase))
            az.assert_not_called()

    def test_bounded_deploy_retry_and_secret_parameter_file(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)):
            for gate in ('local-smoke', 'review', 'claude'):
                common.write_private(lab.LOCAL / ('gate-' + gate + '.txt'), 'offline-test-evidence')
            failure = subprocess.CalledProcessError(1, ['az'], output=b'AuthorizationFailed')
            with patch('lab.parameters', return_value=lab.LOCAL / 'parameters-aks.json'), \
                    patch('lab.az', side_effect=[failure, failure, b'{}']) as az, patch('lab.time.sleep') as sleep, \
                    patch('sys.stdout', new_callable=io.StringIO):
                lab.deploy(types.SimpleNamespace(action='create', phase='aks'))
                self.assertEqual(az.call_count, 3)
                self.assertEqual([c.args[0] for c in sleep.call_args_list], [60, 120])
                for call in az.call_args_list:
                    self.assertIn('@' + str(lab.LOCAL / 'parameters-aks.json'), call.args)
                    self.assertNotIn('--mode', call.args)
                    self.assertNotIn('--no-pretty-print', call.args)
                    self.assertNotIn('--result-format', call.args)

    def test_retry_stderr_exhaustion_and_nonretry_failures(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)):
            for gate in ('local-smoke', 'review', 'claude'):
                common.write_private(lab.LOCAL / ('gate-' + gate + '.txt'), 'synthetic')
            for code, attempts in ((b'AuthorizationFailed', 3), (b'LinkedAuthorizationFailed', 3),
                                   (b'PrincipalNotFound', 3), (b'sentinel-nonretry', 1)):
                error = subprocess.CalledProcessError(1, ['sentinel-command'], output=b'sentinel-stdout', stderr=code)
                with patch('lab.parameters', return_value=lab.LOCAL / 'parameters-aks.json'), \
                        patch('lab.az', side_effect=error) as cli, patch('lab.time.sleep') as sleep:
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        lab.deploy(types.SimpleNamespace(action='create', phase='aks'))
                    self.assertIs(caught.exception, error)
                    self.assertEqual(cli.call_count, attempts)
                    self.assertEqual(sleep.call_count, attempts - 1)

    def test_local_container_loopback_and_security_boundaries(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch('lab.render'), \
                patch('lab.os.getuid', return_value=1000), patch('lab.os.getgid', return_value=1000), \
                patch('lab.subprocess.run') as run:
            common.write_private(lab.LOCAL / 'access-token', 'gho_' + 'x' * 36)
            common.write_private(lab.LOCAL / 'gateway-key', 'sk-synthetic-local')
            lab.local()
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('-p') + 1], '127.0.0.1:4000:4000')
            for value in ('--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '1000:1000', common.IMAGE):
                self.assertIn(value, command)
            self.assertNotIn('sk-synthetic-local', ' '.join(command))
            self.assertEqual(run.call_args.kwargs['env']['LITELLM_MASTER_KEY'], 'sk-synthetic-local')
            for index, value in enumerate(command):
                if value == '--mount':
                    self.assertTrue(command[index + 1].endswith(',readonly'))

    def test_offline_harness_preserves_first_error_and_requires_cleanup(self):
        import container_offline
        identifier = 'a' * 64
        audit = b'{"class":"main","initiator":"user"}\n{"class":"main","initiator":"agent"}\n'
        for scenario in ('missing-image', 'unavailable-logs', 'diagnostic-write', 'primary-cleanup', 'success-cleanup', 'success'):
            primary = subprocess.CalledProcessError(125, ['docker'], output=b'synthetic-primary')
            cleanup = subprocess.CalledProcessError(1, ['docker'], output=b'synthetic-cleanup')
            def docker(*args, timeout=120):
                if args[0] == 'run':
                    if scenario == 'missing-image':
                        raise primary
                    return identifier.encode() + b'\n'
                self.assertEqual(args[1] if args[0] != 'rm' else args[2], identifier)
                if args[0] == 'rm':
                    self.assertLessEqual(timeout, 30)
                    if scenario in ('primary-cleanup', 'success-cleanup'):
                        raise cleanup
                elif args[0] == 'logs':
                    self.assertLessEqual(timeout, 30)
                    if scenario == 'unavailable-logs':
                        raise RuntimeError('synthetic-log-failure')
                    return audit
                elif args[0] == 'exec' and args[-1] == '/etc/lab/native_assertions.py':
                    if scenario not in ('success-cleanup', 'success'):
                        raise primary
                    return b'PASS synthetic native wire assertions'
                return b''
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory, \
                    patch('container_offline.docker', side_effect=docker) as cli, \
                    patch('container_offline.tempfile.tempdir', directory), \
                    patch('sys.stderr', new_callable=io.StringIO) as err, \
                    patch('sys.stdout', new_callable=io.StringIO) as out:
                writer = tempfile.NamedTemporaryFile
                def diagnostic(*args, **kwargs):
                    file = writer(*args, **kwargs)
                    if scenario == 'diagnostic-write':
                        def fail_write(data):
                            raise OSError('synthetic-diagnostic-failure')
                        file.write = fail_write
                    return file
                with patch('container_offline.tempfile.NamedTemporaryFile', side_effect=diagnostic):
                    if scenario == 'success':
                        container_offline.check_container(['run'], 'synthetic-name')
                        self.assertIn('PASS pinned offline suite and container cleanup', out.getvalue())
                    else:
                        with self.assertRaises(subprocess.CalledProcessError) as caught:
                            container_offline.check_container(['run'], 'synthetic-name')
                        self.assertIs(caught.exception, cleanup if scenario == 'success-cleanup' else primary)
                        self.assertNotIn('PASS pinned offline suite', out.getvalue())
                if scenario == 'missing-image':
                    self.assertEqual(cli.call_count, 1)
                else:
                    self.assertEqual(cli.call_args.args, ('rm', '-f', identifier))
                if scenario == 'primary-cleanup':
                    self.assertIn('primary failure preserved', err.getvalue())
                for file in Path(directory).iterdir():
                    self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    @patch.dict(os.environ, TARGET_ENV)
    def test_published_operator_ip_block_offline(self):
        document = (common.ROOT / 'docs/setup.md').read_text()
        block = document.split('<!-- operator-ip-update: tested verbatim offline -->', 1)[1]
        code = block.split("python3 - <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        compiled = compile(code, '<published-operator-ip-block>', 'exec')
        base = '/subscriptions/' + SUBSCRIPTION + '/resourceGroups/' + common.RG + '/providers/'
        cluster_id = base + 'Microsoft.ContainerService/managedClusters/ccviaghcp-aks'
        nat_id = base + 'Microsoft.Network/natGateways/ccviaghcp-nat'
        pip_id = base + 'Microsoft.Network/publicIPAddresses/ccviaghcp-nat-pip'
        subnet_id = base + 'Microsoft.Network/virtualNetworks/ccviaghcp-vnet/subnets/aks'
        identity_id = base + 'Microsoft.ManagedIdentity/userAssignedIdentities/ccviaghcp-aks-control'
        old, new, nat_cidr = '8.8.8.8/32', '8.8.4.4/32', '9.9.9.9/32'
        cluster = {'id': cluster_id, 'provisioningState': 'Succeeded', 'location': common.REGION,
            'enableRbac': True, 'disableLocalAccounts': True,
            'aadProfile': {'tenantId': TENANT, 'managed': True, 'enableAzureRbac': True},
            'identity': {'type': 'UserAssigned', 'userAssignedIdentities': {identity_id: {'principalId': 'synthetic-principal'}}},
            'nodeResourceGroup': 'ccviaghcp-aks-nodes-rg', 'agentPoolProfiles': [{'vnetSubnetId': subnet_id}],
            'apiServerAccessProfile': {'authorizedIpRanges': [old, nat_cidr], 'enablePrivateCluster': False},
            'networkProfile': {'outboundType': 'userAssignedNATGateway', 'networkPlugin': 'azure',
                'networkPluginMode': 'overlay', 'networkDataplane': 'cilium', 'networkPolicy': 'cilium',
                'loadBalancerSku': 'standard', 'podCidr': '10.78.0.0/16', 'serviceCidr': '10.79.0.0/16', 'dnsServiceIp': '10.79.0.10'}}
        nat = {'id': nat_id, 'provisioningState': 'Succeeded', 'location': common.REGION,
            'sku': {'name': 'Standard'}, 'publicIpAddresses': [{'id': pip_id}]}
        pip = {'id': pip_id, 'provisioningState': 'Succeeded', 'location': common.REGION, 'sku': {'name': 'Standard'},
            'publicIPAllocationMethod': 'Static', 'publicIPAddressVersion': 'IPv4', 'ipAddress': nat_cidr[:-3]}
        subnet = {'id': subnet_id, 'provisioningState': 'Succeeded', 'addressPrefix': '10.77.0.0/24', 'natGateway': {'id': nat_id}}
        scenarios = ('success', 'nullable-public-profile', 'network-enum-case', 'private-profile',
            'new-equals-nat', 'wrong-target', 'unbound', 'bad-ip', 'private-ip', 'ipv6', 'missing-nat',
            'unexpected-ranges', 'pending', 'tenant-drift', 'security-drift', 'subnet-drift', 'nat-id-drift',
            'parameter-drift', 'password-drift', 'failed-update', 'interrupted-update', 'pending-readback',
            'wrong-readback', 'already-updated', 'partial-local', 'replace-failure', 'inputs-changed')
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory, \
                    patch('lab.LOCAL', Path(directory)), \
                    patch.dict(os.environ, {'NEW_OPERATOR_IPV4': new[:-3]}), \
                    patch('sys.stdout', new_callable=io.StringIO) as out, \
                    patch('sys.stderr', new_callable=io.StringIO) as err:
                inputs = BINDING | {'operatorObjectId': '00000000-0000-0000-0000-000000000001', 'operatorCidr': old}
                common.write_private(lab.LOCAL / 'deployment-inputs.json', json.dumps(inputs))
                preserved = {'admin-password': 'synthetic-unchanged-password', 'gateway-key': 'synthetic-key',
                             'tls.key': 'synthetic-TLS-bytes', 'ca.key': 'synthetic-CA-bytes',
                             'selection.json': '{}', 'gate-review.txt': 'synthetic-evidence'}
                for name, value in preserved.items():
                    common.write_private(lab.LOCAL / name, value)
                for phase in ('foundation', 'aks'):
                    lab.parameters(phase)
                current, actual_nat = copy.deepcopy(cluster), copy.deepcopy(nat)
                if scenario == 'wrong-target':
                    os.environ['CCVIAGHCP_SUBSCRIPTION_ID'] = TENANT
                elif scenario == 'unbound':
                    (lab.LOCAL / 'deployment-inputs.json').write_text(json.dumps({k: v for k, v in inputs.items() if k not in BINDING}))
                elif scenario in ('bad-ip', 'private-ip', 'ipv6'):
                    os.environ['NEW_OPERATOR_IPV4'] = {'bad-ip': 'sentinel-IP\n', 'private-ip': '10.0.0.1', 'ipv6': '2001:4860:4860::8888'}[scenario]
                elif scenario == 'new-equals-nat':
                    os.environ['NEW_OPERATOR_IPV4'] = nat_cidr[:-3]
                elif scenario == 'nullable-public-profile':
                    current['apiServerAccessProfile']['enablePrivateCluster'] = None
                elif scenario == 'private-profile':
                    current['apiServerAccessProfile']['enablePrivateCluster'] = True
                elif scenario == 'network-enum-case':
                    current['networkProfile'] = {k: v.upper() for k, v in current['networkProfile'].items()}
                elif scenario == 'unexpected-ranges':
                    current['apiServerAccessProfile']['authorizedIpRanges'].append('0.0.0.0/0')
                elif scenario == 'pending':
                    current['provisioningState'] = 'Updating'
                elif scenario == 'tenant-drift':
                    current['aadProfile']['tenantId'] = SUBSCRIPTION
                elif scenario == 'security-drift':
                    current['disableLocalAccounts'] = False
                elif scenario == 'subnet-drift':
                    current['agentPoolProfiles'][0]['vnetSubnetId'] = 'synthetic-wrong-subnet'
                elif scenario == 'nat-id-drift':
                    actual_nat['id'] = 'synthetic-wrong-nat'
                elif scenario in ('parameter-drift', 'password-drift'):
                    path = lab.LOCAL / 'parameters-aks.json'
                    values = json.loads(path.read_text())
                    values['parameters']['adminPassword' if scenario == 'password-drift' else 'operatorObjectId']['value'] = 'synthetic-drift'
                    path.write_text(json.dumps(values))
                elif scenario == 'already-updated':
                    current['apiServerAccessProfile']['authorizedIpRanges'] = [new, nat_cidr]
                before = {p.name: p.read_bytes() for p in lab.LOCAL.iterdir()}
                updates = []
                def azure(*args, timeout=None):
                    self.assertEqual(timeout, 900)
                    self.assertEqual(args[args.index('--resource-group') + 1], common.RG)
                    if args[:2] == ('aks', 'update'):
                        self.assertEqual(args, ('aks', 'update', '--resource-group', common.RG, '--name', 'ccviaghcp-aks',
                            '--api-server-authorized-ip-ranges', ','.join(sorted([new, nat_cidr]))))
                        updates.append(args)
                        if scenario == 'failed-update':
                            raise subprocess.CalledProcessError(1, ['sentinel-command'], stderr=b'sentinel-body')
                        if scenario == 'interrupted-update':
                            raise KeyboardInterrupt('sentinel-interrupted')
                        if scenario != 'wrong-readback':
                            current['apiServerAccessProfile']['authorizedIpRanges'] = [new, nat_cidr]
                        if scenario == 'pending-readback':
                            current['provisioningState'] = 'Updating'
                        if scenario == 'inputs-changed':
                            (lab.LOCAL / 'deployment-inputs.json').write_text(json.dumps(inputs) + '\n')
                        return b'{}'
                    if args[:2] == ('aks', 'show'):
                        value = current
                    elif args[:4] == ('network', 'nat', 'gateway', 'show'):
                        if scenario == 'missing-nat':
                            raise subprocess.CalledProcessError(1, ['az'])
                        value = actual_nat
                    elif args[:3] == ('network', 'public-ip', 'show'):
                        value = pip
                    elif args[:4] == ('network', 'vnet', 'subnet', 'show'):
                        value = subnet
                    else:
                        self.fail('Unexpected Azure operation')
                    return json.dumps(value).encode()
                original_parameters = lab.parameters
                def parameters(phase):
                    if scenario == 'partial-local' and phase == 'aks':
                        raise OSError('sentinel-local-failure')
                    return original_parameters(phase)
                replace = os.replace
                def replace_inputs(*args):
                    if scenario == 'replace-failure':
                        raise OSError('sentinel-replace-failure')
                    return replace(*args)
                with patch('common.az', side_effect=azure) as cli, patch('lab.parameters', side_effect=parameters), \
                        patch('os.replace', side_effect=replace_inputs):
                    if scenario in ('success', 'already-updated', 'nullable-public-profile', 'network-enum-case'):
                        exec(compiled, {})
                        self.assertIn('PASS ARM ranges', out.getvalue())
                    else:
                        with self.assertRaises(SystemExit) as caught:
                            exec(compiled, {})
                        self.assertEqual(caught.exception.code, 1)
                        self.assertNotIn('PASS', out.getvalue())
                    if scenario in ('wrong-target', 'unbound', 'bad-ip', 'private-ip', 'ipv6', 'parameter-drift', 'password-drift'):
                        cli.assert_not_called()
                if scenario in ('success', 'already-updated', 'partial-local', 'nullable-public-profile', 'network-enum-case'):
                    self.assertEqual(json.loads((lab.LOCAL / 'deployment-inputs.json').read_text()), inputs | {'operatorCidr': new})
                elif scenario != 'inputs-changed':
                    self.assertEqual({p.name: p.read_bytes() for p in lab.LOCAL.iterdir()}, before)
                if scenario in ('partial-local', 'replace-failure', 'inputs-changed'):
                    self.assertIn('ARM updated; local reconciliation incomplete', err.getvalue())
                if scenario in ('failed-update', 'interrupted-update', 'pending-readback', 'wrong-readback'):
                    self.assertIn('inspect provisioning state before retry', err.getvalue())
                if scenario == 'already-updated':
                    self.assertEqual(updates, [])
                if scenario in ('new-equals-nat', 'private-profile'):
                    self.assertEqual(updates, [])
                if scenario == 'new-equals-nat':
                    self.assertIn('must differ from the NAT address', err.getvalue())
                self.assertNotIn('sentinel-', out.getvalue() + err.getvalue())
                self.assertNotIn(preserved['admin-password'], out.getvalue() + err.getvalue())
                for name, value in preserved.items():
                    self.assertEqual((lab.LOCAL / name).read_text(), value)
                for path in lab.LOCAL.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                if scenario == 'partial-local':
                    # Rerun the same published block, with ARM already changed and partial local files.
                    updates.clear()
                    with patch('common.az', side_effect=azure):
                        exec(compiled, {})
                    self.assertEqual(updates, [])
                    for phase in ('foundation', 'aks'):
                        self.assertEqual(json.loads((lab.LOCAL / ('parameters-' + phase + '.json')).read_text())['parameters']['operatorCidr']['value'], new)

    def test_operator_ip_shell_preserves_python_exit(self):
        document = (common.ROOT / 'docs/setup.md').read_text()
        block = document.split('<!-- operator-ip-update: tested verbatim offline -->', 1)[1]
        shell = block.split('```bash\n', 1)[1].split('\n```', 1)[0]
        bash = shutil.which('bash')
        self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'python3'
            for code in (0, 7):
                executable.write_text('#!/bin/sh\n'
                    'test "$NEW_OPERATOR_IPV4" = "8.8.4.4" || exit 99\n'
                    '/bin/cat >/dev/null\n' + 'exit ' + str(code) + '\n')
                executable.chmod(0o700)
                result = subprocess.run([bash, '--noprofile', '--norc', '-c', shell],
                    input='8.8.4.4\n', env={'PATH': directory}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code)

    def test_windows_new_window_instructions_precede_bootstrap(self):
        document = (common.ROOT / 'windows/README.md').read_text()
        block = document.split('### Each new PowerShell window', 1)[1].split('## 3.', 1)[0]
        self.assertIn('$launch = ', block)
        self.assertIn('-Scope MachinePolicy', block)
        self.assertIn('-Scope UserPolicy', block)
        self.assertIn('} else {\n    Set-ExecutionPolicy -Scope Process RemoteSigned -Force', block)
        bootstrap = document.split('## 3.', 1)[1].split('## 4.', 1)[0]
        self.assertLess(bootstrap.index('Set-Location'), bootstrap.index('.\\bootstrap.ps1'))

    def test_manual_windows_acceptance_does_not_block_backend_deployment(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)):
            for gate in ('local-smoke', 'review', 'claude'):
                common.write_private(lab.LOCAL / ('gate-' + gate + '.txt'), 'synthetic-only-test-fixture')
            for phase in ('foundation', 'aks'):
                with patch('lab.parameters', return_value=lab.LOCAL / 'synthetic-parameters.json'), \
                        patch('lab.az', return_value=b'{}') as cli, patch('sys.stdout', new_callable=io.StringIO):
                    lab.deploy(types.SimpleNamespace(action='create', phase=phase))
                    cli.assert_called_once()
            self.assertFalse((lab.LOCAL / 'gate-windows-user.txt').exists())

    def test_what_if_requests_machine_readable_resource_ids_only(self):
        resource_id = '/subscriptions/' + SUBSCRIPTION + '/resourceGroups/' + common.RG
        fixture = {'status': 'Succeeded', 'changes': [{'changeType': 'Create', 'resourceId': resource_id}]}
        with patch('lab.parameters', return_value=Path(tempfile.gettempdir()) / 'ccviaghcp-synthetic-parameters.json'), \
                patch('lab.az', return_value=json.dumps(fixture).encode()) as cli, patch('sys.stdout', new_callable=io.StringIO) as output:
            lab.deploy(types.SimpleNamespace(action='what-if', phase='foundation'))
            self.assertIn('--no-pretty-print', cli.call_args.args)
            self.assertEqual(cli.call_args.args[cli.call_args.args.index('--result-format') + 1], 'ResourceIdOnly')
            self.assertIn('Create ' + resource_id, output.getvalue())
        with patch('lab.parameters', return_value=Path(tempfile.gettempdir()) / 'ccviaghcp-synthetic-parameters.json'), patch('lab.az', return_value=b'{}') as cli:
            with patch('sys.stdout', new_callable=io.StringIO):
                lab.deploy(types.SimpleNamespace(action='validate', phase='foundation'))
            self.assertNotIn('--no-pretty-print', cli.call_args.args)
            self.assertNotIn('--result-format', cli.call_args.args)

    def test_kubeconfig_reads_raw_ca_and_rejects_missing_ca(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch.dict(os.environ, TARGET_ENV):
            common.write_private(lab.LOCAL / 'deployment-inputs.json', json.dumps(BINDING))
            common.write_private(lab.LOCAL / 'access-token', 'gho_' + 'x' * 36)
            common.write_private(lab.LOCAL / 'kubeconfig', 'synthetic-only')
            config = {'contexts': [{'name': 'ccviaghcp-aks', 'context': {'cluster': 'lab'}}],
                      'clusters': [{'name': 'lab', 'cluster': {'server': 'https://synthetic.example:443'}}]}
            with patch('lab.render'), \
                    patch('lab.az', side_effect=[b'{}', b'{"fqdn":"synthetic.example"}']), patch('lab.subprocess.run'), \
                    patch('lab.kubectl', return_value=json.dumps(config)) as kubectl:
                with self.assertRaises(ValueError):
                    lab.apply()
                kubectl.assert_called_once_with(lab.LOCAL / 'kubeconfig', 'config', 'view', '--raw', '-o', 'json')

    def test_kubernetes_boundaries(self):
        manifest = json.loads((common.ROOT / 'k8s/gateway.json').read_text())
        _, deployment, service, policy = manifest['items']
        pod = deployment['spec']['template']['spec']
        container = pod['containers'][0]
        self.assertEqual(container['image'], common.IMAGE)
        self.assertEqual(pod['securityContext']['runAsUser'], 1000)
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
        self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
        self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(deployment['spec']['strategy']['type'], 'Recreate')
        self.assertEqual(deployment['spec']['replicas'], 1)
        for name in ('startupProbe', 'livenessProbe', 'readinessProbe'):
            self.assertEqual(container[name]['httpGet']['scheme'], 'HTTPS')
            self.assertEqual(container[name]['httpGet']['port'], 4000)
            self.assertNotEqual(container[name]['httpGet']['path'], '/health')
        self.assertNotIn('subPath', json.dumps(pod))
        self.assertNotIn('copilot-cache', json.dumps(pod))
        self.assertNotIn('PersistentVolume', json.dumps(pod))
        annotations = service['metadata']['annotations']
        self.assertEqual(annotations['service.beta.kubernetes.io/azure-load-balancer-internal'], 'true')
        self.assertFalse(any('probe' in name for name in annotations))
        self.assertEqual(service['spec']['externalTrafficPolicy'], 'Local')
        self.assertEqual(annotations['service.beta.kubernetes.io/azure-load-balancer-ipv4'], '10.77.0.240')
        self.assertEqual(service['spec']['loadBalancerSourceRanges'], ['10.77.1.4/32'])
        self.assertEqual(policy['spec']['ingress'][0]['from'], [{'ipBlock': {'cidr': '10.77.1.4/32'}}])
        self.assertEqual(manifest['items'][0]['metadata']['name'], 'ccviaghcp')
        self.assertTrue(all(item['metadata']['namespace'] == 'ccviaghcp' for item in manifest['items'][1:]))
        self.assertIn('169.254.0.0/16', policy['spec']['egress'][1]['to'][0]['ipBlock']['except'])

    def test_bound_apply_keeps_secret_stdin_and_policy_before_pod(self):
        with tempfile.TemporaryDirectory() as directory, patch('lab.LOCAL', Path(directory)), patch.dict(os.environ, TARGET_ENV):
            common.write_private(lab.LOCAL / 'deployment-inputs.json', json.dumps(BINDING))
            files = {'access-token': 'gho_' + 'x' * 36, 'gateway-key': 'sk-synthetic-only',
                     'tls.key': 'synthetic-key-placeholder', 'tls.crt': 'synthetic-cert-placeholder',
                     'config.json': '{}', 'kubeconfig': 'synthetic-only'}
            for name, value in files.items():
                common.write_private(lab.LOCAL / name, value)
            config = {'contexts': [{'name': 'ccviaghcp-aks', 'context': {'cluster': 'synthetic'}}],
                      'clusters': [{'name': 'synthetic', 'cluster': {'server': 'https://synthetic.example:443',
                                    'certificate-authority-data': 'c3ludGhldGlj'}}]}
            with patch('lab.render'), patch('lab.az', side_effect=[b'{}', b'{"fqdn":"synthetic.example"}']) as cli, \
                    patch('lab.subprocess.run'), patch('lab.kubectl', return_value=json.dumps(config)) as kube, \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                lab.apply()
            self.assertEqual(cli.call_count, 2)
            for call in cli.call_args_list:
                self.assertIn('ccviaghcp-aks', call.args)
                self.assertIn(common.RG, call.args)
            secret_call = kube.call_args_list[2]
            self.assertIn('--server-side', secret_call.args)
            self.assertIn('--field-manager=ccviaghcp-kit', secret_call.args)
            self.assertEqual(secret_call.args[-2:], ('-f', '-'))
            objects = json.loads(secret_call.kwargs['data'])['items']
            self.assertTrue(all(item['metadata']['namespace'] == 'ccviaghcp' for item in objects))
            self.assertEqual(base64.b64decode(objects[0]['data']['access-token']).decode(), files['access-token'])
            for call in kube.call_args_list:
                self.assertNotIn(files['access-token'], str(call.args))
            self.assertNotIn(files['access-token'], output.getvalue())
            self.assertEqual(json.loads(kube.call_args_list[3].kwargs['data'])['kind'], 'NetworkPolicy')
            self.assertEqual(json.loads(kube.call_args_list[4].kwargs['data'])['kind'], 'List')

    def test_infra_and_windows_artifacts(self):
        foundation = (common.ROOT / 'infra/foundation.bicep').read_text()
        main = (common.ROOT / 'infra/main.bicep').read_text()
        aks = (common.ROOT / 'infra/aks.bicep').read_text()
        self.assertIn('param expectedSubscriptionId string\n', main)
        self.assertIn('param expectedTenantId string\n', main)
        self.assertIn('subscription().subscriptionId == expectedSubscriptionId && tenant().tenantId == expectedTenantId', main)
        self.assertIn('expectedTenantId: expectedTenantId', main)
        self.assertIn('tenantID: expectedTenantId', aks)
        self.assertIn("targetScope = 'subscription'", main)
        for required in ("licenseType: 'Windows_Client'", "sku: 'win11-25h2-ent'", "version: '26200.9711.261011'",
                         "securityType: 'TrustedLaunch'", 'secureBootEnabled: true', 'vTpmEnabled: true', "scope: vnet", 'enableAcceleratedNetworking: true'):
            self.assertIn(required, foundation)
        for forbidden in ('-avd', '-entn', 'AzureBastionSubnet', 'publicIPAddress:', "version: 'latest'"):
            self.assertNotIn(forbidden, foundation)
        self.assertNotIn("access: 'Allow'", foundation)
        self.assertIn("name: 'DenyOtherInbound'", foundation)
        bastion = foundation.split("resource bastion ")[1].split("resource nic ")[0]
        for forbidden in ('ipConfigurations', 'scaleUnits', 'enable', 'tunneling'):
            self.assertNotIn(forbidden, bastion)
        self.assertIn("outboundType: 'userAssignedNATGateway'", aks)
        self.assertIn('disableLocalAccounts: true', aks)
        self.assertIn("networkDataplane: 'cilium'", aks)
        self.assertNotIn('managedOutboundIPs', aks)
        self.assertNotIn('CriticalAddonsOnly', aks)
        launcher = (common.ROOT / 'windows/launch.ps1').read_text()
        self.assertIn('-AsSecureString', launcher)
        self.assertIn('finally', launcher)
        self.assertIn('NODE_EXTRA_CA_CERTS', launcher)
        self.assertIn("$env:CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '1'", launcher)
        self.assertIn('$previous.ContainsKey($name)', launcher)
        self.assertIn('$providerFlags', launcher)
        bootstrap = (common.ROOT / 'windows/bootstrap.ps1').read_text()
        self.assertNotIn('[scriptblock]::Create', bootstrap)
        self.assertIn('89d15995a702c15a37cbc986a33cba415aa93e9671114971e137592aad7b2bd1', bootstrap)
        self.assertIn('0416631e846f743110da5282409776fa1313e65f33a588aae066eaf8db0fda7d', bootstrap)
        self.assertLess(bootstrap.index('Native binary hash mismatch'), bootstrap.index('Copy-Item $binaryFile'))
        self.assertNotIn('SetEnvironmentVariable', launcher)
        self.assertNotIn('GITHUB_COPILOT', launcher)
        for file in (common.ROOT / 'windows').glob('*.ps1'):
            self.assertNotIn('SkipCertificateCheck', file.read_text())
            self.assertNotIn('ServerCertificateValidationCallback', file.read_text())

    def test_foundation_and_aks_phases_are_isolated(self):
        main = (common.ROOT / 'infra/main.bicep').read_text()
        self.assertIn("module foundation './foundation.bicep' = if (scopeMatches && phase == 'foundation')", main)
        self.assertIn("module aks './aks.bicep' = if (scopeMatches && phase == 'aks')", main)
        self.assertIn("resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = if (scopeMatches)", main)
        self.assertIn("resource natPip 'Microsoft.Network/publicIPAddresses@2025-01-01' existing = {\n"
                      "  name: 'ccviaghcp-nat-pip'\n  scope: rg\n}", main)
        self.assertIn("resource aksIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {\n"
                      "  name: 'ccviaghcp-aks-control'\n  scope: rg\n}", main)
        self.assertIn("natCidr: (scopeMatches && phase == 'aks') ? '${natPip.properties.ipAddress}/32' : ''", main)
        self.assertIn('identityId: aksIdentity.id', main)
        self.assertIn('@secure()\nparam adminPassword string', main)
        self.assertNotIn('foundation.outputs', main)
        self.assertNotIn('dependsOn', main)

    def test_compiled_arm_isolates_phases_and_lazily_reads_existing_pip(self):
        bicep = shutil.which('bicep')
        if not bicep:
            self.skipTest('local offline Bicep compiler unavailable')
        result = subprocess.run([str(bicep), 'build', str(common.ROOT / 'infra/main.bicep'), '--stdout', '--no-restore'],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        arm = json.loads(result.stdout)
        resources = {r['name']: r for r in arm['resources']}
        self.assertEqual(set(resources), {'ccviaghcp-rg', 'ccviaghcp-foundation', 'ccviaghcp-aks'})
        self.assertEqual(resources['ccviaghcp-rg']['condition'], "[variables('scopeMatches')]")
        self.assertEqual(resources['ccviaghcp-foundation']['condition'],
                         "[and(variables('scopeMatches'), equals(parameters('phase'), 'foundation'))]")
        aks = resources['ccviaghcp-aks']
        self.assertEqual(aks['condition'], "[and(variables('scopeMatches'), equals(parameters('phase'), 'aks'))]")
        self.assertEqual(arm['variables']['scopeMatches'],
                         "[and(equals(subscription().subscriptionId, parameters('expectedSubscriptionId')), equals(tenant().tenantId, parameters('expectedTenantId')))]")
        for name in BINDING:
            self.assertEqual(arm['parameters'][name], {'type': 'string'})
        self.assertEqual(arm['parameters']['adminPassword'], {'type': 'securestring'})
        foundation = resources['ccviaghcp-foundation']['properties']['template']
        self.assertEqual(foundation['parameters']['adminPassword'], {'type': 'securestring'})
        self.assertEqual(set(foundation['outputs']), {'natIp', 'identityId'})
        self.assertEqual(aks['dependsOn'], ["[subscriptionResourceId('Microsoft.Resources/resourceGroups', 'ccviaghcp-rg')]"])
        self.assertEqual(set(aks['properties']['parameters']), {'operatorObjectId', 'operatorCidr', 'natCidr', 'identityId', 'expectedTenantId'})
        self.assertEqual(aks['properties']['parameters']['expectedTenantId'], {'value': "[parameters('expectedTenantId')]"})
        rg_scope = "format('/subscriptions/{0}/resourceGroups/{1}', subscription().subscriptionId, 'ccviaghcp-rg')"
        pip_ref = f"reference(extensionResourceId({rg_scope}, 'Microsoft.Network/publicIPAddresses', 'ccviaghcp-nat-pip'), '2025-01-01')"
        # The same full condition guards deployment and reference: wrong scope/foundation never reads the PIP.
        self.assertEqual(aks['properties']['parameters']['natCidr'],
                         "[if(" + aks['condition'][1:-1] + ", createObject('value', format('{0}/32', " + pip_ref +
                         ".ipAddress)), createObject('value', ''))]")
        self.assertEqual(aks['properties']['parameters']['identityId']['value'],
                         f"[extensionResourceId({rg_scope}, 'Microsoft.ManagedIdentity/userAssignedIdentities', 'ccviaghcp-aks-control')]")
        self.assertNotIn('ccviaghcp-foundation', json.dumps(aks))
        cluster = aks['properties']['template']['resources'][0]
        self.assertEqual(cluster['properties']['aadProfile']['tenantID'], "[parameters('expectedTenantId')]")
        self.assertEqual([r['type'] for r in aks['properties']['template']['resources']],
                         ['Microsoft.ContainerService/managedClusters', 'Microsoft.Authorization/roleAssignments',
                          'Microsoft.Authorization/roleAssignments'])
        standalone = subprocess.run([str(bicep), 'build', str(common.ROOT / 'infra/aks.bicep'), '--stdout', '--no-restore'],
                                    capture_output=True, text=True, timeout=60)
        self.assertEqual(standalone.returncode, 0, standalone.stderr)
        self.assertEqual(aks['properties']['template']['resources'], json.loads(standalone.stdout)['resources'])


if __name__ == '__main__':
    unittest.main()

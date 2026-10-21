"""Preparation, target-bound deployment and local smoke setup for ccviaghcp."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

from common import (HOST, IMAGE, LOCAL, REGION, RG, ROOT, az, azure_target, model_config,
                    protect_dir, read_private, token, write_private)


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, umask=0o077)


def operator_object_id():
    """Decode trusted, target-scoped CLI output in memory, not a JWT verifier."""
    try:
        _, tenant = azure_target()
        account = json.loads(az('account', 'show'))
        if account.get('user', {}).get('type') != 'user':
            raise ValueError('User login required')
        result = json.loads(az('account', 'get-access-token', '--resource', 'https://management.azure.com/'))
        parts = result['accessToken'].split('.')
        if len(parts) != 3 or not all(parts):
            raise ValueError('Malformed CLI token')
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
        if claims['tid'] != tenant:
            raise ValueError('Token tenant mismatch')
        return str(uuid.UUID(claims['oid']))
    except Exception:
        raise ValueError('Cannot discover operator user object ID from target-scoped Azure CLI claims') from None


def prepare(args):
    target = azure_target(required=not args.operator_object_id)
    binding = {} if target is None else {'expectedSubscriptionId': target[0], 'expectedTenantId': target[1]}
    if not (LOCAL / 'deployment-inputs.json').exists():
        operator = args.operator_object_id or operator_object_id()
        operator = str(uuid.UUID(operator))
        ip = ipaddress.ip_address(args.operator_ip)
        if ip.version != 4 or not ip.is_global:
            raise ValueError('Operator must supply current public IPv4 address')
        write_private(LOCAL / 'deployment-inputs.json', json.dumps(
            {'operatorObjectId': operator, 'operatorCidr': str(ip) + '/32'} | binding))
    else:
        inputs = json.loads(read_private(LOCAL / 'deployment-inputs.json'))
        if {key: inputs[key] for key in ('expectedSubscriptionId', 'expectedTenantId') if key in inputs} != binding:
            raise ValueError('Azure target inputs changed or unbound; use a new deployment directory, not a retarget')
        if (inputs['operatorCidr'] != str(ipaddress.ip_address(args.operator_ip)) + '/32'
                or (args.operator_object_id and inputs['operatorObjectId'] != str(uuid.UUID(args.operator_object_id)))):
            raise ValueError('Operator inputs changed; review existing protected inputs, do not silently overwrite')
    protect_dir(LOCAL)
    for name, value in [('admin-password', 'Aa1!' + secrets.token_urlsafe(30)),
                        ('gateway-key', 'sk-' + secrets.token_hex(32))]:
        path = LOCAL / name
        if path.exists():
            if not read_private(path).strip():
                raise ValueError('Empty existing secret; refusing rotation')
        else:
            write_private(path, value)
    certs = ['ca.key', 'ca.crt', 'tls.key', 'tls.crt']
    if any((LOCAL / f).exists() for f in certs):
        if not all((LOCAL / f).exists() for f in certs):
            raise ValueError('Incomplete existing TLS material: stop, do not overwrite')
        for f in certs:
            read_private(LOCAL / f)
        constraints = subprocess.check_output(
            ['openssl', 'x509', '-in', str(LOCAL / 'ca.crt'), '-noout', '-ext', 'nameConstraints'],
            stderr=subprocess.DEVNULL, text=True)
        if 'critical' not in constraints or 'DNS:' + HOST not in constraints:
            raise ValueError('Existing CA lacks the private DNS constraint; stop for reviewed reissue')
        openssl('verify', '-CAfile', LOCAL / 'ca.crt', '-verify_hostname', HOST, LOCAL / 'tls.crt')
    else:
        openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '365',
                '-subj', '/CN=ccviaghcp CA', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'nameConstraints=critical,permitted;DNS:' + HOST,
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', LOCAL / 'ca.key', '-out', LOCAL / 'ca.crt')
        openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-subj', '/CN=' + HOST,
                '-keyout', LOCAL / 'tls.key', '-out', LOCAL / 'tls.csr')
        write_private(LOCAL / 'tls.ext', 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + HOST + '\n')
        openssl('x509', '-req', '-in', LOCAL / 'tls.csr', '-CA', LOCAL / 'ca.crt', '-CAkey', LOCAL / 'ca.key',
                '-set_serial', str(secrets.randbits(128)), '-days', '90', '-sha256', '-extfile', LOCAL / 'tls.ext', '-out', LOCAL / 'tls.crt')
    print('Prepared protected .local inputs. No secret values printed; existing secrets preserved.')


def deployment_inputs():
    subscription, tenant = azure_target()
    inputs = json.loads(read_private(LOCAL / 'deployment-inputs.json'))
    if inputs.get('expectedSubscriptionId') != subscription or inputs.get('expectedTenantId') != tenant:
        raise ValueError('Azure target is unbound or changed; use a new deployment directory, not a retarget')
    return inputs


def parameters(phase):
    inputs = deployment_inputs()
    protect_dir(LOCAL)
    uuid.UUID(inputs['operatorObjectId'])
    network = ipaddress.ip_network(inputs['operatorCidr'])
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError('Invalid operator public /32')
    values = inputs | {'adminPassword': read_private(LOCAL / 'admin-password'), 'phase': phase}
    path = LOCAL / ('parameters-' + phase + '.json')
    if path.exists():
        existing = json.loads(read_private(path))
        if existing['parameters'] != {k: {'value': v} for k, v in values.items()}:
            raise ValueError('Existing parameters differ; review before explicitly removing this derived file')
    else:
        write_private(path, json.dumps({'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#',
                       'contentVersion': '1.0.0.0', 'parameters': {k: {'value': v} for k, v in values.items()}}))
    return path


def deploy(args):
    if args.action == 'create':
        # Windows acceptance is manual after deployment; no credential-automation prerequisite.
        gates = ('local-smoke', 'review', 'claude')
        for gate in gates:
            path = LOCAL / ('gate-' + gate + '.txt')
            if not path.exists() or not read_private(path).strip():
                raise ValueError('STOP: missing evidence gate-' + gate + '.txt')
    params = parameters(args.phase)
    command = ['deployment', 'sub', args.action, '--location', REGION, '--name', 'ccviaghcp-' + args.phase,
               '--template-file', str(ROOT / 'infra/main.bicep'), '--parameters', '@' + str(params)]
    if args.action == 'what-if':
        command.extend(['--no-pretty-print', '--result-format', 'ResourceIdOnly'])
    for attempt in range(3):
        try:
            # Capture ARM results: secure inputs must never be printed by this wrapper.
            result = json.loads(az(*command))
            if args.action == 'what-if':
                for change in result.get('changes', []):
                    print(change['changeType'] + ' ' + change['resourceId'])
            print(args.action + ' ' + args.phase + ' succeeded (ARM operation only).')
            return
        except subprocess.CalledProcessError as exc:
            error = (exc.output or b'').decode(errors='replace')
            if (args.action != 'create' or args.phase != 'aks' or attempt == 2
                    or not any(code in error for code in ('AuthorizationFailed', 'LinkedAuthorizationFailed', 'PrincipalNotFound'))):
                raise
            time.sleep(60 * (attempt + 1))
    raise ValueError('Bounded identity propagation retry exhausted; no privilege changes made')


def render():
    protect_dir(LOCAL)
    config = model_config(json.loads(read_private(LOCAL / 'catalog.json')),
                          json.loads(read_private(LOCAL / 'selection.json')))
    path = LOCAL / 'config.json'
    data = json.dumps(config, indent=2)
    if path.exists():
        if read_private(path) != data:
            raise ValueError('Derived config changed; review and remove only config.json before rerender')
    else:
        write_private(path, data)
    print('Generated explicit live-catalog-backed .local/config.json; no wildcard model.')


def kubectl(kube, *args, data=None):
    return subprocess.run(['kubectl', '--kubeconfig', str(kube), '--context', 'ccviaghcp-aks', *args],
                          input=data, text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def apply():
    deployment_inputs()  # Reject target changes before rendering or touching credentials/kubeconfig.
    render()
    token(read_private(LOCAL / 'access-token'))
    kube = LOCAL / 'kubeconfig'
    if kube.exists():
        read_private(kube)
    az('aks', 'get-credentials', '--resource-group', RG, '--name', 'ccviaghcp-aks', '--file', str(kube), '--overwrite-existing')
    os.chmod(kube, 0o600)
    # Use a dedicated config; never rewrite the operator's normal kubeconfig.
    subprocess.run(['kubelogin', 'convert-kubeconfig', '--kubeconfig', str(kube), '-l', 'azurecli'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    expected = json.loads(az('aks', 'show', '--resource-group', RG, '--name', 'ccviaghcp-aks'))['fqdn']
    actual = json.loads(kubectl(kube, 'config', 'view', '--raw', '-o', 'json'))
    context = next(c['context'] for c in actual['contexts'] if c['name'] == 'ccviaghcp-aks')
    target = next(c['cluster'] for c in actual['clusters'] if c['name'] == context['cluster'])
    if (target['server'] != 'https://' + expected + ':443' or target.get('insecure-skip-tls-verify')
            or not target.get('certificate-authority-data')):
        raise ValueError('Kubernetes server mismatch')
    manifest = json.loads((ROOT / 'k8s/gateway.json').read_text())
    kubectl(kube, 'apply', '-f', '-', data=json.dumps(manifest['items'][0]))
    def secret(name, files, kind='Opaque'):
        values = {key: base64.b64encode(read_private(LOCAL / file).encode()).decode() for key, file in files.items()}
        return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': 'ccviaghcp'}, 'type': kind, 'data': values}
    objects = [secret('copilot', {'access-token': 'access-token'}), secret('gateway-key', {'key': 'gateway-key'}),
               secret('lab-tls', {'tls.key': 'tls.key', 'tls.crt': 'tls.crt'}, 'kubernetes.io/tls'),
               {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'gateway-config', 'namespace': 'ccviaghcp'},
                'data': {'config.json': read_private(LOCAL / 'config.json'),
                         'start_gateway.py': (ROOT / 'scripts/start_gateway.py').read_text(),
                         'gateway_policy.py': (ROOT / 'scripts/gateway_policy.py').read_text(),
                         'common.py': (ROOT / 'scripts/common.py').read_text()}}]
    # stdin only; no Secret YAML, shell arguments, stdout or last-applied annotation.
    kubectl(kube, 'apply', '--server-side', '--field-manager=ccviaghcp-kit', '-f', '-',
            data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}))
    # Policy BEFORE the pod: do not start with an unprotected egress window.
    kubectl(kube, 'apply', '-f', '-', data=json.dumps(manifest['items'][-1]))
    kubectl(kube, 'apply', '-f', '-', data=json.dumps(manifest))
    kubectl(kube, '-n', 'ccviaghcp', 'rollout', 'restart', 'deployment/litellm')
    kubectl(kube, '-n', 'ccviaghcp', 'rollout', 'status', 'deployment/litellm', '--timeout=600s')
    print('Gateway rollout ready. Still verify ILB node probes, private DNS/TLS and inference from Windows.')


def local():
    render()
    token(read_private(LOCAL / 'access-token'))
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise ValueError('Local bind-mounted protected files require operator UID/GID 1000; stop for review')
    mounts = {LOCAL / 'config.json': '/etc/lab/config.json',
              ROOT / 'scripts/start_gateway.py': '/etc/lab/start_gateway.py',
              ROOT / 'scripts/gateway_policy.py': '/etc/lab/gateway_policy.py',
              ROOT / 'scripts/common.py': '/etc/lab/common.py',
              LOCAL / 'access-token': '/var/run/copilot-secret/access-token',
              LOCAL / 'tls.key': '/var/run/lab-tls/tls.key', LOCAL / 'tls.crt': '/var/run/lab-tls/tls.crt'}
    command = ['docker', 'run', '--rm', '--name', 'ccviaghcp-local', '--user', '1000:1000',
               '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=128m',
               '-p', '127.0.0.1:4000:4000', '--env', 'LITELLM_MASTER_KEY']
    for source, target in mounts.items():
        command.extend(['--mount', f'type=bind,src={source},dst={target},readonly'])
    command.extend(['--entrypoint', 'python', IMAGE, '/etc/lab/start_gateway.py'])
    subprocess.run(command, env=os.environ | {'LITELLM_MASTER_KEY': read_private(LOCAL / 'gateway-key')}, check=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--operator-ip', required=True, help='Current operator public IPv4 (never 0.0.0.0/0)')
    prep.add_argument('--operator-object-id', help='Actual Entra USER object ID; otherwise discover signed-in user')
    dep = sub.add_parser('infra')
    dep.add_argument('action', choices=['validate', 'what-if', 'create'])
    dep.add_argument('phase', choices=['foundation', 'aks'])
    for name in ('render', 'apply', 'local'):
        sub.add_parser(name)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args)
    elif args.command == 'infra':
        deploy(args)
    else:
        {'render': render, 'apply': apply, 'local': local}[args.command]()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Lab operation failed; details suppressed to protect secrets. Inspect scope, inputs and Azure deployment status without exposing secure parameters.', file=sys.stderr)
        sys.exit(1)

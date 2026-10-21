"""Explicit consent only. Never reads gh, OpenCode, browser or other credential stores."""
import argparse
from datetime import datetime, timezone
import json
import sys
import time
import urllib.error
import urllib.request

from common import LOCAL, protect_dir, read_private, safe_endpoint, token, write_private

CLIENT_ID = 'Iv1.b507a08c87ecfe98'  # Same public client as the pinned Authenticator.
HEADERS = {'Accept': 'application/json', 'Content-Type': 'application/json',
           'X-GitHub-Api-Version': '2026-08-01', 'User-Agent': 'ccviaghcp-LiteLLM/1.106.0'}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect refused')


def request(url, data=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers=HEADERS | (headers or {}))
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=45) as response:
            return json.load(response)
    except Exception:
        # Response bodies and exception strings may contain credentials. Never echo them.
        raise ValueError('GitHub request failed; details suppressed') from None


def start():
    if (LOCAL / 'access-token').exists() or (LOCAL / 'device-state.json').exists():
        raise ValueError('Existing authorization files; refusing to overwrite')
    result = request('https://github.com/login/device/code', {'client_id': CLIENT_ID, 'scope': 'read:user'})
    import re
    if (result.get('verification_uri') != 'https://github.com/login/device'
            or not re.fullmatch(r'[A-Z0-9-]{4,20}', result.get('user_code', ''))
            or not isinstance(result.get('device_code'), str) or not result['device_code']):
        raise ValueError('Invalid device response')
    interval, expiry = result.get('interval', 5), result.get('expires_in', 0)
    if type(interval) is not int or not 1 <= interval <= 60 or type(expiry) is not int or not 1 <= expiry <= 1800:
        raise ValueError('Invalid authorization timing')
    write_private(LOCAL / 'device-state.json', json.dumps({'device_code': result['device_code'],
                  'interval': interval, 'deadline': time.time() + expiry}))
    print('Visit https://github.com/login/device and enter code ' + result['user_code'])
    print('After human consent, run: python3 scripts/copilot_auth.py finish')


def poll(state, call=request, now=time.time, sleep=time.sleep):
    interval = state['interval']
    while now() + interval < state['deadline']:
        sleep(interval)
        result = call('https://github.com/login/oauth/access_token', {
            'client_id': CLIENT_ID, 'device_code': state['device_code'],
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'})
        if 'access_token' in result:
            return token(result['access_token'])
        error = result.get('error')
        if error == 'slow_down':
            interval += 5
        elif error != 'authorization_pending':
            raise ValueError('Authorization denied, expired or failed; details suppressed')
    raise ValueError('Device authorization expired')


def finish():
    state = json.loads(read_private(LOCAL / 'device-state.json'))
    if (LOCAL / 'access-token').exists():
        raise ValueError('Refusing to overwrite existing access token')
    write_private(LOCAL / 'access-token', poll(state))
    (LOCAL / 'device-state.json').unlink()
    print('Authorized credential saved to protected designated file; no token displayed.')


def discover():
    access = token(read_private(LOCAL / 'access-token'))
    entitlement = request('https://api.github.com/copilot_internal/user', headers={
        'Authorization': 'Bearer ' + access, 'X-GitHub-Api-Version': '2025-04-01'})
    if entitlement.get('chat_enabled') is not True:
        raise ValueError('Copilot chat entitlement not enabled')
    endpoint = safe_endpoint(entitlement.get('endpoints', {}).get('api'))
    catalog = request(endpoint + '/models', headers={'Authorization': 'Bearer ' + access})
    if not isinstance(catalog.get('data'), list):
        raise ValueError('Invalid model catalog; stop for review')
    write_private(LOCAL / 'catalog.json', json.dumps({'verified_at': datetime.now(timezone.utc).isoformat(),
                  'endpoint': endpoint, 'response': catalog}, indent=2))
    print('Live catalog saved to .local/catalog.json; select entitled native Messages Claude IDs.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'finish', 'discover'])
    args = parser.parse_args()
    try:
        protect_dir(LOCAL)
        {'start': start, 'finish': finish, 'discover': discover}[args.action]()
    except Exception:
        print('Copilot operation failed; authorization/input/network details suppressed. Check designated files and consent/expiry.', file=sys.stderr)
        sys.exit(1)

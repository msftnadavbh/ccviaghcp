# Manual Windows setup and acceptance

Run these steps only **after** your new backend is deployed and its private
endpoint is verified. This export has not been accepted on Windows. Linux
PowerShell and fake-executable tests are not Windows runtime proof. Real native
tests consume allowance and require legitimate consent, entitlement, and policy.
No Windows-user gate is required before backend deployment.

## 1. Review access and hand off your new public CA

The example VM is `ccviaghcp-windows` in `ccviaghcp-rg`, private IP `10.77.1.4`,
computer name `ccviaghcp-win`, administrator `ccviaghcpuser`. Use your freshly
generated password only through the genuine login UI, never chat or commands.
Work in the actual target user's session, not SYSTEM or Run Command.

**The foundation NSG is deny-only.** Review an appropriate manual access plan
before attempting the Azure portal's Bastion connection. No RDP source or login is
assumed to work. If login fails, stop for operator review; do not broaden ingress,
disable NLA/firewalls, or add access services as a workaround. Developer Bastion
does not provide native file transfer/tunneling; arrange an approved handoff
channel separately. Agent/Run Command success is not browser-login evidence.

Choose a clean handoff directory, for example `Downloads\ccviaghcp-handoff`.
It is **not supplied or pre-staged** by this repository. Receive only:

- `ca.crt`: the **new deployment's** approved public CA PEM;
- `bootstrap.ps1`, `verify.ps1`, and `launch.ps1` from this repository.

Never copy the whole `.local` tree, private keys, OAuth grant, VM password, gateway
key, or generated configuration. The operator must compute new handoff hashes and
communicate them through an independent trusted channel. In that directory, compare
them before running scripts or trusting the CA:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\ca.crt,.\bootstrap.ps1,.\verify.ps1,.\launch.ps1
Get-ExecutionPolicy -List
if ((Get-ExecutionPolicy -Scope MachinePolicy) -ne 'Undefined' -or
    (Get-ExecutionPolicy -Scope UserPolicy) -ne 'Undefined') {
    throw 'Managed script policy is configured; use an organization-approved execution path, not an override.'
} else {
    Unblock-File -LiteralPath .\bootstrap.ps1,.\verify.ps1,.\launch.ps1
    Set-ExecutionPolicy -Scope Process RemoteSigned -Force
}
```

This unblocks only the verified local scripts and changes no persistent execution
policy. Respect organization policy even when no Group Policy value is present.
Do not import a root certificate or disable auditing.

## 2. Verify and manually install Git

Download this pinned official Git for Windows installer in the Windows browser:

<https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe>

Before running it, verify the public SHA256 and Authenticode signer pin locally:

```powershell
$installer = Join-Path $env:USERPROFILE 'Downloads\Git-2.56.0.2-64-bit.exe'
$expected = '52188f917b378f00c70ec136bcf090005f30d44fbc4eba0bce759cc6592d60f6'
if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Git installer hash mismatch; do not run.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne 'C4BA1DE1C1B6049CF0E3FB393640685052199AEB') {
    throw 'Git installer signature invalid/unexpected; do not run.'
}
$signature.SignerCertificate.Subject
```

These public pins do not replace your local verification. Failure means stop,
not disable signature checks or use an unpinned installer. After both checks pass,
open that checked file yourself and complete the normal interactive installation
(UAC confirmation is allowed), using `Program Files\Git`:

```powershell
Test-Path "$env:ProgramFiles\Git\bin\bash.exe"
Test-Path "$env:ProgramFiles\Git\cmd\git.exe"
```

Both should be `True`. Return to the normal target-user PowerShell session.
No unattended installer or GitHub login is needed for Git setup.

### Each new PowerShell window

Use this block **before bootstrap and in every new target-user PowerShell
window**, including after the Git installer. `$launch` is absolute and may be
defined before installation. Keep the same window for the commands below; if
reopened, repeat this block. Never override organization policy.

```powershell
$launch = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'CCviaGHCP\launch.ps1'))
if ((Get-ExecutionPolicy -Scope MachinePolicy) -ne 'Undefined' -or
    (Get-ExecutionPolicy -Scope UserPolicy) -ne 'Undefined') {
    throw 'Managed script policy is configured; use an organization-approved execution path, not an override.'
} else {
    Set-ExecutionPolicy -Scope Process RemoteSigned -Force
}
```

## 3. Bootstrap the pinned native CLI

Return to the verified handoff directory from step 1; adjust this example path
if you chose a different directory:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Downloads\ccviaghcp-handoff')
.\bootstrap.ps1 -CaFile .\ca.crt
& (Join-Path $env:USERPROFILE '.local\bin\claude.exe') --version
```

Expect native **2.1.284**. Bootstrap downloads the versioned official manifest
and executable, never a remote installer script. It verifies SHA256 before
copying into the target user profile:

| Public vendor artifact | SHA256 |
| --- | --- |
| Versioned manifest | `89d15995a702c15a37cbc986a33cba415aa93e9671114971e137592aad7b2bd1` |
| `win32-x64/claude.exe` | `0416631e846f743110da5282409776fa1313e65f33a588aae066eaf8db0fda7d` |

Missing Git is a prerequisite failure, not an automatic install. Bootstrap copies
the public CA to `%LOCALAPPDATA%\CCviaGHCP\lab-ca.crt` for per-process
`NODE_EXTRA_CA_CERTS`. **No CurrentUser/LocalMachine root import**, TLS bypass,
or root-import fallback is provided.

## 4. Optional credential-free diagnostic

```powershell
& (Join-Path $env:LOCALAPPDATA 'CCviaGHCP\verify.ps1')
```

Unique DNS addresses must be only `10.77.0.240`, with no unexpected IPv6. The script
uses installed System32 `curl.exe`, `--disable` first, the approved CA via
`--cacert`, no proxy or redirects, bounded timeouts, and an allowlisted child
environment. No gateway key/OAuth credential is sent. Success means exit 0, HTTP
200, and remote IP `10.77.0.240` from
`https://litellm.ccviaghcp.test/health/liveliness`.

Older Schannel/PEM support, missing curl, or revocation checks may cause failure.
Report it honestly; **do not weaken TLS/revocation checks or import a root as a
fallback**. Curl success is not native CLI acceptance, and curl-only failure is
not proof of native-client failure. Resolve wrong DNS before accepting the client;
never replace private DNS with a public endpoint or TLS exception.
For example, `CRYPT_E_NO_REVOCATION_CHECK` / “The revocation function was unable
to check revocation” can be an optional-diagnostic-only failure, not a reason to
disable revocation or skip decisive native acceptance.

## 5. Decisive native acceptance (manual, allowance-consuming)

Use a new disposable directory containing no secrets or repository settings.
Keep normal organization auditing intact, but do not enable ad hoc verbose logs
or transcripts that capture credentials. The launcher masks key entry, configures
private HTTPS/model aliases/per-process trust, disables auto-update, enables
subprocess scrubbing, and restores previous environment values in `finally`.
Before prompting or changing the environment it rejects nonempty `NODE_OPTIONS`,
`ANTHROPIC_CUSTOM_HEADERS`, `SSLKEYLOGFILE`, `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` (case-insensitive names). `NODE_TLS_REJECT_UNAUTHORIZED` may only be
absent, empty, or exactly `1`. `NO_PROXY` is not an exemption. This deliberately
does not support proxy-required sessions: use an organization-approved environment
for direct private-gateway access, **not** one with required policy disabled.
These checks cover inherited process variables, not Claude settings, hooks, or
plugins; review and trust those separately.

Invoke **in-session with `& $launch` only**, then inspect `$LASTEXITCODE` for the
native exit. The script restores the environment without terminating its caller;
no `powershell -File` process-exit propagation contract is provided.

```powershell
$work = Join-Path ([IO.Path]::GetTempPath()) ('ccviaghcp-pilot-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
Set-Location $work
```

1. **Negative TLS, dummy key only.** Temporarily move only this user's public CA
   out of the launcher's location and restore it in `finally`:

   ```powershell
   $ca = Join-Path $env:LOCALAPPDATA 'CCviaGHCP\lab-ca.crt'
   $held = "$ca.negative-test"
   if (Test-Path -LiteralPath $held) { throw 'Restore/review the earlier public CA test first.' }
   Move-Item -LiteralPath $ca -Destination $held
   try {
       & $launch --model sonnet --no-session-persistence -p 'Reply OK.'
       $LASTEXITCODE
   } finally {
       Move-Item -LiteralPath $held -Destination $ca
   }
   ```

   At the masked prompt enter an invalid **dummy** key. Require actual trust
   rejection and nonzero native exit, not just a missing-PEM warning or unrelated
   error. A successful request/auth response without the PEM fails this control;
   stop for review. Do not remove existing machine trust to force a test result.
2. **Positive TLS, negative auth.** With the approved PEM restored, run the same
   launcher command using a dummy key. Require gateway authentication rejection
   over verified TLS, not inference. The pinned database-free proxy may return
   `400 / No connected db.` for an unknown key; do not add a database to change it.
3. **Real gateway MASTER/ADMIN key only at the masked prompt.** This credential
   is for one trusted user, not a least-privilege inference key. Obtain it privately from the
   operator's trusted secret workflow. It is **not a GitHub token**. On Windows,
   never put it in arguments, files, scripts, settings, transcripts, or the handoff.
   Run the same native command for `sonnet`, `opus`, and `haiku`, requiring real
   replies and successful exit with no TLS exceptions. Aliases must map to your
   live, entitled selection; a diagnostic or model-name warning is not acceptance.
4. **Read/Write AUTO-tool proof.** Create an unpredictable public nonce whose
   value is not included in the prompt:

   ```powershell
   $nonce = [Guid]::NewGuid().ToString('N')
   Set-Content -LiteralPath .\input.txt -Value $nonce -NoNewline
   & $launch --model sonnet --no-session-persistence --tools 'Read,Write' --allowedTools 'Read,Write' -p 'Use Read to read only input.txt in this directory. Use Write to create only output.txt with exactly the input contents and no newline. Do not access any other path. Reply DONE.'
   if ($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath .\output.txt -Raw) -cne $nonce) {
       throw 'Native tool/nonce proof failed.'
   }
   ```

   Enter the gateway key only at the masked prompt. Require actual Read and Write
   tool use and exact contents, not the model's claim. Do not bypass permissions,
   add other tools/MCP servers, or force a tool choice. Observe the normal native
   UI or approved minimal evidence, not credential-bearing debug logs.

Record only version, aliases, UTC time, and pass/fail/reason privately. The operator
must also verify real background/subagent classification and credential reload
after a reviewed gateway restart; the hints are not billing or authorization proof.

## Authentication boundary

Copilot OAuth stays server-side. A GitHub login/consent flow is appropriate only
when legitimate fresh authorization is needed, never as a reason to copy the
server's grant to Windows. No credential scraping, custom account delivery, or
automated Windows password path is supplied. Do not put gateway or OAuth secrets
in Git credential helpers. Subprocess scrubbing is defense in depth, not same-user
process isolation or guaranteed managed-string zeroization. See
[security and maintenance](../docs/security.md) for renewal, rotation, and costs.

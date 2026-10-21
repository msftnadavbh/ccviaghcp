# Linux pwsh harness with a fake native executable; no Windows/client runtime claim.
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot '../windows/launch.ps1'
foreach ($file in Get-ChildItem (Join-Path $PSScriptRoot '../windows/*.ps1')) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Windows PowerShell source parse failed.' }
}
Write-Host 'PASS all Windows PowerShell scripts parsed'
$root = Join-Path ([IO.Path]::GetTempPath()) ('ccviaghcp-launch-test-' + [Guid]::NewGuid())
$global:CCVIAGHCP_TEST_PROMPTS = 0
function global:Read-Host { $global:CCVIAGHCP_TEST_PROMPTS++; ConvertTo-SecureString 'synthetic-new-key' -AsPlainText -Force }
$conflictNames = @('NODE_OPTIONS', 'ANTHROPIC_CUSTOM_HEADERS', 'SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NODE_TLS_REJECT_UNAUTHORIZED')
# Isolate only this test process from runner-injected proxies/runtime settings.
$runnerConflicts = @(Get-ChildItem Env: | Where-Object { $_.Name.ToUpperInvariant() -in $conflictNames })
foreach ($item in $runnerConflicts) { Remove-Item -LiteralPath ("Env:\" + $item.Name) }
function Environment-Snapshot { (Get-ChildItem Env: | Sort-Object Name | ForEach-Object { @($_.Name, $_.Value) }) | ConvertTo-Json -Compress }
function Assert-Restored {
    if ($env:ANTHROPIC_AUTH_TOKEN -ne 'synthetic-old-key' -or
        $env:ANTHROPIC_API_KEY -ne 'synthetic-original-api-key' -or
        $env:ANTHROPIC_BASE_URL -ne 'https://synthetic.invalid' -or
        $env:CLAUDE_CODE_USE_BEDROCK -ne '1' -or
        $env:CLAUDE_CODE_SUBPROCESS_ENV_SCRUB -ne '0' -or
        (Test-Path Env:\ANTHROPIC_DEFAULT_OPUS_MODEL)) { throw 'Process environment was not restored.' }
}
function Assert-Refused([string]$name) {
    $before = Environment-Snapshot
    $prompts = $global:CCVIAGHCP_TEST_PROMPTS
    $caught = ''
    try { & $launcher } catch { $caught = $_.Exception.Message }
    if (-not $caught.Contains($name) -or -not $caught.Contains('organization-approved environment') -or
        $caught.Contains('synthetic-') -or $caught.Contains('Injected') -or $caught.Contains("`n")) { throw 'Unsafe/missing environment refusal.' }
    if ((Test-Path $env:CCVIAGHCP_TEST_MARKER) -or (Environment-Snapshot) -cne $before -or
        $global:CCVIAGHCP_TEST_PROMPTS -ne $prompts) { throw 'Refusal invoked native, prompted or changed environment.' }
}
try {
    $env:USERPROFILE = Join-Path $root 'profile'
    $env:LOCALAPPDATA = Join-Path $root 'appdata'
    $env:ProgramFiles = Join-Path $root 'programs'
    $env:ANTHROPIC_AUTH_TOKEN = 'synthetic-old-key'
    $env:ANTHROPIC_API_KEY = 'synthetic-original-api-key'
    $env:ANTHROPIC_BASE_URL = 'https://synthetic.invalid'
    $env:CLAUDE_CODE_USE_BEDROCK = '1'
    $env:CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '0'
    Remove-Item Env:\ANTHROPIC_DEFAULT_OPUS_MODEL -ErrorAction SilentlyContinue
    $env:NO_PROXY = 'litellm.ccviaghcp.test,*'
    try {
        & $launcher
        throw 'Expected missing Git Bash failure.'
    } catch {
        if ($_.Exception.Message -ne 'Git Bash missing; run bootstrap in this user session.') { throw }
    }
    Assert-Restored
    $git = Join-Path $env:ProgramFiles 'Git/bin'
    $bin = Join-Path $env:USERPROFILE '.local/bin'
    New-Item -ItemType Directory -Force $git, $bin | Out-Null
    [IO.File]::WriteAllText((Join-Path $git 'bash.exe'), '')
    $fake = Join-Path $bin 'claude.exe'
    $env:CCVIAGHCP_TEST_MARKER = Join-Path $root 'passed'
    [IO.File]::WriteAllText($fake, @'
#!/bin/sh
test "$ANTHROPIC_AUTH_TOKEN" = synthetic-new-key || exit 41
test -z "${ANTHROPIC_API_KEY+x}" || exit 42
test -z "${CLAUDE_CODE_USE_BEDROCK+x}" || exit 43
test "$CLAUDE_CODE_SUBPROCESS_ENV_SCRUB" = 1 || exit 44
test "$CLAUDE_CODE_GATEWAY_HINT_HEADERS" = 1 || exit 45
test "$ANTHROPIC_BASE_URL" = https://litellm.ccviaghcp.test || exit 46
printf pass > "$CCVIAGHCP_TEST_MARKER"
exit "${CCVIAGHCP_TEST_EXIT:-0}"
'@)
    & chmod 700 -- $fake
    if ($LASTEXITCODE -ne 0) { throw 'Cannot make synthetic executable runnable.' }
    foreach ($name in $conflictNames) {
        foreach ($spelling in @($name, $name.ToLowerInvariant())) {
            foreach ($value in @('synthetic-hostile-value', "synthetic-secret`nInjected: value")) {
                Set-Item -LiteralPath ("Env:\" + $spelling) $value
                Assert-Refused $name
                Remove-Item -LiteralPath ("Env:\" + $spelling)
            }
        }
    }
    foreach ($value in @('0', 'true', '1 ', ' 1')) {
        $env:NODE_TLS_REJECT_UNAUTHORIZED = $value
        Assert-Refused 'NODE_TLS_REJECT_UNAUTHORIZED'
    }
    foreach ($value in @($null, '', '1')) {
        if ($null -eq $value) { Remove-Item Env:\NODE_TLS_REJECT_UNAUTHORIZED -ErrorAction SilentlyContinue }
        else { $env:NODE_TLS_REJECT_UNAUTHORIZED = $value }
        & $launcher
        if ($LASTEXITCODE -ne 0) { throw 'Native success exit was not retained in-session.' }
        if (-not (Test-Path $env:CCVIAGHCP_TEST_MARKER) -or (Get-Content $env:CCVIAGHCP_TEST_MARKER -Raw) -ne 'pass') { throw 'Synthetic launcher invocation failed.' }
        Assert-Restored
        Remove-Item -LiteralPath $env:CCVIAGHCP_TEST_MARKER
    }
    $env:CCVIAGHCP_TEST_EXIT = '37'
    & $launcher
    if ($LASTEXITCODE -ne 37 -or -not (Test-Path $env:CCVIAGHCP_TEST_MARKER)) { throw 'Native nonzero exit was not retained in-session.' }
    Assert-Restored
    Write-Host 'PASS launcher conflict refusal before prompt/native/environment changes; success/nonzero restoration and in-session exits'
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Item Function:\Read-Host
    foreach ($item in @(Get-ChildItem Env: | Where-Object { $_.Name.ToUpperInvariant() -in $conflictNames })) { Remove-Item -LiteralPath ("Env:\" + $item.Name) }
    foreach ($item in $runnerConflicts) { Set-Item -LiteralPath ("Env:\" + $item.Name) $item.Value }
    Remove-Variable CCVIAGHCP_TEST_PROMPTS -Scope Global -ErrorAction SilentlyContinue
}

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
function global:Read-Host { ConvertTo-SecureString 'synthetic-new-key' -AsPlainText -Force }
function Assert-Restored {
    if ($env:ANTHROPIC_AUTH_TOKEN -ne 'synthetic-old-key' -or
        $env:ANTHROPIC_API_KEY -ne 'synthetic-original-api-key' -or
        $env:ANTHROPIC_BASE_URL -ne 'https://synthetic.invalid' -or
        $env:CLAUDE_CODE_USE_BEDROCK -ne '1' -or
        $env:CLAUDE_CODE_SUBPROCESS_ENV_SCRUB -ne '0' -or
        (Test-Path Env:\ANTHROPIC_DEFAULT_OPUS_MODEL)) { throw 'Process environment was not restored.' }
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
'@)
    & chmod 700 -- $fake
    if ($LASTEXITCODE -ne 0) { throw 'Cannot make synthetic executable runnable.' }
    & $launcher
    if (-not (Test-Path $env:CCVIAGHCP_TEST_MARKER) -or (Get-Content $env:CCVIAGHCP_TEST_MARKER -Raw) -ne 'pass') { throw 'Synthetic launcher invocation failed.' }
    Assert-Restored
    Write-Host 'PASS launcher environment restoration on success/failure, provider isolation and scrub opt-in'
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Item Function:\Read-Host
}

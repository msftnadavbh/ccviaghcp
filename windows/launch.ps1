$ErrorActionPreference = 'Stop'
$conflicts = @('NODE_OPTIONS', 'ANTHROPIC_CUSTOM_HEADERS', 'SSLKEYLOGFILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')
$blocked = @()
foreach ($item in Get-ChildItem Env:) {
    $name = $item.Name.ToUpperInvariant()
    if (($name -in $conflicts -and $item.Value.Length -gt 0) -or
        ($name -eq 'NODE_TLS_REJECT_UNAUTHORIZED' -and $item.Value.Length -gt 0 -and $item.Value -cne '1')) {
        $blocked += $name
    }
}
if ($blocked.Count) {
    throw ('Conflicting environment: ' + (($blocked | Sort-Object -Unique) -join ', ') +
        '. Use an organization-approved environment for direct private-gateway access; do not disable required organization policy.')
}
$providerFlags = @('CLAUDE_CODE_USE_ANTHROPIC_AWS', 'CLAUDE_CODE_USE_BEDROCK',
    'CLAUDE_CODE_USE_FOUNDRY', 'CLAUDE_CODE_USE_MANTLE', 'CLAUDE_CODE_USE_VERTEX')
$names = @('ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL',
    'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_OPUS_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL',
    'ANTHROPIC_SMALL_FAST_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL', 'NODE_EXTRA_CA_CERTS',
    'CLAUDE_CODE_GIT_BASH_PATH', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'DISABLE_AUTOUPDATER',
    'CLAUDE_CODE_GATEWAY_HINT_HEADERS', 'CLAUDE_CODE_MAX_CONTEXT_TOKENS', 'CLAUDE_CODE_AUTO_COMPACT_WINDOW',
    'CLAUDE_CODE_MAX_OUTPUT_TOKENS', 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB') + $providerFlags
$previous = @{}
foreach ($name in $names) {
    if (Test-Path "Env:\$name") { $previous[$name] = (Get-Item "Env:\$name").Value }
}
$secure = $null
$pointer = [IntPtr]::Zero
try {
    $secure = Read-Host 'Gateway key (not GitHub token)' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $env:ANTHROPIC_AUTH_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($env:ANTHROPIC_AUTH_TOKEN)) { throw 'Empty gateway key.' }
    Remove-Item Env:\ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
    foreach ($name in $providerFlags) { Remove-Item "Env:\$name" -ErrorAction SilentlyContinue }
    $env:ANTHROPIC_BASE_URL = 'https://litellm.ccviaghcp.test'
    $env:ANTHROPIC_MODEL = 'sonnet'
    $env:ANTHROPIC_DEFAULT_SONNET_MODEL = 'sonnet'
    $env:ANTHROPIC_DEFAULT_OPUS_MODEL = 'opus'
    $env:ANTHROPIC_DEFAULT_HAIKU_MODEL = 'haiku'
    $env:ANTHROPIC_SMALL_FAST_MODEL = 'haiku'
    $env:CLAUDE_CODE_SUBAGENT_MODEL = 'sonnet'
    $env:NODE_EXTRA_CA_CERTS = Join-Path $env:LOCALAPPDATA 'CCviaGHCP\lab-ca.crt'
    $env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1'
    $env:DISABLE_AUTOUPDATER = '1'
    $env:CLAUDE_CODE_GATEWAY_HINT_HEADERS = '1'
    $env:CLAUDE_CODE_MAX_CONTEXT_TOKENS = '200000'
    $env:CLAUDE_CODE_AUTO_COMPACT_WINDOW = '200000'
    $env:CLAUDE_CODE_MAX_OUTPUT_TOKENS = '8192'
    $env:CLAUDE_CODE_SUBPROCESS_ENV_SCRUB = '1'
    $bash = @("$env:ProgramFiles\Git\bin\bash.exe", "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $bash) { throw 'Git Bash missing; run bootstrap in this user session.' }
    $env:CLAUDE_CODE_GIT_BASH_PATH = $bash
    & (Join-Path $env:USERPROFILE '.local\bin\claude.exe') @args
} finally {
    foreach ($name in $names) {
        if ($previous.ContainsKey($name)) { Set-Item "Env:\$name" $previous[$name] }
        else { Remove-Item "Env:\$name" -ErrorAction SilentlyContinue }
    }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($secure) { $secure.Dispose() }
}

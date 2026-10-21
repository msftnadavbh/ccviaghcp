# Offline Linux pwsh checks with synthetic DNS and a fake executable, not Windows runtime proof.
$ErrorActionPreference = 'Stop'
$verify = Join-Path $PSScriptRoot '../windows/verify.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('ccviaghcp-manual-test-' + [Guid]::NewGuid())
function global:Resolve-DnsName { $global:CCVIAGHCP_TEST_DNS_RECORDS }
function Check-Diagnostic([string[]]$addresses, [string]$output, [int]$exitCode, [string]$failure = '', [string]$errorText = '') {
    $global:CCVIAGHCP_TEST_DNS_RECORDS = @($addresses | ForEach-Object { [pscustomobject]@{ IPAddress = $_ } })
    $expected = @('--disable', '--silent', '--show-error', '--cacert', $ca, '--noproxy', '*',
        '--connect-timeout', '10', '--max-time', '20', '--max-redirs', '0', '--output', 'NUL',
        '--write-out', '%{http_code} %{remote_ip}', 'https://litellm.ccviaghcp.test/health/liveliness')
    $checks = @('#!/bin/sh', 'test "$#" = 18 || exit 81')
    foreach ($argument in $expected) { $checks += 'test "$1" = ''' + $argument + ''' || exit 82'; $checks += 'shift' }
    foreach ($name in @('ANTHROPIC_AUTH_TOKEN', 'GITHUB_TOKEN', 'HTTP_PROXY', 'SSLKEYLOGFILE', 'CURL_CA_BUNDLE', 'CCVIAGHCP_PARENT_ONLY')) {
        $checks += 'test -z "${' + $name + '+x}" || exit 83'
    }
    $checks += 'test -n "$SystemRoot" && test "$WINDIR" = "$SystemRoot" || exit 84'
    $checks += "printf '%s' '$output'", "printf '%s' '$errorText' >&2", "exit $exitCode"
    [IO.File]::WriteAllText($curl, ($checks -join "`n") + "`n")
    & chmod 700 -- $curl
    if ($LASTEXITCODE -ne 0) { throw 'Cannot make fake curl executable.' }
    Check-Result $failure $errorText
}
function Check-Result([string]$failure, [string]$errorText = '') {
    $caught = ''
    try { & $verify } catch { $caught = $_.Exception.Message }
    if ($failure) {
        if ($caught -notlike "Optional diagnostic failed: $failure*") { throw "Expected $failure; got $caught" }
        if ($errorText -and -not $caught.Contains($errorText)) { throw 'Credential-free curl diagnostic detail was lost.' }
    } elseif ($caught) { throw $caught }
}
try {
    $bootstrap = Get-Content (Join-Path $PSScriptRoot '../windows/bootstrap.ps1') -Raw
    $format = [regex]::Match($bootstrap, '\$publicCa -notmatch ''([^'']+)''').Groups[1].Value
    $publicPem = "-----BEGIN CERTIFICATE-----`nQQ==`n-----END CERTIFICATE-----"
    if (-not $format -or $publicPem -notmatch $format) { throw 'Public PEM format guard rejected a single certificate.' }
    foreach ($invalid in @('not a certificate', ($publicPem + $publicPem), $publicPem.Replace('CERTIFICATE', 'PRIVATE KEY'))) {
        if ($invalid -match $format) { throw 'Public PEM format guard accepted unexpected material.' }
    }
    $env:SystemRoot = Join-Path $root 'system'
    $env:LOCALAPPDATA = Join-Path $root 'app data'
    $curl = Join-Path $env:SystemRoot 'System32/curl.exe'
    $ca = Join-Path $env:LOCALAPPDATA 'CCviaGHCP/lab-ca.crt'
    New-Item -ItemType Directory -Force (Split-Path $curl), (Split-Path $ca) | Out-Null
    [IO.File]::WriteAllText($ca, 'synthetic public PEM placeholder; fake curl only')
    foreach ($name in @('ANTHROPIC_AUTH_TOKEN', 'GITHUB_TOKEN', 'HTTP_PROXY', 'SSLKEYLOGFILE', 'CURL_CA_BUNDLE', 'CCVIAGHCP_PARENT_ONLY')) {
        Set-Item "Env:\$name" 'synthetic-parent-value'
    }
    Check-Diagnostic @('10.77.0.240') '200 10.77.0.240' 0
    Check-Diagnostic @('10.77.0.240', '10.77.0.240') "200 10.77.0.240`n" 0
    Check-Diagnostic @('10.77.0.240') '200 10.77.0.240' 60 'curl exit 60;' 'synthetic certificate diagnostic'
    foreach ($bad in @('302 10.77.0.240', '500 10.77.0.240', '200 10.77.0.241', '200 ::1',
            '000 10.77.0.240', '200', '', "200 10.77.0.240`n200 10.77.0.240")) {
        Check-Diagnostic @('10.77.0.240') $bad 0 'curl exit 0;'
    }
    Check-Diagnostic @() '200 10.77.0.240' 0 'DNS addresses'
    Check-Diagnostic @('10.77.0.241') '200 10.77.0.240' 0 'DNS addresses'
    Check-Diagnostic @('10.77.0.240', '10.77.0.241') '200 10.77.0.240' 0 'DNS addresses'
    Check-Diagnostic @('10.77.0.240', '::1') '200 10.77.0.240' 0 'DNS addresses'
    $global:CCVIAGHCP_TEST_DNS_RECORDS = @([pscustomobject]@{ IPAddress = '10.77.0.240' })
    Remove-Item -LiteralPath $curl
    Check-Result 'System32 curl.exe unavailable.'
    [IO.File]::WriteAllText($curl, '')
    Check-Result 'cannot start System32 curl.exe.'
    Remove-Item -LiteralPath $ca
    Check-Result 'approved user CA PEM missing;'
    function global:Resolve-DnsName { throw 'synthetic DNS lookup failure' }
    Check-Result 'private DNS lookup failed.'
    if ($env:ANTHROPIC_AUTH_TOKEN -ne 'synthetic-parent-value') { throw 'Parent environment changed.' }
    Write-Host 'PASS manual diagnostic: exact DNS, curl args/environment, exit/status/IP/output and unavailable/failure cases'
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Item Function:\Resolve-DnsName
    Remove-Variable CCVIAGHCP_TEST_DNS_RECORDS -Scope Global -ErrorAction SilentlyContinue
}

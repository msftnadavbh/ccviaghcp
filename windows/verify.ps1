$ErrorActionPreference = 'Stop'
# Optional curl diagnostic only; native Claude acceptance is a separate manual check.
try { $records = Resolve-DnsName 'litellm.ccviaghcp.test' }
catch { throw 'Optional diagnostic failed: private DNS lookup failed.' }
$addresses = @($records | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique)
if ($addresses.Count -ne 1 -or $addresses[0] -ne '10.77.0.240') {
    throw 'Optional diagnostic failed: DNS addresses must be exactly 10.77.0.240.'
}
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
$ca = Join-Path $env:LOCALAPPDATA 'CCviaGHCP\lab-ca.crt'
if (-not (Test-Path -LiteralPath $curl -PathType Leaf)) { throw 'Optional diagnostic failed: System32 curl.exe unavailable.' }
if (-not (Test-Path -LiteralPath $ca -PathType Leaf)) { throw 'Optional diagnostic failed: approved user CA PEM missing; run bootstrap.' }
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $curl
$start.WorkingDirectory = Split-Path $curl
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
# No parent keys, proxy/TLS overrides or default curl config may enter this diagnostic.
$start.EnvironmentVariables.Clear()
$start.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
$start.EnvironmentVariables['WINDIR'] = $env:SystemRoot
$start.Arguments = '--disable --silent --show-error --cacert "' + $ca + '" --noproxy "*" --connect-timeout 10 --max-time 20 --max-redirs 0 --output NUL --write-out "%{http_code} %{remote_ip}" https://litellm.ccviaghcp.test/health/liveliness'
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $start
try {
    try { [void]$process.Start() }
    catch { throw 'Optional diagnostic failed: cannot start System32 curl.exe.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(25000)) {
        $process.Kill()
        throw 'Optional diagnostic failed: curl timed out.'
    }
    if ($process.ExitCode -ne 0 -or $stdout.Result.Trim() -cne '200 10.77.0.240') {
        $detail = $stderr.Result.Trim() -replace '[\x00-\x08\x0b-\x1f\x7f]', ''
        if ($detail.Length -gt 1000) { $detail = $detail.Substring(0, 1000) }
        throw "Optional diagnostic failed: curl exit $($process.ExitCode); expected HTTP 200 from 10.77.0.240. $detail Do not weaken TLS/revocation checks; see windows/README.md."
    }
} finally {
    $process.Dispose()
}
Write-Host 'PASS optional DNS/curl CA+hostname TLS diagnostic only; native Claude/model/tool acceptance is still required.'

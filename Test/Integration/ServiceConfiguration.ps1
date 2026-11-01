param(
    [Parameter(Mandatory)][string]$Collector,
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw 'The service configuration check requires an elevated console.'
}
$image = Join-Path $env:SystemRoot 'System32/Cipherazzi.Collector.exe'
$package = Join-Path $env:SystemRoot 'System32/CipherazziLoopback'
$journal = Join-Path $env:ProgramData 'Cipherazzi'
if ((Get-Service Cipherazzi -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $image) -or
    (Test-Path -LiteralPath $package) -or (Test-Path -LiteralPath $journal))
{
    throw 'Existing Cipherazzi service files must be preserved; use a clean machine for this check.'
}
$source = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Collector)
$resultRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$testRoot = Join-Path $env:ProgramData ('Cipherazzi Configuration ' + [guid]::NewGuid().ToString('N'))
$configuration = Join-Path $testRoot 'Collector.json'
$installed = $false
New-Item -ItemType Directory -Path $resultRoot | Out-Null
New-Item -ItemType Directory -Path $testRoot | Out-Null
function Run-Collector([string]$Arguments, [string]$Label)
{
    $process = Start-Process -FilePath (Join-Path $testRoot 'Cipherazzi.Collector.exe') -ArgumentList $Arguments `
        -WorkingDirectory $testRoot -WindowStyle Hidden -Wait -PassThru `
        -RedirectStandardOutput "$resultRoot/$Label.stdout" -RedirectStandardError "$resultRoot/$Label.stderr"
    if ($process.ExitCode) { throw (Get-Content "$resultRoot/$Label.stderr" -Raw) }
}
function Send-Http
{
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $client = [Net.Sockets.TcpClient]::new()
    $server = $null
    try
    {
        $client.Connect([Net.IPAddress]::Loopback, $listener.LocalEndpoint.Port)
        $server = $listener.AcceptTcpClient()
        $client.ReceiveTimeout = $server.ReceiveTimeout = 3000
        $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: service-settings.test`r`n`r`n")
        $client.GetStream().Write($request, 0, $request.Length)
        $buffer = [byte[]]::new(1024)
        if (!$server.GetStream().Read($buffer, 0, $buffer.Length)) { throw 'HTTP request did not arrive.' }
        $response = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 0`r`n`r`n")
        $server.GetStream().Write($response, 0, $response.Length)
        if (!$client.GetStream().Read($buffer, 0, $buffer.Length)) { throw 'HTTP response did not arrive.' }
    }
    finally
    {
        if ($server) { $server.Dispose() }
        $client.Dispose()
        $listener.Stop()
    }
}
try
{
    Copy-Item -LiteralPath $source -Destination "$testRoot/Cipherazzi.Collector.exe"
    Copy-Item -LiteralPath (Join-Path (Split-Path $source) 'CipherazziLoopback') -Destination $testRoot -Recurse
    New-Item -ItemType Directory -Path "$testRoot/Endpoint" | Out-Null
    @{ db = 'disabled.db'; 'no-http' = $true; 'endpoint-only' = $true; 'endpoint-directory' = 'Endpoint';
        'no-process' = $true } |
        ConvertTo-Json | Set-Content -LiteralPath $configuration -Encoding UTF8
    Run-Collector '--install --config Collector.json' 'install'
    $installed = $true
    $service = Get-CimInstance Win32_Service -Filter "Name='Cipherazzi'"
    if (!$service.PathName.Contains('--config') -or !$service.PathName.Contains($configuration))
    {
        throw 'The service did not preserve the absolute configuration path.'
    }
    if (!(Test-Path -LiteralPath "$package/WinDivert.dll"))
    {
        throw 'The installed package cannot support enabling loopback in the configuration.'
    }
    Send-Http
    Stop-Service Cipherazzi
    (Get-Service Cipherazzi).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    foreach ($disabled in $false, $true)
    {
        $database = if ($disabled) { 'hidden.db' } else { 'enabled.db' }
        @{ db = $database; 'no-http' = $disabled; 'loopback-only' = $true; 'no-process' = $true } |
            ConvertTo-Json | Set-Content -LiteralPath $configuration -Encoding UTF8
        Start-Service Cipherazzi
        (Get-Service Cipherazzi).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
        Send-Http
        Start-Sleep -Milliseconds 500
        Stop-Service Cipherazzi
        (Get-Service Cipherazzi).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    $verification = @'
import json, pathlib, sqlite3, sys
root = pathlib.Path(sys.argv[1])
counts = {}
for name in ("disabled", "enabled", "hidden"):
    with sqlite3.connect((root / (name + ".db")).as_uri() + "?mode=ro", uri=True) as db:
        counts[name] = db.execute("SELECT COUNT(*) FROM connections WHERE "
            "json_extract(crypto_json, '$.http_host') = 'service-settings.test'").fetchone()[0]
assert counts == {"disabled": 0, "enabled": 1, "hidden": 0}, counts
print(json.dumps({"config_reference": True, "restart_reloads_settings": True,
    "http_connections": counts, "passed": True}, indent=2))
'@
    $verification | Set-Content -LiteralPath "$resultRoot/verify.py" -Encoding UTF8
    $result = & $Python "$resultRoot/verify.py" $testRoot
    if ($LASTEXITCODE) { throw 'Service capture did not follow the edited configuration.' }
    $result | Set-Content -LiteralPath "$resultRoot/results.json"
}
catch
{
    $_ | Out-String | Set-Content -LiteralPath "$resultRoot/failure.txt"
    throw
}
finally
{
    if ($installed) { Run-Collector '--uninstall' 'uninstall' }
    Get-ChildItem -LiteralPath $testRoot -File | Where-Object Extension -In '.db', '.json' |
        Copy-Item -Destination $resultRoot
    if (Test-Path -LiteralPath "$journal/service.log")
    {
        Copy-Item -LiteralPath "$journal/service.log" -Destination $resultRoot
        Remove-Item -LiteralPath "$journal/service.log"
    }
    if ((Test-Path -LiteralPath $journal) -and !(Get-ChildItem -LiteralPath $journal -Force))
    {
        Remove-Item -LiteralPath $journal
    }
    $resolved = (Resolve-Path -LiteralPath $testRoot).ProviderPath
    if ($resolved -eq [IO.Path]::GetFullPath($testRoot) -and
        (Split-Path $resolved) -eq [IO.Path]::GetFullPath($env:ProgramData))
    {
        Remove-Item -LiteralPath $resolved -Recurse
    }
}

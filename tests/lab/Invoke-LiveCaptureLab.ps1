param([string]$Output, [string]$Python, [ValidateRange(0, 1000000)][double]$BulkMiBPerSecond = 0)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$lab = Get-Content -LiteralPath (Join-Path $cipherRoot '.work/hyperv/lab.json') -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction Stop).Source }
$run = 'capture-stress-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
if (-not $Output) { $Output = Join-Path $lab.root $run }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output | Out-Null
$guestRun = "C:\Cipherazzi\$run"
$session = $null
$server = $null
$rule = $null
$startedVm = $false
$script = Join-Path $cipherRoot 'tests/PerformanceAudit/LiveCapture.py'

try
{
    # Run against the dedicated lab VM and preserve its normal packet offloads and initial power state.
    $vm = Get-VM -Id $lab.id
    if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
    if ($vm.State -eq 'Off') { Start-VM -VM $vm; $startedVm = $true }
    for ($attempt = 0; $attempt -lt 90; ++$attempt)
    {
        try { $session = New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (-not $session) { throw 'The lab VM did not become ready.' }
    $guestIp = Invoke-Command -Session $session -ScriptBlock {
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1 -ExpandProperty IPAddress
    }
    $hostIp = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
        Select-Object -First 1 -ExpandProperty IPAddress
    Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        if (Get-Process Cipherazzi.Collector -ErrorAction SilentlyContinue) { throw 'A collector is already running.' }
        New-Item -ItemType Directory -Path $guestRun | Out-Null
    }
    Copy-Item -LiteralPath $script -Destination "$guestRun\LiveCapture.py" -ToSession $session
    $executable = Join-Path $cipherRoot 'build/bin/Release/Cipherazzi.Collector.exe'
    Copy-Item -LiteralPath $executable -Destination "$guestRun\Cipherazzi.Collector.exe" -ToSession $session
    Copy-Item -LiteralPath (Join-Path (Split-Path $executable) 'CipherazziLoopback') `
        -Destination $guestRun -ToSession $session -Recurse
    Get-FileHash -LiteralPath $executable -Algorithm SHA256 | Select-Object Hash |
        ConvertTo-Json | Set-Content -LiteralPath "$Output\collector-hash.json"
    $rule = New-NetFirewallRule -Name $run -DisplayName "Cipherazzi $run" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 24449 -LocalAddress $hostIp -RemoteAddress $guestIp -Program $Python
    $fixture = Get-Content -LiteralPath (Join-Path $cipherRoot '.work/latest-integration.json') -Raw |
        ConvertFrom-Json
    $certificateRoot = Split-Path $fixture.database
    $arguments = '"' + $script + '" server --host ' + $hostIp + ' --cert "' + $certificateRoot +
        '\cert.pem" --key "' + $certificateRoot + '\key.pem" --output "' + $Output + '\server"'
    $arguments += ' --bulk-mib-per-second ' + $BulkMiBPerSecond.ToString([Globalization.CultureInfo]::InvariantCulture)
    $server = Start-Process -FilePath $Python -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$Output\server.stdout" -RedirectStandardError "$Output\server.stderr"
    $null = $server.Handle
    for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path "$Output\server\ready"); ++$attempt)
    {
        if ($server.HasExited) { throw 'The live capture responder exited.' }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path "$Output\server\ready")) { throw 'The live capture responder did not become ready.' }
    Invoke-Command -Session $session -ArgumentList $guestRun,$hostIp -ScriptBlock {
        param($guestRun,$hostIp)
        $ErrorActionPreference = 'Stop'
        $routes = @()
        $client = $null
        try
        {
            Get-NetAdapterRsc | Select-Object Name,IPv4Enabled,IPv6Enabled | ConvertTo-Json |
                Set-Content -LiteralPath "$guestRun\rsc.json"
            Get-NetAdapterLso | Select-Object Name,IPv4Enabled,IPv6Enabled | ConvertTo-Json |
                Set-Content -LiteralPath "$guestRun\lso.json"
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -PolicyStore ActiveStore `
                -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
            foreach ($route in $routes)
            {
                Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false
            }
            $failedModes = @()
            foreach ($mode in 'default','raw')
            {
                $arguments = '"' + $guestRun + '\LiveCapture.py" capture --host ' + $hostIp +
                    ' --collector "' + $guestRun + '\Cipherazzi.Collector.exe" --output "' + $guestRun +
                    '\' + $mode + '" --duration 45'
                if ($mode -eq 'raw') { $arguments += ' --classify-raw' }
                $client = Start-Process 'C:\Cipherazzi\python\python.exe' -ArgumentList $arguments `
                    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$guestRun\$mode.stdout" `
                    -RedirectStandardError "$guestRun\$mode.stderr"
                $null = $client.Handle
                if (-not $client.WaitForExit(120000)) { throw 'The live capture regression exceeded its deadline.' }
                if ($client.ExitCode) { $failedModes += $mode }
                $client.Dispose()
                $client = $null
            }
            if ($failedModes) { throw "Live capture verification failed: $($failedModes -join ', ')." }
        }
        finally
        {
            if ($client -and -not $client.HasExited) { $client.Kill(); $client.WaitForExit() }
            Get-CimInstance Win32_Process -Filter "Name='Cipherazzi.Collector.exe'" | Where-Object {
                $_.ExecutablePath -eq "$guestRun\Cipherazzi.Collector.exe"
            } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
            foreach ($route in $routes)
            {
                New-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -NextHop $route.NextHop -RouteMetric $route.RouteMetric -PolicyStore ActiveStore | Out-Null
            }
        }
    }
    Copy-Item -FromSession $session -Path "$guestRun\*" -Destination $Output -Recurse
    @{ passed = $true; output = $Output } | ConvertTo-Json
}
catch
{
    if ($session)
    {
        try { Copy-Item -FromSession $session -Path "$guestRun\*" -Destination $Output -Recurse } catch {}
    }
    throw
}
finally
{
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
    if ($rule) { $rule | Remove-NetFirewallRule }
    if ($session) { Remove-PSSession $session }
    if ($startedVm) { Stop-VM -VM (Get-VM -Id $lab.id) }
    @{ restored_state = (Get-VM -Id $lab.id).State.ToString(); firewall_rule_removed = ($null -ne $rule) } |
        ConvertTo-Json | Set-Content -LiteralPath "$Output\cleanup.json"
}

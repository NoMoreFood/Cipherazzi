param([string]$Output, [string]$Python, [string]$Profiles)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction Stop).Source }
$lab = Get-Content -LiteralPath "$cipherRoot\.work\hyperv\lab.json" -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$profilesToRun = if ($Profiles)
{
    Get-Content -LiteralPath $Profiles -Raw | ConvertFrom-Json
}
else
{
    @(
        [pscustomobject]@{label='download'; rate=280; direction='download'; handshakes=100; raw=$false; baseline=$false}
        [pscustomobject]@{label='raw'; rate=280; direction='download'; handshakes=100; raw=$true; baseline=$false}
        [pscustomobject]@{label='duplex'; rate=112; direction='both'; handshakes=50; raw=$false; baseline=$false}
    )
}
$labels = @{}
foreach ($profile in $profilesToRun)
{
    if ($profile.label -notmatch '^[a-z0-9-]+$' -or $labels.ContainsKey($profile.label))
    {
        throw 'Capacity profile labels must be unique lowercase letters, digits, and hyphens.'
    }
    $labels[$profile.label] = $true
}
$run = 'capacity-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
if (-not $Output) { $Output = Join-Path $lab.root $run }
$Output = [IO.Path]::GetFullPath($Output)
$guestRun = "C:\Cipherazzi\$run"
$scriptPath = "$cipherRoot\tests\PerformanceAudit\CaptureCapacity.py"
$session = $null
$server = $null
$rule = $null
$startedVm = $false
New-Item -ItemType Directory -Path $Output | Out-Null
$profilesToRun | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Output\profiles.json"
$failed = @()

function Set-Status([string]$stage, [string]$label)
{
    @{ stage=$stage; label=$label; time=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json |
        Set-Content -LiteralPath "$Output\status.json"
}

try
{
    Set-Status 'connecting' ''
    $vm = Get-VM -Id $lab.id
    if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
    if ($vm.State -eq 'Off') { Start-VM -VM $vm; $startedVm=$true }
    for ($attempt=0; $attempt -lt 90; ++$attempt)
    {
        try { $session=New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (-not $session) { throw 'The lab VM did not become ready.' }
    $guestIp=Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        if (Get-Process Cipherazzi.Collector -ErrorAction SilentlyContinue) { throw 'A collector is already running.' }
        New-Item -ItemType Directory -Path $guestRun | Out-Null
        Get-NetAdapterRsc | Select-Object Name,IPv4Enabled,IPv6Enabled | ConvertTo-Json |
            Set-Content "$guestRun\rsc.json"
        Get-NetAdapterLso | Select-Object Name,IPv4Enabled,IPv6Enabled | ConvertTo-Json |
            Set-Content "$guestRun\lso.json"
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
        $routes | Export-Clixml -LiteralPath "$guestRun\routes.xml"
        foreach ($route in $routes)
        {
            Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false
        }
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1 -ExpandProperty IPAddress
    }
    $hostIp=Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
        Select-Object -First 1 -ExpandProperty IPAddress
    Copy-Item -LiteralPath $scriptPath -Destination "$guestRun\CaptureCapacity.py" -ToSession $session
    $executable="$cipherRoot\build\bin\Release\Cipherazzi.Collector.exe"
    Copy-Item -LiteralPath $executable -Destination "$guestRun\Cipherazzi.Collector.exe" -ToSession $session
    Copy-Item -LiteralPath (Join-Path (Split-Path $executable) 'CipherazziLoopback') `
        -Destination $guestRun -ToSession $session -Recurse
    Get-FileHash -LiteralPath $executable | Select-Object Hash | ConvertTo-Json |
        Set-Content -LiteralPath "$Output\collector-hash.json"
    Copy-Item -LiteralPath "$cipherRoot\build\bin\Release\Cipherazzi.Tests.exe" `
        -Destination "$guestRun\Cipherazzi.Tests.exe" -ToSession $session
    $lifecycle = Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        & "$guestRun\Cipherazzi.Tests.exe" --capture-lifecycle 2>&1 | Out-String
        if ($LASTEXITCODE) { throw 'Live capture lifecycle verification failed.' }
    }
    $lifecycle | Set-Content -LiteralPath "$Output\lifecycle.log"
    $rule=New-NetFirewallRule -Name $run -DisplayName "Cipherazzi $run" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 24449 -LocalAddress $hostIp -RemoteAddress $guestIp -Program $python
    $fixture=Get-Content -LiteralPath "$cipherRoot\.work\latest-integration.json" -Raw | ConvertFrom-Json
    $certificateRoot=Split-Path $fixture.database
    foreach ($profile in $profilesToRun)
    {
        $label=$profile.label
        Set-Status 'running' $label
        $chosen = if ($profile.PSObject.Properties.Name -contains 'executable') { $profile.executable }
            else { $executable }
        Copy-Item -LiteralPath $chosen -Destination "$guestRun\Cipherazzi.Collector.exe" -ToSession $session
        Get-FileHash -LiteralPath $chosen | Select-Object Hash | ConvertTo-Json |
            Set-Content "$Output\$label-collector-hash.json"
        $rate=([double]$profile.rate).ToString([Globalization.CultureInfo]::InvariantCulture)
        $arguments='"' + $scriptPath + '" server --host ' + $hostIp + ' --cert "' + $certificateRoot +
            '\cert.pem" --key "' + $certificateRoot + '\key.pem" --output "' + $Output + '\server-' + $label +
            '" --bulk-mib-per-second ' + $rate
        $server=Start-Process -FilePath $python -ArgumentList $arguments -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput "$Output\server-$label.stdout" `
            -RedirectStandardError "$Output\server-$label.stderr"
        $null=$server.Handle
        for ($attempt=0; $attempt -lt 100 -and -not (Test-Path "$Output\server-$label\ready"); ++$attempt)
        {
            if ($server.HasExited) { throw 'The capacity responder exited.' }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path "$Output\server-$label\ready")) { throw 'The capacity responder did not start.' }
        $result=Invoke-Command -Session $session -ArgumentList $guestRun,$hostIp,$profile,$rate -ScriptBlock {
            param($guestRun,$hostIp,$profile,$rate)
            $label=$profile.label
            $arguments='"' + $guestRun + '\CaptureCapacity.py" capture --host ' + $hostIp +
                ' --collector "' + $guestRun + '\Cipherazzi.Collector.exe" --output "' + $guestRun + '\' + $label +
                '" --duration 55 --seconds 20 --bulk-mib-per-second ' + $rate +
                ' --direction ' + $profile.direction + ' --handshakes-per-second ' + $profile.handshakes
            if ($profile.raw) { $arguments += ' --classify-raw' }
            if ($profile.baseline) { $arguments += ' --without-collector' }
            $client=Start-Process 'C:\Cipherazzi\python\python.exe' -ArgumentList $arguments -WindowStyle Hidden `
                -PassThru -RedirectStandardOutput "$guestRun\$label.stdout" `
                -RedirectStandardError "$guestRun\$label.stderr"
            $null=$client.Handle
            try
            {
                if (-not $client.WaitForExit(180000)) { throw 'The capacity workload exceeded its deadline.' }
                @{ label=$label; exit_code=$client.ExitCode }
            }
            finally
            {
                if (-not $client.HasExited) { $client.Kill(); $client.WaitForExit() }
                Get-CimInstance Win32_Process -Filter "Name='Cipherazzi.Collector.exe'" | Where-Object {
                    $_.ExecutablePath -eq "$guestRun\Cipherazzi.Collector.exe"
                } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
                $client.Dispose()
            }
        }
        if ($result.exit_code) { $failed += $label }
        $result | ConvertTo-Json | Set-Content "$Output\$label-exit.json"
        Copy-Item -FromSession $session -Path "$guestRun\$label*" -Destination $Output -Recurse
        if (-not $server.HasExited) { Stop-Process -Id $server.Id }
        $server.Dispose()
        $server=$null
    }
    Copy-Item -FromSession $session -Path "$guestRun\rsc.json","$guestRun\lso.json" -Destination $Output
    @{ passed=($failed.Count -eq 0); failed_profiles=$failed; output=$Output } | ConvertTo-Json |
        Set-Content -LiteralPath "$Output\verification.json"
    Set-Status 'complete' ''
}
catch
{
    $failure = $_
    if ($session)
    {
        try { Copy-Item -FromSession $session -Path "$guestRun\*" -Destination $Output -Recurse } catch {}
    }
    $failure | Out-String | Set-Content "$Output\error.log"
    Set-Status 'failed' $failure.Exception.Message
    throw
}
finally
{
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
    if ($rule) { $rule | Remove-NetFirewallRule }
    try
    {
        if ($session)
        {
            Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
                param($guestRun)
                if (Test-Path "$guestRun\routes.xml")
                {
                    foreach ($route in @(Import-Clixml -LiteralPath "$guestRun\routes.xml"))
                    {
                        $existing = Get-NetRoute -DestinationPrefix $route.DestinationPrefix `
                            -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop `
                            -PolicyStore ActiveStore -ErrorAction SilentlyContinue
                        if (-not $existing)
                        {
                            New-NetRoute -DestinationPrefix $route.DestinationPrefix `
                                -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop `
                                -RouteMetric $route.RouteMetric -PolicyStore ActiveStore | Out-Null
                        }
                    }
                }
            }
        }
    }
    finally
    {
        if ($session) { Remove-PSSession $session }
        if ($startedVm) { Stop-VM -VM (Get-VM -Id $lab.id) }
        @{ restored_state=(Get-VM -Id $lab.id).State.ToString(); firewall_rule_removed=($null -ne $rule) } |
            ConvertTo-Json | Set-Content "$Output\cleanup.json"
    }
}

if ($failed) { throw "Capacity verification failed: $($failed -join ', ')." }

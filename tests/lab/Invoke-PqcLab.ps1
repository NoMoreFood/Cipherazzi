param([ValidateSet('Pqc','Advanced')][string]$Suite = 'Pqc', [string]$OpenSslDirectory, [string]$Collector,
    [string]$Python, [switch]$ReplayOnly, [switch]$PacketTrace, [switch]$DisableRsc, [switch]$DisableOffload,
    [switch]$AllowCaptureTruncation)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Suite -eq 'Advanced' -and $ReplayOnly)
{
    throw 'The advanced suite requires live capture and actual endpoint results.'
}
if ($AllowCaptureTruncation -and $Suite -ne 'Advanced')
{
    throw 'Capture-size validation is available in the advanced suite.'
}
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$labRoot = Join-Path $cipherRoot '.work/hyperv'
$lab = Get-Content -LiteralPath (Join-Path $labRoot 'lab.json') -Raw | ConvertFrom-Json
if (-not $OpenSslDirectory) { $OpenSslDirectory = Join-Path $cipherRoot '.work/lab-payload/openssl' }
if (-not $Collector) { $Collector = Join-Path $cipherRoot 'build/bin/Release/Cipherazzi.Collector.exe' }
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction Stop).Source }
$OpenSslDirectory = (Resolve-Path -LiteralPath $OpenSslDirectory).Path
$Collector = (Resolve-Path -LiteralPath $Collector).Path
if (-not (Test-Path -LiteralPath (Join-Path $OpenSslDirectory 'openssl.exe')))
{
    throw 'Provide an OpenSSL directory containing openssl.exe and its runtime dependencies.'
}
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$suiteFile = $Suite + 'Integration.py'
$runName = $Suite.ToLowerInvariant() + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$resultRoot = Join-Path $lab.root $runName
$guestRun = "C:\Cipherazzi\$runName"
New-Item -ItemType Directory -Path $resultRoot | Out-Null
$session = $null
$startedVm = $false
$resultsCopied = $false
$server = $null
$firewall = $null
$serverRoot = Join-Path $resultRoot 'server'

try
{
    # Preserve the VM's initial running state and copy only the lab's application and runtimes.
    $vm = Get-VM -Id $lab.id
    if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
    if ($vm.State -eq 'Off')
    {
        Start-VM -VM $vm
        $startedVm = $true
    }
    for ($attempt = 0; $attempt -lt 90; ++$attempt)
    {
        try { $session = New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (-not $session) { throw 'The lab VM did not become ready.' }
    Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        New-Item -ItemType Directory -Path "$guestRun\tools" | Out-Null
    }
    Copy-Item -LiteralPath $Collector -Destination "$guestRun\tools\Cipherazzi.Collector.exe" -ToSession $session
    foreach ($file in 'PqcIntegration.py','AdvancedIntegration.py','Integration.py')
    {
        Copy-Item -LiteralPath (Join-Path $cipherRoot "tests/$file") -Destination "$guestRun\tools" -ToSession $session
    }
    Copy-Item -LiteralPath $OpenSslDirectory -Destination "$guestRun\tools\openssl" -Recurse -ToSession $session
    $pythonPresent = Invoke-Command -Session $session -ScriptBlock { Test-Path C:\Cipherazzi\python\python.exe }
    if (-not $pythonPresent)
    {
        Copy-Item -LiteralPath (Join-Path $cipherRoot '.work/lab-payload/python.zip') `
            -Destination "$guestRun\python.zip" -ToSession $session
        Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
            param($guestRun)
            Expand-Archive -LiteralPath "$guestRun\python.zip" -DestinationPath C:\Cipherazzi\python -Force
        }
    }

    if (-not $ReplayOnly)
    {
        # Restrict the temporary host listeners to this VM on the Hyper-V default switch.
        $hostIp = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
            Select-Object -First 1 -ExpandProperty IPAddress
        $guestIp = Invoke-Command -Session $session -ScriptBlock {
            $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric |
                Select-Object -First 1
            Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
                Where-Object AddressState -EQ Preferred | Select-Object -First 1 -ExpandProperty IPAddress
        }
        if (-not $hostIp -or -not $guestIp) { throw 'The host or VM has no default-switch IPv4 address.' }
        $serverArguments = @('"' + (Join-Path $cipherRoot "tests/$suiteFile") + '"', '--openssl',
            '"' + (Join-Path $OpenSslDirectory 'openssl.exe') + '"', '--serve', $hostIp,
            '--output', '"' + $serverRoot + '"')
        $server = Start-Process -FilePath $Python -ArgumentList $serverArguments -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $resultRoot 'server.stdout') `
            -RedirectStandardError (Join-Path $resultRoot 'server.stderr')
        $manifestPath = Join-Path $serverRoot 'servers.json'
        for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path -LiteralPath $manifestPath); ++$attempt)
        {
            if ($server.HasExited) { throw 'The host OpenSSL servers exited; inspect server.stderr.' }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'The host OpenSSL servers did not start.' }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $ports = @($manifest.ports.PSObject.Properties | ForEach-Object { [string]$_.Value })
        $firewall = New-NetFirewallRule -DisplayName "Cipherazzi lab $runName" -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $ports -LocalAddress $hostIp -RemoteAddress $guestIp `
            -Program (Join-Path $OpenSslDirectory 'openssl.exe')
        if ($Suite -eq 'Advanced')
        {
            $firewall = @($firewall) + @(New-NetFirewallRule -DisplayName "Cipherazzi lab $runName UDP" `
                -Direction Inbound -Action Allow -Protocol UDP -LocalPort $ports -LocalAddress $hostIp `
                -RemoteAddress $guestIp -Program $Python)
        }
        Copy-Item -LiteralPath $manifestPath -Destination "$guestRun\tools\servers.json" -ToSession $session
    }

    # Compare kernel capture with endpoint outcomes and with replay of the exact TLS byte transcript.
    $guestResult = Invoke-Command -Session $session `
        -ArgumentList $guestRun,$ReplayOnly.IsPresent,$PacketTrace.IsPresent,$suiteFile,$DisableRsc.IsPresent,$DisableOffload.IsPresent,$AllowCaptureTruncation.IsPresent -ScriptBlock {
        param($guestRun,$ReplayOnly,$PacketTrace,$suiteFile,$DisableRsc,$DisableOffload,$AllowCaptureTruncation)
        $ErrorActionPreference = 'Stop'
        $capture = $null
        $peakMemory = 0L
        $cpuSeconds = 0.0
        $traceStarted = $false
        $rscAdapters = @()
        $lsoAdapters = @()
        try
        {
            if ($DisableRsc -or $DisableOffload)
            {
                $rscAdapters = @(Get-NetAdapterRsc | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled })
                foreach ($adapter in $rscAdapters) { Disable-NetAdapterRsc -Name $adapter.Name }
            }
            if ($DisableOffload)
            {
                $lsoAdapters = @(Get-NetAdapterLso | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled })
                foreach ($adapter in $lsoAdapters) { Disable-NetAdapterLso -Name $adapter.Name }
            }
            $suiteArguments = @("$guestRun\tools\$suiteFile", '--openssl',
                "$guestRun\tools\openssl\openssl.exe", '--collector', "$guestRun\tools\Cipherazzi.Collector.exe",
                '--output', "$guestRun\results")
            if (-not $ReplayOnly)
            {
                $suiteArguments += @('--servers', "$guestRun\tools\servers.json")
                if ($PacketTrace)
                {
                    $trace = Start-Process pktmon.exe -ArgumentList @('start', '--capture', '--comp', 'nics',
                        '--pkt-size', '0', '--flags', '0x03F', '--file-name', "$guestRun\packets.etl",
                        '--file-size', '64') -WindowStyle Hidden -PassThru -Wait `
                        -RedirectStandardOutput "$guestRun\trace-start.stdout" `
                        -RedirectStandardError "$guestRun\trace-start.stderr"
                    if ($trace.ExitCode) { throw 'Packet tracing did not start; an existing trace is preserved.' }
                    $traceStarted = $true
                }
                $captureArguments = @('--db', "$guestRun\live.db", '--duration', '25')
                if ($suiteFile -eq 'AdvancedIntegration.py')
                {
                    New-Item -ItemType Directory -Path "$guestRun\endpoint" | Out-Null
                    $captureArguments += @('--endpoint-directory', "$guestRun\endpoint")
                    $suiteArguments += @('--endpoint-directory', "$guestRun\endpoint")
                }
                $capture = Start-Process "$guestRun\tools\Cipherazzi.Collector.exe" `
                    -ArgumentList $captureArguments -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput "$guestRun\collector.stdout" `
                    -RedirectStandardError "$guestRun\collector.stderr"
                $null = $capture.Handle
                Start-Sleep -Seconds 3
                if ($capture.HasExited) { throw 'The live collector exited during startup.' }
            }
            $suite = Start-Process C:\Cipherazzi\python\python.exe -ArgumentList $suiteArguments `
                -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput "$guestRun\suite.stdout" `
                -RedirectStandardError "$guestRun\suite.stderr"
            $exitCode = $suite.ExitCode
            if ($capture)
            {
                $deadline = [DateTime]::UtcNow.AddSeconds(35)
                while (-not $capture.HasExited)
                {
                    $capture.Refresh()
                    $peakMemory = [Math]::Max($peakMemory, $capture.PeakWorkingSet64)
                    $cpuSeconds = $capture.TotalProcessorTime.TotalSeconds
                    if ([DateTime]::UtcNow -gt $deadline) { throw 'The live collector did not stop.' }
                    Start-Sleep -Milliseconds 100
                }
                if ($capture.ExitCode) { throw 'The live collector failed.' }
                if (-not $exitCode)
                {
                    $verifyArguments = @("$guestRun\tools\$suiteFile", '--verify-live', "$guestRun\live.db",
                        '--reference', "$guestRun\results\results.json")
                    if ($AllowCaptureTruncation)
                    {
                        $verifyArguments += @('--allow-capture-truncation', '--capture-log', "$guestRun\collector.stderr")
                    }
                    $verify = Start-Process C:\Cipherazzi\python\python.exe `
                        -ArgumentList $verifyArguments -WindowStyle Hidden -PassThru -Wait `
                        -RedirectStandardOutput "$guestRun\live.stdout" -RedirectStandardError "$guestRun\live.stderr"
                    $exitCode = $verify.ExitCode
                }
            }
            @{ exit_code = $exitCode; computer = $env:COMPUTERNAME; results = "$guestRun\results"
                collector_peak_working_set = $peakMemory; collector_cpu_seconds = $cpuSeconds }
        }
        finally
        {
            foreach ($adapter in $lsoAdapters)
            {
                Set-NetAdapterLso -Name $adapter.Name -IPv4Enabled $adapter.IPv4Enabled `
                    -IPv6Enabled $adapter.IPv6Enabled
            }
            foreach ($adapter in $rscAdapters)
            {
                Set-NetAdapterRsc -Name $adapter.Name -IPv4Enabled $adapter.IPv4Enabled `
                    -IPv6Enabled $adapter.IPv6Enabled
            }
            if ($capture -and -not $capture.HasExited) { $capture.Kill(); $capture.WaitForExit() }
            if ($traceStarted)
            {
                $trace = Start-Process pktmon.exe -ArgumentList 'stop' -WindowStyle Hidden -PassThru -Wait `
                    -RedirectStandardOutput "$guestRun\trace-stop.stdout" `
                    -RedirectStandardError "$guestRun\trace-stop.stderr"
                if ($trace.ExitCode) { throw 'The lab packet trace did not stop.' }
                foreach ($format in 'pcap','txt')
                {
                    $extension = if ($format -eq 'pcap') { 'pcapng' } else { 'txt' }
                    $arguments = @("etl2$format", "$guestRun\packets.etl", '--out', "$guestRun\packets.$extension")
                    if ($format -eq 'txt') { $arguments += @('--metadata', '--verbose', '--hex') }
                    $convert = Start-Process pktmon.exe -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait `
                        -RedirectStandardOutput "$guestRun\trace-$format.stdout" `
                        -RedirectStandardError "$guestRun\trace-$format.stderr"
                    if ($convert.ExitCode) { throw 'The lab packet trace conversion failed.' }
                }
            }
        }
    }
    Copy-Item -LiteralPath $guestRun -Destination $resultRoot -Recurse -FromSession $session
    $resultsCopied = $true
    $summary = @{ vm = $lab.name; vm_id = $lab.id; computer = $guestResult.computer
        collector_sha256 = (Get-FileHash -LiteralPath $Collector).Hash.ToLowerInvariant()
        exit_code = $guestResult.exit_code; artifacts = (Join-Path $resultRoot $runName)
        suite = $Suite; capture = if ($Suite -eq 'Advanced') { 'Actual OpenSSL TCP/QUIC endpoints with public-result reports' } else { 'Actual OpenSSL TLS through byte relay and replay' }
        live_packet_monitor_tested = -not $ReplayOnly.IsPresent; started_vm = $startedVm
        packet_trace_requested = $PacketTrace.IsPresent; rsc_disabled_for_test = $DisableRsc.IsPresent -or $DisableOffload.IsPresent; lso_disabled_for_test = $DisableOffload.IsPresent
        capture_size_limit_validated = $AllowCaptureTruncation.IsPresent
        collector_peak_working_set = $guestResult.collector_peak_working_set
        collector_cpu_seconds = $guestResult.collector_cpu_seconds }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resultRoot 'summary.json')
    if ($guestResult.exit_code) { throw "The cryptography suite failed; inspect $resultRoot" }
    $summary | ConvertTo-Json
}
finally
{
    if ($server)
    {
        if (Test-Path -LiteralPath $serverRoot)
        {
            New-Item -ItemType File -Path (Join-Path $serverRoot 'stop') -Force | Out-Null
        }
        if (-not $server.WaitForExit(15000))
        {
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($server.Id)"
            $server.Kill()
            foreach ($child in $children)
            {
                if ($child.ExecutablePath -eq (Join-Path $OpenSslDirectory 'openssl.exe'))
                {
                    Stop-Process -Id $child.ProcessId -ErrorAction Continue
                }
            }
        }
    }
    if ($firewall) { Remove-NetFirewallRule -Name $firewall.Name }
    if ($session)
    {
        if (-not $resultsCopied)
        {
            Copy-Item -LiteralPath $guestRun -Destination $resultRoot -Recurse -FromSession $session `
                -ErrorAction Continue
        }
        Remove-PSSession $session
    }
    if ($startedVm) { Stop-VM -VM (Get-VM -Id $lab.id) -Confirm:$false }
}

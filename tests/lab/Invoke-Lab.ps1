param([int]$Connections = 1000, [switch]$SkipRuntimeCopy, [ValidateRange(20, 300)][int]$Duration = 60,
    [switch]$Telemetry, [switch]$Service, [ValidateSet('TLSv1.2','TLSv1.3')][string]$LoadTls = 'TLSv1.3')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$labRoot = Join-Path $cipherRoot '.work/hyperv'
$lab = Get-Content (Join-Path $labRoot 'lab.json') -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$runName = 'run-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$resultRoot = Join-Path $lab.root $runName
New-Item -ItemType Directory -Path $resultRoot | Out-Null
$session = $null
$server = $null
$firewall = $null
function Set-LabStatus([string]$State, [string]$Detail)
{
    @{ state = $State; detail = $Detail; results = $resultRoot; utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'test-status.json')
}
try
{
    Set-LabStatus 'deploying' 'Copying the applications and TLS clients into the VM'
    $vm = Get-VM -Id $lab.id
    if ($vm.State -eq 'Off') { Start-VM -VM $vm }
    for ($attempt = 0; $attempt -lt 90; ++$attempt)
    {
        try { $session = New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (-not $session) { throw 'The lab VM did not become ready.' }
    $interactive = Invoke-Command -Session $session -ScriptBlock {
        @(Get-Process explorer -ErrorAction SilentlyContinue).Count -gt 0
    }
    if (-not $interactive)
    {
        # The isolated lab account logs on once so the viewer runs on an interactive Windows desktop.
        Invoke-Command -Session $session -ArgumentList $credential.GetNetworkCredential().Password -ScriptBlock {
            param($password)
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty -LiteralPath $key -Name DefaultUserName -Value 'LabAdmin'
            Set-ItemProperty -LiteralPath $key -Name DefaultDomainName -Value $env:COMPUTERNAME
            Set-ItemProperty -LiteralPath $key -Name DefaultPassword -Value $password
            Set-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '1'
            Set-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -Type DWord
            shutdown.exe /r /t 2 /f | Out-Null
        }
        Remove-PSSession $session
        $session = $null
        Start-Sleep -Seconds 8
        for ($attempt = 0; $attempt -lt 90; ++$attempt)
        {
            try
            {
                $session = New-PSSession -VMId $lab.id -Credential $credential
                $interactive = Invoke-Command -Session $session -ScriptBlock {
                    @(Get-Process explorer -ErrorAction SilentlyContinue).Count -gt 0
                }
                if ($interactive) { break }
                Remove-PSSession $session
                $session = $null
            }
            catch {}
            Start-Sleep -Seconds 1
        }
        if (-not $session) { throw 'The interactive lab desktop did not become ready.' }
        Invoke-Command -Session $session -ScriptBlock {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0'
            Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue
        }
    }
    Invoke-Command -Session $session -ScriptBlock {
        New-Item -ItemType Directory -Path C:\Cipherazzi -Force | Out-Null
    }
    foreach ($file in 'Cipherazzi.Collector.exe','Cipherazzi.Viewer.exe','Cipherazzi.Relay.exe',
        'Cipherazzi.Viewer.config','Watch-Java.ps1')
    {
        $sourceFile = Join-Path $cipherRoot "dist/$file"
        $localHash = (Get-FileHash -LiteralPath $sourceFile).Hash
        $guestHash = Invoke-Command -Session $session -ArgumentList $file -ScriptBlock {
            param($file)
            if (Test-Path -LiteralPath "C:\Cipherazzi\$file") { (Get-FileHash -LiteralPath "C:\Cipherazzi\$file").Hash }
        }
        if ($guestHash -ne $localHash)
        {
            Copy-Item -LiteralPath $sourceFile -Destination C:\Cipherazzi -ToSession $session
        }
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Traffic.py') -Destination C:\Cipherazzi -ToSession $session
    Copy-Item -LiteralPath (Join-Path $cipherRoot 'tests/clients/JavaClient.java') -Destination C:\Cipherazzi -ToSession $session
    Copy-Item -LiteralPath (Join-Path $cipherRoot 'tests/clients/JavaTelemetry.java') -Destination C:\Cipherazzi -ToSession $session
    Copy-Item -LiteralPath (Join-Path $cipherRoot '.work/lab-payload/schannel/SchannelClient.exe') `
        -Destination C:\Cipherazzi -ToSession $session
    if (-not $SkipRuntimeCopy)
    {
        foreach ($runtime in 'java','python')
        {
            Copy-Item -LiteralPath (Join-Path $cipherRoot ".work/lab-payload/$runtime.zip") `
                -Destination C:\Cipherazzi -ToSession $session
            Invoke-Command -Session $session -ArgumentList $runtime -ScriptBlock {
                param($runtime)
                Expand-Archive -LiteralPath "C:\Cipherazzi\$runtime.zip" -DestinationPath "C:\Cipherazzi\$runtime" -Force
            }
        }
    }
    $guestIp = Invoke-Command -Session $session -ScriptBlock {
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -Like '172.22.*' |
            Select-Object -First 1 -ExpandProperty IPAddress
    }
    $hostIp = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
    if (-not $guestIp) { throw 'The lab VM has no default-switch IPv4 address.' }
    $python = 'C:\Users\Bryan Berns\AppData\Local\Programs\Python\Python312\python.exe'
    $fixture = Get-Content (Join-Path $cipherRoot '.work/latest-integration.json') -Raw | ConvertFrom-Json
    $certRoot = Split-Path $fixture.database
    Copy-Item -LiteralPath (Join-Path $certRoot 'cert.pem') -Destination C:\Cipherazzi -ToSession $session
    $firewall = New-NetFirewallRule -DisplayName "Cipherazzi lab $runName" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 24443 -LocalAddress $hostIp -RemoteAddress $guestIp -Program $python
    $serverArgs = @('"' + (Join-Path $PSScriptRoot 'Traffic.py') + '"', 'server', '--host', $hostIp,
        '--duration', '300', '--cert', '"' + (Join-Path $certRoot 'cert.pem') + '"',
        '--key', '"' + (Join-Path $certRoot 'key.pem') + '"', '--log', '"' + (Join-Path $resultRoot 'server.jsonl') + '"')
    $server = Start-Process -FilePath $python -ArgumentList $serverArgs -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $resultRoot 'server.stdout') `
        -RedirectStandardError (Join-Path $resultRoot 'server.stderr')
    for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path (Join-Path $resultRoot 'server.jsonl.ready')); ++$attempt)
    {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path (Join-Path $resultRoot 'server.jsonl.ready'))) { throw 'The lab TLS server did not start.' }
    Set-LabStatus 'capturing' 'Running live TLS traffic and measuring observation arrival times'
    $guestResult = Invoke-Command -Session $session -ArgumentList $hostIp,$runName,$Connections,$Duration,
        $Telemetry.IsPresent,$Service.IsPresent,$LoadTls -ScriptBlock {
        param($hostIp,$runName,$Connections,$Duration,$Telemetry,$Service,$LoadTls)
        $ErrorActionPreference = 'Stop'
        $run = "C:\Cipherazzi\$runName"
        New-Item -ItemType Directory -Path $run | Out-Null
        New-Item -ItemType Directory -Path "$run\jfr" | Out-Null
        $channel = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-CAPI2/Operational'
        $channelEnabled = $channel.IsEnabled
        $installedByLab = $false
        try
        {
            if ($Telemetry) { $channel.IsEnabled = $true; $channel.SaveChanges() }
            & C:\Cipherazzi\Cipherazzi.Collector.exe --list-sources > "$run\sources.txt" 2> "$run\sources-error.txt"
            $options = "--db $run\capture.db"
            if ($Telemetry) { $options += " --schannel --jfr-directory $run\jfr" }
            if ($Service)
            {
                if (Get-Service Cipherazzi -ErrorAction SilentlyContinue) { throw 'The lab service is already installed.' }
                $setup = Start-Process C:\Cipherazzi\Cipherazzi.Collector.exe -ArgumentList "--install $options" `
                    -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput "$run\install.stdout" `
                    -RedirectStandardError "$run\install.stderr"
                if ($setup.ExitCode) { throw (Get-Content "$run\install.stderr" -Raw) }
                $installedByLab = $true
                $capture = Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='Cipherazzi'").ProcessId
            }
            else
            {
                $capture = Start-Process C:\Cipherazzi\Cipherazzi.Collector.exe -ArgumentList "$options --duration $Duration" `
                    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$run\collector.stdout" `
                    -RedirectStandardError "$run\collector.stderr"
            }
            $null = $capture.Handle
            $observer = Start-Process C:\Cipherazzi\python\python.exe -ArgumentList @('C:\Cipherazzi\Traffic.py',
                'observe', '--database', "$run\capture.db", '--log', "$run\arrivals.jsonl", '--duration', $Duration) `
                -WindowStyle Hidden -PassThru -RedirectStandardOutput "$run\observer.stdout" `
                -RedirectStandardError "$run\observer.stderr"
            Start-Sleep -Seconds 3
            if ($capture.HasExited) { throw (Get-Content "$run\collector.stderr" -Raw) }
            if ($Telemetry)
            {
                $java = Start-Process C:\Cipherazzi\java\bin\java.exe -ArgumentList @('C:\Cipherazzi\JavaTelemetry.java',
                    $hostIp,'24443','C:\Cipherazzi\cert.pem') -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput "$run\java-endpoint.stdout" -RedirectStandardError "$run\java-endpoint.stderr"
                Start-Sleep -Seconds 2
                $watcher = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',
                    'C:\Cipherazzi\Watch-Java.ps1','-ProcessId',$java.Id,'-JavaHome','C:\Cipherazzi\java',
                    '-OutputDirectory',"$run\jfr",'-DurationSeconds','15','-IntervalSeconds','2') `
                    -WindowStyle Hidden -PassThru -RedirectStandardOutput "$run\jfr.stdout" `
                    -RedirectStandardError "$run\jfr.stderr"
            }
            $clients = @()
            foreach ($version in 'TLSv1.2','TLSv1.3')
            {
                $suffix = $version.Substring($version.Length-1)
                $watch = [Diagnostics.Stopwatch]::StartNew()
                $javaOutput = & C:\Cipherazzi\java\bin\java.exe C:\Cipherazzi\JavaClient.java 24443 $version "java-$suffix.cipherazzi.test" $hostIp
                if ($LASTEXITCODE) { throw 'Java TLS exchange failed.' }
                $clients += @{ stack = 'Java'; version = $version; result = $javaOutput; seconds = $watch.Elapsed.TotalSeconds }
                $schannelOutput = & C:\Cipherazzi\SchannelClient.exe 24443 $version "schannel-$suffix.cipherazzi.test" $hostIp
                if ($LASTEXITCODE) { throw 'Schannel TLS exchange failed.' }
                $clients += @{ stack = 'Schannel'; version = $version; result = $schannelOutput }
                & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Traffic.py client --host $hostIp --tls $version `
                    --sni "openssl-$suffix.cipherazzi.test" --log "$run\openssl.jsonl" > "$run\openssl-$suffix.stdout"
                if ($LASTEXITCODE) { throw 'OpenSSL TLS exchange failed.' }
            }
            $clients | ConvertTo-Json | Set-Content "$run\clients.json"
            $started = [DateTime]::UtcNow
            & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Traffic.py client --host $hostIp --tls $LoadTls `
                --sni load.cipherazzi.test --count $Connections --parallel 16 --log "$run\load.jsonl" > "$run\load.stdout"
            if ($LASTEXITCODE) { throw 'Live TLS load test failed.' }
            $timeout = [DateTime]::UtcNow.AddSeconds($Duration + 30)
            $peakMemory = 0L
            $cpuSeconds = 0.0
            $shutdownSent = $false
            while (-not $capture.HasExited)
            {
                $capture.Refresh()
                $peakMemory = [Math]::Max($peakMemory, $capture.PeakWorkingSet64)
                $cpuSeconds = $capture.TotalProcessorTime.TotalSeconds
                if (-not $shutdownSent -and
                    ([DateTime]::UtcNow - $capture.StartTime.ToUniversalTime()).TotalSeconds -gt ($Duration - 1))
                {
                    & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Traffic.py client --host $hostIp --tls TLSv1.3 `
                        --sni shutdown.cipherazzi.test --count 4 --parallel 4 --log "$run\shutdown.jsonl" > "$run\shutdown.stdout"
                    if ($LASTEXITCODE) { throw 'Shutdown-boundary TLS exchange failed.' }
                    $shutdownSent = $true
                    if ($Service) { Stop-Service Cipherazzi }
                }
                if ([DateTime]::UtcNow -gt $timeout) { $capture.Kill(); throw 'The collector did not stop.' }
                Start-Sleep -Milliseconds 100
            }
            $capture.WaitForExit()
            $observer.WaitForExit()
            if ($Telemetry)
            {
                $watcher.WaitForExit()
                if ($watcher.ExitCode) { throw (Get-Content "$run\jfr.stderr" -Raw) }
            }
            $summary = @{ collector_exit = $capture.ExitCode; viewer_exit = $null; collector_pid = $capture.Id
                peak_memory = $peakMemory; cpu_seconds = $cpuSeconds
                computer_name = [Environment]::MachineName
                process_account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                process_account_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                os = [Environment]::OSVersion.VersionString; run = $run; load_started = $started.ToString('o') }
            $summary | ConvertTo-Json | Set-Content "$run\summary.json"
            $taskName = "Cipherazzi-UI-$runName"
            $action = New-ScheduledTaskAction -Execute C:\Cipherazzi\Cipherazzi.Viewer.exe `
                -Argument "--verify-ui $run\capture.db $run\viewer.png"
            $principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\LabAdmin" -LogonType Interactive
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
            try
            {
                $viewerWatch = [Diagnostics.Stopwatch]::StartNew()
                Start-ScheduledTask -TaskName $taskName
                $timeout = [DateTime]::UtcNow.AddSeconds(120)
                do
                {
                    Start-Sleep -Milliseconds 200
                    if ([DateTime]::UtcNow -gt $timeout) { throw 'Interactive viewer verification timed out.' }
                    $info = Get-ScheduledTaskInfo -TaskName $taskName
                } while ($info.LastTaskResult -eq 267009 -or -not (Test-Path "$run\viewer.png.txt"))
                $summary.viewer_exit = $info.LastTaskResult
                $summary.viewer_seconds = $viewerWatch.Elapsed.TotalSeconds
            }
            finally
            {
                Stop-ScheduledTask -TaskName $taskName
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                $summary | ConvertTo-Json | Set-Content "$run\summary.json"
            }
            return $run
        }
        finally
        {
            if ($installedByLab)
            {
                $remove = Start-Process C:\Cipherazzi\Cipherazzi.Collector.exe -ArgumentList '--uninstall' `
                    -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput "$run\uninstall.stdout" `
                    -RedirectStandardError "$run\uninstall.stderr"
                if ($remove.ExitCode) { throw 'The lab service could not be removed.' }
            }
            $channel.IsEnabled = $channelEnabled
            $channel.SaveChanges()
            $channel.Dispose()
        }
    }
    Copy-Item -FromSession $session -Path "$guestResult\*" -Destination $resultRoot -Recurse
    Set-LabStatus 'complete' 'Live capture, TLS clients, load test, and guest viewer verification finished'
}
catch
{
    if ($session)
    {
        try { Copy-Item -FromSession $session -Path "C:\Cipherazzi\$runName\*" -Destination $resultRoot -Recurse } catch {}
    }
    Set-LabStatus 'failed' $_.Exception.Message
    throw
}
finally
{
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id }
    if ($firewall) { $firewall | Remove-NetFirewallRule }
    if ($session) { Remove-PSSession $session }
}

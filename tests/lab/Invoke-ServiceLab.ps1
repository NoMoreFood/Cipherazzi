param([int]$Connections = 1000, [ValidateRange(0, 100)][int]$RestartCycles = 0)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$labRoot = Join-Path $cipherRoot '.work/hyperv'
$lab = Get-Content (Join-Path $labRoot 'lab.json') -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$runName = 'service-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$resultRoot = Join-Path $lab.root $runName
New-Item -ItemType Directory -Path $resultRoot | Out-Null
$session = $null
$server = $null
$firewall = $null
function Set-LabStatus([string]$State, [string]$Detail)
{
    @{ state = $State; detail = $Detail; results = $resultRoot; utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'service-status.json')
}
function Connect-Lab([string]$PreviousBoot = '')
{
    for ($attempt = 0; $attempt -lt 180; ++$attempt)
    {
        $candidate = $null
        try
        {
            $candidate = New-PSSession -VMId $lab.id -Credential $credential -ErrorAction Stop
            $boot = Invoke-Command -Session $candidate -ScriptBlock {
                (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
            }
            if ($boot -ne $PreviousBoot) { return $candidate }
        }
        catch {}
        if ($candidate) { Remove-PSSession $candidate }
        Start-Sleep -Seconds 1
    }
    throw 'The lab VM did not become ready.'
}
try
{
    Set-LabStatus 'starting' 'Starting the existing lab VM'
    $vm = Get-VM -Id $lab.id
    if ($vm.State -eq 'Off') { Start-VM -VM $vm }
    $session = Connect-Lab
    Invoke-Command -Session $session -ArgumentList $runName -ScriptBlock {
        param($runName)
        New-Item -ItemType Directory -Path "C:\Cipherazzi\$runName" | Out-Null
        New-Item -ItemType Directory -Path 'C:\Cipherazzi\Service Lab' -Force | Out-Null
    }
    $collector = Join-Path $cipherRoot 'dist/Cipherazzi.Collector.exe'
    Copy-Item -LiteralPath $collector -Destination 'C:\Cipherazzi\Service Lab\Cipherazzi.Collector.exe' `
        -ToSession $session
    foreach ($file in 'Traffic.py','Verify-Service.py')
    {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination C:\Cipherazzi -ToSession $session
    }
    $guestIp = Invoke-Command -Session $session -ScriptBlock {
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -Like '172.22.*' |
            Select-Object -First 1 -ExpandProperty IPAddress
    }
    $hostIp = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
    $python = 'C:\Users\Bryan Berns\AppData\Local\Programs\Python\Python312\python.exe'
    $fixture = Get-Content (Join-Path $cipherRoot '.work/latest-integration.json') -Raw | ConvertFrom-Json
    $certRoot = Split-Path $fixture.database
    $firewall = New-NetFirewallRule -DisplayName "Cipherazzi lab $runName" -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 24443 -LocalAddress $hostIp -RemoteAddress $guestIp -Program $python
    $serverArgs = @('"' + (Join-Path $PSScriptRoot 'Traffic.py') + '"', 'server', '--host', $hostIp,
        '--duration', '600', '--cert', '"' + (Join-Path $certRoot 'cert.pem') + '"',
        '--key', '"' + (Join-Path $certRoot 'key.pem') + '"',
        '--log', '"' + (Join-Path $resultRoot 'server.jsonl') + '"')
    $server = Start-Process $python -ArgumentList $serverArgs -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $resultRoot 'server.stdout') `
        -RedirectStandardError (Join-Path $resultRoot 'server.stderr')
    for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path (Join-Path $resultRoot 'server.jsonl.ready')); ++$attempt)
    {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path (Join-Path $resultRoot 'server.jsonl.ready'))) { throw 'The TLS server did not start.' }
    Set-LabStatus 'testing' 'Testing installation, real TLS traffic, stop, recovery, and self-removal'
    $beforeBoot = Invoke-Command -Session $session -ArgumentList $hostIp,$runName,$Connections,$RestartCycles -ScriptBlock {
        param($hostIp,$runName,$Connections,$RestartCycles)
        $ErrorActionPreference = 'Stop'
        $run = "C:\Cipherazzi\$runName"
        $source = 'C:\Cipherazzi\Service Lab\Cipherazzi.Collector.exe'
        $installed = "$env:SystemRoot\System32\Cipherazzi.Collector.exe"
        $journal = "$env:ProgramData\Cipherazzi\$runName\traffic.db"
        New-Item -ItemType Directory -Path (Split-Path $journal) -Force | Out-Null
        $installArguments = '--install --db "' + $journal + '"'
        function Require($condition, [string]$message) { if (-not $condition) { throw $message } }
        function Invoke-Collector([string]$arguments, [string]$label, [int]$expected = 0, [switch]$Self)
        {
            $path = if ($Self) { $installed } else { $source }
            $process = Start-Process $path -ArgumentList $arguments -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput "$run\$label.stdout" -RedirectStandardError "$run\$label.stderr"
            $null = $process.Handle
            if (-not $process.WaitForExit(90000)) { throw "Collector timed out: $label" }
            Require ($process.ExitCode -eq $expected) `
                ("Collector failed: $label " + (Get-Content "$run\$label.stderr" -Raw))
        }
        function Wait-Running([uint32]$PreviousPid = 0)
        {
            for ($attempt = 0; $attempt -lt 400; ++$attempt)
            {
                $service = Get-CimInstance Win32_Service -Filter "Name='Cipherazzi'"
                if ($service.State -eq 'Running' -and $service.ProcessId -ne $PreviousPid) { return $service }
                Start-Sleep -Milliseconds 100
            }
            throw 'The service did not enter Running.'
        }
        if (Get-Service Cipherazzi -ErrorAction SilentlyContinue)
        {
            Invoke-Collector '--uninstall' 'previous-run-cleanup'
        }
        Invoke-Collector ($installArguments + ' --source 9999999') 'failed-start' 1
        Require (-not (Get-Service Cipherazzi -ErrorAction SilentlyContinue)) `
            'Failed setup left a service registration.'
        Require (-not (Test-Path $installed)) 'Failed setup left an executable.'
        Invoke-Collector $installArguments 'install'
        $service = Wait-Running
        Require ($service.StartMode -eq 'Auto' -and $service.StartName -eq 'LocalSystem') `
            'Wrong service startup or account.'
        Require ($service.PathName.StartsWith('"' + $installed + '" --service',
            [StringComparison]::OrdinalIgnoreCase)) 'System32 service path is not quoted.'
        Require ((Get-FileHash $source).Hash -eq (Get-FileHash $installed).Hash) 'The installed image differs.'
        $initialPid = $service.ProcessId
        Invoke-Collector $installArguments 'repeat-install'
        Require ((Wait-Running).ProcessId -eq $initialPid) 'Repeated setup restarted a running service.'
        $acl = Get-Acl "$env:ProgramData\Cipherazzi"
        Require $acl.AreAccessRulesProtected 'The journal directory has an inheritable write ACL.'
        $acl.Sddl | Set-Content "$run\data-acl.txt"
        (Get-Acl $installed).Sddl | Set-Content "$run\image-acl.txt"

        # Exercise Windows and non-Windows crypto while the collector runs in session zero.
        $suffix = "$runName.cipherazzi.test"
        foreach ($version in 'TLSv1.2','TLSv1.3')
        {
            $number = $version.Substring($version.Length - 1)
            & C:\Cipherazzi\java\bin\java.exe C:\Cipherazzi\JavaClient.java 24443 $version `
                "java-$number.$suffix" $hostIp
            Require ($LASTEXITCODE -eq 0) 'Java TLS failed.'
            & C:\Cipherazzi\SchannelClient.exe 24443 $version "schannel-$number.$suffix" $hostIp
            Require ($LASTEXITCODE -eq 0) 'Schannel TLS failed.'
            & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Traffic.py client --host $hostIp --tls $version `
                --sni "openssl-$number.$suffix" --log "$run\openssl.jsonl"
            Require ($LASTEXITCODE -eq 0) 'OpenSSL TLS failed.'
        }
        & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Traffic.py client --host $hostIp --count $Connections `
            --parallel 16 --sni "load.$suffix" --log "$run\load.jsonl" > "$run\load.stdout"
        Require ($LASTEXITCODE -eq 0) 'Load traffic failed.'
        $watch = [Diagnostics.Stopwatch]::StartNew()
        Stop-Service Cipherazzi
        $stopMilliseconds = $watch.Elapsed.TotalMilliseconds
        & C:\Cipherazzi\python\python.exe C:\Cipherazzi\Verify-Service.py $journal $suffix ($Connections + 6) `
            "$run\capture.json"
        Require ($LASTEXITCODE -eq 0) 'Service capture verification failed.'
        Copy-Item $journal "$run\capture.db"
        $cycles = @()
        for ($index = 0; $index -lt $RestartCycles; ++$index)
        {
            Start-Service Cipherazzi
            $null = Wait-Running
            Start-Sleep -Milliseconds 100
            $watch.Restart()
            Stop-Service Cipherazzi
            $cycles += $watch.Elapsed.TotalMilliseconds
            Require ($cycles[-1] -lt 10000) 'An idle service restart cycle stalled during shutdown.'
        }
        Start-Service Cipherazzi
        $beforeCrash = (Wait-Running).ProcessId
        Stop-Process -Id $beforeCrash -Force
        $recovered = Wait-Running $beforeCrash
        Invoke-Collector '--uninstall' 'self-uninstall' -Self
        Require (-not (Get-Service Cipherazzi -ErrorAction SilentlyContinue)) 'Self-removal left the service.'
        Require (-not (Test-Path $installed)) 'Self-removal left the installed filename.'
        Require (Test-Path $journal) 'Self-removal deleted the journal.'
        $retired = @(Get-ChildItem "$installed.*.remove" | Select-Object -ExpandProperty FullName)
        Require ($retired.Count -eq 1) 'The running image was not retired for reboot cleanup.'
        $customDirectory = "$env:ProgramData\Cipherazzi\$runName\Service Data " + [char]0x03A9
        New-Item -ItemType Directory -Path $customDirectory -Force | Out-Null
        $custom = Join-Path $customDirectory 'custom capture.db'
        Invoke-Collector ('--install --db "' + $custom + '" --max-flows 4096 --buffer-mb 64 --no-process') `
            'custom-install'
        $service = Wait-Running
        Require (Test-Path $custom) 'The quoted Unicode journal path was not used.'
        @{ stop_ms = $stopMilliseconds; initial_pid = $initialPid; recovered_pid = $recovered.ProcessId
            restart_cycles = $cycles
            retired = $retired; custom_database = $custom; service_command = $service.PathName
            setup_rollback = $true; repeated_install = $true; crash_recovery = $true; self_uninstall = $true } |
            ConvertTo-Json -Depth 4 | Set-Content "$run\lifecycle.json" -Encoding UTF8
        Copy-Item "$env:ProgramData\Cipherazzi\service.log" "$run\service.log"
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    }
    Set-LabStatus 'rebooting' 'Checking automatic startup, orderly shutdown, and retired-image cleanup'
    Invoke-Command -Session $session -ScriptBlock {
        Start-Process shutdown.exe -ArgumentList '/r /t 0' -WindowStyle Hidden
    }
    Remove-PSSession $session
    $session = $null
    $session = Connect-Lab $beforeBoot[-1]
    Invoke-Command -Session $session -ArgumentList $runName -ScriptBlock {
        param($runName)
        $ErrorActionPreference = 'Stop'
        $run = "C:\Cipherazzi\$runName"
        $report = Get-Content "$run\lifecycle.json" -Raw | ConvertFrom-Json
        (Get-Service Cipherazzi).WaitForStatus('Running', [TimeSpan]::FromSeconds(90))
        if (-not (Test-Path "$env:SystemRoot\System32\Cipherazzi.Collector.exe"))
        {
            throw 'Reboot removed the new image.'
        }
        foreach ($path in $report.retired)
        {
            if (Test-Path $path) { throw 'Reboot did not clean the retired image.' }
        }
        Stop-Service Cipherazzi
        $check = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); " +
            "s=c.execute('select status,process_status from capture_sessions').fetchall(); " +
            "assert len(s)>=2 and all(r[0]=='stopped' and 'disabled' in r[1] for r in s),s"
        $process = Start-Process C:\Cipherazzi\python\python.exe -ArgumentList @('-c', ('"' + $check + '"'),
            ('"' + $report.custom_database + '"')) -WindowStyle Hidden -Wait -PassThru `
            -RedirectStandardOutput "$run\reboot.stdout" -RedirectStandardError "$run\reboot.stderr"
        if ($process.ExitCode) { throw ('Reboot verification failed: ' + (Get-Content "$run\reboot.stderr" -Raw)) }
        Copy-Item $report.custom_database "$run\custom.db"
        foreach ($label in 'external-uninstall','repeat-uninstall')
        {
            $process = Start-Process 'C:\Cipherazzi\Service Lab\Cipherazzi.Collector.exe' -ArgumentList '--uninstall' `
                -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput "$run\$label.stdout" `
                -RedirectStandardError "$run\$label.stderr"
            if ($process.ExitCode) { throw "Removal failed: $label" }
        }
        if (Get-Service Cipherazzi -ErrorAction SilentlyContinue) { throw 'Removal left the service.' }
        if (Test-Path "$env:SystemRoot\System32\Cipherazzi.Collector.exe") { throw 'Removal left the image.' }
        if (-not (Test-Path $report.custom_database)) { throw 'Removal deleted data.' }
        $report | Add-Member -NotePropertyName reboot_autostart -NotePropertyValue $true
        $report | Add-Member -NotePropertyName reboot_cleanup -NotePropertyValue $true
        $report | Add-Member -NotePropertyName external_uninstall -NotePropertyValue $true
        $report | Add-Member -NotePropertyName custom_options_preserved -NotePropertyValue $true
        $report | ConvertTo-Json -Depth 4 | Set-Content "$run\lifecycle.json" -Encoding UTF8
    }
    Copy-Item -FromSession $session -Path "C:\Cipherazzi\$runName\*" -Destination $resultRoot -Recurse
    Set-LabStatus 'complete' 'Service installation, capture, recovery, reboot, and removal passed'
}
catch
{
    if ($session)
    {
        try
        {
            Copy-Item -FromSession $session -Path "C:\Cipherazzi\$runName\*" -Destination $resultRoot -Recurse
        }
        catch {}
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

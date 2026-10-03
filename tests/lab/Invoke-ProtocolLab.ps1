param([switch]$ClassifyRaw, [string]$Python)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$lab = Get-Content -LiteralPath (Join-Path $cipherRoot '.work/hyperv/lab.json') -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
if (-not $Python) { $Python = (Get-Command python.exe -ErrorAction Stop).Source }
$run = 'protocol-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
$output = Join-Path $lab.root $run
$guestRun = "C:\Cipherazzi\$run"
$serverRoot = Join-Path $output 'server'
New-Item -ItemType Directory -Path $serverRoot -Force | Out-Null
$session = $null
$startedVm = $false
$sshServer = $null
$rawServer = $null
$rules = @()

try
{
    # Preserve the lab state and restrict the temporary SSH private keys to local administrators and their owner.
    $acl = Get-Acl -LiteralPath $serverRoot
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544'))
    {
        $identity = New-Object Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $serverRoot -AclObject $acl
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
        New-Item -ItemType Directory -Path $guestRun | Out-Null
    }
    foreach ($file in @('build/bin/Release/Cipherazzi.Collector.exe', 'tests/ProtocolIntegration.py'))
    {
        Copy-Item -LiteralPath (Join-Path $cipherRoot $file) -Destination $guestRun -ToSession $session
    }
    Copy-Item -LiteralPath "$env:WINDIR\System32\OpenSSH\ssh.exe" -Destination $guestRun -ToSession $session
    $keygen = "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe"
    foreach ($kind in @('ed25519', 'rsa'))
    {
        $key = Start-Process $keygen -ArgumentList @('-q', '-t', $kind, '-N', '""', '-f', "$serverRoot\$kind") `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput "$serverRoot\$kind.stdout" `
            -RedirectStandardError "$serverRoot\$kind.stderr"
        $null = $key.Handle
        $key.WaitForExit()
        if ($key.ExitCode) { throw "SSH $kind host key generation failed." }
    }
    $serverPath = $serverRoot.Replace('\', '/')
    @"
Port 24422
ListenAddress $hostIp
HostKey $serverPath/ed25519
HostKey $serverPath/rsa
PidFile $serverPath/sshd.pid
LogLevel DEBUG2
PasswordAuthentication no
PubkeyAuthentication no
KbdInteractiveAuthentication no
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,ssh-rsa
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group1-sha1
Ciphers aes128-ctr,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,3des-cbc
MACs hmac-sha2-256,hmac-sha1
"@ | Set-Content -LiteralPath "$serverRoot\sshd_config" -Encoding ascii
    $sshServer = Start-Process "$env:WINDIR\System32\OpenSSH\sshd.exe" `
        -ArgumentList @('-D', '-e', '-f', "$serverRoot\sshd_config") -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$serverRoot\ssh.stdout" -RedirectStandardError "$serverRoot\ssh.stderr"
    $null = $sshServer.Handle
    $rawServer = Start-Process $Python -ArgumentList @("$cipherRoot\tests\ProtocolIntegration.py", '--serve',
        $hostIp, '--output', $serverRoot) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput "$serverRoot\raw.stdout" -RedirectStandardError "$serverRoot\raw.stderr"
    $null = $rawServer.Handle
    for ($attempt = 0; $attempt -lt 50 -and -not (Test-Path "$serverRoot\ready.json"); ++$attempt)
    {
        if ($sshServer.HasExited -or $rawServer.HasExited) { throw 'A protocol responder exited during startup.' }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path "$serverRoot\ready.json")) { throw 'The raw responder did not become ready.' }
    foreach ($protocol in @('TCP', 'UDP'))
    {
        $ports = if ($protocol -eq 'TCP') { @(24422, 24446) } else { @(24446) }
        $rules += New-NetFirewallRule -Name "$run-$protocol" -DisplayName "Cipherazzi $run $protocol" `
            -Direction Inbound -Action Allow -Protocol $protocol -LocalAddress $hostIp -LocalPort $ports `
            -RemoteAddress $guestIp -Profile Any
    }
    $result = Invoke-Command -Session $session -ArgumentList $guestRun,$hostIp,$ClassifyRaw.IsPresent -ScriptBlock {
        param($guestRun,$hostIp,$classifyRaw)
        $ErrorActionPreference = 'Stop'
        $routes = @()
        $rsc = @()
        $lso = @()
        $capture = $null
        try
        {
            # Keep the verification traffic on the lab switch and preserve offload state.
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -PolicyStore ActiveStore `
                -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
            foreach ($route in $routes)
            {
                Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false
            }
            $rsc = @(Get-NetAdapterRsc | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled })
            $lso = @(Get-NetAdapterLso | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled })
            foreach ($adapter in $rsc) { Disable-NetAdapterRsc -Name $adapter.Name }
            foreach ($adapter in $lso) { Disable-NetAdapterLso -Name $adapter.Name }
            $arguments = @('--db', "$guestRun\capture.db", '--duration', '35')
            if ($classifyRaw) { $arguments += '--classify-raw' }
            $capture = Start-Process "$guestRun\Cipherazzi.Collector.exe" -ArgumentList $arguments `
                -WindowStyle Hidden -PassThru -RedirectStandardOutput "$guestRun\collector.stdout" `
                -RedirectStandardError "$guestRun\collector.stderr"
            $null = $capture.Handle
            Start-Sleep -Seconds 3
            if ($capture.HasExited) { throw 'The collector exited during startup.' }
            $client = Start-Process C:\Cipherazzi\python\python.exe -ArgumentList @(
                "$guestRun\ProtocolIntegration.py", '--host', $hostIp, '--ssh', "$guestRun\ssh.exe",
                '--output', $guestRun) -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput "$guestRun\client.stdout" -RedirectStandardError "$guestRun\client.stderr"
            $null = $client.Handle
            $client.WaitForExit()
            if ($client.ExitCode) { throw 'Protocol endpoint execution failed.' }
            if (-not $capture.WaitForExit(40000) -or $capture.ExitCode) { throw 'The collector did not stop cleanly.' }
            @{ host = $hostIp; collector_sha256 = (Get-FileHash "$guestRun\Cipherazzi.Collector.exe").Hash }
        }
        finally
        {
            if ($capture -and -not $capture.HasExited) { $capture.Kill(); $capture.WaitForExit() }
            foreach ($adapter in $lso)
            {
                Set-NetAdapterLso -Name $adapter.Name -IPv4Enabled $adapter.IPv4Enabled -IPv6Enabled $adapter.IPv6Enabled
            }
            foreach ($adapter in $rsc)
            {
                Set-NetAdapterRsc -Name $adapter.Name -IPv4Enabled $adapter.IPv4Enabled -IPv6Enabled $adapter.IPv6Enabled
            }
            foreach ($route in $routes)
            {
                if (Get-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object NextHop -EQ $route.NextHop)
                { continue }
                try
                {
                    New-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                        -NextHop $route.NextHop -RouteMetric $route.RouteMetric -PolicyStore ActiveStore | Out-Null
                }
                catch
                {
                    if ($_.Exception.Message -notlike '*already exists*') { throw }
                }
            }
        }
    }
    Copy-Item -Path "$guestRun\*" -Destination $output -Recurse -FromSession $session
    $arguments = @("$cipherRoot\tests\ProtocolIntegration.py", '--verify', "$output\capture.db", '--output', $output)
    if ($ClassifyRaw) { $arguments += '--raw-enabled' }
    & $Python @arguments
    if ($LASTEXITCODE) { throw 'The protocol database verification failed.' }
    $result | Add-Member -NotePropertyName verified -NotePropertyValue $true -PassThru |
        ConvertTo-Json | Set-Content -LiteralPath "$output\summary.json"
    Write-Host "Protocol verification artifacts: $output"
}
catch
{
    if ($session) { Copy-Item -Path "$guestRun\*" -Destination $output -Recurse -FromSession $session -ErrorAction Continue }
    $_ | Out-String | Set-Content -LiteralPath "$output\failure.txt"
    throw
}
finally
{
    foreach ($process in @($sshServer, $rawServer))
    {
        if ($process -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    }
    foreach ($rule in $rules) { Remove-NetFirewallRule -Name $rule.Name }
    if ($session) { Remove-PSSession $session }
    if ($startedVm) { Stop-VM -VM (Get-VM -Id $lab.id) -Confirm:$false }
    @{ vm = $lab.name; restored_state = (Get-VM -Id $lab.id).State.ToString(); firewall_rules_removed = $rules.Count } |
        ConvertTo-Json | Set-Content -LiteralPath "$output\cleanup.json"
}

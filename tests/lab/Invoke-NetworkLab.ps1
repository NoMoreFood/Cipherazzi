param([string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$lab = Get-Content "$cipherRoot\.work\hyperv\lab.json" -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$run = 'network-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
if (!$Output) { $Output = "$cipherRoot\.work\$run" }
if (![IO.Path]::IsPathRooted($Output)) { $Output = Join-Path $cipherRoot $Output }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output | Out-Null
$guestRun = "C:\Cipherazzi\$run"
$session = $null
$servers = @()
$rules = @()
$startedVm = $false
try
{
    $vm = Get-VM -Id $lab.id
    if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
    if ($vm.State -eq 'Off') { Start-VM -VM $vm; $startedVm = $true }
    for ($attempt=0; $attempt -lt 90; ++$attempt)
    {
        try { $session=New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (!$session) { throw 'The lab VM did not become ready.' }
    $guestIp = Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        New-Item -ItemType Directory -Path $guestRun | Out-Null
        New-Item -ItemType Directory -Path "$guestRun\openssl" | Out-Null
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1 -ExpandProperty IPAddress
    }
    $hostIp = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
        Select-Object -First 1 -ExpandProperty IPAddress
    foreach ($file in Get-ChildItem "$cipherRoot\.work\lab-payload\openssl" -File)
    {
        Copy-Item -LiteralPath $file.FullName "$guestRun\openssl\$($file.Name)" -ToSession $session
    }
    Copy-Item "$cipherRoot\build\bin\Release\Cipherazzi.Collector.exe" "$guestRun\collector.exe" -ToSession $session
    Copy-Item "$PSScriptRoot\NetworkTraffic.py" "$guestRun\NetworkTraffic.py" -ToSession $session
    $fixture = Get-Content "$cipherRoot\.work\latest-integration.json" -Raw | ConvertFrom-Json
    $certRoot = Split-Path $fixture.database
    $openssl = "$cipherRoot\.work\lab-payload\openssl\openssl.exe"
    $rules += New-NetFirewallRule -DisplayName "Cipherazzi $run" -Direction Inbound -Action Allow -Protocol UDP `
        -LocalAddress $hostIp -RemoteAddress $guestIp -LocalPort 24621,24622 -Program $openssl
    foreach ($version in 'dtls1','dtls1_2')
    {
        $port = if ($version -eq 'dtls1') { 24621 } else { 24622 }
        $arguments = @('s_server','-accept',"${hostIp}:$port", "-$version",'-cert',"`"$certRoot\cert.pem`"",
            '-key',"`"$certRoot\key.pem`"",'-cipher','ALL:@SECLEVEL=0','-quiet','-naccept','1')
        $servers += Start-Process $openssl -ArgumentList $arguments -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput "$Output\$version.server.out" -RedirectStandardError "$Output\$version.server.err"
    }
    Invoke-Command -Session $session -ArgumentList $guestRun,$hostIp,$guestIp -ScriptBlock {
        param($guestRun,$hostIp,$guestIp)
        $ErrorActionPreference='Stop'
        $routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
        $routes | Export-Clixml "$guestRun\routes.xml"
        $collector=$null
        try
        {
            foreach ($route in $routes)
            {
                Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -NextHop $route.NextHop -PolicyStore ActiveStore -Confirm:$false
            }
            $collector=Start-Process "$guestRun\collector.exe" `
                -ArgumentList "--db $guestRun\capture.db --duration 25 --no-process" `
                -WindowStyle Hidden -PassThru -RedirectStandardOutput "$guestRun\collector.out" `
                -RedirectStandardError "$guestRun\collector.err"
            Start-Sleep -Seconds 2
            foreach ($version in 'dtls1','dtls1_2')
            {
                $port=if ($version -eq 'dtls1') { 24621 } else { 24622 }
                "test`n" | Set-Content "$guestRun\request.txt"
                $client=Start-Process "$guestRun\openssl\openssl.exe" -ArgumentList @('s_client','-connect',
                    "${hostIp}:$port","-$version",'-cipher','ALL:@SECLEVEL=0','-servername',
                    "$version.network.lab",'-brief') `
                    -WindowStyle Hidden -PassThru -RedirectStandardInput "$guestRun\request.txt" `
                    -RedirectStandardOutput "$guestRun\$version.client.out" `
                    -RedirectStandardError "$guestRun\$version.client.err"
                try
                {
                    if (!$client.WaitForExit(15000)) { throw "DTLS client timed out: $version" }
                    if ($client.ExitCode) { throw "DTLS client failed: $version" }
                }
                finally { if (!$client.HasExited) { Stop-Process -Id $client.Id } }
            }
            & C:\Cipherazzi\python\python.exe "$guestRun\NetworkTraffic.py" --source $guestIp --destination $hostIp `
                > "$guestRun\fragments.txt" 2> "$guestRun\fragments.err"
            if ($LASTEXITCODE) { throw 'Raw fragmented datagram could not be sent.' }
            if (!$collector.WaitForExit(40000)) { throw 'Collector did not stop.' }
            if ($collector.ExitCode) { throw 'Collector failed.' }
        }
        finally
        {
            if ($collector -and !$collector.HasExited) { Stop-Process -Id $collector.Id }
            foreach ($route in $routes)
            {
                New-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex `
                    -NextHop $route.NextHop -RouteMetric $route.RouteMetric -PolicyStore ActiveStore `
                    -ErrorAction Continue |
                    Out-Null
            }
        }
    }
}
finally
{
    if ($session)
    {
        Copy-Item "$guestRun\*" $Output -FromSession $session -Recurse -Force -ErrorAction Continue
        Remove-PSSession $session
    }
    foreach ($server in $servers) { if (!$server.HasExited) { Stop-Process -Id $server.Id } }
    foreach ($rule in $rules) { Remove-NetFirewallRule -Name $rule.Name -ErrorAction Continue }
    if ($startedVm) { Stop-VM -VM $vm }
}
$python = 'C:\Users\Bryan Berns\AppData\Local\Programs\Python\Python312\python.exe'
& $python "$PSScriptRoot\Verify-Network.py" --directory $Output
if ($LASTEXITCODE) { throw 'Network coverage verification failed.' }

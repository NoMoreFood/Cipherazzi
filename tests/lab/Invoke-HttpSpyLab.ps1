#requires -Version 7
param([string]$Output, [string]$Payload, [string]$LabRoot, [string]$ServerVm, [pscredential]$ServerCredential,
    [ValidateRange(1,65535)][int]$Port = 443)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$cipherPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$cipherPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw 'HTTP Spy verification requires an elevated console for Hyper-V lab access.'
}
if (!$Payload) { $Payload = Join-Path $cipherRoot 'tools/artifacts/dist' }
if (!$LabRoot) { $LabRoot = Join-Path $cipherRoot 'tools/artifacts/work/hyperv' }
$cipherTests = Join-Path $cipherRoot 'tools/artifacts/build/bin/Release/Cipherazzi.Tests.exe'
foreach ($cipherInput in @((Join-Path $Payload 'Cipherazzi.Collector.exe'),
    (Join-Path $Payload 'CipherazziLoopback/WinDivert64.sys'), $cipherTests))
{
    if (!(Test-Path -LiteralPath $cipherInput -PathType Leaf))
    {
        throw 'Build the collector, native checks, and CipherazziLoopback package before HTTP Spy verification.'
    }
}
$cipherLab = Get-Content -LiteralPath (Join-Path $LabRoot 'lab.json') -Raw | ConvertFrom-Json
$cipherCredential = Import-Clixml -LiteralPath (Join-Path $cipherLab.root 'credential.xml')
$cipherRun = 'httpspy-' + [Guid]::NewGuid().ToString('N')
if (!$Output) { $Output = Join-Path $cipherRoot "tools/artifacts/work/$cipherRun" }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output | Out-Null
$cipherGuestRun = "C:\Cipherazzi\$cipherRun"
$cipherSession = $null
$cipherServerSession = $null
$cipherServerRun = $null
$cipherServer = $null
$cipherFirewall = $null
$cipherStartedVm = $false
$cipherThumbprint = $null
try
{
    # The fixture's throwaway identity becomes a PFX for the server and a public certificate for the guest.
    $cipherIdentity = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile(
        (Join-Path $cipherRoot 'tests/fixtures/HttpSpyServer.pem'), (Join-Path $cipherRoot 'tests/fixtures/HttpSpyServer.pem'))
    [IO.File]::WriteAllBytes((Join-Path $Output 'fixture.pfx'), $cipherIdentity.Export('Pfx', 'lab'))
    [IO.File]::WriteAllBytes((Join-Path $Output 'fixture.cer'), $cipherIdentity.Export('Cert'))
    $cipherPin = [Convert]::ToBase64String(
        [Security.Cryptography.SHA256]::HashData($cipherIdentity.PublicKey.ExportSubjectPublicKeyInfo()))

    # Use the identified lab VM and restore its initial power state after testing.
    $cipherVm = Get-VM -Id $cipherLab.id
    if ($cipherVm.Name -ne $cipherLab.name) { throw 'The configured lab VM identity does not match.' }
    if ($cipherVm.State -eq 'Off') { Start-VM -VM $cipherVm; $cipherStartedVm = $true }
    for ($cipherAttempt = 0; $cipherAttempt -lt 90; ++$cipherAttempt)
    {
        try { $cipherSession = New-PSSession -VMId $cipherLab.id -Credential $cipherCredential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (!$cipherSession) { throw 'The lab VM did not become ready.' }
    $cipherGuestIp = Invoke-Command -Session $cipherSession -ScriptBlock {
        if (Get-Process Cipherazzi.Collector -ErrorAction SilentlyContinue) { throw 'A lab collector is already running.' }
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'
        } | Select-Object -First 1 -ExpandProperty IPAddress
    }

    # Run the fixture outside the capture guest to exercise its physical network interface.
    $cipherStart = {
        param($cipherDirectory, $cipherGuestIp)
        New-Item -ItemType Directory -Path $cipherDirectory | Out-Null
        $cipherGuest = [IPAddress]::Parse($cipherGuestIp).GetAddressBytes()
        $cipherAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $own = [IPAddress]::Parse($_.IPAddress).GetAddressBytes()
            $mask = [uint32]::MaxValue -shl (32 - $_.PrefixLength)
            $same = $true
            for ($i = 0; $i -lt 4; ++$i)
            {
                $maskByte = ($mask -shr (24 - 8 * $i)) -band 255
                if (($own[$i] -band $maskByte) -ne ($cipherGuest[$i] -band $maskByte)) { $same = $false }
            }
            $same -and $_.IPAddress -ne $cipherGuestIp
        } | Select-Object -First 1 -ExpandProperty IPAddress
        if (!$cipherAddress) { throw 'The fixture host has no address on the lab VM subnet.' }
        $cipherAddress
    }
    if ($ServerVm)
    {
        if (!$ServerCredential) { $ServerCredential = $cipherCredential }
        $cipherServerSession = New-PSSession -VMName $ServerVm -Credential $ServerCredential
        $cipherServerRun = "C:\Cipherazzi\$cipherRun"
        $cipherHostIp = Invoke-Command -Session $cipherServerSession -ScriptBlock $cipherStart `
            -ArgumentList $cipherServerRun, $cipherGuestIp
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'HttpSpyServer.ps1'), (Join-Path $Output 'fixture.pfx') `
            -Destination $cipherServerRun -ToSession $cipherServerSession
        Invoke-Command -Session $cipherServerSession -ArgumentList $cipherServerRun, $cipherHostIp, $cipherGuestIp, $Port `
            -ScriptBlock {
            param($cipherDirectory, $cipherHostIp, $cipherGuestIp, $cipherPort)
            New-NetFirewallRule -DisplayName "Cipherazzi lab $cipherDirectory" -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $cipherPort -LocalAddress $cipherHostIp -RemoteAddress $cipherGuestIp | Out-Null
            Start-Process pwsh.exe -WindowStyle Hidden -ArgumentList '-NoProfile', '-File',
                "$cipherDirectory\HttpSpyServer.ps1", '-Address', $cipherHostIp, '-Identity',
                "$cipherDirectory\fixture.pfx", '-Ready', "$cipherDirectory\ready", '-Port', $cipherPort `
                -RedirectStandardOutput "$cipherDirectory\server.stdout" -RedirectStandardError "$cipherDirectory\server.stderr"
            for ($attempt = 0; $attempt -lt 100 -and !(Test-Path "$cipherDirectory\ready"); ++$attempt)
            {
                Start-Sleep -Milliseconds 100
            }
            if (!(Test-Path "$cipherDirectory\ready")) { throw 'The HTTPS fixture did not start.' }
        }
    }
    else
    {
        $cipherServerRun = Join-Path $Output 'server'
        $cipherHostIp = & $cipherStart $cipherServerRun $cipherGuestIp
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'HttpSpyServer.ps1'), (Join-Path $Output 'fixture.pfx') `
            -Destination $cipherServerRun
        $cipherFirewall = New-NetFirewallRule -DisplayName "Cipherazzi lab $cipherRun" -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress $cipherHostIp -RemoteAddress $cipherGuestIp
        $cipherServer = Start-Process pwsh -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-File',
            "$cipherServerRun\HttpSpyServer.ps1", '-Address', $cipherHostIp, '-Identity',
            "$cipherServerRun\fixture.pfx", '-Ready', "$cipherServerRun\ready", '-Port', $Port `
            -RedirectStandardOutput "$cipherServerRun\server.stdout" -RedirectStandardError "$cipherServerRun\server.stderr"
        for ($cipherAttempt = 0; $cipherAttempt -lt 100 -and !(Test-Path "$cipherServerRun\ready"); ++$cipherAttempt)
        {
            Start-Sleep -Milliseconds 100
        }
        if (!(Test-Path "$cipherServerRun\ready"))
        {
            throw ('The HTTPS fixture did not start. ' +
                (Get-Content -LiteralPath "$cipherServerRun\server.stderr" -Raw -ErrorAction SilentlyContinue))
        }
    }

    # The fixture certificate is trusted for the run only, so the proxy can validate the server it relays to.
    Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun -ScriptBlock {
        param($cipherGuestRun)
        New-Item -ItemType Directory -Path $cipherGuestRun | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $Payload 'Cipherazzi.Collector.exe') -Destination $cipherGuestRun `
        -ToSession $cipherSession
    Copy-Item -LiteralPath $cipherTests -Destination $cipherGuestRun -ToSession $cipherSession
    Copy-Item -LiteralPath (Join-Path $Payload 'CipherazziLoopback') -Destination $cipherGuestRun `
        -ToSession $cipherSession -Recurse
    Copy-Item -LiteralPath (Join-Path $Output 'fixture.cer') -Destination $cipherGuestRun -ToSession $cipherSession
    $cipherThumbprint = Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun -ScriptBlock {
        param($cipherGuestRun)
        (Import-Certificate -FilePath "$cipherGuestRun\fixture.cer" -CertStoreLocation Cert:\LocalMachine\Root).Thumbprint
    }
    $cipherResults = Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun, $cipherHostIp, $cipherPin, $Port `
        -ScriptBlock {
        param($cipherGuestRun, $cipherHostIp, $cipherPin, $cipherPort)
        Set-Location $cipherGuestRun
        & "$cipherGuestRun\Cipherazzi.Tests.exe" --proxy-certificates |
            Set-Content -LiteralPath "$cipherGuestRun\certificates.log"
        if ($LASTEXITCODE) { throw 'Certificate renewal checks failed.' }
        & "$cipherGuestRun\Cipherazzi.Tests.exe" --httpspy-storage |
            Set-Content -LiteralPath "$cipherGuestRun\storage-recovery.log"
        if ($LASTEXITCODE) { throw 'Elevated storage permission and recovery checks failed.' }
        $collector = Start-Process "$cipherGuestRun\Cipherazzi.Collector.exe" -WindowStyle Hidden -PassThru `
            -ArgumentList '--db', "$cipherGuestRun\capture.db", '--httpspy', '--httpspy-port', $cipherPort,
                '--httpspy-process', 'curl.exe', '--httpspy-host', 'httpspy.test', '--httpspy-host', 'wrong.test',
                '--duration', '90' `
            -RedirectStandardOutput "$cipherGuestRun\collector.stdout" `
            -RedirectStandardError "$cipherGuestRun\collector.stderr"
        Start-Sleep -Seconds 10
        $results = [ordered]@{}
        function Fetch([string]$Name, [string]$Url, [string[]]$Arguments = @())
        {
            # No --ssl-no-revoke: the proxy's certificates must pass a revocation check.
            $text = & curl.exe -s --max-time 20 --resolve "httpspy.test:${cipherPort}:$cipherHostIp" `
                --resolve "wrong.test:${cipherPort}:$cipherHostIp" @Arguments $Url 2>&1
            $results[$Name] = @{ exit = $LASTEXITCODE; body = ($text -join "`n") }
        }
        $base = "https://httpspy.test:${cipherPort}"
        Fetch 'get' "$base/ok"
        Fetch 'post' "$base/echo" @('-d', 'a=b', '-H', 'Authorization: Bearer secret',
            '-H', 'Expect: 100-Continue', '-H', 'Transfer-Encoding: ChUnKeD', '-H', 'Cookie: session=abc')
        Fetch 'chunked' "$base/chunked" @("$base/ok")
        Fetch 'close' "$base/close"
        foreach ($path in 'interrupted-close', 'interrupted-length', 'interrupted-chunked', 'headers', 'headers-ok')
        {
            Fetch $path "$base/$path"
        }
        1..66 | ForEach-Object { "X-Fixture-${_}: " + ('a' * 1000) } |
            Set-Content -LiteralPath "$cipherGuestRun\headers.txt" -Encoding ascii
        Fetch 'requestHeaders' "$base/request-headers" @('-H', "@$cipherGuestRun\headers.txt")
        Fetch 'wrongHost' "https://wrong.test:${cipherPort}/ok"

        # A pinning client rejects the proxy's certificate once; the address is then left alone.
        Fetch 'pinFirst' "$base/ok" @('--pinnedpubkey', "sha256//$cipherPin")
        Fetch 'pinSecond' "$base/ok" @('--pinnedpubkey', "sha256//$cipherPin")
        $collector | Wait-Process -Timeout 120

        # Disabling attribution applies to both the proxy's decoded messages and the packet journal.
        $collector = Start-Process "$cipherGuestRun\Cipherazzi.Collector.exe" -WindowStyle Hidden -PassThru `
            -ArgumentList '--db', "$cipherGuestRun\no-process.db", '--httpspy', '--no-process',
                '--httpspy-port', $cipherPort, '--httpspy-process', 'curl.exe', '--duration', '20' `
            -RedirectStandardOutput "$cipherGuestRun\no-process.stdout" `
            -RedirectStandardError "$cipherGuestRun\no-process.stderr"
        Start-Sleep -Seconds 8
        Fetch 'noProcess' "$base/ok"
        $collector | Wait-Process -Timeout 45
        $results | ConvertTo-Json -Depth 4
    }
    $cipherResults | Set-Content -LiteralPath (Join-Path $Output 'client-results.json')
}
finally
{
    if ($cipherSession)
    {
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\capture.db" `
            -Destination (Join-Path $Output 'journal.db') -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\HttpSpy\capture.db" `
            -Destination (Join-Path $Output 'store.db') -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\no-process.db" `
            -Destination (Join-Path $Output 'no-process.db') -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\HttpSpy\no-process.db" `
            -Destination (Join-Path $Output 'no-process-store.db') -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\collector.stdout", `
            "$cipherGuestRun\collector.stderr", "$cipherGuestRun\certificates.log", "$cipherGuestRun\storage-recovery.log" `
            -Destination $Output -ErrorAction Continue
        Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun, $cipherThumbprint -ScriptBlock {
            param($cipherGuestRun, $cipherThumbprint)
            if ([IO.Path]::GetFullPath($cipherGuestRun) -notmatch '^C:\\Cipherazzi\\httpspy-[a-f0-9]{32}$')
            {
                throw 'Refusing cleanup outside the owned HTTP Spy lab directory.'
            }
            Set-Location $env:SystemRoot
            Get-CimInstance Win32_Process -Filter "Name='Cipherazzi.Collector.exe'" | Where-Object {
                $_.ExecutablePath -eq "$cipherGuestRun\Cipherazzi.Collector.exe"
            } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
            if ($cipherThumbprint) { Remove-Item "Cert:\LocalMachine\Root\$cipherThumbprint" -ErrorAction SilentlyContinue }

            # The driver loads from the run directory and keeps its file open until the service stops.
            $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'"
            if ($driver -and $driver.PathName -like "*$cipherGuestRun*")
            {
                sc.exe stop WinDivert | Out-Null
            }
            for ($attempt = 0; $attempt -lt 30 -and (Test-Path -LiteralPath $cipherGuestRun); ++$attempt)
            {
                Remove-Item -LiteralPath $cipherGuestRun -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $cipherGuestRun) { Start-Sleep -Seconds 1 }
            }
            if (Test-Path -LiteralPath $cipherGuestRun)
            {
                try { Remove-Item -LiteralPath $cipherGuestRun -Recurse -Force -ErrorAction Stop }
                catch { Write-Warning "The guest run directory remains: $($_.Exception.Message)" }
            }
        } -ErrorAction Continue
        Remove-PSSession $cipherSession
    }
    if ($cipherServerSession)
    {
        Invoke-Command -Session $cipherServerSession -ArgumentList $cipherServerRun -ScriptBlock {
            param($cipherDirectory)
            if ([IO.Path]::GetFullPath($cipherDirectory) -notmatch '^C:\\Cipherazzi\\httpspy-[a-f0-9]{32}$')
            {
                throw 'Refusing cleanup outside the owned HTTPS fixture directory.'
            }
            Get-CimInstance Win32_Process -Filter "Name='pwsh.exe'" | Where-Object {
                $_.CommandLine -like "*$cipherDirectory\HttpSpyServer.ps1*"
            } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
            Get-NetFirewallRule -DisplayName "Cipherazzi lab $cipherDirectory" -ErrorAction SilentlyContinue |
                Remove-NetFirewallRule
            Remove-Item -LiteralPath $cipherDirectory -Recurse -Force -ErrorAction SilentlyContinue
        } -ErrorAction Continue
        Remove-PSSession $cipherServerSession
    }
    if ($cipherServer -and !$cipherServer.HasExited) { Stop-Process -Id $cipherServer.Id }
    if ($cipherFirewall) { $cipherFirewall | Remove-NetFirewallRule }
    if ($cipherStartedVm) { Stop-VM -Id $cipherLab.id -Shutdown }
}

# The collector wrote the journal and the store inside the guest; judge them here, where Python is available.
& python.exe (Join-Path $PSScriptRoot 'Verify-HttpSpy.py') $Output $Port
if ($LASTEXITCODE) { throw 'HTTP Spy verification failed; inspect the copied lab artifacts.' }
Write-Output "HTTP Spy lab verification completed: $Output"

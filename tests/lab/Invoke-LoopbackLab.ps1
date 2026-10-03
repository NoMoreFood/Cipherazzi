param([string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$cipherPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$cipherPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw 'Loopback verification requires an elevated console for Hyper-V lab access and signed-driver activation.'
}
$cipherPayload = Join-Path $cipherRoot 'dist'
$cipherPublishingTests = Join-Path $cipherRoot '.work/loopback-lab-runner/Publishing.exe'
foreach ($cipherInput in @($cipherPublishingTests, (Join-Path $cipherPayload 'Cipherazzi.Collector.exe'),
    (Join-Path $cipherPayload 'Cipherazzi.Publisher.exe'),
    (Join-Path $cipherPayload 'CipherazziLoopback/WinDivert64.sys')))
{
    if (!(Test-Path -LiteralPath $cipherInput -PathType Leaf))
    {
        throw 'Build the current distribution and self-contained Publishing test runner before lab verification.'
    }
}
$cipherLab = Get-Content -LiteralPath (Join-Path $cipherRoot '.work/hyperv/lab.json') -Raw | ConvertFrom-Json
$cipherCredential = Import-Clixml -LiteralPath (Join-Path $cipherLab.root 'credential.xml')
$cipherRun = 'loopback-' + [Guid]::NewGuid().ToString('N')
if (!$Output) { $Output = Join-Path $cipherRoot ".work/$cipherRun" }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output | Out-Null
$cipherGuestRun = "C:\Cipherazzi\$cipherRun"
$cipherSession = $null
$cipherStartedVm = $false
try
{
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
    Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun -ScriptBlock {
        param($cipherGuestRun)
        if (Get-Process Cipherazzi.Collector -ErrorAction SilentlyContinue)
        {
            throw 'A lab collector is already running.'
        }
        if ((Get-Service Cipherazzi -ErrorAction SilentlyContinue) -or
            (Test-Path -LiteralPath "$env:SystemRoot\System32\Cipherazzi.Collector.exe") -or
            (Test-Path -LiteralPath "$env:SystemRoot\System32\CipherazziLoopback"))
        {
            throw 'Existing collector service or service payloads were left intact.'
        }
        New-Item -ItemType Directory -Path $cipherGuestRun | Out-Null
    }
    $cipherExecutable = Join-Path $cipherPayload 'Cipherazzi.Collector.exe'
    Copy-Item -LiteralPath $cipherExecutable -Destination "$cipherGuestRun\Cipherazzi.Collector.exe" `
        -ToSession $cipherSession
    Copy-Item -LiteralPath (Join-Path $cipherRoot 'build/bin/Release/Cipherazzi.Tests.exe') `
        -Destination "$cipherGuestRun\Cipherazzi.Tests.exe" -ToSession $cipherSession
    Copy-Item -LiteralPath (Join-Path $cipherPayload 'CipherazziLoopback') `
        -Destination $cipherGuestRun -ToSession $cipherSession -Recurse
    Copy-Item -LiteralPath (Join-Path $cipherRoot 'tests/LoopbackCapture.py') `
        -Destination "$cipherGuestRun\LoopbackCapture.py" -ToSession $cipherSession
    Copy-Item -LiteralPath (Join-Path $cipherPayload 'Cipherazzi.Publisher.exe') `
        -Destination "$cipherGuestRun\Cipherazzi.Publisher.exe" -ToSession $cipherSession
    Copy-Item -LiteralPath $cipherPublishingTests -Destination "$cipherGuestRun\Publishing.Tests.exe" `
        -ToSession $cipherSession
    $cipherOpenSsl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
    & $cipherOpenSsl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=loopback.lab' `
        -keyout "$Output/key.pem" -out "$Output/cert.pem" 2> "$Output/certificate.stderr"
    if ($LASTEXITCODE) { throw 'Loopback certificate generation failed.' }
    Copy-Item -LiteralPath "$Output/key.pem", "$Output/cert.pem" -Destination $cipherGuestRun -ToSession $cipherSession
    Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun -ScriptBlock {
        param($cipherGuestRun)
        $ErrorActionPreference = 'Stop'
        & "$cipherGuestRun\Cipherazzi.Tests.exe" --capture-lifecycle `
            1> "$cipherGuestRun\lifecycle.stdout" 2> "$cipherGuestRun\lifecycle.stderr"
        if ($LASTEXITCODE) { throw 'Capture lifecycle verification failed.' }
        & 'C:\Cipherazzi\python\python.exe' "$cipherGuestRun\LoopbackCapture.py" `
            --collector "$cipherGuestRun\Cipherazzi.Collector.exe" --certificate "$cipherGuestRun\cert.pem" `
            --key "$cipherGuestRun\key.pem" --output "$cipherGuestRun\results" `
            --with-service `
            1> "$cipherGuestRun\verification.stdout" 2> "$cipherGuestRun\verification.stderr"
        if ($LASTEXITCODE) { throw 'Live loopback verification failed; inspect the copied lab artifacts.' }
        & "$cipherGuestRun\Publishing.Tests.exe" "$cipherGuestRun\Cipherazzi.Publisher.exe" `
            "$cipherGuestRun\Cipherazzi.Collector.exe" "$cipherGuestRun\publishing-results" --windows-events `
            1> "$cipherGuestRun\publishing.stdout" 2> "$cipherGuestRun\publishing.stderr"
        if ($LASTEXITCODE) { throw 'Live Event Log verification failed; inspect the copied lab artifacts.' }
    }
}
finally
{
    if ($cipherSession)
    {
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\results", `
            "$cipherGuestRun\verification.stdout", "$cipherGuestRun\verification.stderr" `
            -Destination $Output -Recurse -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\lifecycle.stdout", `
            "$cipherGuestRun\lifecycle.stderr" -Destination $Output -ErrorAction Continue
        Copy-Item -FromSession $cipherSession -Path "$cipherGuestRun\publishing-results", `
            "$cipherGuestRun\publishing.stdout", "$cipherGuestRun\publishing.stderr" `
            -Destination $Output -Recurse -ErrorAction Continue
        Invoke-Command -Session $cipherSession -ArgumentList $cipherGuestRun -ScriptBlock {
            param($cipherGuestRun)
            $cipherService = Get-CimInstance Win32_Service -Filter "Name='Cipherazzi'"
            $cipherServiceCleanupFailed = $false
            if ($cipherService -and $cipherService.PathName.IndexOf($cipherGuestRun,
                [StringComparison]::OrdinalIgnoreCase) -ge 0)
            {
                & "$cipherGuestRun\Cipherazzi.Collector.exe" --uninstall
                $cipherServiceCleanupFailed = $LASTEXITCODE -ne 0
            }
            Get-CimInstance Win32_Process -Filter "Name='Cipherazzi.Collector.exe'" | Where-Object {
                $_.ExecutablePath -eq "$cipherGuestRun\Cipherazzi.Collector.exe"
            } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath "$cipherGuestRun\key.pem" -ErrorAction SilentlyContinue
            if ($cipherServiceCleanupFailed) { throw 'The owned loopback lab service could not be removed.' }
        } -ErrorAction Continue
        Remove-PSSession $cipherSession
    }
    Remove-Item -LiteralPath "$Output/key.pem" -ErrorAction SilentlyContinue
    if ($cipherStartedVm) { Stop-VM -Id $cipherLab.id -Shutdown }
}
Write-Output "Loopback lab verification completed: $Output"

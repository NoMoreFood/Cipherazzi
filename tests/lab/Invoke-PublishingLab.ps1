param([string]$Output)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$lab = Get-Content "$cipherRoot\.work\hyperv\lab.json" -Raw | ConvertFrom-Json
$credential = Import-Clixml -LiteralPath (Join-Path $lab.root 'credential.xml')
$run = 'publishing-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
if (!$Output) { $Output = "$cipherRoot\.work\$run" }
if (![IO.Path]::IsPathRooted($Output)) { $Output = Join-Path $cipherRoot $Output }
$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $Output | Out-Null
$guestRun = "C:\Cipherazzi\$run"
$session = $null
$startedVm = $false
try
{
    # Preserve the lab's power state and use a dedicated run directory.
    $vm = Get-VM -Id $lab.id
    if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
    if ($vm.State -eq 'Off') { Start-VM -VM $vm; $startedVm = $true }
    for ($attempt = 0; $attempt -lt 90; ++$attempt)
    {
        try { $session = New-PSSession -VMId $lab.id -Credential $credential; break }
        catch { Start-Sleep -Seconds 1 }
    }
    if (!$session) { throw 'The lab VM did not become ready.' }
    Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        New-Item -ItemType Directory -Path $guestRun | Out-Null
    }
    foreach ($file in 'Cipherazzi.Collector.exe', 'Cipherazzi.Publisher.exe')
    {
        Copy-Item -LiteralPath "$cipherRoot\dist\$file" -Destination "$guestRun\$file" -ToSession $session
    }
    Copy-Item -LiteralPath "$cipherRoot\.work\publishing-check\test-tool\Publishing.exe" `
        -Destination "$guestRun\Publishing.exe" -ToSession $session

    # Replay exercises output without enabling live capture or changing trust roots.
    $result = Invoke-Command -Session $session -ArgumentList $guestRun -ScriptBlock {
        param($guestRun)
        $ErrorActionPreference = 'Stop'
        $process = Start-Process "$guestRun\Publishing.exe" -ArgumentList `
            "$guestRun\Cipherazzi.Publisher.exe", "$guestRun\Cipherazzi.Collector.exe", `
            "$guestRun\results", '--windows-events' -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput "$guestRun\tests.out" -RedirectStandardError "$guestRun\tests.err"
        try
        {
            if (!$process.WaitForExit(180000)) { throw 'The publishing test process did not stop.' }
            [pscustomobject]@{ ExitCode = $process.ExitCode; Computer = $env:COMPUTERNAME }
        }
        finally { if (!$process.HasExited) { Stop-Process -Id $process.Id } }
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath "$Output\lab.json" -Encoding UTF8
    if ($result.ExitCode) { throw 'Publishing verification failed in the lab VM; inspect the copied results.' }
}
finally
{
    if ($session)
    {
        Copy-Item -Path "$guestRun\results", "$guestRun\tests.out", "$guestRun\tests.err" `
            -Destination $Output -FromSession $session -Recurse -Force -ErrorAction Continue
        Remove-PSSession $session
    }
    if ($startedVm) { Stop-VM -VM $vm }
}

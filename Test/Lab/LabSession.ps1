# Starts the dedicated lab VM when it is off and waits for a remoting session. Started reports whether this run
# powered the VM on, so the caller can restore its state; a VM started here is stopped again if no session opens.
function Open-LabSession($Lab, [pscredential]$Credential)
{
    $vm = Get-VM -Id $Lab.id
    if ($vm.Name -ne $Lab.name) { throw 'The lab VM identity does not match.' }
    $started = $vm.State -eq 'Off'
    if ($started) { Start-VM -VM $vm }
    for ($attempt = 0; $attempt -lt 90; ++$attempt)
    {
        try
        {
            $session = New-PSSession -VMId $Lab.id -Credential $Credential
            return [pscustomobject]@{ Vm = $vm; Session = $session; Started = $started }
        }
        catch { Start-Sleep -Seconds 1 }
    }
    if ($started) { Stop-VM -VM $vm -Force }
    throw 'The lab VM did not become ready.'
}

# Keep the OpenSSL runtime local to the disposable test tools and fail before starting capture.
function Copy-LabOpenSsl([string]$Source, [string]$Destination, $Session)
{
    Invoke-Command -Session $Session -ArgumentList $Destination -ScriptBlock {
        param($Destination)
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }
    Copy-Item -Path (Join-Path $Source '*') -Destination $Destination -Recurse -Force -ToSession $Session
    if (-not (Test-Path -LiteralPath (Join-Path $Source 'vcruntime140.dll')))
    {
        Copy-Item -LiteralPath "$env:SystemRoot\System32\vcruntime140.dll" `
            -Destination $Destination -ToSession $Session
    }
    Invoke-Command -Session $Session -ArgumentList $Destination -ScriptBlock {
        param($Destination)
        $process = Start-Process "$Destination\openssl.exe" -ArgumentList 'version' -WindowStyle Hidden `
            -PassThru -RedirectStandardOutput "$Destination\version.stdout" `
            -RedirectStandardError "$Destination\version.stderr"
        $null = $process.Handle
        try
        {
            if (-not $process.WaitForExit(10000)) { throw 'The OpenSSL runtime check timed out.' }
            if ($process.ExitCode) { throw "OpenSSL could not load its runtime (exit $($process.ExitCode))." }
        }
        finally
        {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
}

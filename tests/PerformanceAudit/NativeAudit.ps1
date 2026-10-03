param([string]$Executable, [string]$Pcap, [string]$LocalDirectory, [string]$WorkspaceDirectory)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $LocalDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $WorkspaceDirectory -Force | Out-Null
$localExecutable=Join-Path $LocalDirectory 'Cipherazzi.Collector.exe'
$localPcap=Join-Path $LocalDirectory 'load.pcap'
Copy-Item -LiteralPath $Executable -Destination $localExecutable
Copy-Item -LiteralPath $Pcap -Destination $localPcap
$results=@()

# Compare storage locations with the same executable and input, including CPU and peak memory.
foreach ($location in @('local','workspace'))
{
    for ($iteration=0; $iteration -lt 3; ++$iteration)
    {
        $directory=if ($location -eq 'local') {$LocalDirectory} else {$WorkspaceDirectory}
        $database=Join-Path $directory ('native-' + $iteration + '-' + [guid]::NewGuid().ToString('N') + '.db')
        $stdout=$database + '.stdout'
        $stderr=$database + '.stderr'
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $arguments='--replay "' + $localPcap + '" --db "' + $database + '"'
        $process=Start-Process -FilePath $localExecutable -ArgumentList $arguments -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $null=$process.Handle
        $peakWorkingSet=0L
        while (!$process.HasExited -and $watch.ElapsedMilliseconds -lt 60000)
        {
            $process.Refresh()
            $peakWorkingSet=[Math]::Max($peakWorkingSet,$process.WorkingSet64)
            Start-Sleep -Milliseconds 10
        }
        if (!$process.HasExited)
        {
            $process.Kill()
            throw 'Collector replay exceeded its deadline.'
        }
        $process.WaitForExit()
        $process.Refresh()
        $results+=@{location=$location; iteration=$iteration; elapsed_ms=$watch.Elapsed.TotalMilliseconds;
            cpu_ms=$process.TotalProcessorTime.TotalMilliseconds; sampled_peak_working_set_bytes=$peakWorkingSet;
            exit_code=$process.ExitCode; output=(Get-Content -LiteralPath $stdout); errors=(Get-Content -LiteralPath $stderr)}
        $process.Dispose()
        if ($results[-1].exit_code -ne 0) {throw 'Collector replay failed.'}
    }
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $WorkspaceDirectory 'native-storage-audit.json')

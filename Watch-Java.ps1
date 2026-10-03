param(
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$ProcessId,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$JavaHome = $env:JAVA_HOME,
    [ValidateRange(2, 60)][int]$IntervalSeconds = 5,
    [ValidateRange(0, 86400)][int]$DurationSeconds = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $JavaHome)
{
    $JavaHome = Split-Path (Split-Path (Get-Command jcmd.exe -ErrorAction Stop).Source)
}
$javaCommand = Join-Path $JavaHome 'bin/jcmd.exe'
$javaRecorder = Join-Path $JavaHome 'bin/jfr.exe'
if (-not (Test-Path -LiteralPath $javaCommand) -or -not (Test-Path -LiteralPath $javaRecorder))
{
    throw 'Choose a JDK directory containing jcmd.exe and jfr.exe.'
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$recordingName = 'Cipherazzi-' + [Guid]::NewGuid().ToString('N')
$stage = Join-Path $outputRoot $recordingName
New-Item -ItemType Directory -Path $stage | Out-Null
$settings = Join-Path $stage 'security.jfc'
$recording = Join-Path $stage 'security.jfr'
$export = Join-Path $stage 'events.json'
$commandFile = Join-Path $stage 'command.txt'
$destination = Join-Path $outputRoot "jfr-$ProcessId.json"
$encoding = [Text.UTF8Encoding]::new($false)
$configuration = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration version="2.0" label="Cipherazzi" description="TLS and certificate metadata" provider="Cipherazzi">
  <event name="jdk.TLSHandshake"><setting name="enabled">true</setting><setting name="stackTrace">false</setting></event>
  <event name="jdk.X509Certificate"><setting name="enabled">true</setting><setting name="stackTrace">false</setting></event>
  <event name="jdk.X509Validation"><setting name="enabled">true</setting><setting name="stackTrace">false</setting></event>
</configuration>
'@
[IO.File]::WriteAllText($settings, $configuration, $encoding)
$started = $false
$javaProcess = Get-Process -Id $ProcessId -ErrorAction Stop
$javaExecutable = [string]$javaProcess.Path
$javaName = if ($javaExecutable) { [IO.Path]::GetFileName($javaExecutable) } else { $javaProcess.ProcessName }
$javaStartedUs = ([DateTimeOffset]$javaProcess.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() * 1000
$watch = [Diagnostics.Stopwatch]::StartNew()
function Invoke-Jfr([string]$Command)
{
    # Let jcmd parse quoted paths from a command file instead of rebuilding native arguments.
    [IO.File]::WriteAllText($commandFile, $Command, $encoding)
    $result = & $javaCommand $ProcessId -f $commandFile
    if ($LASTEXITCODE) { throw 'The JVM rejected the diagnostic command.' }
    return $result
}
try
{
    # Attach only to the requested JVM and keep its other recordings intact.
    Invoke-Jfr ('JFR.start name=' + $recordingName + ' settings="' + $settings + '" maxage=30s maxsize=16m')
    $check = Invoke-Jfr "JFR.check name=$recordingName"
    if (($check -join ' ') -notmatch [regex]::Escape("name=$recordingName"))
    {
        throw 'The JVM did not start the recording. Use the same account as the JVM.'
    }
    $started = $true
    while (($currentProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue) -and
        $currentProcess.StartTime -eq $javaProcess.StartTime)
    {
        Start-Sleep -Seconds $IntervalSeconds
        $currentProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $currentProcess -or $currentProcess.StartTime -ne $javaProcess.StartTime) { break }
        if (Test-Path -LiteralPath $recording) { Remove-Item -LiteralPath $recording }
        Invoke-Jfr ('JFR.dump name=' + $recordingName + ' filename="' + $recording + '"') | Out-Null
        if (-not (Test-Path -LiteralPath $recording)) { throw 'The JVM recording could not be read.' }
        $eventNames = 'jdk.TLSHandshake,jdk.X509Certificate,jdk.X509Validation'
        & $javaRecorder print --json --events $eventNames $recording |
            Set-Content -LiteralPath $export -Encoding UTF8
        if ($LASTEXITCODE) { throw 'The JFR recording could not be exported.' }
        $payload = Get-Content -LiteralPath $export -Raw | ConvertFrom-Json
        $payload | Add-Member -NotePropertyName pid -NotePropertyValue $ProcessId
        $payload | Add-Member -NotePropertyName process_started_us -NotePropertyValue $javaStartedUs
        $payload | Add-Member -NotePropertyName process_name -NotePropertyValue $javaName
        $payload | Add-Member -NotePropertyName process_path -NotePropertyValue $javaExecutable
        $temporary = $destination + '.tmp'
        [IO.File]::WriteAllText($temporary, ($payload | ConvertTo-Json -Depth 32 -Compress), $encoding)
        if (Test-Path -LiteralPath $destination)
        {
            [IO.File]::Replace($temporary, $destination, (Join-Path $stage 'previous.json'))
        }
        else { [IO.File]::Move($temporary, $destination) }
        if ($DurationSeconds -and $watch.Elapsed.TotalSeconds -ge $DurationSeconds) { break }
    }
}
finally
{
    $currentProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($started -and $currentProcess -and $currentProcess.StartTime -eq $javaProcess.StartTime)
    {
        Invoke-Jfr "JFR.stop name=$recordingName" | Out-Null
    }
    # Remove only this invocation's staging files; retain the final export for restart-safe ingestion.
    $resolvedStage = [IO.Path]::GetFullPath($stage)
    if ($resolvedStage.StartsWith($outputRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase))
    {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}

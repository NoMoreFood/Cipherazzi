param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$UiTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$native = Join-Path $cipherRoot "tools/artifacts/build/bin/$Configuration"
$managed = Join-Path $cipherRoot 'tools/artifacts/build/managed/bin'
$configurationFolder = $Configuration.ToLowerInvariant()
$output = Join-Path $cipherRoot ('tools/artifacts/work/checks-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $output | Out-Null

function Check([string]$Executable, [string[]]$Arguments)
{
    & $Executable @Arguments
    if ($LASTEXITCODE) { throw "Check failed: $Executable $Arguments" }
}

# Build realistic offline journals through the collector and use fresh outputs for every check.
$python = (Get-Command python -ErrorAction Stop).Source
Check (Join-Path $native 'Cipherazzi.Tests.exe') @()
Check $python @((Join-Path $cipherRoot 'tests/integration/CollectorLifecycle.py'),
    (Join-Path $native 'Cipherazzi.Collector.exe'), (Join-Path $output 'collector-lifecycle'))
$endpoint = Join-Path $output 'endpoints.db'
$negotiation = Join-Path $output 'negotiations.db'
$migration = Join-Path $output 'migration.db'
$pcap = Join-Path $output 'negotiations.pcap'
Check (Join-Path $native 'Cipherazzi.Tests.exe') @('--endpoint-integration', $endpoint)
Check $python @((Join-Path $cipherRoot 'tests/integration/NegotiationFixture.py'), $pcap)
Check (Join-Path $native 'Cipherazzi.Collector.exe') @('--replay', $pcap, '--db', $negotiation)
Check $python @((Join-Path $cipherRoot 'tests/integration/MigrationFixture.py'), $endpoint, $migration,
    '--certificate-source', $negotiation, '--count', '1000')
$httpSpy = Join-Path $output 'httpspy'
Check $python @((Join-Path $cipherRoot 'tests/integration/HttpSpy.py'),
    '--collector', (Join-Path $native 'Cipherazzi.Collector.exe'), '--output', $httpSpy)
Check (Join-Path $native 'Cipherazzi.Tests.exe') @('--live-keylog', (Join-Path $httpSpy 'httpspy.pcap'),
    (Join-Path $httpSpy 'secrets.log'))
$database = Join-Path $managed "DatabaseLab/$configurationFolder/DatabaseLab.exe"
Check $database @('--endpoint-evidence', $endpoint, (Join-Path $output 'endpoints'), '--local')
Check $database @('--protocol-policies', $endpoint, (Join-Path $output 'policies'))
Check $database @('--protocol-recovery', $migration, (Join-Path $output 'protocol-recovery'))
Check $database @('--data-stress', $endpoint, (Join-Path $output 'data'))
Check $database @('--certificate-metadata', $migration, (Join-Path $output 'certificate-metadata'))
Check $database @('--migration', $migration, (Join-Path $output 'migration'))
Check $database @('--investigation', $migration, (Join-Path $output 'investigation'))
Check $database @('--report-recovery', $migration, (Join-Path $output 'report-recovery'))
Check $database @('--endpoint-recovery', $migration, (Join-Path $output 'endpoint-recovery'))
Check $database @('--sqlite-stress', $migration, (Join-Path $output 'sqlite'))
Check (Join-Path $managed "Publishing/$configurationFolder/Publishing.exe") @(
    (Join-Path $managed "Cipherazzi.Publisher/$configurationFolder/Cipherazzi.Publisher.exe"),
    (Join-Path $native 'Cipherazzi.Collector.exe'), (Join-Path $output 'publishing'))

# Exercise live refresh, protocol rendering, and scaled layouts without touching user settings or live capture.
if ($UiTests)
{
    $viewer = Join-Path $managed "Cipherazzi.UiTests/$configurationFolder/Cipherazzi.UiTests.exe"
    Check $viewer @($migration, (Join-Path $output 'ui'))
    Check $viewer @('--refresh-ui', $migration, (Join-Path $output 'refresh-ui'))
    Check $viewer @('--protocol-ui', $negotiation, (Join-Path $output 'protocol-ui'), '--negotiation')
    Check $viewer @('--performance-ui', $endpoint, (Join-Path $output 'endpoint-ui'))
    Check $viewer @('--httpspy-ui', (Join-Path $httpSpy 'secrets.db'), (Join-Path $output 'httpspy-ui'))
    Check $viewer @('--collector-ui', (Join-Path $native 'Cipherazzi.Collector.exe'), $httpSpy,
        (Join-Path $output 'collector-ui'), $migration)
    Check $viewer @('--migration-ui', $migration, (Join-Path $output 'migration-ui'))
    Check $viewer @('--configuration-ui', $migration, (Join-Path $output 'configuration-ui'))
    Check $viewer @('--source-ui', $migration, (Join-Path $output 'source-ui'))
    Check $viewer @('--layout-audit', $migration, (Join-Path $output 'layout'))
}
Write-Host "Verification results: $output"

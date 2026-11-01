param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ProductVersion = '1.0.0',
    [ValidateSet('true', 'false')][string]$SignArtifacts = 'false'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = Split-Path $PSScriptRoot
$cipherBuild = [IO.Path]::GetFullPath((Join-Path $cipherRoot 'Build/Temp'))
$cipherStage = [IO.Path]::GetFullPath((Join-Path $cipherBuild "package/$Configuration"))
if (!$cipherStage.StartsWith("$cipherBuild\", [StringComparison]::OrdinalIgnoreCase))
{
    throw 'The package destination is outside the build directory.'
}
if (Test-Path -LiteralPath $cipherStage) { Remove-Item -LiteralPath $cipherStage -Recurse -Force }
New-Item -ItemType Directory -Force $cipherStage | Out-Null

# Publish each application into an isolated directory before collecting the installer payload.
foreach ($cipherApplication in @('Viewer', 'Relay', 'Publisher'))
{
    $cipherProject = Join-Path $cipherRoot "Source/$cipherApplication/Cipherazzi.$cipherApplication.csproj"
    $cipherPublish = Join-Path $cipherBuild "publish/$Configuration/$cipherApplication"
    dotnet publish $cipherProject -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -p:DebugSymbols=false "-p:ProductVersion=$ProductVersion" -o $cipherPublish
    if ($LASTEXITCODE) { throw "$cipherApplication publishing failed." }
    Copy-Item -LiteralPath (Join-Path $cipherPublish "Cipherazzi.$cipherApplication.exe") -Destination $cipherStage
}
Copy-Item -LiteralPath (Join-Path $cipherBuild "publish/$Configuration/Viewer/Cipherazzi.Viewer.config") `
    -Destination $cipherStage
Copy-Item -LiteralPath (Join-Path $cipherBuild "bin/$Configuration/Cipherazzi.Collector.exe") `
    -Destination $cipherStage
Copy-Item -LiteralPath (Join-Path $cipherBuild "bin/$Configuration/CipherazziLoopback") `
    -Destination $cipherStage -Recurse
foreach ($cipherFile in @('Source/Collector/EndpointReport.schema.json', 'Source/Publisher/Event.schema.json'))
{
    Copy-Item -LiteralPath (Join-Path $cipherRoot $cipherFile) -Destination $cipherStage
}
Copy-Item -Path (Join-Path $cipherRoot 'Source/Deployment/*.example.json') -Destination $cipherStage
if ($SignArtifacts -eq 'true')
{
    $cipherSignFiles = @((Get-ChildItem -LiteralPath $cipherStage -Filter 'Cipherazzi.*.exe').FullName)
    & (Join-Path $PSScriptRoot 'Sign.ps1') -Path $cipherSignFiles
}

# Expose the same signed payload beside the MSI for portable deployment.
$cipherDistribution = Join-Path $cipherRoot 'Build/Output'
New-Item -ItemType Directory -Force $cipherDistribution | Out-Null
Get-ChildItem -LiteralPath $cipherStage | Copy-Item -Destination $cipherDistribution -Recurse -Force

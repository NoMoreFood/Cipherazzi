param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [ValidateRange(0, 64)][int]$NativeJobs = 0,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ProductVersion = '1.0.0',
    [switch]$Sign,
    [switch]$SkipTests,
    [switch]$UiTests,
    [switch]$Rebuild,
    [switch]$Publish,
    [switch]$Installer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Sign -and !$Publish -and !$Installer) { throw 'Use -Sign with -Publish or -Installer.' }
$cipherRoot = $PSScriptRoot
$cipherVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (!(Test-Path -LiteralPath $cipherVswhere)) { throw 'Visual Studio 2026 or its Build Tools are required.' }
$cipherVs = & $cipherVswhere -latest -products * -version '[18.0,19.0)' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$cipherVs) { throw 'Install the Visual Studio 2026 C++ workload and Windows SDK.' }
$cipherMsbuild = Join-Path $cipherVs 'MSBuild/Current/Bin/amd64/MSBuild.exe'
$cipherJobs = $NativeJobs
if (!$cipherJobs)
{
    $cipherMemory = Get-CimInstance Win32_OperatingSystem
    $cipherAvailable = [Math]::Min($cipherMemory.FreePhysicalMemory, $cipherMemory.FreeVirtualMemory) * 1024
    $cipherJobs = [int][Math]::Max(1, [Math]::Min([Environment]::ProcessorCount,
        [Math]::Floor($cipherAvailable / 2GB)))
}

# Build the applications and checks before optional publishing and packaging.
$cipherTarget = if ($Rebuild) { 'Rebuild' } else { 'Build' }
$cipherSigning = $Sign.IsPresent.ToString().ToLowerInvariant()
Write-Host "Building Cipherazzi $ProductVersion ($Configuration, signing $cipherSigning)..."
& $cipherMsbuild (Join-Path $cipherRoot 'Cipherazzi.slnx') /restore "/t:$cipherTarget" "/m:$cipherJobs" `
    /nologo /verbosity:minimal "/p:Configuration=$Configuration" /p:Platform=x64 `
    "/p:ProductVersion=$ProductVersion" "/p:SignArtifacts=$cipherSigning" `
    /p:PreferredToolArchitecture=x64 /p:CL_MPCount=1
if ($LASTEXITCODE) { throw 'The solution build failed.' }

# Run local data checks by default; visual checks also require an interactive Windows desktop.
if (!$SkipTests)
{
    & (Join-Path $cipherRoot 'tools/build/Verify.ps1') -Configuration $Configuration -UiTests:$UiTests
}
if ($Installer)
{
    & $cipherMsbuild (Join-Path $cipherRoot 'tools/installer/Cipherazzi.Installer.wixproj') /restore /t:Build `
        "/m:$cipherJobs" /nologo /verbosity:minimal "/p:Configuration=$Configuration" /p:Platform=x64 `
        "/p:ProductVersion=$ProductVersion" "/p:SignArtifacts=$cipherSigning" `
        /p:PreferredToolArchitecture=x64 /p:CL_MPCount=1
    if ($LASTEXITCODE) { throw 'The installer build failed.' }
    if (!$SkipTests)
    {
        & python (Join-Path $cipherRoot 'tests/integration/Installer.py') `
            (Join-Path $cipherRoot 'tools/artifacts/dist/Cipherazzi-win-x64.msi') `
            (Join-Path $cipherRoot "tools/artifacts/build/package/$Configuration") `
            (Join-Path $cipherRoot 'tools/artifacts/work/installer-checks')
        if ($LASTEXITCODE) { throw 'Installer checks failed.' }
    }
    Write-Host "Installer: $cipherRoot\tools\artifacts\dist\Cipherazzi-win-x64.msi"
}
elseif ($Publish)
{
    & (Join-Path $cipherRoot 'tools/build/Package.ps1') -Configuration $Configuration `
        -ProductVersion $ProductVersion -SignArtifacts $cipherSigning
    Write-Host "Published applications: $cipherRoot\tools\artifacts\dist"
}
Write-Host "Build complete ($Configuration)."

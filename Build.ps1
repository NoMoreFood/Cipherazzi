param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Publish,
    [switch]$Installer,
    [ValidateRange(0, 64)][int]$NativeJobs = 0,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ProductVersion = '1.0.0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = $PSScriptRoot
$cipherCmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cipherCmake)
{
    $cipherCmakePath = $cipherCmake.Source
}
else
{
    $cipherVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $cipherVs = & $cipherVswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $cipherCmakePath = Join-Path $cipherVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}

& $cipherCmakePath -S $cipherRoot -B "$cipherRoot/build" -G 'Visual Studio 18 2026' -A x64 `
    -DBUILD_TESTING=ON -DCIPHERAZZI_ENDPOINT_ADAPTER=ON "-DCIPHERAZZI_VERSION=$ProductVersion"
if ($LASTEXITCODE) { throw 'CMake configuration failed.' }
$cipherNativeJobs = $NativeJobs
if (!$cipherNativeJobs)
{
    $cipherMemory = Get-CimInstance Win32_OperatingSystem
    $cipherAvailable = [Math]::Min($cipherMemory.FreePhysicalMemory, $cipherMemory.FreeVirtualMemory) * 1024
    $cipherNativeJobs = [int][Math]::Max(1, [Math]::Min([Environment]::ProcessorCount,
        [Math]::Floor($cipherAvailable / 2GB)))
}
& $cipherCmakePath --build "$cipherRoot/build" --config $Configuration --parallel $cipherNativeJobs -- `
    /p:PreferredToolArchitecture=x64 "/p:MultiProcMaxCount=$cipherNativeJobs" "/p:CL_MPCount=$cipherNativeJobs"
if ($LASTEXITCODE) { throw 'Native build failed.' }
& (Join-Path (Split-Path $cipherCmakePath) 'ctest.exe') --test-dir "$cipherRoot/build" -C $Configuration --output-on-failure
if ($LASTEXITCODE) { throw 'Native checks failed.' }
dotnet build "$cipherRoot/viewer/Cipherazzi.Viewer.csproj" -c $Configuration `
    -p:Version=$ProductVersion
if ($LASTEXITCODE) { throw 'Viewer build failed.' }
dotnet build "$cipherRoot/relay/Cipherazzi.Relay.csproj" -c $Configuration -p:Version=$ProductVersion
if ($LASTEXITCODE) { throw 'Relay build failed.' }
dotnet build "$cipherRoot/publisher/Cipherazzi.Publisher.csproj" -c $Configuration -p:Version=$ProductVersion
if ($LASTEXITCODE) { throw 'Publisher build failed.' }

if ($Publish -or $Installer)
{
    New-Item -ItemType Directory -Force "$cipherRoot/dist" | Out-Null
    Copy-Item -LiteralPath "$cipherRoot/build/bin/$Configuration/Cipherazzi.Collector.exe" -Destination "$cipherRoot/dist/"
    New-Item -ItemType Directory -Force "$cipherRoot/dist/CipherazziLoopback" | Out-Null
    Copy-Item -LiteralPath "$cipherRoot/build/bin/$Configuration/CipherazziLoopback/WinDivert.dll", `
        "$cipherRoot/build/bin/$Configuration/CipherazziLoopback/WinDivert64.sys", `
        "$cipherRoot/build/bin/$Configuration/CipherazziLoopback/LICENSE" -Destination "$cipherRoot/dist/CipherazziLoopback/"
    Copy-Item -LiteralPath "$cipherRoot/build/bin/$Configuration/Cipherazzi.EndpointAdapter.exe" -Destination "$cipherRoot/dist/"
    Copy-Item -LiteralPath "$cipherRoot/adapters/Frida.COPYING", "$cipherRoot/adapters/Frida.COPYING.LIB" `
        -Destination "$cipherRoot/dist/"
    Copy-Item -LiteralPath "$cipherRoot/collector/EndpointReport.schema.json" -Destination "$cipherRoot/dist/"
    Copy-Item -LiteralPath "$cipherRoot/publisher/Event.schema.json" -Destination "$cipherRoot/dist/"
    Copy-Item -LiteralPath "$cipherRoot/Watch-Java.ps1" -Destination "$cipherRoot/dist/"
    Copy-Item -Path "$cipherRoot/deployment/*.example.json" -Destination "$cipherRoot/dist/"
    dotnet publish "$cipherRoot/viewer/Cipherazzi.Viewer.csproj" -c $Configuration -r win-x64 `
        --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -p:DebugSymbols=false -p:Version=$ProductVersion -o "$cipherRoot/dist"
    if ($LASTEXITCODE) { throw 'Viewer publishing failed.' }
    dotnet publish "$cipherRoot/relay/Cipherazzi.Relay.csproj" -c $Configuration -r win-x64 `
        --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -p:DebugSymbols=false -p:Version=$ProductVersion -o "$cipherRoot/dist"
    if ($LASTEXITCODE) { throw 'Relay publishing failed.' }
    dotnet publish "$cipherRoot/publisher/Cipherazzi.Publisher.csproj" -c $Configuration -r win-x64 `
        --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:DebugType=None -p:DebugSymbols=false -p:Version=$ProductVersion -o "$cipherRoot/dist"
    if ($LASTEXITCODE) { throw 'Publisher publishing failed.' }
}

if ($Installer)
{
    dotnet build "$cipherRoot/installer/Cipherazzi.Installer.wixproj" -c $Configuration `
        -p:ProductVersion=$ProductVersion "-p:PayloadDirectory=$cipherRoot/dist" "-p:OutputPath=$cipherRoot/dist/"
    if ($LASTEXITCODE) { throw 'Installer build failed.' }
}

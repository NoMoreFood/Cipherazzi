param([string]$LoopbackOutput)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = Split-Path (Split-Path $PSScriptRoot)
$cipherDependencies = Join-Path $cipherRoot 'tools/artifacts/build/dependencies'
$cipherArchives = Join-Path $cipherDependencies 'archives'
New-Item -ItemType Directory -Force $cipherArchives | Out-Null

# Pin source archives and verify their contents before making them available to the compiler.
$cipherPackages = @(
    @('sqlite', 'https://www.sqlite.org/2026/sqlite-amalgamation-3540000.zip',
        '68e913b0fe8ec6b4e5f391c594a28872884e80d6cd042a1e50c957be46b5aa4d', 'sqlite-amalgamation-3540000'),
    @('json', 'https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz',
        '42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa', 'json'),
    @('windivert', 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip',
        '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15', 'WinDivert-2.2.2-A'),
    @('nghttp2', 'https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz',
        'e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2', 'nghttp2-1.70.0'),
    @('frida',
        'https://github.com/frida/frida/releases/download/17.23.3/frida-core-devkit-17.23.3-windows-x86_64.tar.xz',
        '38c8f04ac2c3c7ce06c5511bae3ca2b7c9b7ccc1205108ee9b3bf2740d70e06b', '.')
)
foreach ($cipherPackage in $cipherPackages)
{
    $cipherName, $cipherUrl, $cipherHash, $cipherFolder = $cipherPackage
    $cipherDestination = Join-Path $cipherDependencies $cipherName
    $cipherStamp = Join-Path $cipherDestination '.archive.sha256'
    if ((Test-Path -LiteralPath $cipherStamp) -and
        (Get-Content -LiteralPath $cipherStamp -Raw).Trim() -eq $cipherHash)
    {
        continue
    }
    $cipherArchive = Join-Path $cipherArchives ([Uri]$cipherUrl).Segments[-1]
    if (!(Test-Path -LiteralPath $cipherArchive))
    {
        Write-Host "Downloading $cipherName..."
        Invoke-WebRequest -Uri $cipherUrl -OutFile "$cipherArchive.download"
        Move-Item -LiteralPath "$cipherArchive.download" -Destination $cipherArchive -Force
    }
    if ((Get-FileHash -LiteralPath $cipherArchive -Algorithm SHA256).Hash -ne $cipherHash)
    {
        throw "Dependency hash mismatch: $cipherArchive"
    }

    # Extract into a fresh sibling and replace only this dependency's generated directory.
    $cipherTemporary = Join-Path $cipherDependencies "$cipherName.extract"
    foreach ($cipherPath in @($cipherTemporary, $cipherDestination))
    {
        $cipherResolved = [IO.Path]::GetFullPath($cipherPath)
        if (![IO.Path]::GetDirectoryName($cipherResolved).Equals(
            [IO.Path]::GetFullPath($cipherDependencies), [StringComparison]::OrdinalIgnoreCase))
        {
            throw 'The dependency destination is outside the build directory.'
        }
        if (Test-Path -LiteralPath $cipherResolved)
        {
            Remove-Item -LiteralPath $cipherResolved -Recurse -Force
        }
    }
    New-Item -ItemType Directory $cipherTemporary | Out-Null
    & tar.exe -xf $cipherArchive -C $cipherTemporary
    if ($LASTEXITCODE) { throw "Dependency extraction failed: $cipherName" }
    if ($cipherFolder -eq '.')
    {
        Move-Item -LiteralPath $cipherTemporary -Destination $cipherDestination
    }
    else
    {
        Move-Item -LiteralPath (Join-Path $cipherTemporary $cipherFolder) -Destination $cipherDestination
        Remove-Item -LiteralPath $cipherTemporary
    }
    Set-Content -LiteralPath $cipherStamp -Value $cipherHash -Encoding ascii
}

# Generate the upstream version header; Windows platform features are supplied by the native project.
$cipherVersionTemplate = Join-Path $cipherDependencies 'nghttp2/lib/includes/nghttp2/nghttp2ver.h.in'
$cipherVersionHeader = $cipherVersionTemplate -replace '\.in$', ''
$cipherVersionText = (Get-Content -LiteralPath $cipherVersionTemplate -Raw).
    Replace('@PACKAGE_VERSION@', '1.70.0').Replace('@PACKAGE_VERSION_NUM@', '0x014600')
if (!(Test-Path -LiteralPath $cipherVersionHeader) -or
    (Get-Content -LiteralPath $cipherVersionHeader -Raw) -ne $cipherVersionText)
{
    [IO.File]::WriteAllText($cipherVersionHeader, $cipherVersionText)
}

if ($LoopbackOutput)
{
    # Leave an identical loaded driver in place even when archive timestamps differ.
    New-Item -ItemType Directory -Force $LoopbackOutput | Out-Null
    foreach ($cipherFile in @('x64/WinDivert.dll', 'x64/WinDivert64.sys', 'LICENSE'))
    {
        $cipherSource = Join-Path $cipherDependencies "windivert/$cipherFile"
        $cipherTarget = Join-Path $LoopbackOutput ([IO.Path]::GetFileName($cipherFile))
        if ((Test-Path -LiteralPath $cipherTarget) -and
            (Get-FileHash -LiteralPath $cipherSource).Hash -eq (Get-FileHash -LiteralPath $cipherTarget).Hash)
        {
            continue
        }
        Copy-Item -LiteralPath $cipherSource -Destination $cipherTarget -Force
    }
}

param([string]$LoopbackOutput)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = Split-Path $PSScriptRoot
$cipherDependencies = Join-Path $cipherRoot 'Build/Temp/dependencies'
$cipherArchives = Join-Path $cipherDependencies 'archives'
New-Item -ItemType Directory -Force $cipherArchives | Out-Null

# Pin source archives and verify their contents before making them available to the compiler.
$cipherPackages = @(
    @('sqlite', 'https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip',
        '0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9', 'sqlite-amalgamation-3540100'),
    @('windivert', 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip',
        '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15', 'WinDivert-2.2.2-A')
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
    # Fresh source files must invalidate compiler outputs even when the archive contains older timestamps.
    $cipherRestored = [DateTime]::UtcNow
    Get-ChildItem -LiteralPath $cipherDestination -File -Recurse | ForEach-Object {
        $_.LastWriteTimeUtc = $cipherRestored
    }
    Set-Content -LiteralPath $cipherStamp -Value $cipherHash -Encoding ascii
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

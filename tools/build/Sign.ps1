param(
    [Parameter(Mandatory)][string[]]$Path,
    [ValidateNotNullOrEmpty()][string]$TimestampUrl = 'http://time.certum.pl/',
    [switch]$MachineStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherKits = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
$cipherSignTool = Get-ChildItem -LiteralPath (Join-Path $cipherKits 'bin') -Directory |
    Where-Object { $_.Name -match '^10\.0\.\d+\.0$' } |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64/signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (!$cipherSignTool) { throw 'The Windows SDK signing tool is unavailable.' }

# Prefer an eligible signer in the user store and fall back to the machine store.
$cipherNow = Get-Date
$cipherStores = if ($MachineStore) { @('LocalMachine') } else { @('CurrentUser', 'LocalMachine') }
$cipherStore = $cipherStores | Where-Object {
    Get-ChildItem -LiteralPath "Cert:\$_\My" -CodeSigningCert | Where-Object {
        $_.HasPrivateKey -and $_.NotBefore -le $cipherNow -and $_.NotAfter -gt $cipherNow
    } | Select-Object -First 1
} | Select-Object -First 1
if (!$cipherStore) { throw 'No valid code-signing certificate with a private key was found in the Personal stores.' }

# Sign only first-party deliverables; retain the vendor signature on the loopback driver.
$cipherArguments = @('sign', '/a', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
if ($cipherStore -eq 'LocalMachine') { $cipherArguments += '/sm' }
foreach ($cipherFile in $Path)
{
    & $cipherSignTool @cipherArguments $cipherFile
    if ($LASTEXITCODE) { throw "Code signing failed: $cipherFile" }
    & $cipherSignTool verify /pa /all /tw $cipherFile
    if ($LASTEXITCODE) { throw "Signature verification failed: $cipherFile" }
}

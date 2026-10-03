param(
    [Parameter(Mandatory)][string]$IsoPath,
    [string]$Name = 'Cipherazzi-Lab-20261002',
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$cipherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$labRoot = Join-Path $cipherRoot '.work/hyperv'
$vmRoot = Join-Path $labRoot $Name
if ($Name -notmatch '^Cipherazzi-Lab-[a-zA-Z0-9-]+$') { throw 'Invalid lab VM name.' }
New-Item -ItemType Directory -Path $labRoot -Force | Out-Null
$statusPath = Join-Path $labRoot 'setup-status.json'
function Set-LabStatus([string]$State, [string]$Detail)
{
    @{ state = $State; detail = $Detail; vm = $Name; root = $vmRoot; utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath
}

try
{
    Set-LabStatus 'preparing' 'Checking Hyper-V and installation media'
    if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw 'The lab VM name is already in use.' }
    if ((Test-Path -LiteralPath $vmRoot) -and -not $Resume) { throw 'The lab directory already exists.' }
    $switch = Get-VMSwitch -Name 'Default Switch'
    New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null
    $password = 'Cz!' + [Guid]::NewGuid().ToString('N') + 'a9'
    $credential = [PSCredential]::new('LabAdmin', (ConvertTo-SecureString $password -AsPlainText -Force))
    if ($Resume)
    {
        $credential = Import-Clixml -LiteralPath (Join-Path $vmRoot 'credential.xml')
        $password = $credential.GetNetworkCredential().Password
    }
    else { $credential | Export-Clixml -LiteralPath (Join-Path $vmRoot 'credential.xml') }
    $vhdPath = Join-Path $vmRoot 'Windows.vhdx'
    $mountedIso = $false
    $mountedVhd = $false
    try
    {
        if (-not $Resume)
        {
            $iso = Get-DiskImage -ImagePath $IsoPath
            if (-not $iso.Attached)
            {
                $iso = Mount-DiskImage -ImagePath $IsoPath -PassThru
                $mountedIso = $true
            }
            $isoLetter = ($iso | Get-Volume).DriveLetter
            $imagePath = "${isoLetter}:\sources\install.wim"
            if (-not (Test-Path -LiteralPath $imagePath)) { throw 'The ISO does not contain install.wim.' }
            $windowsImage = Get-WindowsImage -ImagePath $imagePath |
                Where-Object ImageName -eq 'Windows 11 Enterprise' | Select-Object -First 1
            if (-not $windowsImage) { throw 'The ISO does not contain Windows 11 Enterprise.' }
            New-VHD -Path $vhdPath -Dynamic -SizeBytes 80GB | Out-Null
            $disk = Mount-VHD -Path $vhdPath -PassThru | Get-Disk
            $mountedVhd = $true
            if ($disk.PartitionStyle -ne 'RAW' -or $disk.Size -ne 80GB) { throw 'Unexpected new virtual disk.' }
            $disk | Initialize-Disk -PartitionStyle GPT
            $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter
            $efi | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'CIPHER_BOOT' -Confirm:$false | Out-Null
            New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
            $os = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
            $os | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'CIPHER_LAB' -Confirm:$false | Out-Null
            $osRoot = "$($os.DriveLetter):\"
            Set-LabStatus 'installing' 'Applying Windows to the new lab disk'
            Expand-WindowsImage -ImagePath $imagePath -Index $windowsImage.ImageIndex -ApplyPath $osRoot |
                Out-File -LiteralPath (Join-Path $vmRoot 'image-result.txt')
        }
        else
        {
            $disk = Mount-VHD -Path $vhdPath -PassThru | Get-Disk
            $mountedVhd = $true
        }
        $efi = Get-Partition -DiskNumber $disk.Number | Where-Object GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $os = Get-Partition -DiskNumber $disk.Number | Where-Object Size -gt 1GB
        foreach ($partition in @($efi, $os))
        {
            if ([int][char]$partition.DriveLetter -lt 65)
            {
                $letter = [char[]](72..90) | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -First 1
                $partition | Add-PartitionAccessPath -AccessPath "${letter}:\"
            }
        }
        $efi = Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber
        $os = Get-Partition -DiskNumber $disk.Number -PartitionNumber $os.PartitionNumber
        $osRoot = "$($os.DriveLetter):\"
        @($efi, $os) | Select-Object DiskNumber,PartitionNumber,DriveLetter,AccessPaths | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $vmRoot 'partitions.json')
        $boot = Start-Process -FilePath "$env:SystemRoot\System32\bcdboot.exe" -WindowStyle Hidden -Wait -PassThru `
            -ArgumentList @((Join-Path $osRoot 'Windows'), '/s', "$($efi.DriveLetter):", '/f', 'UEFI', '/offline', '/c', '/v') `
            -RedirectStandardOutput (Join-Path $vmRoot 'boot-result.txt') `
            -RedirectStandardError (Join-Path $vmRoot 'boot-error.txt')
        $guestBootRepair = $boot.ExitCode -ne 0
        $panther = Join-Path $osRoot 'Windows/Panther'
        New-Item -ItemType Directory -Path $panther -Force | Out-Null
        @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>CIPHERAZZI-LAB</ComputerName><TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" wcm:action="add"><Name>LabAdmin</Name><DisplayName>Cipherazzi Lab</DisplayName><Group>Administrators</Group><Password><Value>$password</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Username>LabAdmin</Username><Enabled>true</Enabled><LogonCount>1</LogonCount><Password><Value>$password</Value><PlainText>true</PlainText></Password></AutoLogon>
    </component>
  </settings>
</unattend>
"@ | Set-Content -LiteralPath (Join-Path $panther 'unattend.xml') -Encoding UTF8
    }
    finally
    {
        if ($mountedVhd) { Dismount-VHD -Path $vhdPath }
        if ($mountedIso) { Dismount-DiskImage -ImagePath $IsoPath | Out-Null }
    }
    Set-LabStatus 'booting' 'Starting the new VM and waiting for PowerShell Direct'
    $vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes 8GB -VHDPath $vhdPath -Path $vmRoot -SwitchName $switch.Name
    Set-VM -VM $vm -ProcessorCount 4 -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    if ($guestBootRepair)
    {
        Add-VMDvdDrive -VM $vm -Path $IsoPath
        Set-VMFirmware -VM $vm -FirstBootDevice (Get-VMDvdDrive -VM $vm)
    }
    Start-VM -VM $vm
    if ($guestBootRepair)
    {
        # Build the guest BCD from Windows PE when the host cannot load another BCD hive.
        $keyboard = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_Keyboard -Filter "SystemName='$($vm.Id)'"
        for ($key = 0; $key -lt 8; ++$key)
        {
            Start-Sleep -Seconds 1
            $keyboard.PressKey(13) | Out-Null
            $keyboard.ReleaseKey(13) | Out-Null
        }
        Start-Sleep -Seconds 40
        $keyboard.PressKey(16) | Out-Null
        $keyboard.PressKey(121) | Out-Null
        $keyboard.ReleaseKey(121) | Out-Null
        $keyboard.ReleaseKey(16) | Out-Null
        Start-Sleep -Seconds 3
        $repair = '(echo select disk 0&echo select partition 2&echo assign letter=S) > X:\esp.txt & diskpart /s X:\esp.txt & bcdboot C:\Windows /s S: /f UEFI /c > C:\CipherazziBoot.log 2>&1 && wpeutil reboot'
        $keyboard.TypeText($repair) | Out-Null
        $keyboard.PressKey(13) | Out-Null
        $keyboard.ReleaseKey(13) | Out-Null
    }
    $session = $null
    for ($attempt = 0; $attempt -lt 120; ++$attempt)
    {
        Start-Sleep -Seconds 5
        try { $session = New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop } catch {}
        if ($session) { break }
    }
    if (-not $session) { throw 'Windows did not become ready for PowerShell Direct within ten minutes.' }
    try
    {
        $guest = Invoke-Command -Session $session -ScriptBlock {
            [pscustomobject]@{ computer = $env:COMPUTERNAME; os = [Environment]::OSVersion.VersionString
                pktmon = (Get-Item C:\Windows\System32\PktMonApi.dll).VersionInfo.FileVersion
                addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress) }
        }
        $guest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $vmRoot 'guest.json')
        @{ name = $Name; id = $vm.Id.ToString(); root = $vmRoot } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $labRoot 'lab.json')
    }
    finally { Remove-PSSession $session }
    Set-LabStatus 'ready' 'Windows and the Packet Monitor API are ready'
}
catch
{
    Set-LabStatus 'failed' $_.Exception.Message
    throw
}

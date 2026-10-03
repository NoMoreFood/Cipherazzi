param([string]$Name = 'Cipherazzi-Lab-20261002')
$ErrorActionPreference = 'Stop'
$labRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../.work/hyperv'))
try
{
    $vm = Get-VM -Name $Name
    $vm | Select-Object Name,Id,State,Status,Uptime,CPUUsage | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $labRoot 'vm-state.json')
    if ($vm.State -eq 'Off') { return }
    $computer = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name='$($vm.Id)'"
    $settings = $computer.GetRelated('Msvm_VirtualSystemSettingData') |
        Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' | Select-Object -First 1
    $service = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $result = $service.GetVirtualSystemThumbnailImage($settings.__PATH, 1024, 768)
    if ($result.ReturnValue) { throw "Thumbnail failed: $($result.ReturnValue)" }
    [IO.File]::WriteAllBytes((Join-Path $labRoot 'console.rgb565'), $result.ImageData)
    $credential = Import-Clixml -LiteralPath (Join-Path $labRoot "$Name/credential.xml")
    $session = New-PSSession -VMId $vm.Id -Credential $credential
    try
    {
        Invoke-Command -Session $session -ScriptBlock {
            Get-ChildItem C:\Cipherazzi -ErrorAction SilentlyContinue | Select-Object Name,Length,Mode
            Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime
            Get-CimInstance Win32_ComputerSystem | Select-Object UserName
            Get-Process explorer -ErrorAction SilentlyContinue | Select-Object Name,SessionId
            Get-WinEvent -FilterHashtable @{LogName='System';Id=1074,6008} -MaxEvents 3 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated,Id,Message
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $labRoot 'guest-state.json')
    }
    finally { Remove-PSSession $session }
}
catch { $_ | Out-String | Set-Content -LiteralPath (Join-Path $labRoot 'state-error.txt'); throw }

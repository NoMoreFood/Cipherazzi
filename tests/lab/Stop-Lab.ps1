$ErrorActionPreference = 'Stop'
$labRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../.work/hyperv'))
$lab = Get-Content (Join-Path $labRoot 'lab.json') -Raw | ConvertFrom-Json
$vm = Get-VM -Id $lab.id
if ($vm.Name -ne $lab.name) { throw 'The lab VM identity does not match.' }
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Confirm:$false }
$vm = Get-VM -Id $lab.id
@{ name = $vm.Name; id = $vm.Id.ToString(); state = $vm.State.ToString(); retained = $true
    utc = [DateTime]::UtcNow.ToString('o')
    firewall_rules = @(Get-NetFirewallRule -DisplayName 'Cipherazzi lab *' -ErrorAction SilentlyContinue).Count } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'lab-final.json')

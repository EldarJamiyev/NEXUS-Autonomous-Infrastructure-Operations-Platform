<#
.SYNOPSIS
  Compare current Windows settings with the NEXUS baseline. Exit code 1 when drift exists.
.EXAMPLE
  .\Test-NexusWindowsBaseline.ps1
.EXAMPLE
  .\Test-NexusWindowsBaseline.ps1 -Report | ConvertTo-Json -Depth 3
#>
[CmdletBinding()]
param([switch]$Report)
$ErrorActionPreference = 'Stop'
$desired = [ordered]@{
    smb1_enabled        = $false
    firewall_profiles   = @('Domain', 'Private', 'Public')
    rdp_nla_required    = $true
    min_password_length = 14
    audit_logon_events  = $true
    lockout_threshold   = 10
}
$actual = & (Join-Path $PSScriptRoot 'Get-NexusWindowsBaseline.ps1')
$results = foreach ($key in $desired.Keys) {
    $want = $desired[$key]
    $have = $actual[$key]
    $match = if ($want -is [array]) { -not (Compare-Object @($want) @($have)) } else { $want -eq $have }
    [pscustomobject]@{ Setting = $key; Desired = ($want -join ','); Actual = ($have -join ','); Status = $(if ($match) { 'PASS' } else { 'DRIFT' }) }
}
if ($Report) { return $results }
$results | Format-Table -AutoSize
if ($results.Status -contains 'DRIFT') { exit 1 }

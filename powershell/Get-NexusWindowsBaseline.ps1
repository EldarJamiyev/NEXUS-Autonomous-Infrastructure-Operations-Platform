<#
.SYNOPSIS
  Report the Windows security settings NEXUS tracks (keys match baselines/dc01.yaml -> windows).
.EXAMPLE
  .\Get-NexusWindowsBaseline.ps1 | ConvertTo-Json
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$profiles = @(Get-NetFirewallProfile | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication -eq 1
$minLength = $null
$lockout = $null
try {
    $policy = Get-ADDefaultDomainPasswordPolicy
    $minLength = $policy.MinPasswordLength
    $lockout = $policy.LockoutThreshold
} catch {
    $accounts = net accounts
    $minLength = [int](($accounts | Select-String 'Minimum password length').ToString().Split(':')[-1].Trim())
    $lockoutText = ($accounts | Select-String 'Lockout threshold').ToString().Split(':')[-1].Trim()
    $lockout = if ($lockoutText -match '^\d+$') { [int]$lockoutText } else { 0 }
}
$audit = (auditpol /get /subcategory:"Logon" /r | ConvertFrom-Csv).'Inclusion Setting' -match 'Success'

[ordered]@{
    smb1_enabled        = [bool]$smb1
    firewall_profiles   = $profiles
    rdp_nla_required    = [bool]$nla
    min_password_length = $minLength
    audit_logon_events  = [bool]$audit
    lockout_threshold   = $lockout
}

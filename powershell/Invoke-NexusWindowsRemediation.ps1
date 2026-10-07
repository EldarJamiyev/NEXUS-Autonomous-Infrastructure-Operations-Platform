<#
.SYNOPSIS
  Restore Windows baseline settings. Called by NEXUS (REM-WIN-BASELINE) or by an operator.
.DESCRIPTION
  Only the named settings can be changed (ValidateSet = allowlist). Previous values are saved to a JSON
  backup before any change. Supports -WhatIf.
.EXAMPLE
  .\Invoke-NexusWindowsRemediation.ps1 -Setting smb1 -WhatIf
.EXAMPLE
  .\Invoke-NexusWindowsRemediation.ps1 -Setting all
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('all', 'smb1', 'firewall', 'nla', 'audit', 'password')][string]$Setting,
    [string]$BackupDir = "$env:ProgramData\NEXUS\backups"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$before = & (Join-Path $PSScriptRoot 'Get-NexusWindowsBaseline.ps1')
$backup = Join-Path $BackupDir ("windows-baseline-{0:yyyyMMddTHHmmss}.json" -f (Get-Date))
$before | ConvertTo-Json -Depth 3 | Set-Content -Path $backup -Encoding utf8
$changed = @()
$want = if ($Setting -eq 'all') { @('smb1', 'firewall', 'nla', 'audit', 'password') } else { @($Setting) }

if ('smb1' -in $want -and $before.smb1_enabled -and $PSCmdlet.ShouldProcess('SMB server', 'Disable SMBv1')) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; $changed += 'smb1'
}
if ('firewall' -in $want -and $before.firewall_profiles.Count -lt 3 -and $PSCmdlet.ShouldProcess('Windows Firewall', 'Enable all profiles')) {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True; $changed += 'firewall'
}
if ('nla' -in $want -and -not $before.rdp_nla_required -and $PSCmdlet.ShouldProcess('RDP', 'Require Network Level Authentication')) {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1; $changed += 'nla'
}
if ('audit' -in $want -and -not $before.audit_logon_events -and $PSCmdlet.ShouldProcess('Audit policy', 'Audit logon success and failure')) {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null; $changed += 'audit'
}
if ('password' -in $want -and ($before.min_password_length -lt 14 -or $before.lockout_threshold -ne 10) -and $PSCmdlet.ShouldProcess('Domain password policy', 'Min length 14, lockout 10')) {
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 14 -LockoutThreshold 10; $changed += 'password'
}
$after = & (Join-Path $PSScriptRoot 'Get-NexusWindowsBaseline.ps1')
[ordered]@{ changed = $changed; backup = $backup; before = $before; after = $after } | ConvertTo-Json -Depth 4

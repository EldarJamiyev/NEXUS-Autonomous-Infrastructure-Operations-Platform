<#
.SYNOPSIS
  Export AD users, security groups and computers and push them to NEXUS (POST /api/ingest/ad-inventory).
.DESCRIPTION
  Real-lab integration. Read-only against Active Directory. Requires the ActiveDirectory module (RSAT) and an
  ADMIN API key configured in NEXUS_API_KEYS. Use -OutFile to inspect the payload without sending it.
.EXAMPLE
  .\Get-NexusADInventory.ps1 -NexusUrl https://nexus.corp.nexus.lab -ApiKey $env:NEXUS_API_KEY
.EXAMPLE
  .\Get-NexusADInventory.ps1 -OutFile .\ad-inventory.json
#>
[CmdletBinding()]
param(
    [string]$NexusUrl = $env:NEXUS_URL,
    [string]$ApiKey = $env:NEXUS_API_KEY,
    [string]$SearchBase,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$scope = @{}
if ($SearchBase) { $scope['SearchBase'] = $SearchBase }

$users = Get-ADUser -Filter * @scope -Properties DisplayName, Department, Title, Mail, MemberOf, Enabled, DistinguishedName |
    ForEach-Object {
        [ordered]@{
            SamAccountName    = $_.SamAccountName
            DisplayName       = $_.DisplayName
            Department        = $_.Department
            Title             = $_.Title
            Mail              = $_.Mail
            Enabled           = [bool]$_.Enabled
            DistinguishedName = $_.DistinguishedName
            MemberOf          = @($_.MemberOf)
        }
    }
$groups = Get-ADGroup -Filter "GroupCategory -eq 'Security'" @scope -Properties Description |
    ForEach-Object { [ordered]@{ Name = $_.Name; Description = $_.Description } }
$computers = Get-ADComputer -Filter * @scope -Properties OperatingSystem, DNSHostName, LastLogonDate |
    ForEach-Object { [ordered]@{ Name = $_.Name; OperatingSystem = $_.OperatingSystem; DNSHostName = $_.DNSHostName; LastLogon = "$($_.LastLogonDate)" } }

$payload = [ordered]@{ users = @($users); groups = @($groups); computers = @($computers) }
$json = $payload | ConvertTo-Json -Depth 5

if ($OutFile) {
    $json | Set-Content -Path $OutFile -Encoding utf8
    Write-Host "Wrote $($users.Count) users, $($groups.Count) groups, $($computers.Count) computers to $OutFile"
    return
}
if (-not $NexusUrl -or -not $ApiKey) { throw 'NexusUrl and ApiKey (or NEXUS_URL / NEXUS_API_KEY) are required unless -OutFile is used.' }
$response = Invoke-RestMethod -Method Post -Uri "$($NexusUrl.TrimEnd('/'))/api/ingest/ad-inventory" -ContentType 'application/json' `
    -Headers @{ Authorization = "Bearer $ApiKey" } -Body $json
$response | ConvertTo-Json

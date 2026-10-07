<#
.SYNOPSIS
  Collect Windows Security events and forward them to NEXUS in its normalised format.
.DESCRIPTION
  Event IDs: 4624 4625 4634 4647 4672 4720 4726 4728 4729 4732 4733. Run on a domain controller
  (or a Windows Event Collector) as a scheduled task every few minutes. Requires an ENGINEER API key.
.EXAMPLE
  .\Get-NexusSecurityEvents.ps1 -Minutes 5 -NexusUrl https://nexus.corp.nexus.lab -ApiKey $env:NEXUS_API_KEY
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 1440)][int]$Minutes = 5,
    [string]$NexusUrl = $env:NEXUS_URL,
    [string]$ApiKey = $env:NEXUS_API_KEY,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
$ids = 4624, 4625, 4634, 4647, 4672, 4720, 4726, 4728, 4729, 4732, 4733

function Get-EventField {
    param($Xml, [string]$Name)
    ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
}

$raw = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = (Get-Date).AddMinutes(-$Minutes) } -ErrorAction SilentlyContinue
$events = foreach ($e in $raw) {
    [xml]$x = $e.ToXml()
    $user = Get-EventField $x 'TargetUserName'
    if ($e.Id -in 4624, 4634 -and $user -match '\$$') { continue }   # skip computer accounts
    [ordered]@{
        EventID         = $e.Id
        TimeCreated     = $e.TimeCreated.ToUniversalTime().ToString('o')
        Computer        = $e.MachineName
        TargetUserName  = $user
        SubjectUserName = Get-EventField $x 'SubjectUserName'
        WorkstationName = Get-EventField $x 'WorkstationName'
        IpAddress       = Get-EventField $x 'IpAddress'
        LogonType       = Get-EventField $x 'LogonType'
        Status          = Get-EventField $x 'Status'
        SubStatus       = Get-EventField $x 'SubStatus'
        MemberName      = Get-EventField $x 'MemberName'
    }
}
$batch = @($events)
if ($OutFile) { $batch | ConvertTo-Json -Depth 3 | Set-Content -Path $OutFile -Encoding utf8; Write-Host "Wrote $($batch.Count) events"; return }
if ($batch.Count -eq 0) { Write-Host 'No matching events.'; return }
if (-not $NexusUrl -or -not $ApiKey) { throw 'NexusUrl and ApiKey are required unless -OutFile is used.' }
Invoke-RestMethod -Method Post -Uri "$($NexusUrl.TrimEnd('/'))/api/ingest/windows-events" -ContentType 'application/json' `
    -Headers @{ Authorization = "Bearer $ApiKey" } -Body (ConvertTo-Json -InputObject $batch -Depth 3) | ConvertTo-Json

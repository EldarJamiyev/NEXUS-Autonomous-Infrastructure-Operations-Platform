<#
.SYNOPSIS
  Windows helper: build and start NEXUS OMNIS with Docker Desktop, then open the console.
.EXAMPLE
  .\scripts\start.ps1
.EXAMPLE
  .\scripts\start.ps1 -Observability
#>
[CmdletBinding()]
param([switch]$Observability)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker Desktop is required: https://www.docker.com/products/docker-desktop/' }
$composeArgs = @('compose')
if ($Observability) { $composeArgs += @('--profile', 'observability') }
$composeArgs += @('up', '--build', '-d')
& docker @composeArgs
Write-Host 'Waiting for NEXUS to become healthy...'
for ($i = 0; $i -lt 60; $i++) {
    try {
        if ((Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:8000/health' -TimeoutSec 3).StatusCode -eq 200) { break }
    } catch { Start-Sleep -Seconds 2 }
}
Start-Process 'http://localhost:8000'

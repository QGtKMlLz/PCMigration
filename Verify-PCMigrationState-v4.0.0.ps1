#requires -version 5.1
<# Recaptures the destination and regenerates the complete v4.0.0 comparison. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceCapture,
    [Parameter(Mandatory=$true)][string]$DestinationCapturePath,
    [Parameter(Mandatory=$true)][string]$ReportPath,
    [switch]$SkipCaptureHashValidation
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PCMigration.Common-v4.0.0.ps1')

$source=[IO.Path]::GetFullPath($SourceCapture)
$meta=Read-PCJson (Join-Path $source 'Meta.json')
if($null -eq $meta -or [string]$meta.SchemaVersion -ne '4.0'){throw "SourceCapture is not a compatible v4.0 capture: $source"}
$mode=[string](Get-PCProperty $meta 'InventoryMode' 'Standard')
$searchSecure=((Get-PCCollectorStatus -CapturePath $source -Name 'SecureManual.SecureFileCandidates') -eq 'Success')
$startInventoryServices=[bool](Get-PCProperty $meta 'StartStoppedInventoryServices' $false)

Write-Host 'Creating a fresh destination verification capture...' -ForegroundColor Cyan
$captureArguments=@{
    OutputPath=[IO.Path]::GetFullPath($DestinationCapturePath)
    InventoryMode=$mode
}
if($searchSecure){$captureArguments.SearchSecureFileCandidates=$true}
if($startInventoryServices){$captureArguments.StartStoppedInventoryServices=$true}
& (Join-Path $PSScriptRoot 'Capture-PCMigrationState-v4.0.0.ps1') @captureArguments

Write-Host 'Comparing the fresh destination capture to the source...' -ForegroundColor Cyan
$compareArguments=@{
    SourceCapture=$source
    DestinationCapture=[IO.Path]::GetFullPath($DestinationCapturePath)
    OutputPath=[IO.Path]::GetFullPath($ReportPath)
}
if($SkipCaptureHashValidation){$compareArguments.SkipCaptureHashValidation=$true}
& (Join-Path $PSScriptRoot 'Compare-PCMigrationState-v4.0.0.ps1') @compareArguments

Write-Host ''
Write-Host 'Verification complete. Review Regression-Checks.csv and Likely-Migration-Gaps.csv.' -ForegroundColor Green

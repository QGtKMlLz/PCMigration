#requires -version 5.1
<#
.SYNOPSIS
Previews or applies individually approved v4.0.0 repair-plan rows.

.DESCRIPTION
Every Repair-Plan.csv row starts with Approved=NO. This script executes only
approved rows and only when their method, identity, source artifact, destination,
and hash are independently authorized by the source capture. Preview is the
default. Destination files/registry keys are backed up before mutation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceCapture,
    [Parameter(Mandatory=$true)][string]$PlanPath,
    [switch]$Apply,
    [switch]$AllowHighRisk,
    [switch]$AllowAdminChanges,
    [switch]$StopOnError
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PCMigration.Common-v4.0.0.ps1')

$source=[IO.Path]::GetFullPath($SourceCapture)
$planFile=[IO.Path]::GetFullPath($PlanPath)
if(-not [IO.File]::Exists((Join-Path $source 'Meta.json'))){throw "Source capture is invalid: $source"}
$sourceMeta=Read-PCJson (Join-Path $source 'Meta.json')
if($null -eq $sourceMeta -or [string](Get-PCProperty $sourceMeta 'SchemaVersion' '') -ne '4.0'){
    throw "Source capture schema is not compatible with v4.0.0: $source"
}
if(-not [IO.File]::Exists($planFile)){throw "Repair plan not found: $planFile"}
$integrityFailures=@(Test-PCCaptureManifest -CapturePath $source)
if($integrityFailures.Count){throw ('Source capture failed integrity validation: '+($integrityFailures -join '; '))}
$plan=@(Import-Csv -LiteralPath $planFile)
$approved=@($plan|Where-Object {[string]$_.Approved -match '^(?i:yes|true|1|approved)$'})
$isAdmin=Test-PCAdministrator

$desktop=[Environment]::GetFolderPath('Desktop')
if(-not $desktop){$desktop=Join-Path $env:USERPROFILE 'Desktop'}
$backup=Join-Path $desktop ('PCMigration-v4.0.0-Backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
$backupRows=New-Object System.Collections.ArrayList
$resultRows=New-Object System.Collections.ArrayList

function Save-PCBackupManifest {
    if(-not $Apply){return}
    New-PCDirectory $backup
    Export-PCCsv -Path (Join-Path $backup 'Backup-Manifest.csv') -Rows $script:backupRows.ToArray() -Columns @(
        'ActionId','Type','Destination','BackupRelativePath','Note'
    )
}

function Save-PCRepairResults {
    if(-not $Apply){return}
    New-PCDirectory $backup
    Export-PCCsv -Path (Join-Path $backup 'Repair-Results.csv') -Rows $script:resultRows.ToArray() -Columns @(
        'ActionId','Method','Item','Status','Message','StartedAt','FinishedAt'
    )
}

function Resolve-PCArtifact {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    if([IO.Path]::IsPathRooted($RelativePath)){throw "SourceArtifact must be capture-relative: $RelativePath"}
    $full=[IO.Path]::GetFullPath((Join-Path $source $RelativePath))
    $prefix=$source.TrimEnd('\')+'\'
    if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw "SourceArtifact escapes the capture: $RelativePath"}
    if(-not [IO.File]::Exists($full)){throw "Source artifact missing: $RelativePath"}
    return $full
}

function Test-PCExpectedHash {
    param([string]$Path,[string]$Expected)
    if(-not $Expected){throw "ExpectedSourceSHA256 is required for artifact action: $Path"}
    $actual=Get-PCSha256File $Path
    if($actual -ne $Expected.ToLowerInvariant()){throw "Source artifact hash mismatch: $Path"}
}

function Get-PCShortcutDestination {
    param([Parameter(Mandatory=$true)][string]$Identity)
    if($Identity -notmatch '^([^|]+)\|(.+)$'){throw "Invalid shortcut identity: $Identity"}
    $rootId=$matches[1];$relative=$matches[2]
    if(($relative -split '\\') -contains '..'){throw "Shortcut parent traversal is not allowed: $Identity"}
    $root=switch($rootId){
        'UserStartMenu' {[Environment]::GetFolderPath('StartMenu')}
        'CommonStartMenu' {[Environment]::GetFolderPath('CommonStartMenu')}
        'UserDesktop' {[Environment]::GetFolderPath('Desktop')}
        'CommonDesktop' {[Environment]::GetFolderPath('CommonDesktopDirectory')}
        'UserStartup' {[Environment]::GetFolderPath('Startup')}
        'CommonStartup' {[Environment]::GetFolderPath('CommonStartup')}
        'UserPinned' {Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned'}
        default {throw "Unsupported shortcut root: $rootId"}
    }
    if(-not $root){throw "Shortcut destination root is unavailable: $rootId"}
    return Join-Path $root $relative
}

function Test-PCRegistryTarget {
    param([Parameter(Mandatory=$true)][string]$Target)
    if($Target -notmatch '^(HKCU|HKLM)\\(.+)$'){return $false}
    $provider=if($matches[1] -eq 'HKCU'){'Registry::HKEY_CURRENT_USER\'+$matches[2]}else{'Registry::HKEY_LOCAL_MACHINE\'+$matches[2]}
    return (Test-Path -LiteralPath $provider -ErrorAction SilentlyContinue)
}

function Backup-PCFile {
    param([string]$ActionId,[string]$Destination)
    New-PCDirectory $backup
    if([IO.File]::Exists($Destination)){
        $name=(Get-PCSafeFileName ($ActionId+'-'+[IO.Path]::GetFileName($Destination)))+'.destination.bak'
        $backupFile=Join-Path $backup ('Files\'+$name)
        New-PCDirectory ([IO.Path]::GetDirectoryName($backupFile))
        [IO.File]::Copy($Destination,$backupFile,$true)
        [void]$script:backupRows.Add([pscustomobject]@{
            ActionId=$ActionId;Type='File';Destination=$Destination
            BackupRelativePath=$backupFile.Substring($backup.Length).TrimStart('\')
            Note='Existing destination file'
        })
    }else{
        [void]$script:backupRows.Add([pscustomobject]@{
            ActionId=$ActionId;Type='File-New';Destination=$Destination;BackupRelativePath=''
            Note='Destination did not exist before repair'
        })
    }
    Save-PCBackupManifest
}

function Backup-PCRegistry {
    param([string]$ActionId,[string]$Target)
    New-PCDirectory $backup
    if(Test-PCRegistryTarget $Target){
        $file=Join-Path $backup ('Registry\'+(Get-PCSafeFileName ($ActionId+'-'+$Target))+'.reg')
        New-PCDirectory ([IO.Path]::GetDirectoryName($file))
        $reg=Join-Path $env:SystemRoot 'System32\reg.exe'
        $result=Invoke-PCNativeProcess -FilePath $reg -Arguments ('export "'+$Target+'" "'+$file+'" /y')
        if($result.ExitCode -ne 0){throw "Destination registry backup failed for $($Target): $($result.StdErr.Trim())"}
        [void]$script:backupRows.Add([pscustomobject]@{
            ActionId=$ActionId;Type='Registry';Destination=$Target
            BackupRelativePath=$file.Substring($backup.Length).TrimStart('\')
            Note='Existing destination registry subtree'
        })
    }else{
        [void]$script:backupRows.Add([pscustomobject]@{
            ActionId=$ActionId;Type='Registry-New';Destination=$Target;BackupRelativePath=''
            Note='Registry target did not exist before repair'
        })
    }
    Save-PCBackupManifest
}

function Copy-PCFileWithBackup {
    param([string]$ActionId,[string]$SourceFile,[string]$DestinationFile)
    Backup-PCFile -ActionId $ActionId -Destination $DestinationFile
    New-PCDirectory ([IO.Path]::GetDirectoryName($DestinationFile))
    [IO.File]::Copy($SourceFile,$DestinationFile,$true)
}

function Import-PCRegistryWithBackup {
    param([string]$ActionId,[string]$SourceFile,[string]$DestinationTarget)
    Backup-PCRegistry -ActionId $ActionId -Target $DestinationTarget
    $reg=Join-Path $env:SystemRoot 'System32\reg.exe'
    $result=Invoke-PCNativeProcess -FilePath $reg -Arguments ('import "'+$SourceFile+'"')
    if($result.ExitCode -ne 0){throw "Registry import failed: $($result.StdErr.Trim())"}
}

function Set-PC24HourClock {
    param([string]$ActionId)
    Backup-PCRegistry -ActionId $ActionId -Target 'HKCU\Control Panel\International'
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Control Panel\International')
    try{
        $kind=[Microsoft.Win32.RegistryValueKind]::String
        $key.SetValue('sShortTime','HH:mm',$kind)
        $key.SetValue('sTimeFormat','HH:mm:ss',$kind)
        $key.SetValue('iTime','1',$kind)
        $key.SetValue('iTLZero','1',$kind)
    }finally{$key.Dispose()}
    try{
        if(-not ('PCMigration.RepairNativeMethods' -as [type])){
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PCMigration {
  public static class RepairNativeMethods {
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
      IntPtr hWnd, uint Msg, IntPtr wParam, string lParam,
      uint flags, uint timeout, out IntPtr result);
  }
}
'@
        }
        $sendResult=[IntPtr]::Zero
        [void][PCMigration.RepairNativeMethods]::SendMessageTimeout([IntPtr]0xffff,0x001A,[IntPtr]::Zero,'Intl',2,5000,[ref]$sendResult)
    }catch{}
}

# Build immutable authorization maps from the source capture.
$authorizedRegistry=@{}
foreach($item in @(Import-PCCsv (Join-Path $source 'ApplicationState\Registry-Payload-Catalog.csv'))){
    if($item.Present -eq 'True' -and $item.Artifact){
        $authorizedRegistry[$item.Artifact.ToLowerInvariant()]=[pscustomobject]@{
            Target=$item.Hive+'\'+$item.SubKey;SHA256=$item.SHA256;Risk=$item.Risk;Method=$item.AutoMethod
        }
    }
}
$authorizedFiles=@{}
foreach($item in @(Import-PCCsv (Join-Path $source 'ApplicationState\Settings-Files.csv'))){
    if($item.PayloadRelativePath){
        $authorizedFiles[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target='%'+$item.RootToken+'%\'+$item.RelativePath;SHA256=$item.SHA256;Type='CopyFile'
        }
    }
}
foreach($item in @(Import-PCCsv (Join-Path $source 'UserState\PowerShell\Profiles.csv'))){
    if($item.PayloadRelativePath){
        $authorizedFiles[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target=$item.DestinationPath;SHA256=$item.SHA256;Type='CopyFile'
        }
    }
}
foreach($item in @(Import-PCCsv (Join-Path $source 'UserState\Windows-Terminal.csv'))){
    if($item.PayloadRelativePath){
        $authorizedFiles[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target=$item.DestinationPath;SHA256=$item.SHA256;Type='CopyFile'
        }
    }
}
foreach($item in @(Import-PCCsv (Join-Path $source 'ApplicationState\KLite-Files.csv'))){
    if($item.PayloadRelativePath){
        $target='%'+$item.RootToken+'%\'+$item.RootRelativePath
        if($item.RelativePath){$target+='\'+$item.RelativePath}
        $authorizedFiles[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target=$target;SHA256=$item.SHA256;Type='CopyFile'
        }
    }
}
foreach($item in @(Import-PCCsv (Join-Path $source 'Integration\System-Files.csv'))){
    if($item.PayloadRelativePath){
        $authorizedFiles[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target=$item.DestinationPath;SHA256=$item.SHA256;Type='CopyFile'
        }
    }
}
$authorizedShortcuts=@{}
foreach($item in @(Import-PCCsv (Join-Path $source 'Applications\Shortcuts.csv'))){
    if($item.PayloadRelativePath){
        $authorizedShortcuts[$item.PayloadRelativePath.ToLowerInvariant()]=[pscustomobject]@{
            Target=$item.RootId+'|'+$item.RelativePath;SHA256=$item.SHA256;ShortcutTarget=$item.TargetPath
        }
    }
}
$authorizedWinget=@{}
foreach($package in @(Get-PCWingetPackages $source)){
    if($package.PackageIdentifier){$authorizedWinget[$package.PackageIdentifier.ToLowerInvariant()]=$package}
}
foreach($package in @(Import-PCCsv (Join-Path $source 'Applications\Regression-Package-Catalog.csv'))){
    if($package.PackageIdentifier){$authorizedWinget[$package.PackageIdentifier.ToLowerInvariant()]=$package}
}
$authorizedFeatures=@{}
foreach($feature in @(Import-PCCsv (Join-Path $source 'Integration\Enabled-Optional-Features.csv'))){
    if($feature.FeatureName){$authorizedFeatures[$feature.FeatureName.ToLowerInvariant()]=$true}
}
$authorizedCapabilities=@{}
foreach($capability in @(Import-PCCsv (Join-Path $source 'Integration\Installed-Capabilities.csv'))){
    if($capability.Name){$authorizedCapabilities[$capability.Name.ToLowerInvariant()]=$true}
}
$sourceRegional=Read-PCJson (Join-Path $source 'UserState\Regional-Language.json')
$authorizedTimeZone=[string](Get-PCProperty $sourceRegional 'TimeZoneId' '')

Write-Host "PCMigration repair v4.0.0 - $(if($Apply){'APPLY'}else{'PREVIEW'})" -ForegroundColor Cyan
Write-Host "Approved rows: $($approved.Count) of $($plan.Count)"
if($approved.Count -eq 0){
    Write-Warning 'No rows are approved. Edit only the Approved column in Repair-Plan.csv to YES for reviewed actions.'
    return
}
if($Apply){
    New-PCDirectory $backup
    [IO.File]::Copy($planFile,(Join-Path $backup 'Approved-Repair-Plan.csv'),$true)
    Save-PCBackupManifest
    Save-PCRepairResults
}

foreach($action in $approved){
    $started=Get-Date
    $status='Ready';$message='';$stopAfterResult=$false
    try{
        if($action.Method -notin @('WingetInstall','CopyFile','CopyShortcut','ImportRegistry','Set24HourClock','SetTimeZone','EnableFeature','AddCapability')){
            throw "Unsupported repair method: $($action.Method)"
        }
        if($action.Risk -eq 'High' -and -not $AllowHighRisk){throw 'High-risk action requires -AllowHighRisk.'}
        if($action.RequiresAdmin -eq 'True'){
            if(-not $AllowAdminChanges){throw 'Administrative action requires -AllowAdminChanges.'}
            if(-not $isAdmin){throw 'Administrative action requires an elevated PowerShell window.'}
        }

        switch($action.Method){
            'WingetInstall' {
                if(-not $action.PackageId -or -not $authorizedWinget.ContainsKey($action.PackageId.ToLowerInvariant())){throw 'Package ID is not authorized by source Winget-Export.json.'}
                if($action.PackageId -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}$'){throw 'Package ID contains unsupported characters.'}
                $sourceName=[string]$authorizedWinget[$action.PackageId.ToLowerInvariant()].SourceName
                if($action.PackageSource -and $sourceName -and $action.PackageSource -ne $sourceName){throw 'Package source differs from source capture.'}
                $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
                if($null -eq $winget){throw 'winget.exe is unavailable.'}
                $arguments='install --id "'+$action.PackageId+'" --exact --accept-package-agreements --accept-source-agreements --disable-interactivity'
                if($sourceName -and $sourceName -match '^[A-Za-z0-9._-]+$'){$arguments+=' --source "'+$sourceName+'"'}
                Write-Host ('  winget '+$arguments)
                if($Apply){
                    [void]$backupRows.Add([pscustomobject]@{ActionId=$action.ActionId;Type='NonReversible';Destination=$action.PackageId;BackupRelativePath='';Note='Package installation was attempted and is not automatically rolled back.'})
                    Save-PCBackupManifest
                    $result=Invoke-PCNativeProcess -FilePath $winget.Source -Arguments $arguments
                    if($result.StdOut){Write-Host $result.StdOut.TrimEnd()}
                    if($result.ExitCode -ne 0){throw "winget returned exit code $($result.ExitCode): $($result.StdErr.Trim())"}
                }
            }
            'CopyFile' {
                if(-not $action.SourceArtifact -or -not $authorizedFiles.ContainsKey($action.SourceArtifact.ToLowerInvariant())){throw 'File artifact is not authorized by source manifests.'}
                $authorization=$authorizedFiles[$action.SourceArtifact.ToLowerInvariant()]
                if($action.DestinationTarget -ne $authorization.Target){throw 'File destination differs from source manifest authorization.'}
                $sourceFile=Resolve-PCArtifact $action.SourceArtifact
                Test-PCExpectedHash -Path $sourceFile -Expected $authorization.SHA256
                $destinationFile=Resolve-PCTokenPath $authorization.Target
                Write-Host ("  copy {0} -> {1}" -f $action.SourceArtifact,$destinationFile)
                if($Apply){Copy-PCFileWithBackup -ActionId $action.ActionId -SourceFile $sourceFile -DestinationFile $destinationFile}
            }
            'CopyShortcut' {
                if(-not $action.SourceArtifact -or -not $authorizedShortcuts.ContainsKey($action.SourceArtifact.ToLowerInvariant())){throw 'Shortcut artifact is not authorized by source manifest.'}
                $authorization=$authorizedShortcuts[$action.SourceArtifact.ToLowerInvariant()]
                if($action.DestinationTarget -ne $authorization.Target){throw 'Shortcut destination differs from source manifest authorization.'}
                if($authorization.ShortcutTarget -match '^%[A-Z0-9_]+%'){
                    $resolvedTarget=Resolve-PCTokenPath $authorization.ShortcutTarget
                    if(-not (Test-Path -LiteralPath $resolvedTarget)){throw "Shortcut target is not installed: $resolvedTarget"}
                }
                $sourceFile=Resolve-PCArtifact $action.SourceArtifact
                Test-PCExpectedHash -Path $sourceFile -Expected $authorization.SHA256
                $destinationFile=Get-PCShortcutDestination $authorization.Target
                Write-Host ("  shortcut {0} -> {1}" -f $action.SourceArtifact,$destinationFile)
                if($Apply){Copy-PCFileWithBackup -ActionId $action.ActionId -SourceFile $sourceFile -DestinationFile $destinationFile}
            }
            'ImportRegistry' {
                if(-not $action.SourceArtifact -or -not $authorizedRegistry.ContainsKey($action.SourceArtifact.ToLowerInvariant())){throw 'Registry artifact is not authorized by source catalog.'}
                $authorization=$authorizedRegistry[$action.SourceArtifact.ToLowerInvariant()]
                if($authorization.Method -ne 'ImportRegistry'){throw 'Source catalog marks this registry family as manual-only.'}
                if($action.DestinationTarget -ne $authorization.Target){throw 'Registry target differs from source catalog authorization.'}
                if($action.ExpectedSourceSHA256 -and $action.ExpectedSourceSHA256 -ne $authorization.SHA256){throw 'Plan registry hash differs from source catalog.'}
                if($action.DestinationTarget -like 'HKLM\*'){
                    if(-not $AllowAdminChanges -or -not $isAdmin){throw 'HKLM import requires elevation and -AllowAdminChanges.'}
                }
                $sourceFile=Resolve-PCArtifact $action.SourceArtifact
                Test-PCExpectedHash -Path $sourceFile -Expected $authorization.SHA256
                Write-Host ("  registry {0} -> {1}" -f $action.SourceArtifact,$action.DestinationTarget)
                if($Apply){Import-PCRegistryWithBackup -ActionId $action.ActionId -SourceFile $sourceFile -DestinationTarget $action.DestinationTarget}
            }
            'Set24HourClock' {
                Write-Host '  set current-user clock to HH:mm / HH:mm:ss'
                if($Apply){Set-PC24HourClock -ActionId $action.ActionId}
            }
            'SetTimeZone' {
                if(-not $authorizedTimeZone -or $action.DestinationTarget -ne $authorizedTimeZone){throw 'Time-zone ID differs from source capture.'}
                if(-not $isAdmin -or -not $AllowAdminChanges){throw 'Time-zone change requires elevation and -AllowAdminChanges.'}
                Write-Host ('  set system time zone: '+$authorizedTimeZone)
                if($Apply){
                    $previous=[TimeZoneInfo]::Local.Id
                    [void]$backupRows.Add([pscustomobject]@{ActionId=$action.ActionId;Type='TimeZone';Destination=$authorizedTimeZone;BackupRelativePath='';Note=$previous})
                    Save-PCBackupManifest
                    Set-TimeZone -Id $authorizedTimeZone -ErrorAction Stop
                }
            }
            'EnableFeature' {
                if(-not $action.FeatureName -or -not $authorizedFeatures.ContainsKey($action.FeatureName.ToLowerInvariant())){throw 'Feature is not enabled in the source capture.'}
                if(-not $isAdmin -or -not $AllowAdminChanges){throw 'Feature enable requires elevation and -AllowAdminChanges.'}
                Write-Host ('  enable Windows feature: '+$action.FeatureName)
                if($Apply){
                    [void]$backupRows.Add([pscustomobject]@{ActionId=$action.ActionId;Type='NonReversible';Destination=$action.FeatureName;BackupRelativePath='';Note='Feature enable was attempted and is not automatically rolled back.'})
                    Save-PCBackupManifest
                    Enable-WindowsOptionalFeature -Online -FeatureName $action.FeatureName -All -NoRestart -ErrorAction Stop|Out-Null
                }
            }
            'AddCapability' {
                if(-not $action.CapabilityName -or -not $authorizedCapabilities.ContainsKey($action.CapabilityName.ToLowerInvariant())){throw 'Capability is not installed in the source capture.'}
                if(-not $isAdmin -or -not $AllowAdminChanges){throw 'Capability install requires elevation and -AllowAdminChanges.'}
                Write-Host ('  add Windows capability: '+$action.CapabilityName)
                if($Apply){
                    [void]$backupRows.Add([pscustomobject]@{ActionId=$action.ActionId;Type='NonReversible';Destination=$action.CapabilityName;BackupRelativePath='';Note='Capability install was attempted and is not automatically rolled back.'})
                    Save-PCBackupManifest
                    Add-WindowsCapability -Online -Name $action.CapabilityName -ErrorAction Stop|Out-Null
                }
            }
        }
        if($Apply){$status='Applied'}else{$status='Ready (preview)'}
    }catch{
        $status='Blocked/Failed';$message=$_.Exception.Message
        Write-Warning "$($action.ActionId) $($action.Item): $message"
        if($StopOnError -and $Apply){$stopAfterResult=$true}
    }
    [void]$resultRows.Add([pscustomobject]@{
        ActionId=$action.ActionId;Method=$action.Method;Item=$action.Item;Status=$status
        Message=$message;StartedAt=$started.ToString('o');FinishedAt=(Get-Date).ToString('o')
    })
    Save-PCRepairResults
    if($stopAfterResult){throw "Repair stopped after $($action.ActionId): $message"}
}

if($Apply){
    Save-PCBackupManifest
    Save-PCRepairResults
    Write-Host ''
    Write-Host "Repair pass finished. Backup and results: $backup" -ForegroundColor Green
    Write-Host 'Recapture the destination and run Compare-PCMigrationState-v4.0.0.ps1 again.' -ForegroundColor Green
}else{
    Write-Host ''
    Write-Host 'Preview only. Resolve all Blocked items, then add -Apply.' -ForegroundColor Green
}

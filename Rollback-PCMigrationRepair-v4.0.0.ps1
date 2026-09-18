#requires -version 5.1
<# Preview or roll back file/registry mutations recorded by a v4.0.0 repair pass. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BackupPath,
    [switch]$RemoveNewRegistryKeys,
    [switch]$Apply,
    [switch]$StopOnError
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PCMigration.Common-v4.0.0.ps1')

$backup=[IO.Path]::GetFullPath($BackupPath)
$manifestPath=Join-Path $backup 'Backup-Manifest.csv'
if(-not [IO.File]::Exists($manifestPath)){throw "Backup-Manifest.csv not found: $backup"}
$manifest=@(Import-Csv -LiteralPath $manifestPath)
$rows=New-Object System.Collections.ArrayList

Write-Host "PCMigration rollback v4.0.0 - $(if($Apply){'APPLY'}else{'PREVIEW'})" -ForegroundColor Cyan
Write-Host "Backup: $backup"

for($index=$manifest.Count-1;$index -ge 0;$index--){
    $item=$manifest[$index]
    $status='Ready';$message=''
    try{
        switch($item.Type){
            'File' {
                if(-not $item.BackupRelativePath){throw 'File backup path is missing.'}
                $sourceFile=[IO.Path]::GetFullPath((Join-Path $backup $item.BackupRelativePath))
                if(-not $sourceFile.StartsWith($backup.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Backup path escapes backup folder.'}
                if(-not [IO.File]::Exists($sourceFile)){throw "Backup file is missing: $sourceFile"}
                Write-Host ("  restore file: {0}" -f $item.Destination)
                if($Apply){
                    New-PCDirectory ([IO.Path]::GetDirectoryName($item.Destination))
                    [IO.File]::Copy($sourceFile,$item.Destination,$true)
                }
            }
            'File-New' {
                Write-Host ("  remove newly created file: {0}" -f $item.Destination)
                if($Apply -and [IO.File]::Exists($item.Destination)){[IO.File]::Delete($item.Destination)}
            }
            'Registry' {
                if(-not $item.BackupRelativePath){throw 'Registry backup path is missing.'}
                $sourceFile=[IO.Path]::GetFullPath((Join-Path $backup $item.BackupRelativePath))
                if(-not $sourceFile.StartsWith($backup.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Backup path escapes backup folder.'}
                if(-not [IO.File]::Exists($sourceFile)){throw "Registry backup is missing: $sourceFile"}
                Write-Host ("  restore registry: {0}" -f $item.Destination)
                if($Apply){
                    $reg=Join-Path $env:SystemRoot 'System32\reg.exe'
                    $canonical=if($item.Destination -match '^HKCU\\(.+)$'){
                        'HKEY_CURRENT_USER\'+$matches[1]
                    }elseif($item.Destination -match '^HKLM\\(.+)$'){
                        'HKEY_LOCAL_MACHINE\'+$matches[1]
                    }else{throw 'Unsafe registry target in backup manifest.'}
                    $header=@([IO.File]::ReadAllLines($sourceFile)|Where-Object {$_ -match '^\[([^\]]+)\]$'}|Select-Object -First 1)
                    $headerPath=if($header.Count -and $header[0].Length -ge 2){$header[0].Substring(1,$header[0].Length-2)}else{''}
                    if(-not $headerPath -or $headerPath -ne $canonical){throw 'Registry backup header does not match the recorded destination.'}
                    $deleteResult=Invoke-PCNativeProcess -FilePath $reg -Arguments ('delete "'+$item.Destination+'" /f')
                    $deleteText=$deleteResult.StdOut+[Environment]::NewLine+$deleteResult.StdErr
                    if($deleteResult.ExitCode -ne 0 -and $deleteText -notmatch '(?i)unable to find|not find'){throw "Registry cleanup before rollback failed: $($deleteText.Trim())"}
                    $result=Invoke-PCNativeProcess -FilePath $reg -Arguments ('import "'+$sourceFile+'"')
                    if($result.ExitCode -ne 0){throw "Registry rollback failed: $($result.StdErr.Trim())"}
                }
            }
            'Registry-New' {
                if(-not $RemoveNewRegistryKeys){
                    $status='Skipped'
                    $message='Use -RemoveNewRegistryKeys to delete a registry subtree that did not exist before repair.'
                    Write-Warning "$($item.Destination): $message"
                }else{
                    if($item.Destination -notmatch '^(HKCU|HKLM)\\.+'){throw 'Unsafe registry target in backup manifest.'}
                    Write-Host ("  delete newly created registry subtree: {0}" -f $item.Destination)
                    if($Apply){
                        $reg=Join-Path $env:SystemRoot 'System32\reg.exe'
                        $result=Invoke-PCNativeProcess -FilePath $reg -Arguments ('delete "'+$item.Destination+'" /f')
                        $deleteText=$result.StdOut+[Environment]::NewLine+$result.StdErr
                        if($result.ExitCode -ne 0 -and $deleteText -notmatch '(?i)unable to find|not find'){throw "Registry deletion failed: $($deleteText.Trim())"}
                    }
                }
            }
            'TimeZone' {
                if(-not $item.Note){throw 'Previous time-zone ID is missing from the backup manifest.'}
                Write-Host ("  restore system time zone: {0}" -f $item.Note)
                if($Apply){Set-TimeZone -Id $item.Note -ErrorAction Stop}
            }
            'NonReversible' {
                $status='Manual'
                $message=$item.Note
                Write-Warning "$($item.ActionId): $message"
            }
            default {throw "Unknown backup item type: $($item.Type)"}
        }
        if($status -eq 'Ready'){$status=if($Apply){'Rolled back'}else{'Ready (preview)'}}
    }catch{
        $status='Failed';$message=$_.Exception.Message
        Write-Warning "$($item.ActionId): $message"
        if($StopOnError -and $Apply){throw}
    }
    [void]$rows.Add([pscustomobject]@{
        ActionId=$item.ActionId;Type=$item.Type;Destination=$item.Destination
        Status=$status;Message=$message
    })
}

if($Apply){
    Export-PCCsv -Path (Join-Path $backup ('Rollback-Results-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.csv')) -Rows $rows.ToArray() -Columns @(
        'ActionId','Type','Destination','Status','Message'
    )
    Write-Host 'Rollback pass finished. Sign out/in if shell or regional state was restored.' -ForegroundColor Green
}else{Write-Host 'Preview only. Add -Apply after reviewing every row.' -ForegroundColor Green}

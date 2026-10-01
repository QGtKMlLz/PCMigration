#requires -version 5.1
<# Windows 10 tile-grid fallback. Preview by default. Replaces only one tile-grid subtree.
   Independent from Repair-Plan.csv. Undocumented binary format; use after XML omissions are established. #>
[CmdletBinding(DefaultParameterSetName='Restore')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Restore')][string]$CapturePath,
    [Parameter(Mandatory=$true,ParameterSetName='Rollback')][string]$RollbackBackup,
    [Parameter(ParameterSetName='Restore')][string]$DestinationTileGridChildName,
    [Parameter(ParameterSetName='Restore')][switch]$ForceDifferentBuild,
    [switch]$Apply
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StartMenu.Common-v4.1.0.ps1')
$os=Assert-PCStartHost
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Assert-PCStartBackup {
    param([string]$Directory)
    $manifest=Assert-PCStartManifest $Directory
    foreach($rel in @('BackupMeta.json','Destination-TileGrid.reg','StartPolicy.json')){
        Assert-PCStartListed $manifest $rel
    }
    $meta=[IO.File]::ReadAllText((Join-Path $Directory 'BackupMeta.json'))|ConvertFrom-Json
    if([string]$meta.BackupType -ne 'StartTileGrid-1.0' -or [string]$meta.UserSid -ne $sid -or
        [string]$meta.ComputerName -ne $env:COMPUTERNAME -or [string]$meta.WindowsBuild -ne [string]$os.BuildNumber){
        throw 'Rollback backup must belong to this user, computer, and Windows build.'
    }
    if(-not (Test-PCStartChild ([string]$meta.DestinationChildName))){throw 'Invalid rollback target.'}
    return $meta
}

if($PSCmdlet.ParameterSetName -eq 'Rollback'){
    $rb=[IO.Path]::GetFullPath($RollbackBackup).TrimEnd('\')
    $bm=Assert-PCStartBackup $rb
    $child=[string]$bm.DestinationChildName
    $text=[IO.File]::ReadAllText((Join-Path $rb 'Destination-TileGrid.reg'))
    [void](Convert-PCStartReg $text $child $child)
    $policy=@([IO.File]::ReadAllText((Join-Path $rb 'StartPolicy.json'))|ConvertFrom-Json)
    Write-Host "Rollback ONLY this tile-grid and three Start policy values: $child" -ForegroundColor Yellow
    if(-not $Apply){Write-Host 'Preview only. Re-run with -Apply.';return}
    try{
        Stop-PCStartShell
        Remove-PCStartTileKey $child
        Invoke-PCStartReg @('import',(Join-Path $rb 'Destination-TileGrid.reg'))
        Set-PCStartPolicyState $policy
    }finally{Start-Process -FilePath "$env:SystemRoot\explorer.exe"}
    Write-Host 'Rollback completed. SIGN OUT and SIGN BACK IN.' -ForegroundColor Green
    return
}

$capture=[IO.Path]::GetFullPath($CapturePath).TrimEnd('\')
$verifiedCapture=Read-PCStartMeta $capture
$sourceMeta=$verifiedCapture.Meta
if([int]$sourceMeta.WindowsBuild -lt 10240 -or [int]$sourceMeta.WindowsBuild -ge 22000){throw 'Source must be a Windows 10 tile capture.'}
if([string]$sourceMeta.WindowsBuild -ne [string]$os.BuildNumber -and -not $ForceDifferentBuild){
    throw 'Windows builds differ. Binary tile-grid restore is blocked. -ForceDifferentBuild is an explicit unsupported override for Windows 10 only.'
}
if($ForceDifferentBuild){Write-Warning 'Different Windows 10 builds can interpret tile-grid binary state differently.'}
$indexRel='CloudStore\CloudStore-KeyIndex.csv'
Assert-PCStartListed $verifiedCapture.Manifest $indexRel
$indexFile=Get-PCStartContainedFile $capture $indexRel
$sourceKeys=@(Import-Csv -LiteralPath $indexFile | Where-Object {
    (Test-PCStartChild ([string]$_.ChildName)) -and [string]$_.ExportExitCode -eq '0'
})
if($sourceKeys.Count -ne 1){throw "Expected one successfully captured tile-grid; found $($sourceKeys.Count). Review the capture index."}
$source=$sourceKeys[0]
$regLeaf=[string]$source.RegFile
if([IO.Path]::GetFileName($regLeaf) -cne $regLeaf -or $regLeaf -notmatch '^Key-[0-9]+\.reg$'){throw 'Invalid tile-grid export filename.'}
$regRel='CloudStore\'+$regLeaf
Assert-PCStartListed $verifiedCapture.Manifest $regRel
$regFile=Get-PCStartContainedFile $capture $regRel
$destKeys=@(Get-PCStartKeys)
if($DestinationTileGridChildName){$destKeys=@($destKeys|Where-Object ChildName -eq $DestinationTileGridChildName)}
if($destKeys.Count -gt 1){
    $withData=@($destKeys|Where-Object HasData)
    if($withData.Count -eq 1){$destKeys=$withData}
}
if($destKeys.Count -eq 0){throw 'No destination tile-grid found. Pin one tile, sign out/in, and retry.'}
if($destKeys.Count -gt 1){
    $destKeys|Format-Table -Property @('ChildName','HasData') -AutoSize
    throw 'Ambiguous destination tile-grid. Supply -DestinationTileGridChildName from the displayed list.'
}
$child=[string]$destKeys[0].ChildName
$srcChild=[string]$source.ChildName
$mapped=Convert-PCStartReg ([IO.File]::ReadAllText($regFile)) $srcChild $child
$regPath='HKCU\'+$script:PCStartCloudSub+'\'+$child
Write-Host "Source tile-grid:      $srcChild"
Write-Host "Destination identity:  $child"
Write-Host 'Only the registry HEADER paths are remapped; source values remain intact.'
Write-Host 'This replaces the tile grid and clears three current-user Start layout policy values.'
Write-Host 'App identities and installed apps must already exist. Shortcuts are not copied here.'
if(-not $Apply){Write-Host 'Preview only. Re-run with -Apply.' -ForegroundColor Yellow;return}

$backup=New-PCStartBackupDirectory 'PCMigration-StartTileGrid-Backup'
$destBackup=Join-Path $backup 'Destination-TileGrid.reg'
Invoke-PCStartReg @('export',$regPath,$destBackup,'/y')
[void](Convert-PCStartReg ([IO.File]::ReadAllText($destBackup)) $child $child)
$policy=@(Get-PCStartPolicyState)
Write-PCStartJson (Join-Path $backup 'StartPolicy.json') $policy
Write-PCStartJson (Join-Path $backup 'BackupMeta.json') ([ordered]@{
    BackupType='StartTileGrid-1.0';ToolkitVersion='4.1.0';CapturedAt=(Get-Date).ToString('o')
    UserSid=$sid;ComputerName=$env:COMPUTERNAME;WindowsBuild=[string]$os.BuildNumber
    DestinationChildName=$child;SourceChildName=$srcChild;SourceCapture=$capture
})
Write-PCStartManifest $backup
[void](Assert-PCStartBackup $backup)
Write-Host "Backup: $backup" -ForegroundColor Cyan
# Small native .reg staging file outside the capture/package and removed in finally.
$work=Join-Path $env:TEMP ('PCMigration-TileGrid-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$patched=Join-Path $work 'Mapped.reg'
$mutated=$false
try{
    [IO.File]::WriteAllText($patched,$mapped,[Text.Encoding]::Unicode)
    Stop-PCStartShell
    $mutated=$true
    Clear-PCStartPolicy
    Remove-PCStartTileKey $child
    Invoke-PCStartReg @('import',$patched)
    $after=Join-Path $work 'After.reg'
    Invoke-PCStartReg @('export',$regPath,$after,'/y')
    $actual=Convert-PCStartReg ([IO.File]::ReadAllText($after)) $child $child
    if(($mapped -replace "`r`n","`n").Trim() -cne ($actual -replace "`r`n","`n").Trim()){
        throw 'Post-import registry verification failed.'
    }
}catch{
    $original=$_.Exception.Message
    if($mutated){
        try{
            Remove-PCStartTileKey $child
            Invoke-PCStartReg @('import',$destBackup)
            Set-PCStartPolicyState $policy
            Write-Warning 'The operation failed; the previous tile-grid and Start policy were restored.'
        }catch{
            throw "Restore failed: $original. Automatic rollback also failed: $($_.Exception.Message). Keep backup: $backup"
        }
    }
    throw "Restore failed: $original. Backup: $backup"
}finally{
    Start-Process -FilePath "$env:SystemRoot\explorer.exe"
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'Tile-grid import and immediate registry verification completed. SIGN OUT and SIGN BACK IN.' -ForegroundColor Green
Write-Host 'Registry verification does not prove that every application tile will render.'
Write-Host "Rollback: .\Restore-StartTileGrid-v4.1.0.ps1 -RollbackBackup '$backup' -Apply"

#requires -version 5.1
<# Windows 10 XML layout diagnostics and explicit policy application.
   Output creation is read-only with respect to Windows settings. Shortcut repair uses the main toolkit. #>
[CmdletBinding(DefaultParameterSetName='Diagnose')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Diagnose')][string]$CapturePath,
    [Parameter(ParameterSetName='Diagnose')][string]$OutputPath,
    [Parameter(ParameterSetName='Diagnose')][ValidateSet('Links','IDs')][string]$LayoutMode='Links',
    [Parameter(ParameterSetName='Diagnose')][string]$NameMatchPattern,
    [Parameter(ParameterSetName='Diagnose')][switch]$BuildCorrectedLayout,
    [Parameter(ParameterSetName='Diagnose')][switch]$ApplyPolicy,
    [Parameter(Mandatory=$true,ParameterSetName='Remove')][switch]$RemovePolicy,
    [Parameter(Mandatory=$true,ParameterSetName='Rollback')][string]$RollbackBackup,
    [switch]$Apply
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StartMenu.Common-v4.1.0.ps1')
$os=Assert-PCStartHost
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function New-PCLayoutPolicyBackup {
    $dir=New-PCStartBackupDirectory 'PCMigration-StartPolicy-Backup'
    Write-PCStartJson (Join-Path $dir 'StartPolicy.json') @(Get-PCStartPolicyState)
    Write-PCStartJson (Join-Path $dir 'BackupMeta.json') ([ordered]@{
        BackupType='StartLayoutPolicy-1.0';UserSid=$sid;ComputerName=$env:COMPUTERNAME
        WindowsBuild=[string]$os.BuildNumber;CapturedAt=(Get-Date).ToString('o');ToolkitVersion='4.1.0'
    })
    Write-PCStartManifest $dir
    return $dir
}

if($PSCmdlet.ParameterSetName -eq 'Rollback'){
    $rb=[IO.Path]::GetFullPath($RollbackBackup).TrimEnd('\')
    $manifest=Assert-PCStartManifest $rb
    foreach($name in @('BackupMeta.json','StartPolicy.json')){Assert-PCStartListed $manifest $name}
    $meta=[IO.File]::ReadAllText((Join-Path $rb 'BackupMeta.json'))|ConvertFrom-Json
    if([string]$meta.BackupType -ne 'StartLayoutPolicy-1.0' -or [string]$meta.UserSid -ne $sid -or
        [string]$meta.ComputerName -ne $env:COMPUTERNAME -or [string]$meta.WindowsBuild -ne [string]$os.BuildNumber){
        throw 'Policy rollback must use a backup from this user, computer, and Windows build.'
    }
    $rows=@([IO.File]::ReadAllText((Join-Path $rb 'StartPolicy.json'))|ConvertFrom-Json)
    Write-Host 'Would restore only the three backed-up current-user Start policy values.'
    if(-not $Apply){Write-Host 'Preview only. Re-run with -Apply.';return}
    Set-PCStartPolicyState $rows
    Write-Host 'Policy rollback completed. Sign out/in. This does not restore a prior tile grid.' -ForegroundColor Green
    return
}

if($PSCmdlet.ParameterSetName -eq 'Remove'){
    Write-Host 'Would clear LockedStartLayout, StartLayoutFile, and ReapplyStartLayoutEveryLogon for this user.'
    if(-not $Apply){Write-Host 'Preview only. Re-run with -Apply.';return}
    $backup=New-PCLayoutPolicyBackup
    Clear-PCStartPolicy
    Write-Host "Policy values cleared. Backup: $backup" -ForegroundColor Green
    Write-Host 'Sign out/in. Managed policy may be reapplied. Removing policy does not restore the previous tile layout.'
    return
}

$capture=[IO.Path]::GetFullPath($CapturePath).TrimEnd('\')
$verifiedCapture=Read-PCStartMeta $capture
$meta=$verifiedCapture.Meta
if([int]$meta.WindowsBuild -lt 10240 -or [int]$meta.WindowsBuild -ge 22000){throw 'Source must be a Windows 10 Start capture.'}
if(-not $OutputPath){$OutputPath=Join-Path $env:LOCALAPPDATA ('PCMigration\StartReports-'+[guid]::NewGuid().ToString('N'))}
$out=[IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
if($out.Equals($capture,[StringComparison]::OrdinalIgnoreCase) -or $out.StartsWith($capture+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'Report output must be outside the source capture.'
}
if(Test-Path -LiteralPath $out){throw 'Use a new, nonexistent report directory.'}
[void][IO.Directory]::CreateDirectory($out)
$apps=@(Get-StartApps -ErrorAction Stop)
$ids=@{}
foreach($app in $apps){if($app.AppID){$ids[[string]$app.AppID]=$true}}

function Expand-PCLayoutLink {
    param([string]$Path)
    if(-not $Path){return ''}
    $value=$Path
    # New captures record source roots so absolute links can be remapped between user names.
    foreach($pair in @(@('SourceAppData',$env:APPDATA),@('SourceProgramData',$env:ProgramData),@('SourceUserProfile',$env:USERPROFILE))){
        $prop=$meta.PSObject.Properties[$pair[0]]
        if($null -eq $prop -or -not $prop.Value){continue}
        $prefix=([string]$prop.Value).TrimEnd('\')
        if($value.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase)){
            $value=[string]$pair[1]+$value.Substring($prefix.Length);break
        }
    }
    return [Environment]::ExpandEnvironmentVariables($value)
}

function Get-PCLayoutRelativeLocation {
    param([string]$Path)
    foreach($pair in @(@('current user',(Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu')),
                      @('all users',(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu')))){
        $prefix=([string]$pair[1]).TrimEnd('\')
        if($Path.StartsWith($prefix+'\',[StringComparison]::OrdinalIgnoreCase)){
            return 'Start Menu ('+$pair[0]+')\'+$Path.Substring($prefix.Length+1)
        }
    }
    return $Path
}

$documents=@{}
$allRows=New-Object System.Collections.ArrayList
foreach($mode in @('Links','IDs')){
    $rel='StartLayout-'+$mode+'.xml'
    if(-not [IO.File]::Exists((Join-Path $capture $rel))){continue}
    Assert-PCStartListed $verifiedCapture.Manifest $rel
    $doc=Read-PCStartXml (Get-PCStartContainedFile $capture $rel)
    $documents[$mode]=$doc
    $rows=New-Object System.Collections.ArrayList
    $n=0
    foreach($node in @($doc.SelectNodes("//*[local-name()='DesktopApplicationTile' or local-name()='Tile' or local-name()='SecondaryTile']"))){
        $n++
        $link=[string]$node.GetAttribute('DesktopApplicationLinkPath')
        $did=[string]$node.GetAttribute('DesktopApplicationID')
        $aumid=[string]$node.GetAttribute('AppUserModelID')
        $expanded=Expand-PCLayoutLink $link
        $exists=($expanded -and (Test-Path -LiteralPath $expanded -PathType Leaf))
        $relative=if($expanded){Get-PCLayoutRelativeLocation $expanded}else{''}
        $resolved=($did -and $ids.ContainsKey($did)) -or ($aumid -and $ids.ContainsKey($aumid))
        $group='';$parent=$node.ParentNode
        while($null -ne $parent){
            if($parent.LocalName -in @('Group','StartGroup','AppendGroup')){$group=[string]$parent.GetAttribute('Name');break}
            $parent=$parent.ParentNode
        }
        $row=[pscustomobject]@{
            ExportMode=$mode;TileNumber=$n;Group=$group;TileType=$node.LocalName
            RelativeLocation=$relative;DesktopApplicationLinkPath=$link;DestinationLinkPath=$expanded
            DestinationShortcutExists=[bool]$exists;DesktopApplicationID=$did;AppUserModelID=$aumid
            IdentityResolved=[bool]$resolved
        }
        [void]$rows.Add($row);[void]$allRows.Add($row)
        # Build only from existing destination links, never stage or blindly copy source shortcuts.
        if($link -and $exists){$node.SetAttribute('DesktopApplicationLinkPath',$expanded)}
    }
    $rows.ToArray()|Export-Csv -LiteralPath (Join-Path $out ('StartTiles-'+$mode+'-Diagnostics.csv')) -NoTypeInformation -Encoding UTF8
}
if($NameMatchPattern){
    $allRows.ToArray()|Where-Object {($_|ConvertTo-Json -Compress) -match $NameMatchPattern} |
        Export-Csv -LiteralPath (Join-Path $out 'Named-Tile-Matches.csv') -NoTypeInformation -Encoding UTF8
    $apps|Where-Object {([string]$_.Name+' '+[string]$_.AppID) -match $NameMatchPattern} |
        Export-Csv -LiteralPath (Join-Path $out 'Named-StartApps-Matches.csv') -NoTypeInformation -Encoding UTF8
}

if($BuildCorrectedLayout -or $ApplyPolicy){
    if(-not $documents.ContainsKey($LayoutMode)){throw "Source $LayoutMode layout export is unavailable."}
    $layout=$documents[$LayoutMode]
    if($layout.DocumentElement.LocalName -ne 'LayoutModificationTemplate' -or
       $null -eq $layout.SelectSingleNode("//*[local-name()='StartLayoutCollection']")){
        throw 'Expected a Windows 10 XML Start layout.'
    }
    # This workflow concerns Start tiles, not taskbar pins.
    foreach($node in @($layout.SelectNodes("//*[local-name()='CustomTaskbarLayoutCollection']"))){[void]$node.ParentNode.RemoveChild($node)}
    $corrected=Join-Path $out 'StartLayout-Corrected.xml'
    $settings=New-Object Xml.XmlWriterSettings
    $settings.Encoding=New-Object Text.UTF8Encoding($true)
    $settings.Indent=$true
    $writer=[Xml.XmlWriter]::Create($corrected,$settings)
    try{$layout.Save($writer)}finally{$writer.Dispose()}
    Write-Host "Corrected UTF-8 XML: $corrected"
    $unresolved=@($allRows.ToArray()|Where-Object {$_.ExportMode -eq $LayoutMode -and -not $_.DestinationShortcutExists -and -not $_.IdentityResolved})
    if($unresolved.Count){Write-Warning "$($unresolved.Count) tiles have unresolved links/identities. Install apps and use the core shortcut repair first."}
    if($ApplyPolicy){
        Write-Host 'Would install a full Start layout policy. It locks customization until policy is removed.' -ForegroundColor Yellow
        if(-not $Apply){Write-Host 'Preview only. Use -ApplyPolicy -Apply to change Windows.'}
        else{
            $backup=New-PCLayoutPolicyBackup
            $policyDir=Join-Path $env:LOCALAPPDATA ('PCMigration\StartLayout-'+[guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($policyDir)
            $policyFile=Join-Path $policyDir 'StartLayout.xml'
            [IO.File]::Copy($corrected,$policyFile,$false)
            try{
                Set-PCStartPolicyState @(
                    [pscustomobject]@{Name='LockedStartLayout';Present=$true;Kind='DWord';Value=1}
                    [pscustomobject]@{Name='StartLayoutFile';Present=$true;Kind='ExpandString';Value=$policyFile}
                    [pscustomobject]@{Name='ReapplyStartLayoutEveryLogon';Present=$true;Kind='DWord';Value=1}
                )
            }catch{
                $previous=@([IO.File]::ReadAllText((Join-Path $backup 'StartPolicy.json'))|ConvertFrom-Json)
                Set-PCStartPolicyState $previous
                throw
            }
            Write-Host "Policy installed. Backup: $backup" -ForegroundColor Green
            Write-Host 'SIGN OUT/IN. Once checked, use -RemovePolicy -Apply, then sign out/in to unlock it.'
            Write-Host 'Policy rollback restores policy values only. Capture the destination with Capture-StartMenu before applying if the old tile layout matters.'
        }
    }
}elseif($Apply){throw '-Apply requires -ApplyPolicy for layout diagnosis.'}
Write-Host "Start layout diagnostics: $out" -ForegroundColor Green
Write-Host 'Compare both export modes with the visible source. XML omissions cannot be recovered by editing XML.'

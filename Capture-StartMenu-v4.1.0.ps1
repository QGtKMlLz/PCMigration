#requires -version 5.1
<# Separate Windows 10 Start capture. Does not stop shell processes or change the registry. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StartMenu.Common-v4.1.0.ps1')
$os=Assert-PCStartHost
$out=[IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
if(Test-Path -LiteralPath $out){throw 'Use a new, nonexistent Start capture directory.'}
[void][IO.Directory]::CreateDirectory($out)
$status=New-Object System.Collections.ArrayList
$shortcutRows=New-Object System.Collections.ArrayList
$index=New-Object System.Collections.ArrayList
$meta=[ordered]@{
    SchemaVersion='StartMenu-1.0';ToolkitVersion='4.1.0';CapturedAt=(Get-Date).ToString('o')
    ComputerName=$env:COMPUTERNAME;UserName=$env:USERNAME
    UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    WindowsBuild=[string]$os.BuildNumber;WindowsVersion=[string]$os.Version
    SourceAppData=$env:APPDATA;SourceProgramData=$env:ProgramData;SourceUserProfile=$env:USERPROFILE
}
Write-PCStartJson (Join-Path $out 'Meta.json') $meta

function Copy-PCStartShortcuts {
    param([string]$Source,[string]$Token)
    if(-not (Test-Path -LiteralPath $Source -PathType Container)){return}
    $sourceRoot=[IO.Path]::GetFullPath($Source).TrimEnd('\')
    $queue=New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($sourceRoot)
    while($queue.Count){
        $directory=$queue.Dequeue()
        # Skip junctions before recursing; copying only .lnk/.url is intentional.
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)){
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            if($item.PSIsContainer){$queue.Enqueue($item.FullName);continue}
            if($item.Extension -notin @('.lnk','.url')){continue}
            $rel=$item.FullName.Substring($sourceRoot.Length).TrimStart('\')
            $dst=Join-Path (Join-Path $out ('StartMenu\'+$Token)) $rel
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dst))
            [IO.File]::Copy($item.FullName,$dst,$false)
            [void]$shortcutRows.Add([pscustomobject]@{
                Scope=$Token;RelativeLocation=('Start Menu ('+$Token+')\'+$rel)
                RelativePath=$rel;SourcePath=$item.FullName;CapturePath=('StartMenu\'+$Token+'\'+$rel)
                SHA256=(Get-PCStartHash $dst)
            })
        }
    }
}

foreach($pair in @(@('User',(Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu')),
                  @('Common',(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu')))){
    try{
        Copy-PCStartShortcuts $pair[1] $pair[0]
        [void]$status.Add([pscustomobject]@{Collector=('Shortcuts.'+$pair[0]);Status='Success';Message=''})
    }catch{[void]$status.Add([pscustomobject]@{Collector=('Shortcuts.'+$pair[0]);Status='Partial';Message=$_.Exception.Message})}
}

foreach($mode in @('Links','IDs')){
    try{
        $path=Join-Path $out ('StartLayout-'+$mode+'.xml')
        if($mode -eq 'IDs'){Export-StartLayout -LiteralPath $path -UseDesktopApplicationID -ErrorAction Stop}
        else{Export-StartLayout -LiteralPath $path -ErrorAction Stop}
        [void](Read-PCStartXml $path)
        [void]$status.Add([pscustomobject]@{Collector=('Layout.'+$mode);Status='Success';Message='Export may omit live pins; compare visually with the source.'})
    }catch{[void]$status.Add([pscustomobject]@{Collector=('Layout.'+$mode);Status='Failed';Message=$_.Exception.Message})}
}
try{
    Get-StartApps -ErrorAction Stop | Select-Object -Property @('Name','AppID') |
        Export-Csv -LiteralPath (Join-Path $out 'Get-StartApps.csv') -NoTypeInformation -Encoding UTF8
    [void]$status.Add([pscustomobject]@{Collector='StartApps';Status='Success';Message=''})
}catch{[void]$status.Add([pscustomobject]@{Collector='StartApps';Status='Failed';Message=$_.Exception.Message})}

$cloudOut=Join-Path $out 'CloudStore'
[void][IO.Directory]::CreateDirectory($cloudOut)
$keys=@(Get-PCStartKeys)
$n=0
foreach($key in $keys){
    $n++;$file=('Key-{0:D3}.reg' -f $n);$path=Join-Path $cloudOut $file
    $regPath='HKCU\'+$script:PCStartCloudSub+'\'+$key.ChildName
    $rc=0;$message=''
    try{
        Invoke-PCStartReg @('export',$regPath,$path,'/y')
        # Validate every exported header before accepting the capture.
        [void](Convert-PCStartReg ([IO.File]::ReadAllText($path)) $key.ChildName $key.ChildName)
    }catch{$rc=1;$message=$_.Exception.Message}
    [void]$index.Add([pscustomobject]@{
        ChildName=$key.ChildName;RegistryPath=$regPath;RegFile=$file;ExportExitCode=$rc
        HasData=$key.HasData;SHA256=$(if($rc -eq 0){Get-PCStartHash $path}else{''});Message=$message
    })
}
$cloudStatus=if($keys.Count -eq 0){'Missing'}elseif(@($index.ToArray()|Where-Object ExportExitCode -ne 0).Count){'Partial'}else{'Success'}
[void]$status.Add([pscustomobject]@{Collector='CloudStore.TileGrid';Status=$cloudStatus;Message='Only curated Start tile-grid keys are exported; systempartitionindex is excluded.'})
$index.ToArray()|Export-Csv -LiteralPath (Join-Path $cloudOut 'CloudStore-KeyIndex.csv') -NoTypeInformation -Encoding UTF8
$shortcutRows.ToArray()|Export-Csv -LiteralPath (Join-Path $out 'StartMenu-Shortcuts.csv') -NoTypeInformation -Encoding UTF8
$status.ToArray()|Export-Csv -LiteralPath (Join-Path $out 'Capture-Status.csv') -NoTypeInformation -Encoding UTF8
Write-PCStartManifest $out
$status.ToArray()|Format-Table -Property @('Collector','Status','Message') -AutoSize -Wrap
Write-Host "Separate Start capture saved: $out" -ForegroundColor Green
Write-Host 'Retain this entire directory. A successful XML export does not prove that every visible pin was serialized.'

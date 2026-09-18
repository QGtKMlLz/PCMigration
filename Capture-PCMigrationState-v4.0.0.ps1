#requires -version 5.1
<#
.SYNOPSIS
Creates a multi-evidence inventory of a Windows 10/11 PC for migration reconciliation.

.DESCRIPTION
Run once on the source and once on the destination while logged on as the user
being migrated. The default capture is read-only outside OutputPath. Administrator
rights increase coverage but are not required; every collector records Success,
Partial, Unavailable, or Failed so incomplete coverage is never silently treated
as an absence on the PC.

When explicitly requested, inventory-only services can be temporarily started
and verified third-party application services can be quiesced around file
capture. Their original running/stopped state is restored and audited.

Standard mode inventories configuration-like files recursively while pruning
volatile caches. Deep mode inventories every nonvolatile file. Repair payload
capture is opt-in and copies only non-sensitive, non-database configuration files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateSet('Fast','Standard','Deep')][string]$InventoryMode='Standard',
    [bool]$IncludeAllUsersAppx=$true,
    [bool]$IncludeProgramData=$true,
    [string[]]$AdditionalPortableRoots=@(),
    [ValidateRange(1,512)][int]$MaximumHashedFileMiB=64,
    [ValidateRange(1,4096)][int]$MaximumPayloadMiB=512,
    [switch]$CaptureSettingsPayload,
    [switch]$CaptureRegistrySafetyBackup,
    [switch]$RegistryBackupTargetedOnly,
    [switch]$IncludePSReadLineHistory,
    [switch]$SearchSecureFileCandidates,
    [switch]$StartStoppedInventoryServices,
    [string[]]$QuiesceServiceName=@(),
    [ValidateRange(5,300)][int]$ServiceTransitionTimeoutSeconds=30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PCMigration.Common-v4.0.0.ps1')
. (Join-Path $PSScriptRoot 'RegistryBackup-v4.0.0.ps1')

$capture=[IO.Path]::GetFullPath($OutputPath)
if([IO.Directory]::Exists($capture) -and @(Get-ChildItem -LiteralPath $capture -Force -ErrorAction SilentlyContinue).Count -gt 0){
    throw "OutputPath must be new or empty so captures cannot be mixed: $capture"
}
New-PCDirectory $capture
$statusRows=New-Object System.Collections.ArrayList
$script:PCCollectorStatus='Success'
$script:PCCollectorMessage=''
$script:PCPayloadBytes=[int64]0
$script:PCServiceStateRows=New-Object System.Collections.ArrayList
$script:PCQuiescedServices=New-Object System.Collections.ArrayList
$captureStopwatch=[Diagnostics.Stopwatch]::StartNew()

function Set-PCCollectorPartial {
    param([Parameter(Mandatory=$true)][string]$Message)
    $script:PCCollectorStatus='Partial'
    if($script:PCCollectorMessage -notlike ('*'+$Message+'*')){
        if($script:PCCollectorMessage){$script:PCCollectorMessage+=' | '}
        $script:PCCollectorMessage+=$Message
    }
}

function Set-PCCollectorWarning {
    param([Parameter(Mandatory=$true)][string]$Message)
    if($script:PCCollectorMessage -notlike ('*'+$Message+'*')){
        if($script:PCCollectorMessage){$script:PCCollectorMessage+=' | '}
        $script:PCCollectorMessage+=$Message
    }
}

function Invoke-PCCaptureCollector {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Script
    )
    Write-Host ("[{0,2}] {1}" -f ($statusRows.Count+1),$Name) -ForegroundColor Cyan
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $script:PCCollectorStatus='Success'
    $script:PCCollectorMessage=''
    $count=0
    try{
        $result=& $Script
        if($null -ne $result){$count=[int]$result}
    }catch{
        $script:PCCollectorStatus='Failed'
        $script:PCCollectorMessage=$_.Exception.Message
        Write-Warning "$Name failed: $($script:PCCollectorMessage)"
        Write-PCText -Path (Join-Path $capture ('Errors\'+(Get-PCSafeFileName $Name)+'.txt')) -Text ($_|Out-String)
    }finally{$watch.Stop()}
    [void]$statusRows.Add([pscustomobject]@{
        Collector=$Name
        Status=$script:PCCollectorStatus
        Records=$count
        ElapsedSeconds=[Math]::Round($watch.Elapsed.TotalSeconds,3)
        Message=$script:PCCollectorMessage
    })
}

function Test-PCServiceQuiesceDenied {
    param($Service)
    $identity=([string]$Service.Name+'|'+[string]$Service.DisplayName)
    if($identity -match '(?i)(defender|kaspersky|antivirus|endpoint|security health|firewall)'){return $true}
    return ([string]$Service.Name -in @(
        'WinDefend','WdNisSvc','Sense','SecurityHealthService','mpssvc','BFE',
        'EventLog','RpcSs','DcomLaunch','RpcEptMapper','SamSs','LSM','ProfSvc',
        'UserManager','CryptSvc','WSearch','WpnService','CDPSvc','WlanSvc',
        'WwanSvc','Eaphost','AppXSvc','StateRepository','ClipSVC','InstallService',
        'TrustedInstaller','VSS','swprv'
    ))
}

function Restore-PCQuiescedServices {
    for($index=$script:PCQuiescedServices.Count-1;$index -ge 0;$index--){
        $entry=$script:PCQuiescedServices[$index]
        try{
            $service=Get-Service -Name $entry.Name -ErrorAction Stop
            if($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running){
                Start-Service -InputObject $service -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds($ServiceTransitionTimeoutSeconds))
            }
            $entry.RestoreResult='Running'
        }catch{
            $entry.RestoreResult='FAILED: '+$_.Exception.Message
            Write-Warning "Service $($entry.Name) could not be restored to Running: $($_.Exception.Message)"
            [void]$statusRows.Add([pscustomobject]@{
                Collector='Safety.ServiceRestore.'+$entry.Name;Status='Failed';Records=0;ElapsedSeconds=0
                Message='A service stopped for file capture could not be restored to Running: '+$_.Exception.Message
            })
        }
    }
    $script:PCQuiescedServices.Clear()
}

function Stop-PCRequestedServicesForFileCapture {
    if(@($QuiesceServiceName).Count -eq 0){return}
    if(-not (Test-PCAdministrator)){throw '-QuiesceServiceName requires an elevated PowerShell process.'}
    try{
        foreach($name in @($QuiesceServiceName|Where-Object {$_}|Sort-Object -Unique)){
            $service=Get-Service -Name $name -ErrorAction Stop
            $row=[pscustomobject]@{
                Name=[string]$service.Name
                DisplayName=[string]$service.DisplayName
                RequestedAction='StopForApplicationStateFileCapture'
                StatusBefore=[string]$service.Status
                TransitionResult='NotRequired'
                RestoreResult='NotRequired'
                Message=''
            }
            [void]$script:PCServiceStateRows.Add($row)
            if(Test-PCServiceQuiesceDenied -Service $service){
                $row.TransitionResult='Denied'
                $row.Message='Protected, security, operating-system, or nonportable-state service; quiescing is prohibited.'
                throw "Service quiescing is prohibited for $($service.Name) ($($service.DisplayName))."
            }
            if($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running){
                Stop-Service -InputObject $service -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds($ServiceTransitionTimeoutSeconds))
                $row.TransitionResult='Stopped'
                $row.RestoreResult='Pending'
                [void]$script:PCQuiescedServices.Add($row)
            }
        }
    }catch{
        Restore-PCQuiescedServices
        throw
    }
}

function Invoke-PCTemporaryServiceStart {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Operation
    )
    $service=$null;$started=$false
    $row=[pscustomobject]@{
        Name=$Name;DisplayName='';RequestedAction='StartForInventory'
        StatusBefore='Unavailable';TransitionResult='NotRequired';RestoreResult='NotRequired';Message=''
    }
    try{
        $service=Get-Service -Name $Name -ErrorAction Stop
    }catch{
        $row.TransitionResult='ServiceUnavailable'
        $row.Message=$_.Exception.Message
        [void]$script:PCServiceStateRows.Add($row)
        return (& $Operation)
    }
    $row.DisplayName=[string]$service.DisplayName
    $row.StatusBefore=[string]$service.Status
    if($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running -and $StartStoppedInventoryServices){
        try{
            Start-Service -InputObject $service -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds($ServiceTransitionTimeoutSeconds))
            $started=$true
            $row.TransitionResult='Started'
            $row.RestoreResult='Pending'
        }catch{
            $row.TransitionResult='StartFailed'
            $row.Message=$_.Exception.Message
        }
    }
    try{
        return (& $Operation)
    }finally{
        if($started -and $null -ne $service){
            try{
                Stop-Service -InputObject $service -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds($ServiceTransitionTimeoutSeconds))
                $row.RestoreResult='Stopped'
            }catch{
                $row.RestoreResult='FAILED: '+$_.Exception.Message
                Write-Warning "Service $Name could not be restored to Stopped: $($_.Exception.Message)"
                [void]$statusRows.Add([pscustomobject]@{
                    Collector='Safety.ServiceRestore.'+$Name;Status='Failed';Records=0;ElapsedSeconds=0
                    Message='A service started for inventory could not be restored to Stopped: '+$_.Exception.Message
                })
            }
        }
        [void]$script:PCServiceStateRows.Add($row)
    }
}

function Get-PCUninstallInventory {
    $locations=@(
        @{Hive='HKLM';View=[Microsoft.Win32.RegistryView]::Registry64;Sub='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'},
        @{Hive='HKLM';View=[Microsoft.Win32.RegistryView]::Registry32;Sub='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'},
        @{Hive='HKCU';View=[Microsoft.Win32.RegistryView]::Default;Sub='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'}
    )
    $rows=New-Object System.Collections.ArrayList
    foreach($location in $locations){
        $base=$null;$root=$null
        try{
            $base=Get-PCRegistryBase -Hive $location.Hive -View $location.View
            $root=$base.OpenSubKey($location.Sub,$false)
            if($null -eq $root){continue}
            foreach($keyName in @($root.GetSubKeyNames())){
                $key=$null
                try{
                    $key=$root.OpenSubKey($keyName,$false)
                    if($null -eq $key){continue}
                    $name=[string]$key.GetValue('DisplayName','')
                    if(-not $name){continue}
                    [void]$rows.Add([pscustomobject]@{
                        Hive=$location.Hive
                        View=[string]$location.View
                        KeyName=$keyName
                        DisplayName=$name
                        NormalizedName=Normalize-PCApplicationName $name
                        DisplayVersion=[string]$key.GetValue('DisplayVersion','')
                        Publisher=[string]$key.GetValue('Publisher','')
                        InstallLocation=ConvertTo-PCTokenPath ([string]$key.GetValue('InstallLocation',''))
                        InstallSource=ConvertTo-PCTokenPath ([string]$key.GetValue('InstallSource',''))
                        InstallDate=[string]$key.GetValue('InstallDate','')
                        UninstallString=ConvertTo-PCNormalizedText ([string]$key.GetValue('UninstallString',''))
                        QuietUninstallString=ConvertTo-PCNormalizedText ([string]$key.GetValue('QuietUninstallString',''))
                        ModifyPath=ConvertTo-PCNormalizedText ([string]$key.GetValue('ModifyPath',''))
                        EstimatedSizeKiB=[string]$key.GetValue('EstimatedSize','')
                        WindowsInstaller=[string]$key.GetValue('WindowsInstaller','')
                        SystemComponent=[string]$key.GetValue('SystemComponent','')
                        ReleaseType=[string]$key.GetValue('ReleaseType','')
                    })
                }catch{}
                finally{if($null -ne $key){$key.Dispose()}}
            }
        }finally{
            if($null -ne $root){$root.Dispose()}
            if($null -ne $base){$base.Dispose()}
        }
    }
    return $rows.ToArray()
}

function Convert-PCAppxPackage {
    param($Package,[string]$Scope)
    return [pscustomobject]@{
        Scope=$Scope
        Name=[string](Get-PCProperty $Package 'Name' '')
        PackageFullName=[string](Get-PCProperty $Package 'PackageFullName' '')
        PackageFamilyName=[string](Get-PCProperty $Package 'PackageFamilyName' '')
        Version=[string](Get-PCProperty $Package 'Version' '')
        Architecture=[string](Get-PCProperty $Package 'Architecture' '')
        Publisher=[string](Get-PCProperty $Package 'Publisher' '')
        PublisherId=[string](Get-PCProperty $Package 'PublisherId' '')
        IsFramework=[string](Get-PCProperty $Package 'IsFramework' $false)
        IsResourcePackage=[string](Get-PCProperty $Package 'IsResourcePackage' $false)
        NonRemovable=[string](Get-PCProperty $Package 'NonRemovable' $false)
        SignatureKind=[string](Get-PCProperty $Package 'SignatureKind' '')
        Status=[string](Get-PCProperty $Package 'Status' '')
    }
}

function Copy-PCPayloadFile {
    param(
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$RelativePayloadPath
    )
    $file=Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    $limit=[int64]$MaximumPayloadMiB*1MB
    if(($script:PCPayloadBytes+$file.Length) -gt $limit){
        Set-PCCollectorPartial "Payload limit of $MaximumPayloadMiB MiB reached; later candidates were inventory-only."
        return ''
    }
    $destination=Join-Path $capture ('Payload\'+$RelativePayloadPath)
    New-PCDirectory ([IO.Path]::GetDirectoryName($destination))
    $sourceStream=$null;$destinationStream=$null
    try{
        $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
        $sourceStream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
        $destinationStream=[IO.File]::Open($destination,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $sourceStream.CopyTo($destinationStream,1MB)
        $destinationStream.Flush()
    }catch{
        if($null -ne $destinationStream){$destinationStream.Dispose();$destinationStream=$null}
        try{if([IO.File]::Exists($destination)){[IO.File]::Delete($destination)}}catch{}
        throw
    }finally{
        if($null -ne $destinationStream){$destinationStream.Dispose()}
        if($null -ne $sourceStream){$sourceStream.Dispose()}
    }
    $script:PCPayloadBytes+=$file.Length
    return $destination.Substring($capture.TrimEnd('\').Length).TrimStart('\')
}

function Get-PCShortcutRows {
    $roots=@(
        @{Id='UserStartMenu';Path=[Environment]::GetFolderPath('StartMenu')},
        @{Id='CommonStartMenu';Path=[Environment]::GetFolderPath('CommonStartMenu')},
        @{Id='UserDesktop';Path=[Environment]::GetFolderPath('Desktop')},
        @{Id='CommonDesktop';Path=[Environment]::GetFolderPath('CommonDesktopDirectory')},
        @{Id='UserStartup';Path=[Environment]::GetFolderPath('Startup')},
        @{Id='CommonStartup';Path=[Environment]::GetFolderPath('CommonStartup')},
        @{Id='UserPinned';Path=(Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned')}
    )
    $rows=New-Object System.Collections.ArrayList
    $shell=New-Object -ComObject WScript.Shell
    try{
        foreach($root in $roots){
            if(-not $root.Path -or -not [IO.Directory]::Exists($root.Path)){continue}
            $shortcutFiles=@()
            try{$shortcutFiles=@(Get-ChildItem -LiteralPath $root.Path -File -Recurse -Force -ErrorAction Stop|Where-Object {$_.Extension -in @('.lnk','.url','.appref-ms')})}
            catch{Set-PCCollectorPartial "Some shortcuts under $($root.Id) could not be enumerated."}
            foreach($file in $shortcutFiles){
                $target='';$arguments='';$working='';$icon='';$description=''
                if($file.Extension -eq '.lnk'){
                    try{
                        $link=$shell.CreateShortcut($file.FullName)
                        $target=[string]$link.TargetPath
                        $arguments=[string]$link.Arguments
                        $working=[string]$link.WorkingDirectory
                        $icon=[string]$link.IconLocation
                        $description=[string]$link.Description
                    }catch{}
                }elseif($file.Extension -eq '.url'){
                    try{
                        foreach($line in [IO.File]::ReadAllLines($file.FullName)){
                            if(-not $target -and $line -match '^(?i:URL)=(.*)$'){$target=$matches[1]}
                            elseif(-not $icon -and $line -match '^(?i:IconFile)=(.*)$'){$icon=$matches[1]}
                        }
                    }catch{}
                }
                $relative=$file.FullName.Substring($root.Path.Length).TrimStart('\')
                $argumentSensitive=Test-PCSensitiveText -Text $arguments
                $payload=''
                if($CaptureSettingsPayload -and -not $argumentSensitive){
                    try{$payload=Copy-PCPayloadFile -Source $file.FullName -RelativePayloadPath ('Shortcuts\'+$root.Id+'\'+$relative)}catch{}
                }
                $normalizedTarget=ConvertTo-PCTokenPath $target
                $normalizedArguments=if($argumentSensitive){'[REDACTED]'}else{ConvertTo-PCNormalizedText $arguments}
                $normalizedWorking=ConvertTo-PCTokenPath $working
                $normalizedIcon=ConvertTo-PCNormalizedText $icon
                $binaryHash=Get-PCSha256File $file.FullName
                $semanticHash=if($file.Extension -in @('.lnk','.url')){
                    Get-PCShortcutSemanticDigest -Extension $file.Extension -TargetPath $normalizedTarget `
                        -Arguments $normalizedArguments -WorkingDirectory $normalizedWorking `
                        -IconLocation $normalizedIcon -Description $description
                }else{$binaryHash}
                [void]$rows.Add([pscustomobject]@{
                    RootId=$root.Id
                    RelativePath=$relative
                    RelativeLocation=Get-PCShortcutRelativeLocation -RootId $root.Id -RelativePath $relative
                    Name=$file.BaseName
                    Extension=$file.Extension
                    TargetPath=$normalizedTarget
                    TargetExists=if($target){Test-Path -LiteralPath $target}else{$false}
                    Arguments=$normalizedArguments
                    WorkingDirectory=$normalizedWorking
                    IconLocation=$normalizedIcon
                    Description=$description
                    SemanticSHA256=$semanticHash
                    SHA256=$binaryHash
                    PayloadRelativePath=$payload
                })
            }
        }
    }finally{try{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}catch{}}
    return $rows.ToArray()
}

function Get-PCStateFileManifest {
    param([array]$Roots)
    $rows=New-Object System.Collections.ArrayList
    $rootRows=New-Object System.Collections.ArrayList
    $issueRows=New-Object System.Collections.ArrayList
    $hashLimit=[int64]$MaximumHashedFileMiB*1MB
    foreach($root in $Roots){
        if(-not $root.Path -or -not [IO.Directory]::Exists($root.Path)){continue}
        $topStats=@{}
        $stack=New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
        $stack.Push((Get-Item -LiteralPath $root.Path -Force))
        while($stack.Count -gt 0){
            $directory=$stack.Pop()
            $relativeDirectory=$directory.FullName.Substring($root.Path.TrimEnd('\').Length).TrimStart('\')
            $directoryExclusion=if($relativeDirectory){Get-PCFilePolicyExclusionReason -RootToken $root.Token -RelativePath $relativeDirectory}else{''}
            if($directoryExclusion){
                Add-PCPolicyExclusion -Category 'FileTree' -Scope $root.Token -Path $relativeDirectory -Reason $directoryExclusion
                continue
            }
            if($relativeDirectory -and (Test-PCVolatileStatePath $relativeDirectory)){continue}
            if($directory.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            try{
                foreach($child in $directory.EnumerateDirectories()){
                    if(-not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)){$stack.Push($child)}
                }
            }catch{
                [void]$issueRows.Add([pscustomobject]@{
                    RootToken=$root.Token;RelativePath=$relativeDirectory;Operation='EnumerateDirectories';Message=$_.Exception.Message
                })
            }
            try{$files=@($directory.EnumerateFiles())}
            catch{
                [void]$issueRows.Add([pscustomobject]@{
                    RootToken=$root.Token;RelativePath=$relativeDirectory;Operation='EnumerateFiles';Message=$_.Exception.Message
                })
                continue
            }
            foreach($file in $files){
                $relative=$file.FullName.Substring($root.Path.TrimEnd('\').Length).TrimStart('\')
                $fileExclusion=Get-PCFilePolicyExclusionReason -RootToken $root.Token -RelativePath $relative
                if($fileExclusion){
                    Add-PCPolicyExclusion -Category 'File' -Scope $root.Token -Path $relative -Reason $fileExclusion
                    continue
                }
                $top=if($relative -match '^([^\\]+)'){$matches[1]}else{'(Root)'}
                if(-not $topStats.ContainsKey($top)){
                    $topStats[$top]=[ordered]@{FileCount=0;Bytes=[int64]0;CandidateCount=0;LatestUtc=[DateTime]::MinValue}
                }
                $stats=$topStats[$top]
                $stats.FileCount++
                $stats.Bytes+=$file.Length
                if($file.LastWriteTimeUtc -gt $stats.LatestUtc){$stats.LatestUtc=$file.LastWriteTimeUtc}
                $classification=Get-PCFileClassification $file.FullName
                $include=($InventoryMode -eq 'Deep' -or ($InventoryMode -eq 'Standard' -and $classification -ne 'Other'))
                if(-not $include){continue}
                $stats.CandidateCount++
                $sensitive=Test-PCSensitiveStatePath $relative
                if(-not $sensitive -and $CaptureSettingsPayload -and $classification -in @('Configuration','Script')){
                    $sensitive=Test-PCSensitiveFileContent -Path $file.FullName
                }
                $hash=''
                if($file.Length -le $hashLimit){
                    try{$hash=Get-PCSha256File -Path $file.FullName -ThrowOnFailure}
                    catch{
                        [void]$issueRows.Add([pscustomobject]@{
                            RootToken=$root.Token;RelativePath=$relative;Operation='HashFile';Message=$_.Exception.Message
                        })
                    }
                }
                $payload=''
                if($CaptureSettingsPayload -and -not $sensitive -and $classification -in @('Configuration','Script') -and $file.Length -le $hashLimit){
                    try{$payload=Copy-PCPayloadFile -Source $file.FullName -RelativePayloadPath ('Files\'+$root.Token+'\'+$relative)}
                    catch{
                        [void]$issueRows.Add([pscustomobject]@{
                            RootToken=$root.Token;RelativePath=$relative;Operation='CopyPayload';Message=$_.Exception.Message
                        })
                    }
                }
                [void]$rows.Add([pscustomobject]@{
                    RootToken=$root.Token
                    RelativePath=$relative
                    TopLevelRoot=$top
                    Classification=$classification
                    Sensitive=$sensitive
                    Length=$file.Length
                    LastWriteTimeUtc=$file.LastWriteTimeUtc.ToString('o')
                    SHA256=$hash
                    PayloadRelativePath=$payload
                })
            }
        }
        foreach($top in @($topStats.Keys|Sort-Object)){
            $stats=$topStats[$top]
            [void]$rootRows.Add([pscustomobject]@{
                RootToken=$root.Token
                Name=$top
                FileCount=$stats.FileCount
                Bytes=$stats.Bytes
                CandidateCount=$stats.CandidateCount
                LatestWriteTimeUtc=if($stats.LatestUtc -eq [DateTime]::MinValue){''}else{$stats.LatestUtc.ToString('o')}
            })
        }
    }
    return [pscustomobject]@{Files=$rows.ToArray();Roots=$rootRows.ToArray();Issues=$issueRows.ToArray()}
}

function Get-PCBrowserInventory {
    $profiles=New-Object System.Collections.ArrayList
    $extensions=New-Object System.Collections.ArrayList
    $chromiumRoots=@(
        @{Browser='Google Chrome';Path=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data')},
        @{Browser='Microsoft Edge';Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')},
        @{Browser='Brave';Path=(Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data')},
        @{Browser='Vivaldi';Path=(Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data')}
    )
    foreach($browser in $chromiumRoots){
        if(-not [IO.Directory]::Exists($browser.Path)){continue}
        foreach($profile in @(Get-ChildItem -LiteralPath $browser.Path -Directory -Force -ErrorAction SilentlyContinue|Where-Object {$_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$'})){
            [void]$profiles.Add([pscustomobject]@{Browser=$browser.Browser;Profile=$profile.Name;Path=ConvertTo-PCTokenPath $profile.FullName})
            $extensionRoot=Join-Path $profile.FullName 'Extensions'
            if(-not [IO.Directory]::Exists($extensionRoot)){continue}
            foreach($idFolder in @(Get-ChildItem -LiteralPath $extensionRoot -Directory -Force -ErrorAction SilentlyContinue)){
                foreach($versionFolder in @(Get-ChildItem -LiteralPath $idFolder.FullName -Directory -Force -ErrorAction SilentlyContinue)){
                    $manifestPath=Join-Path $versionFolder.FullName 'manifest.json'
                    $name='';$version=$versionFolder.Name
                    if([IO.File]::Exists($manifestPath)){
                        try{
                            $manifest=[IO.File]::ReadAllText($manifestPath)|ConvertFrom-Json
                            $name=[string](Get-PCProperty $manifest 'name' '')
                            $manifestVersion=[string](Get-PCProperty $manifest 'version' '')
                            if($manifestVersion){$version=$manifestVersion}
                        }catch{}
                    }
                    [void]$extensions.Add([pscustomobject]@{Browser=$browser.Browser;Profile=$profile.Name;Id=$idFolder.Name;Name=$name;Version=$version;Type='Chromium'})
                }
            }
        }
    }
    $firefoxRoot=Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
    if([IO.Directory]::Exists($firefoxRoot)){
        foreach($profile in @(Get-ChildItem -LiteralPath $firefoxRoot -Directory -Force -ErrorAction SilentlyContinue)){
            [void]$profiles.Add([pscustomobject]@{Browser='Mozilla Firefox';Profile=$profile.Name;Path=ConvertTo-PCTokenPath $profile.FullName})
            $extensionsFile=Join-Path $profile.FullName 'extensions.json'
            if(-not [IO.File]::Exists($extensionsFile)){continue}
            try{
                $document=[IO.File]::ReadAllText($extensionsFile)|ConvertFrom-Json
                foreach($addon in @(Get-PCProperty $document 'addons' @())){
                    $locale=Get-PCProperty $addon 'defaultLocale' $null
                    [void]$extensions.Add([pscustomobject]@{
                        Browser='Mozilla Firefox';Profile=$profile.Name
                        Id=[string](Get-PCProperty $addon 'id' '')
                        Name=[string](Get-PCProperty $locale 'name' '')
                        Version=[string](Get-PCProperty $addon 'version' '')
                        Type=[string](Get-PCProperty $addon 'type' 'Firefox')
                    })
                }
            }catch{Set-PCCollectorPartial "Could not parse Firefox extensions for $($profile.Name)."}
        }
    }
    return [pscustomobject]@{Profiles=$profiles.ToArray();Extensions=$extensions.ToArray()}
}

$os=Get-CimInstance Win32_OperatingSystem
$computer=Get-CimInstance Win32_ComputerSystem
$meta=[ordered]@{
    SchemaVersion=$script:PCMigrationSchemaVersion
    ToolVersion='4.0.0'
    CapturedAt=(Get-Date).ToString('o')
    InventoryMode=$InventoryMode
    CaptureSettingsPayload=[bool]$CaptureSettingsPayload
    CaptureRegistrySafetyBackup=[bool]$CaptureRegistrySafetyBackup
    RegistryBackupTargetedOnly=[bool]$RegistryBackupTargetedOnly
    StartStoppedInventoryServices=[bool]$StartStoppedInventoryServices
    QuiesceServiceName=@($QuiesceServiceName)
    ComputerName=$env:COMPUTERNAME
    UserName=$env:USERNAME
    UserSid=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    UserProfile=$env:USERPROFILE
    WindowsBuild=[string]$os.BuildNumber
    WindowsVersion=[string]$os.Version
    WindowsCaption=[string]$os.Caption
    OSArchitecture=[string]$os.OSArchitecture
    Manufacturer=[string]$computer.Manufacturer
    Model=[string]$computer.Model
    PowerShellVersion=[string]$PSVersionTable.PSVersion
    Is64BitProcess=[Environment]::Is64BitProcess
    IsAdministrator=Test-PCAdministrator
}
Write-PCJson -Path (Join-Path $capture 'Meta.json') -Value $meta -Depth 5

# ---------------------------------------------------------------------------
# Applications: multiple independent sources are intentional. No single source
# (including winget) can enumerate every Store, desktop, portable, or shortcut-
# visible application.
# ---------------------------------------------------------------------------
Invoke-PCCaptureCollector -Name 'Applications.AppxCurrentUser' -Script {
    $directory=Join-Path $capture 'Applications';New-PCDirectory $directory
    $rows=New-Object System.Collections.ArrayList
    $packages=@()
    try{$packages=@(Get-AppxPackage -PackageTypeFilter Main,Framework,Bundle,Resource,Optional -ErrorAction Stop)}
    catch{$packages=@(Get-AppxPackage -ErrorAction Stop);Set-PCCollectorPartial 'PackageTypeFilter was unavailable; default AppX types were captured.'}
    foreach($package in $packages){[void]$rows.Add((Convert-PCAppxPackage -Package $package -Scope 'CurrentUser'))}
    Export-PCCsv -Path (Join-Path $directory 'Appx-CurrentUser.csv') -Rows $rows.ToArray() -Columns @(
        'Scope','Name','PackageFullName','PackageFamilyName','Version','Architecture','Publisher',
        'PublisherId','IsFramework','IsResourcePackage','NonRemovable','SignatureKind','Status'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.AppxAllUsers' -Script {
    $directory=Join-Path $capture 'Applications';New-PCDirectory $directory
    $rows=New-Object System.Collections.ArrayList
    if(-not $IncludeAllUsersAppx){
        Set-PCCollectorPartial 'Disabled by IncludeAllUsersAppx.'
    }else{
        try{
            $packages=@(Get-AppxPackage -AllUsers -PackageTypeFilter Main,Framework,Bundle,Resource,Optional -ErrorAction Stop)
            foreach($package in $packages){[void]$rows.Add((Convert-PCAppxPackage -Package $package -Scope 'AllUsers'))}
        }catch{
            Set-PCCollectorPartial 'All-user inventory requires elevation; current-user AppX inventory remains authoritative for this user.'
        }
    }
    Export-PCCsv -Path (Join-Path $directory 'Appx-AllUsers.csv') -Rows $rows.ToArray() -Columns @(
        'Scope','Name','PackageFullName','PackageFamilyName','Version','Architecture','Publisher',
        'PublisherId','IsFramework','IsResourcePackage','NonRemovable','SignatureKind','Status'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.AppxProvisioned' -Script {
    $directory=Join-Path $capture 'Applications';New-PCDirectory $directory
    $rows=New-Object System.Collections.ArrayList
    if(Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue){
        try{
            foreach($package in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)){
                [void]$rows.Add([pscustomobject]@{
                    DisplayName=[string](Get-PCProperty $package 'DisplayName' '')
                    PackageName=[string](Get-PCProperty $package 'PackageName' '')
                    Version=[string](Get-PCProperty $package 'Version' '')
                    Architecture=[string](Get-PCProperty $package 'Architecture' '')
                    ResourceId=[string](Get-PCProperty $package 'ResourceId' '')
                })
            }
        }catch{Set-PCCollectorPartial 'Provisioned-package inventory was denied or unavailable.'}
    }else{Set-PCCollectorPartial 'Get-AppxProvisionedPackage is unavailable.'}
    Export-PCCsv -Path (Join-Path $directory 'Appx-Provisioned.csv') -Rows $rows.ToArray() -Columns @('DisplayName','PackageName','Version','Architecture','ResourceId')
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.DesktopRegistrations' -Script {
    $rows=@(Get-PCUninstallInventory)
    Export-PCCsv -Path (Join-Path $capture 'Applications\Desktop-Applications.csv') -Rows $rows -Columns @(
        'Hive','View','KeyName','DisplayName','NormalizedName','DisplayVersion','Publisher',
        'InstallLocation','InstallSource','InstallDate','UninstallString','QuietUninstallString',
        'ModifyPath','EstimatedSizeKiB','WindowsInstaller','SystemComponent','ReleaseType'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.Winget' -Script {
    $directory=Join-Path $capture 'Applications';New-PCDirectory $directory
    $winget=Get-Command winget.exe -ErrorAction SilentlyContinue
    if($null -eq $winget){
        Set-PCCollectorPartial 'winget.exe is unavailable in this user context.'
        Write-PCText -Path (Join-Path $directory 'Winget-Unavailable.txt') -Text 'winget.exe is unavailable.'
        return 0
    }
    $export=Join-Path $directory 'Winget-Export.json'
    $result=Invoke-PCNativeProcess -FilePath $winget.Source -Arguments ('export --output "'+$export+'" --include-versions --accept-source-agreements --disable-interactivity')
    Write-PCText -Path (Join-Path $directory 'Winget-Export-stdout.txt') -Text $result.StdOut
    Write-PCText -Path (Join-Path $directory 'Winget-Export-stderr.txt') -Text $result.StdErr
    if($result.ExitCode -ne 0 -or -not [IO.File]::Exists($export)){
        Set-PCCollectorPartial "winget export returned exit code $($result.ExitCode)."
    }
    $list=Invoke-PCNativeProcess -FilePath $winget.Source -Arguments 'list --accept-source-agreements --disable-interactivity'
    Write-PCText -Path (Join-Path $directory 'Winget-List.txt') -Text $list.StdOut
    Write-PCText -Path (Join-Path $directory 'Winget-List-stderr.txt') -Text $list.StdErr
    $count=0
    if([IO.File]::Exists($export)){
        try{
            $json=Read-PCJson $export
            foreach($source in @(Get-PCProperty $json 'Sources' @())){$count+=@(Get-PCProperty $source 'Packages' @()).Count}
        }catch{}
    }
    return $count
}

Invoke-PCCaptureCollector -Name 'Applications.StartApps' -Script {
    $rows=@()
    if(Get-Command Get-StartApps -ErrorAction SilentlyContinue){
        $rows=@(Get-StartApps -ErrorAction Stop|ForEach-Object {
            [pscustomobject]@{Name=[string]$_.Name;AppID=ConvertTo-PCNormalizedText ([string]$_.AppID)}
        })
    }else{Set-PCCollectorPartial 'Get-StartApps is unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'Applications\Start-Apps.csv') -Rows $rows -Columns @('Name','AppID')
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.Shortcuts' -Script {
    $rows=@(Get-PCShortcutRows)
    Export-PCCsv -Path (Join-Path $capture 'Applications\Shortcuts.csv') -Rows $rows -Columns @(
        'RootId','RelativePath','RelativeLocation','Name','Extension','TargetPath','TargetExists','Arguments',
        'WorkingDirectory','IconLocation','Description','SemanticSHA256','SHA256','PayloadRelativePath'
    )
    return $rows.Count
}

# The v2.7 source package supplied three exact package IDs. Keep them only as
# regression fallbacks when the corresponding application is actually detected
# on the source; they do not define the scope of the broader inventory.
Invoke-PCCaptureCollector -Name 'Applications.RegressionPackageCatalog' -Script {
    $desktop=@(Import-PCCsv (Join-Path $capture 'Applications\Desktop-Applications.csv'))
    $appx=@(Import-PCCsv (Join-Path $capture 'Applications\Appx-CurrentUser.csv'))
    $start=@(Import-PCCsv (Join-Path $capture 'Applications\Start-Apps.csv'))
    $winget=@(Get-PCWingetPackages $capture)
    $evidence=New-Object System.Collections.ArrayList
    foreach($item in $desktop){[void]$evidence.Add('Desktop:'+[string]$item.DisplayName)}
    foreach($item in $appx){[void]$evidence.Add('AppX:'+[string]$item.Name+' '+[string]$item.PackageFamilyName)}
    foreach($item in $start){[void]$evidence.Add('Start:'+[string]$item.Name+' '+[string]$item.AppID)}
    foreach($item in $winget){[void]$evidence.Add('Winget:'+[string]$item.PackageIdentifier)}
    $definitions=@(
        @{Name='2fast';Pattern='(?i)2fast|9P9D81GLH89Q';PackageIdentifier='9P9D81GLH89Q';SourceName='msstore'},
        @{Name='Keeper';Pattern='(?i)keeper|9N040SRQ0S8C';PackageIdentifier='9N040SRQ0S8C';SourceName='msstore'},
        @{Name='K-Lite Codec Pack Full';Pattern='(?i)K[\s-]?Lite|MPC[\s-]?HC|CodecGuide\.K-Lite';PackageIdentifier='CodecGuide.K-LiteCodecPack.Full';SourceName='winget'}
    )
    $rows=New-Object System.Collections.ArrayList
    foreach($definition in $definitions){
        $matchedEvidence=@($evidence|Where-Object {$_ -match $definition.Pattern})
        if($matchedEvidence.Count -eq 0){continue}
        [void]$rows.Add([pscustomobject]@{
            Name=$definition.Name;PackageIdentifier=$definition.PackageIdentifier
            SourceName=$definition.SourceName;DetectedEvidence=($matchedEvidence -join ' | ')
            Origin='Exact package mapping retained from supplied v2.7 source'
        })
    }
    Export-PCCsv -Path (Join-Path $capture 'Applications\Regression-Package-Catalog.csv') -Rows $rows.ToArray() -Columns @(
        'Name','PackageIdentifier','SourceName','DetectedEvidence','Origin'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Applications.PortableExecutables' -Script {
    $roots=New-Object System.Collections.ArrayList
    $portableCandidates=@(
        [Environment]::GetFolderPath('Desktop'),
        (Join-Path $env:USERPROFILE 'Downloads')
    )+@($AdditionalPortableRoots)
    foreach($path in $portableCandidates){
        if(-not $path){continue}
        try{$full=[IO.Path]::GetFullPath($path)}catch{continue}
        $alreadyPresent=(@($roots|Where-Object {$_.Equals($full,[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0)
        if([IO.Directory]::Exists($full) -and -not $alreadyPresent){[void]$roots.Add($full)}
    }
    $rows=New-Object System.Collections.ArrayList
    foreach($root in $roots){
        $portableFiles=@()
        try{$portableFiles=@(Get-ChildItem -LiteralPath $root -Filter '*.exe' -File -Recurse -Force -ErrorAction Stop)}
        catch{Set-PCCollectorPartial "Some portable executables under $root could not be enumerated."}
        foreach($file in $portableFiles){
            if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            $version=$file.VersionInfo
            [void]$rows.Add([pscustomobject]@{
                Root=ConvertTo-PCTokenPath $root
                Path=ConvertTo-PCTokenPath $file.FullName
                FileName=$file.Name
                ProductName=[string]$version.ProductName
                ProductVersion=[string]$version.ProductVersion
                CompanyName=[string]$version.CompanyName
                Length=$file.Length
                SHA256=if($file.Length -le ([int64]$MaximumHashedFileMiB*1MB)){Get-PCSha256File $file.FullName}else{''}
            })
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'Applications\Portable-Executables.csv') -Rows $rows.ToArray() -Columns @(
        'Root','Path','FileName','ProductName','ProductVersion','CompanyName','Length','SHA256'
    )
    return $rows.Count
}

# ---------------------------------------------------------------------------
# Application settings: value/file-level fingerprints replace v2.7's shallow
# root-name comparison. Sensitive values are hashed and redacted, never emitted.
# ---------------------------------------------------------------------------
Stop-PCRequestedServicesForFileCapture
try{
Invoke-PCCaptureCollector -Name 'ApplicationState.Files' -Script {
    $roots=New-Object System.Collections.ArrayList
    [void]$roots.Add([pscustomobject]@{Token='APPDATA';Path=$env:APPDATA})
    [void]$roots.Add([pscustomobject]@{Token='LOCALAPPDATA';Path=$env:LOCALAPPDATA})
    if($IncludeProgramData){[void]$roots.Add([pscustomobject]@{Token='PROGRAMDATA';Path=$env:ProgramData})}
    $manifest=Get-PCStateFileManifest -Roots $roots.ToArray()
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Settings-Files.csv') -Rows $manifest.Files -Columns @(
        'RootToken','RelativePath','TopLevelRoot','Classification','Sensitive','Length',
        'LastWriteTimeUtc','SHA256','PayloadRelativePath'
    )
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\State-Roots.csv') -Rows $manifest.Roots -Columns @(
        'RootToken','Name','FileCount','Bytes','CandidateCount','LatestWriteTimeUtc'
    )
    Export-PCCsv -Path (Join-Path $capture 'Diagnostics\File-Inventory-Issues.csv') -Rows $manifest.Issues -Columns @(
        'RootToken','RelativePath','Operation','Message'
    )
    $enumerationIssueCount=@($manifest.Issues|Where-Object {$_.Operation -in @('EnumerateDirectories','EnumerateFiles')}).Count
    $hashIssueCount=@($manifest.Issues|Where-Object {$_.Operation -eq 'HashFile'}).Count
    $payloadIssueCount=@($manifest.Issues|Where-Object {$_.Operation -eq 'CopyPayload'}).Count
    if($enumerationIssueCount -gt 0){
        Set-PCCollectorPartial "$enumerationIssueCount directory/file enumeration operation(s) failed; see Diagnostics\File-Inventory-Issues.csv."
    }
    if($hashIssueCount -gt 0){
        Set-PCCollectorWarning "$hashIssueCount inventoried file(s) could not be hashed; presence and metadata were still captured."
    }
    if($payloadIssueCount -gt 0){
        Set-PCCollectorWarning "$payloadIssueCount eligible payload file(s) could not be copied; inventory rows remain available."
    }
    $policyExclusionCount=@($script:PCPolicyExclusionRows|Where-Object {$_.Category -in @('File','FileTree')}).Count
    if($policyExclusionCount -gt 0){
        Set-PCCollectorWarning "$policyExclusionCount volatile, protected, or nonportable file path(s) were intentionally excluded; see Diagnostics\Policy-Exclusions.csv."
    }
    return @($manifest.Files).Count
}
}finally{
    Restore-PCQuiescedServices
}

Invoke-PCCaptureCollector -Name 'ApplicationState.RegistryCurrentUser' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $policyExclusionsBefore=$script:PCPolicyExclusionRows.Count
    $exclusions=@(
        '(?i)^Microsoft\\Vault',
        '(?i)^Microsoft\\Credentials',
        '(?i)^Microsoft\\IdentityCRL',
        '(?i)^Microsoft\\Windows\\CurrentVersion\\CloudStore',
        '(?i)^Microsoft\\Windows\\CurrentVersion\\Authentication',
        '(?i)^Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage'
    )
    $rows=@(Get-PCRegistryValueManifest -Hive HKCU -SubKey 'Software' -ExcludeRelativePatterns $exclusions)
    $digests=@(Get-PCRegistryRootDigest -Rows $rows)
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKCU-Software.csv') -Rows $rows -Columns @(
        'Hive','View','Root','Key','Name','Kind','DataLength','DataSHA256','Preview','Sensitive'
    )
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKCU-Software-Roots.csv') -Rows $digests -Columns @('Name','ValueCount','Digest')
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount current-user registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    $policyExclusionCount=$script:PCPolicyExclusionRows.Count-$policyExclusionsBefore
    if($policyExclusionCount -gt 0){Set-PCCollectorWarning "$policyExclusionCount protected/nonportable registry subtree(s) were intentionally excluded."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'ApplicationState.RegistryMachine64' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $policyExclusionsBefore=$script:PCPolicyExclusionRows.Count
    $exclusions=@(
        '(?i)^Classes(?:\\|$)',
        '(?i)^WOW6432Node\\Classes(?:\\|$)',
        '(?i)^Microsoft\\Windows(?:\\|$)',
        '(?i)^Microsoft\\Cryptography(?:\\|$)',
        '(?i)^Microsoft\\SystemCertificates(?:\\|$)',
        '(?i)^Microsoft\\EAPSIMMethods(?:\\|$)',
        '(?i)^Microsoft\\WcmSvc\\wifinetworkmanager\\SharedProfiles(?:\\|$)',
        '(?i)^Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\System(?:\\|$)',
        '(?i)^Microsoft\\WwanSvc\\(?:DMProfiles|Profiles|Security)(?:\\|$)',
        '(?i)^WOW6432Node\\Microsoft\\EAPSIMMethods(?:\\|$)',
        '(?i)^WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\AppModel\\CloudExtensions(?:\\|$)'
    )
    $rows=@(Get-PCRegistryValueManifest -Hive HKLM -SubKey 'SOFTWARE' -View ([Microsoft.Win32.RegistryView]::Registry64) -ExcludeRelativePatterns $exclusions)
    $digests=@(Get-PCRegistryRootDigest -Rows $rows)
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKLM64-Software.csv') -Rows $rows -Columns @(
        'Hive','View','Root','Key','Name','Kind','DataLength','DataSHA256','Preview','Sensitive'
    )
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKLM64-Software-Roots.csv') -Rows $digests -Columns @('Name','ValueCount','Digest')
    if(-not (Test-PCAdministrator)){Set-PCCollectorPartial 'Not elevated; some machine registry keys may be unreadable.'}
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount 64-bit machine registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    $policyExclusionCount=$script:PCPolicyExclusionRows.Count-$policyExclusionsBefore
    if($policyExclusionCount -gt 0){Set-PCCollectorWarning "$policyExclusionCount protected/nonportable registry subtree(s) were intentionally excluded."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'ApplicationState.RegistryMachine32' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $policyExclusionsBefore=$script:PCPolicyExclusionRows.Count
    $exclusions=@(
        '(?i)^Classes(?:\\|$)',
        '(?i)^Microsoft\\Windows(?:\\|$)',
        '(?i)^Microsoft\\Cryptography(?:\\|$)',
        '(?i)^Microsoft\\SystemCertificates(?:\\|$)',
        '(?i)^Microsoft\\EAPSIMMethods(?:\\|$)',
        '(?i)^Microsoft\\WcmSvc\\wifinetworkmanager\\SharedProfiles(?:\\|$)',
        '(?i)^Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\System(?:\\|$)',
        '(?i)^Microsoft\\WwanSvc\\(?:DMProfiles|Profiles|Security)(?:\\|$)',
        '(?i)^Microsoft\\Windows\\CurrentVersion\\AppModel\\CloudExtensions(?:\\|$)'
    )
    $rows=@(Get-PCRegistryValueManifest -Hive HKLM -SubKey 'SOFTWARE' -View ([Microsoft.Win32.RegistryView]::Registry32) -ExcludeRelativePatterns $exclusions)
    $digests=@(Get-PCRegistryRootDigest -Rows $rows)
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKLM32-Software.csv') -Rows $rows -Columns @(
        'Hive','View','Root','Key','Name','Kind','DataLength','DataSHA256','Preview','Sensitive'
    )
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-HKLM32-Software-Roots.csv') -Rows $digests -Columns @('Name','ValueCount','Digest')
    if(-not (Test-PCAdministrator)){Set-PCCollectorPartial 'Not elevated; some 32-bit machine registry keys may be unreadable.'}
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount 32-bit machine registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    $policyExclusionCount=$script:PCPolicyExclusionRows.Count-$policyExclusionsBefore
    if($policyExclusionCount -gt 0){Set-PCCollectorWarning "$policyExclusionCount protected/nonportable registry subtree(s) were intentionally excluded."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'ApplicationState.RepairableRegistryPayload' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $definitions=@(
        @{Id='Console';Hive='HKCU';SubKey='Console';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Regional-International';Hive='HKCU';SubKey='Control Panel\International';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Regional-TimeDate';Hive='HKCU';SubKey='Control Panel\TimeDate';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Keyboard-Layout';Hive='HKCU';SubKey='Keyboard Layout';Risk='Medium';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='PowerShell-ISE';Hive='HKCU';SubKey='Software\Microsoft\PowerShell\3\PowerShellISE';Risk='Low';RequiresApp='PowerShell ISE';AutoMethod='ImportRegistry'},
        @{Id='Explorer-Advanced';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';Risk='Medium';RequiresApp='';AutoMethod='Manual'},
        @{Id='Personalization-Desktop';Hive='HKCU';SubKey='Control Panel\Desktop';Risk='Medium';RequiresApp='';AutoMethod='Manual'},
        @{Id='Personalization-Cursors';Hive='HKCU';SubKey='Control Panel\Cursors';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Personalization-Colors';Hive='HKCU';SubKey='Control Panel\Colors';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Personalization-DWM';Hive='HKCU';SubKey='Software\Microsoft\Windows\DWM';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Personalization-Theme';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\Themes\Personalize';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Accessibility';Hive='HKCU';SubKey='Control Panel\Accessibility';Risk='Medium';RequiresApp='';AutoMethod='Manual'},
        @{Id='Mouse';Hive='HKCU';SubKey='Control Panel\Mouse';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='Keyboard';Hive='HKCU';SubKey='Control Panel\Keyboard';Risk='Low';RequiresApp='';AutoMethod='ImportRegistry'},
        @{Id='User-Environment';Hive='HKCU';SubKey='Environment';Risk='High';RequiresApp='';AutoMethod='Manual'},
        @{Id='Command-Processor';Hive='HKCU';SubKey='Software\Microsoft\Command Processor';Risk='High';RequiresApp='';AutoMethod='Manual'},
        @{Id='MPC-HC';Hive='HKCU';SubKey='Software\MPC-HC';Risk='Medium';RequiresApp='MPC-HC';AutoMethod='ImportRegistry'},
        @{Id='Codec-Guide';Hive='HKCU';SubKey='Software\Codec Guide';Risk='Medium';RequiresApp='K-Lite Codec Pack';AutoMethod='ImportRegistry'},
        @{Id='Icaros';Hive='HKCU';SubKey='Software\Icaros';Risk='Medium';RequiresApp='Icaros';AutoMethod='ImportRegistry'},
        @{Id='LAV';Hive='HKCU';SubKey='Software\LAV';Risk='High';RequiresApp='LAV Filters';AutoMethod='ImportRegistry'},
        @{Id='MadVR';Hive='HKCU';SubKey='Software\madshi\madVR';Risk='High';RequiresApp='madVR';AutoMethod='ImportRegistry'},
        @{Id='Gabest';Hive='HKCU';SubKey='Software\Gabest';Risk='Medium';RequiresApp='MPC-HC';AutoMethod='ImportRegistry'}
    )
    $rows=New-Object System.Collections.ArrayList
    $issues=New-Object System.Collections.ArrayList
    foreach($definition in $definitions){
        $present=Test-PCRegistryKey -Hive $definition.Hive -SubKey $definition.SubKey
        $stateRows=@()
        if($present){$stateRows=@(Get-PCRegistryValueManifest -Hive $definition.Hive -SubKey $definition.SubKey)}
        $artifact='Payload\Registry\'+$definition.Id+'.reg'
        $absolute=Join-Path $capture $artifact
        $exported=$false
        if($present -and $CaptureSettingsPayload -and $definition.AutoMethod -eq 'ImportRegistry'){
            try{
                $exported=Export-PCRegistryKey -Hive $definition.Hive -SubKey $definition.SubKey -Path $absolute
                if($exported -and (Test-PCSensitiveFileContent -Path $absolute)){
                    [IO.File]::Delete($absolute)
                    $exported=$false
                    [void]$issues.Add([pscustomobject]@{
                        Id=$definition.Id;Operation='ScreenExport';Message='Export contained potentially sensitive content and was excluded from the repair payload.'
                    })
                }
            }catch{
                $exported=$false
                [void]$issues.Add([pscustomobject]@{Id=$definition.Id;Operation='ExportRegistry';Message=$_.Exception.Message})
            }
        }
        [void]$rows.Add([pscustomobject]@{
            Id=$definition.Id;Hive=$definition.Hive;SubKey=$definition.SubKey
            Risk=$definition.Risk;RequiresApp=$definition.RequiresApp
            AutoMethod=$definition.AutoMethod;Present=$present
            ValueCount=$stateRows.Count;StateDigest=Get-PCRegistryManifestDigest -Rows $stateRows
            Artifact=if($exported){$artifact}else{''}
            SHA256=if($exported){Get-PCSha256File $absolute}else{''}
        })
    }
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Registry-Payload-Catalog.csv') -Rows $rows.ToArray() -Columns @(
        'Id','Hive','SubKey','Risk','RequiresApp','AutoMethod','Present','ValueCount','StateDigest','Artifact','SHA256'
    )
    Export-PCCsv -Path (Join-Path $capture 'Diagnostics\Registry-Payload-Issues.csv') -Rows $issues.ToArray() -Columns @('Id','Operation','Message')
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount scoped registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    if($issues.Count -gt 0){Set-PCCollectorWarning "$($issues.Count) registry payload export/screening issue(s) were recorded in Diagnostics\Registry-Payload-Issues.csv."}
    return @($rows|Where-Object {$_.Present}).Count
}

if($CaptureRegistrySafetyBackup){
Invoke-PCCaptureCollector -Name 'ApplicationState.RegistrySafetyBackup' -Script {
    if(-not (Test-PCAdministrator) -and -not $RegistryBackupTargetedOnly){
        throw 'Broad registry safety snapshots require an elevated Windows PowerShell process. Use -RegistryBackupTargetedOnly or rerun elevated.'
    }
    $results=@(Invoke-PCMigrationRegistryBackup -BackupRoot $capture -SkipBinarySnapshots:$RegistryBackupTargetedOnly)
    return @($results|Where-Object {$_.Succeeded}).Count
}
}

Invoke-PCCaptureCollector -Name 'ApplicationState.Browsers' -Script {
    $inventory=Get-PCBrowserInventory
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Browser-Profiles.csv') -Rows $inventory.Profiles -Columns @('Browser','Profile','Path')
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\Browser-Extensions.csv') -Rows $inventory.Extensions -Columns @('Browser','Profile','Id','Name','Version','Type')
    return @($inventory.Extensions).Count
}

# ---------------------------------------------------------------------------
# User shell, console, PowerShell, regional, fonts, defaults, and startup state.
# ---------------------------------------------------------------------------
Invoke-PCCaptureCollector -Name 'UserState.RegistryValues' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $definitions=@(
        @{Id='Console';Hive='HKCU';SubKey='Console'},
        @{Id='International';Hive='HKCU';SubKey='Control Panel\International'},
        @{Id='TimeDate';Hive='HKCU';SubKey='Control Panel\TimeDate'},
        @{Id='KeyboardLayout';Hive='HKCU';SubKey='Keyboard Layout'},
        @{Id='PowerShellISE';Hive='HKCU';SubKey='Software\Microsoft\PowerShell\3\PowerShellISE'},
        @{Id='ExplorerAdvanced';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'},
        @{Id='Desktop';Hive='HKCU';SubKey='Control Panel\Desktop'},
        @{Id='Cursors';Hive='HKCU';SubKey='Control Panel\Cursors'},
        @{Id='Colors';Hive='HKCU';SubKey='Control Panel\Colors'},
        @{Id='DWM';Hive='HKCU';SubKey='Software\Microsoft\Windows\DWM'},
        @{Id='Theme';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'},
        @{Id='Accessibility';Hive='HKCU';SubKey='Control Panel\Accessibility'},
        @{Id='Mouse';Hive='HKCU';SubKey='Control Panel\Mouse'},
        @{Id='Keyboard';Hive='HKCU';SubKey='Control Panel\Keyboard'},
        @{Id='UserEnvironment';Hive='HKCU';SubKey='Environment'},
        @{Id='UserRun';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\Run'},
        @{Id='UserRunOnce';Hive='HKCU';SubKey='Software\Microsoft\Windows\CurrentVersion\RunOnce'}
    )
    $rows=New-Object System.Collections.ArrayList
    foreach($definition in $definitions){
        foreach($item in @(Get-PCRegistryValueManifest -Hive $definition.Hive -SubKey $definition.SubKey)){
            [void]$rows.Add([pscustomobject]@{
                StateId=$definition.Id;Hive=$item.Hive;View=$item.View;Root=$item.Root
                Key=$item.Key;Name=$item.Name;Kind=$item.Kind;DataLength=$item.DataLength
                DataSHA256=$item.DataSHA256;Preview=$item.Preview;Sensitive=$item.Sensitive
            })
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'UserState\Registry-Values.csv') -Rows $rows.ToArray() -Columns @(
        'StateId','Hive','View','Root','Key','Name','Kind','DataLength','DataSHA256','Preview','Sensitive'
    )
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount user-state registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'UserState.RegionalLanguage' -Script {
    $culture=Get-Culture
    $languages=@()
    try{
        $languages=@(Get-WinUserLanguageList -ErrorAction Stop|ForEach-Object {
            [pscustomobject]@{
                LanguageTag=[string](Get-PCProperty $_ 'LanguageTag' '')
                EnglishName=[string](Get-PCProperty $_ 'EnglishName' '')
                Autonym=[string](Get-PCProperty $_ 'Autonym' '')
                InputMethodTips=(@(Get-PCProperty $_ 'InputMethodTips' @()) -join '; ')
                Handwriting=[string](Get-PCProperty $_ 'Handwriting' '')
            }
        })
    }catch{Set-PCCollectorPartial 'Windows language-list cmdlets were unavailable.'}
    $systemLocale='';$homeGeoId='';$inputOverride=''
    try{$systemLocale=(Get-WinSystemLocale).Name}catch{}
    try{$homeGeoId=[string](Get-WinHomeLocation).GeoId}catch{}
    try{$inputOverride=[string](Get-WinDefaultInputMethodOverride)}catch{}
    $data=[ordered]@{
        CultureName=$culture.Name
        DisplayName=$culture.DisplayName
        ShortDatePattern=$culture.DateTimeFormat.ShortDatePattern
        LongDatePattern=$culture.DateTimeFormat.LongDatePattern
        ShortTimePattern=$culture.DateTimeFormat.ShortTimePattern
        LongTimePattern=$culture.DateTimeFormat.LongTimePattern
        FirstDayOfWeek=[string]$culture.DateTimeFormat.FirstDayOfWeek
        TimeZoneId=[TimeZoneInfo]::Local.Id
        SystemLocale=$systemLocale
        HomeGeoId=$homeGeoId
        DefaultInputMethodOverride=$inputOverride
        UserLanguages=$languages
    }
    Write-PCJson -Path (Join-Path $capture 'UserState\Regional-Language.json') -Value $data -Depth 8
    return (1+$languages.Count)
}

Invoke-PCCaptureCollector -Name 'UserState.PowerShell' -Script {
    $directory=Join-Path $capture 'UserState\PowerShell';New-PCDirectory $directory
    $documents=[Environment]::GetFolderPath('MyDocuments')
    $definitions=@(
        @{Id='WindowsPowerShell-CurrentUserAllHosts';Path=(Join-Path $documents 'WindowsPowerShell\profile.ps1');Scope='CurrentUser'},
        @{Id='WindowsPowerShell-CurrentUserCurrentHost';Path=(Join-Path $documents 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1');Scope='CurrentUser'},
        @{Id='PowerShell-CurrentUserAllHosts';Path=(Join-Path $documents 'PowerShell\profile.ps1');Scope='CurrentUser'},
        @{Id='PowerShell-CurrentUserCurrentHost';Path=(Join-Path $documents 'PowerShell\Microsoft.PowerShell_profile.ps1');Scope='CurrentUser'},
        @{Id='WindowsPowerShell-AllUsersAllHosts';Path=(Join-Path $PSHOME 'profile.ps1');Scope='AllUsers'},
        @{Id='WindowsPowerShell-AllUsersCurrentHost';Path=(Join-Path $PSHOME 'Microsoft.PowerShell_profile.ps1');Scope='AllUsers'}
    )
    $profiles=New-Object System.Collections.ArrayList
    foreach($definition in $definitions){
        if(-not [IO.File]::Exists($definition.Path)){continue}
        $payload=''
        if($CaptureSettingsPayload -and -not (Test-PCSensitiveFileContent -Path $definition.Path)){
            $payload=Copy-PCPayloadFile -Source $definition.Path -RelativePayloadPath ('PowerShell\Profiles\'+$definition.Id+'.ps1')
        }
        [void]$profiles.Add([pscustomobject]@{
            Id=$definition.Id
            Scope=$definition.Scope
            DestinationPath=ConvertTo-PCTokenPath $definition.Path
            Length=(Get-Item -LiteralPath $definition.Path).Length
            SHA256=Get-PCSha256File $definition.Path
            PayloadRelativePath=$payload
        })
    }
    Export-PCCsv -Path (Join-Path $directory 'Profiles.csv') -Rows $profiles.ToArray() -Columns @(
        'Id','Scope','DestinationPath','Length','SHA256','PayloadRelativePath'
    )
    $modules=@()
    try{$modules=@(Get-Module -ListAvailable -ErrorAction Stop|Select-Object Name,Version,ModuleType,Guid,@{N='Path';E={ConvertTo-PCTokenPath $_.Path}}|Sort-Object Name,Version,Path)}
    catch{Set-PCCollectorPartial 'One or more PowerShell module paths could not be inventoried.'}
    Export-PCCsv -Path (Join-Path $directory 'Modules.csv') -Rows $modules -Columns @('Name','Version','ModuleType','Guid','Path')
    $policies=@()
    try{$policies=@(Get-ExecutionPolicy -List|ForEach-Object {[pscustomobject]@{Scope=[string]$_.Scope;ExecutionPolicy=[string]$_.ExecutionPolicy}})}catch{}
    Export-PCCsv -Path (Join-Path $directory 'Execution-Policy.csv') -Rows $policies -Columns @('Scope','ExecutionPolicy')
    if($IncludePSReadLineHistory){
        foreach($definition in @(
            @{Id='WindowsPowerShell';Path=(Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine')},
            @{Id='PowerShell';Path=(Join-Path $env:APPDATA 'Microsoft\PowerShell\PSReadLine')}
        )){
            if(-not [IO.Directory]::Exists($definition.Path)){continue}
            foreach($file in @(Get-ChildItem -LiteralPath $definition.Path -File -Force -ErrorAction SilentlyContinue)){
                [void](Copy-PCPayloadFile -Source $file.FullName -RelativePayloadPath ('PowerShell\PSReadLine\'+$definition.Id+'\'+$file.Name))
            }
        }
        Write-PCText -Path (Join-Path $directory 'PSReadLine-Warning.txt') -Text 'PSReadLine history can contain commands, paths, host names, and secrets. Review before transfer.'
    }
    return ($profiles.Count+$modules.Count+$policies.Count)
}

Invoke-PCCaptureCollector -Name 'UserState.WindowsTerminal' -Script {
    $rows=New-Object System.Collections.ArrayList
    $candidates=New-Object System.Collections.ArrayList
    $packages=Join-Path $env:LOCALAPPDATA 'Packages'
    if([IO.Directory]::Exists($packages)){
        foreach($folder in @(Get-ChildItem -LiteralPath $packages -Directory -Filter 'Microsoft.WindowsTerminal*' -ErrorAction SilentlyContinue)){
            [void]$candidates.Add([pscustomobject]@{Id='Package-'+$folder.Name;Path=(Join-Path $folder.FullName 'LocalState\settings.json')})
        }
    }
    [void]$candidates.Add([pscustomobject]@{Id='Unpackaged';Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json')})
    foreach($candidate in $candidates){
        if(-not [IO.File]::Exists($candidate.Path)){continue}
        $payload=''
        if($CaptureSettingsPayload -and -not (Test-PCSensitiveFileContent -Path $candidate.Path)){$payload=Copy-PCPayloadFile -Source $candidate.Path -RelativePayloadPath ('WindowsTerminal\'+(Get-PCSafeFileName $candidate.Id)+'\settings.json')}
        [void]$rows.Add([pscustomobject]@{
            Id=$candidate.Id
            DestinationPath=ConvertTo-PCTokenPath $candidate.Path
            Length=(Get-Item -LiteralPath $candidate.Path).Length
            SHA256=Get-PCSha256File $candidate.Path
            PayloadRelativePath=$payload
        })
    }
    Export-PCCsv -Path (Join-Path $capture 'UserState\Windows-Terminal.csv') -Rows $rows.ToArray() -Columns @(
        'Id','DestinationPath','Length','SHA256','PayloadRelativePath'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'ApplicationState.KLiteRegression' -Script {
    $programFilesX86=[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $roots=@(
        @{Token='APPDATA';Base=$env:APPDATA;Relative='MPC-HC'},
        @{Token='LOCALAPPDATA';Base=$env:LOCALAPPDATA;Relative='MPC-HC'},
        @{Token='APPDATA';Base=$env:APPDATA;Relative='Icaros'},
        @{Token='LOCALAPPDATA';Base=$env:LOCALAPPDATA;Relative='Icaros'},
        @{Token='APPDATA';Base=$env:APPDATA;Relative='K-Lite Codec Pack'},
        @{Token='LOCALAPPDATA';Base=$env:LOCALAPPDATA;Relative='K-Lite Codec Pack'},
        @{Token='PROGRAMFILES';Base=$env:ProgramFiles;Relative='K-Lite Codec Pack'},
        @{Token='PROGRAMFILESX86';Base=$programFilesX86;Relative='K-Lite Codec Pack'}
    )
    $rows=New-Object System.Collections.ArrayList
    foreach($root in $roots){
        if(-not $root.Base){continue}
        $base=Join-Path $root.Base $root.Relative
        if(-not [IO.Directory]::Exists($base)){continue}
        foreach($file in @(Get-ChildItem -LiteralPath $base -File -Recurse -Force -ErrorAction SilentlyContinue)){
            if((Get-PCFileClassification $file.FullName) -notin @('Configuration','Script')){continue}
            $relative=$file.FullName.Substring($base.Length).TrimStart('\')
            $sensitive=Test-PCSensitiveStatePath $relative
            $payload=''
            if($CaptureSettingsPayload -and -not $sensitive -and -not (Test-PCSensitiveFileContent -Path $file.FullName) -and $file.Length -le ([int64]$MaximumHashedFileMiB*1MB)){
                $payload=Copy-PCPayloadFile -Source $file.FullName -RelativePayloadPath ('KLite\'+$root.Token+'\'+$root.Relative+'\'+$relative)
            }
            [void]$rows.Add([pscustomobject]@{
                RootToken=$root.Token;RootRelativePath=$root.Relative;RelativePath=$relative
                Length=$file.Length;SHA256=if($file.Length -le ([int64]$MaximumHashedFileMiB*1MB)){Get-PCSha256File $file.FullName}else{''}
                Sensitive=$sensitive;PayloadRelativePath=$payload
            })
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'ApplicationState\KLite-Files.csv') -Rows $rows.ToArray() -Columns @(
        'RootToken','RootRelativePath','RelativePath','Length','SHA256','Sensitive','PayloadRelativePath'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'UserState.Fonts' -Script {
    $rows=New-Object System.Collections.ArrayList
    $fontRoots=@(
        @{Scope='CurrentUser';Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Fonts')},
        @{Scope='System';Path=(Join-Path $env:WINDIR 'Fonts')}
    )
    foreach($root in $fontRoots){
        if(-not [IO.Directory]::Exists($root.Path)){continue}
        foreach($file in @(Get-ChildItem -LiteralPath $root.Path -File -Force -ErrorAction SilentlyContinue)){
            if($file.Extension -notin @('.ttf','.otf','.ttc','.fon')){continue}
            [void]$rows.Add([pscustomobject]@{
                Scope=$root.Scope;Name=$file.Name;Length=$file.Length
                Version=[string]$file.VersionInfo.FileVersion
                SHA256=if($root.Scope -eq 'CurrentUser' -and $file.Length -le ([int64]$MaximumHashedFileMiB*1MB)){Get-PCSha256File $file.FullName}else{''}
            })
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'UserState\Fonts.csv') -Rows $rows.ToArray() -Columns @('Scope','Name','Length','Version','SHA256')
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'UserState.DefaultApplications' -Script {
    $directory=Join-Path $capture 'UserState';New-PCDirectory $directory
    $dism=Join-Path $env:SystemRoot 'System32\dism.exe'
    $file=Join-Path $directory 'Default-App-Associations.xml'
    if(-not [IO.File]::Exists($dism)){Set-PCCollectorPartial 'dism.exe is unavailable.';return 0}
    $result=Invoke-PCNativeProcess -FilePath $dism -Arguments ('/Online /Export-DefaultAppAssociations:"'+$file+'" /English')
    Write-PCText -Path (Join-Path $directory 'Default-App-Associations.log.txt') -Text ($result.StdOut+[Environment]::NewLine+$result.StdErr)
    if($result.ExitCode -ne 0 -or -not [IO.File]::Exists($file)){Set-PCCollectorPartial "DISM export returned exit code $($result.ExitCode).";return 0}
    $count=0
    try{
        $document=New-Object Xml.XmlDocument
        $document.Load($file)
        $count=@($document.SelectNodes('//Association')).Count
    }catch{Set-PCCollectorPartial 'Default-app XML was written but could not be parsed.'}
    return $count
}

# ---------------------------------------------------------------------------
# Machine/user integration state. Most of these categories are inventory-only:
# the correct repair is commonly reinstall/recreate, not registry transplantation.
# ---------------------------------------------------------------------------
Invoke-PCCaptureCollector -Name 'Integration.Services' -Script {
    $rows=@(Get-CimInstance Win32_Service -ErrorAction Stop|ForEach-Object {
        [pscustomobject]@{
            Name=[string]$_.Name
            DisplayName=[string]$_.DisplayName
            State=[string]$_.State
            StartMode=[string]$_.StartMode
            StartName=[string]$_.StartName
            PathName=ConvertTo-PCNormalizedText ([string]$_.PathName)
            ProcessId=[string]$_.ProcessId
            Description=[string]$_.Description
        }
    })
    Export-PCCsv -Path (Join-Path $capture 'Integration\Services.csv') -Rows $rows -Columns @(
        'Name','DisplayName','State','StartMode','StartName','PathName','ProcessId','Description'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.ScheduledTasks' -Script {
    $rows=New-Object System.Collections.ArrayList
    $issues=New-Object System.Collections.ArrayList
    if(-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)){
        Set-PCCollectorPartial 'ScheduledTasks module is unavailable.'
    }else{
        foreach($task in @(Get-ScheduledTask -ErrorAction Stop)){
            try{
                $actions=@(@(Get-PCProperty $task 'Actions' @())|ForEach-Object {
                    (ConvertTo-PCNormalizedText ([string](Get-PCProperty $_ 'Execute' '')))+'|'+
                    (ConvertTo-PCNormalizedText ([string](Get-PCProperty $_ 'Arguments' '')))+'|'+
                    (ConvertTo-PCTokenPath ([string](Get-PCProperty $_ 'WorkingDirectory' '')))
                })
                $triggers=@(@(Get-PCProperty $task 'Triggers' @())|ForEach-Object {
                    $type=Get-PCScheduledTaskTriggerType -Trigger $_
                    $start=[string](Get-PCProperty $_ 'StartBoundary' '')
                    $enabled=[string](Get-PCProperty $_ 'Enabled' '')
                    $type+'|'+$start+'|'+$enabled
                })
                $principal=Get-PCProperty $task 'Principal' $null
                $settings=Get-PCProperty $task 'Settings' $null
                [void]$rows.Add([pscustomobject]@{
                    TaskPath=[string](Get-PCProperty $task 'TaskPath' '')
                    TaskName=[string](Get-PCProperty $task 'TaskName' '')
                    State=[string](Get-PCProperty $task 'State' '')
                    Author=[string](Get-PCProperty $task 'Author' '')
                    Description=[string](Get-PCProperty $task 'Description' '')
                    UserId=[string](Get-PCProperty $principal 'UserId' '')
                    RunLevel=[string](Get-PCProperty $principal 'RunLevel' '')
                    Actions=($actions -join ' || ')
                    Triggers=($triggers -join ' || ')
                    Enabled=[string](Get-PCProperty $settings 'Enabled' '')
                    Hidden=[string](Get-PCProperty $settings 'Hidden' '')
                })
            }catch{
                [void]$issues.Add([pscustomobject]@{
                    TaskPath=[string](Get-PCProperty $task 'TaskPath' '')
                    TaskName=[string](Get-PCProperty $task 'TaskName' '')
                    Message=$_.Exception.Message
                })
            }
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Scheduled-Tasks.csv') -Rows $rows.ToArray() -Columns @(
        'TaskPath','TaskName','State','Author','Description','UserId','RunLevel','Actions','Triggers','Enabled','Hidden'
    )
    Export-PCCsv -Path (Join-Path $capture 'Diagnostics\Scheduled-Task-Issues.csv') -Rows $issues.ToArray() -Columns @('TaskPath','TaskName','Message')
    if($issues.Count -gt 0){Set-PCCollectorPartial "$($issues.Count) scheduled task(s) could not be normalized; see Diagnostics\Scheduled-Task-Issues.csv."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.MachineEnvironmentStartup' -Script {
    $registryErrorsBefore=$script:PCRegistryReadErrorCount
    $definitions=@(
        @{Id='MachineEnvironment';Hive='HKLM';SubKey='SYSTEM\CurrentControlSet\Control\Session Manager\Environment';View=[Microsoft.Win32.RegistryView]::Registry64},
        @{Id='MachineRun64';Hive='HKLM';SubKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Run';View=[Microsoft.Win32.RegistryView]::Registry64},
        @{Id='MachineRunOnce64';Hive='HKLM';SubKey='SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';View=[Microsoft.Win32.RegistryView]::Registry64},
        @{Id='MachineRun32';Hive='HKLM';SubKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Run';View=[Microsoft.Win32.RegistryView]::Registry32},
        @{Id='MachineRunOnce32';Hive='HKLM';SubKey='SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';View=[Microsoft.Win32.RegistryView]::Registry32}
    )
    $rows=New-Object System.Collections.ArrayList
    foreach($definition in $definitions){
        foreach($item in @(Get-PCRegistryValueManifest -Hive $definition.Hive -SubKey $definition.SubKey -View $definition.View)){
            [void]$rows.Add([pscustomobject]@{
                StateId=$definition.Id;Hive=$item.Hive;View=$item.View;Root=$item.Root
                Key=$item.Key;Name=$item.Name;Kind=$item.Kind;DataLength=$item.DataLength
                DataSHA256=$item.DataSHA256;Preview=$item.Preview;Sensitive=$item.Sensitive
            })
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Machine-Environment-Startup.csv') -Rows $rows.ToArray() -Columns @(
        'StateId','Hive','View','Root','Key','Name','Kind','DataLength','DataSHA256','Preview','Sensitive'
    )
    if(-not (Test-PCAdministrator)){Set-PCCollectorPartial 'Not elevated; some machine keys may be unreadable.'}
    $registryErrorCount=$script:PCRegistryReadErrorCount-$registryErrorsBefore
    if($registryErrorCount -gt 0){Set-PCCollectorPartial "$registryErrorCount machine environment/startup registry read operation(s) failed; see Diagnostics\Registry-Read-Issues.csv."}
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.Printers' -Script {
    $printers=New-Object System.Collections.ArrayList
    $drivers=@();$ports=@()
    if(Get-Command Get-Printer -ErrorAction SilentlyContinue){
        $defaultPrinter=[string](Get-CimInstance Win32_Printer -Filter 'Default=True' -ErrorAction SilentlyContinue|Select-Object -First 1 -ExpandProperty Name)
        foreach($printer in @(Get-Printer -ErrorAction Stop)){
            [void]$printers.Add([pscustomobject]@{
                Name=[string]$printer.Name
                DriverName=[string]$printer.DriverName
                PortName=[string]$printer.PortName
                Type=[string]$printer.Type
                Shared=[string]$printer.Shared
                ShareName=[string]$printer.ShareName
                Published=[string]$printer.Published
                ComputerName=[string]$printer.ComputerName
                Default=if($printer.Name -eq $defaultPrinter){'True'}else{'False'}
            })
        }
        try{$drivers=@(Get-PrinterDriver -ErrorAction Stop|Select-Object Name,Manufacturer,MajorVersion,InfPath,PrinterEnvironment)}catch{}
        try{$ports=@(Get-PrinterPort -ErrorAction Stop|Select-Object Name,Description,PrinterHostAddress,PortNumber,Protocol)}catch{}
    }else{
        foreach($printer in @(Get-CimInstance Win32_Printer -ErrorAction Stop)){
            [void]$printers.Add([pscustomobject]@{
                Name=[string]$printer.Name;DriverName=[string]$printer.DriverName;PortName=[string]$printer.PortName
                Type='CIM';Shared=[string]$printer.Shared;ShareName=[string]$printer.ShareName
                Published=[string]$printer.Published;ComputerName=[string]$printer.SystemName;Default=[string]$printer.Default
            })
        }
        Set-PCCollectorPartial 'PrintManagement cmdlets unavailable; CIM printer inventory used.'
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Printers.csv') -Rows $printers.ToArray() -Columns @(
        'Name','DriverName','PortName','Type','Shared','ShareName','Published','ComputerName','Default'
    )
    Export-PCCsv -Path (Join-Path $capture 'Integration\Printer-Drivers.csv') -Rows $drivers -Columns @('Name','Manufacturer','MajorVersion','InfPath','PrinterEnvironment')
    Export-PCCsv -Path (Join-Path $capture 'Integration\Printer-Ports.csv') -Rows $ports -Columns @('Name','Description','PrinterHostAddress','PortNumber','Protocol')
    return ($printers.Count+$drivers.Count+$ports.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.NetworkMappingsVpnWifi' -Script {
    $mappings=New-Object System.Collections.ArrayList
    foreach($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=4' -ErrorAction SilentlyContinue)){
        [void]$mappings.Add([pscustomobject]@{Type='MappedDrive';LocalPath=[string]$drive.DeviceID;RemotePath=[string]$drive.ProviderName;Status='';UserName=''})
    }
    if(Get-Command Get-SmbMapping -ErrorAction SilentlyContinue){
        try{
            foreach($mapping in @(Get-SmbMapping -ErrorAction Stop)){
                [void]$mappings.Add([pscustomobject]@{Type='SmbMapping';LocalPath=[string]$mapping.LocalPath;RemotePath=[string]$mapping.RemotePath;Status=[string]$mapping.Status;UserName=[string]$mapping.UserName})
            }
        }catch{Set-PCCollectorPartial 'SMB mappings could not be fully enumerated.'}
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Network-Mappings.csv') -Rows $mappings.ToArray() -Columns @('Type','LocalPath','RemotePath','Status','UserName')
    $vpn=New-Object System.Collections.ArrayList
    if(Get-Command Get-VpnConnection -ErrorAction SilentlyContinue){
        foreach($scope in @($false,$true)){
            try{
                $connections=if($scope){@(Get-VpnConnection -AllUserConnection -ErrorAction Stop)}else{@(Get-VpnConnection -ErrorAction Stop)}
                foreach($connection in $connections){
                    [void]$vpn.Add([pscustomobject]@{
                        Scope=if($scope){'AllUsers'}else{'CurrentUser'}
                        Name=[string]$connection.Name
                        ServerAddress=[string]$connection.ServerAddress
                        TunnelType=[string]$connection.TunnelType
                        AuthenticationMethod=(@($connection.AuthenticationMethod) -join '; ')
                        EncryptionLevel=[string]$connection.EncryptionLevel
                        SplitTunneling=[string]$connection.SplitTunneling
                        RememberCredential=[string]$connection.RememberCredential
                    })
                }
            }catch{if($scope){Set-PCCollectorPartial 'All-user VPN inventory unavailable.'}}
        }
    }else{Set-PCCollectorPartial 'VPN cmdlets unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\VPN-Connections.csv') -Rows $vpn.ToArray() -Columns @(
        'Scope','Name','ServerAddress','TunnelType','AuthenticationMethod','EncryptionLevel','SplitTunneling','RememberCredential'
    )
    $wifi=New-Object System.Collections.ArrayList
    $netsh=Join-Path $env:SystemRoot 'System32\netsh.exe'
    if([IO.File]::Exists($netsh)){
        $result=Invoke-PCTemporaryServiceStart -Name 'WlanSvc' -Operation {
            Invoke-PCNativeProcess -FilePath $netsh -Arguments 'wlan show profiles'
        }
        $netshText=($result.StdOut+[Environment]::NewLine+$result.StdErr).Trim()
        Write-PCText -Path (Join-Path $capture 'Integration\WiFi-Profiles-Raw.txt') -Text $netshText
        foreach($line in @($result.StdOut -split '\r?\n')){
            if($line -match '^\s*All User Profile\s*:\s*(.+?)\s*$'){
                [void]$wifi.Add([pscustomobject]@{Name=$matches[1];Scope='AllUsers';CredentialCaptured='False'})
            }
        }
        if($result.ExitCode -ne 0){
            if($netshText -match '(?i)no wireless interface'){
                Set-PCCollectorWarning 'Wi-Fi inventory is not applicable because Windows reports no wireless interface.'
            }elseif($netshText -match '(?i)(wlansvc|wireless autoconfig).*(not running|not started)'){
                Set-PCCollectorPartial 'Wi-Fi profiles could not be inventoried because the WLAN AutoConfig service is not running.'
            }else{
                $detail=($netshText -replace '\s+',' ').Trim()
                if($detail.Length -gt 240){$detail=$detail.Substring(0,240)+'...'}
                Set-PCCollectorPartial "netsh wlan show profiles returned exit code $($result.ExitCode): $detail"
            }
        }
    }else{Set-PCCollectorWarning 'Wi-Fi inventory is unavailable because netsh.exe was not found.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\WiFi-Profiles.csv') -Rows $wifi.ToArray() -Columns @('Name','Scope','CredentialCaptured')
    return ($mappings.Count+$vpn.Count+$wifi.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.NetworkContext' -Script {
    $adapters=@();$addresses=@();$dns=@()
    if(Get-Command Get-NetAdapter -ErrorAction SilentlyContinue){
        try{$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,MediaType,PhysicalMediaType,DriverInformation)}catch{}
    }
    if(Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue){
        try{$addresses=@(Get-NetIPAddress -ErrorAction Stop|Select-Object InterfaceAlias,AddressFamily,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin)}catch{}
    }
    if(Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue){
        try{$dns=@(Get-DnsClientServerAddress -ErrorAction Stop|ForEach-Object {[pscustomobject]@{InterfaceAlias=$_.InterfaceAlias;AddressFamily=$_.AddressFamily;ServerAddresses=(@($_.ServerAddresses)-join '; ')}})}catch{}
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Network-Adapters.csv') -Rows $adapters -Columns @('Name','InterfaceDescription','Status','MacAddress','LinkSpeed','MediaType','PhysicalMediaType','DriverInformation')
    Export-PCCsv -Path (Join-Path $capture 'Integration\Network-Addresses.csv') -Rows $addresses -Columns @('InterfaceAlias','AddressFamily','IPAddress','PrefixLength','PrefixOrigin','SuffixOrigin')
    Export-PCCsv -Path (Join-Path $capture 'Integration\Network-DNS.csv') -Rows $dns -Columns @('InterfaceAlias','AddressFamily','ServerAddresses')
    if($adapters.Count -eq 0){Set-PCCollectorPartial 'NetTCPIP/NetAdapter cmdlets were unavailable or returned no data.'}
    return ($adapters.Count+$addresses.Count+$dns.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.FeaturesCapabilities' -Script {
    $features=@();$capabilities=@()
    if(Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue){
        try{$features=@(Get-WindowsOptionalFeature -Online -ErrorAction Stop|Where-Object {$_.State -eq 'Enabled'}|Select-Object FeatureName,State)}catch{Set-PCCollectorPartial 'Optional-feature inventory requires elevation on some systems.'}
    }else{Set-PCCollectorPartial 'DISM optional-feature cmdlets unavailable.'}
    if(Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue){
        try{$capabilities=@(Get-WindowsCapability -Online -ErrorAction Stop|Where-Object {$_.State -eq 'Installed'}|Select-Object Name,State)}catch{Set-PCCollectorPartial 'Windows-capability inventory requires elevation on some systems.'}
    }else{Set-PCCollectorPartial 'Windows-capability cmdlets unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\Enabled-Optional-Features.csv') -Rows $features -Columns @('FeatureName','State')
    Export-PCCsv -Path (Join-Path $capture 'Integration\Installed-Capabilities.csv') -Rows $capabilities -Columns @('Name','State')
    return ($features.Count+$capabilities.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.DriversDevices' -Script {
    $drivers=@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop|ForEach-Object {
        [pscustomobject]@{
            DeviceName=[string]$_.DeviceName
            DeviceClass=[string]$_.DeviceClass
            Manufacturer=[string]$_.Manufacturer
            DriverProviderName=[string]$_.DriverProviderName
            DriverVersion=[string]$_.DriverVersion
            DriverDate=[string]$_.DriverDate
            InfName=[string]$_.InfName
            IsSigned=[string]$_.IsSigned
            Signer=[string]$_.Signer
            DeviceID=[string]$_.DeviceID
        }
    })
    Export-PCCsv -Path (Join-Path $capture 'Integration\PnP-Signed-Drivers.csv') -Rows $drivers -Columns @(
        'DeviceName','DeviceClass','Manufacturer','DriverProviderName','DriverVersion','DriverDate','InfName','IsSigned','Signer','DeviceID'
    )
    $devices=@()
    if(Get-Command Get-PnpDevice -ErrorAction SilentlyContinue){
        try{$devices=@(Get-PnpDevice -PresentOnly -ErrorAction Stop|Select-Object Class,FriendlyName,InstanceId,Status,Problem)}catch{}
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Present-PnP-Devices.csv') -Rows $devices -Columns @('Class','FriendlyName','InstanceId','Status','Problem')
    return ($drivers.Count+$devices.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.Certificates' -Script {
    $rows=New-Object System.Collections.ArrayList
    $storeRows=New-Object System.Collections.ArrayList
    $certificateIssues=New-Object System.Collections.ArrayList
    foreach($definition in @(
        @{Scope='CurrentUser';Store='My';Path='Cert:\CurrentUser\My'},
        @{Scope='CurrentUser';Store='Root';Path='Cert:\CurrentUser\Root'},
        @{Scope='LocalMachine';Store='My';Path='Cert:\LocalMachine\My'},
        @{Scope='LocalMachine';Store='Root';Path='Cert:\LocalMachine\Root'}
    )){
        $certificates=@();$providerError='';$fallbackError='';$usedFallback=$false
        try{
            $certificates=@(Get-ChildItem -LiteralPath $definition.Path -ErrorAction Stop)
        }catch{
            $providerError=$_.Exception.Message
            $storeObject=$null
            try{
                $storeName=[Enum]::Parse([Security.Cryptography.X509Certificates.StoreName],[string]$definition.Store,$true)
                $storeLocation=[Enum]::Parse([Security.Cryptography.X509Certificates.StoreLocation],[string]$definition.Scope,$true)
                $storeObject=[Security.Cryptography.X509Certificates.X509Store]::new($storeName,$storeLocation)
                $flags=[Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
                $storeObject.Open($flags)
                $certificates=@($storeObject.Certificates)
                $usedFallback=$true
            }catch{$fallbackError=$_.Exception.Message}
            finally{if($null -ne $storeObject){$storeObject.Dispose()}}
        }
        if($fallbackError){
            $message='Certificate provider failed: '+$providerError+' | X509Store fallback failed: '+$fallbackError
            [void]$storeRows.Add([pscustomobject]@{
                Scope=$definition.Scope;Store=$definition.Store;Status='Failed';Records=0;Message=$message
            })
            if($definition.Scope -eq 'CurrentUser' -and $definition.Store -eq 'My'){
                Set-PCCollectorPartial 'The CurrentUser personal certificate store could not be read by either provider; missing personal certificates cannot be determined.'
            }else{
                Set-PCCollectorWarning "$($definition.Scope)\$($definition.Store) certificate-store inventory failed; see Integration\Certificate-Store-Status.csv."
            }
            continue
        }
        $storeCount=0;$storeIssueCount=0
        foreach($certificate in $certificates){
            try{
                $enhancedKeyUsage=''
                try{$enhancedKeyUsage=(@($certificate.EnhancedKeyUsageList|ForEach-Object {$_.ObjectId.Value}) -join '; ')}catch{}
                [void]$rows.Add([pscustomobject]@{
                    Scope=$definition.Scope;Store=$definition.Store
                    Thumbprint=[string]$certificate.Thumbprint
                    Subject=[string]$certificate.Subject
                    Issuer=[string]$certificate.Issuer
                    NotBefore=$certificate.NotBefore.ToUniversalTime().ToString('o')
                    NotAfter=$certificate.NotAfter.ToUniversalTime().ToString('o')
                    HasPrivateKey=[string]$certificate.HasPrivateKey
                    FriendlyName=[string]$certificate.FriendlyName
                    EnhancedKeyUsage=$enhancedKeyUsage
                })
                $storeCount++
            }catch{
                $storeIssueCount++
                $certificateError=$_.Exception.Message
                $failedThumbprint=''
                try{$failedThumbprint=[string]$certificate.Thumbprint}catch{}
                [void]$certificateIssues.Add([pscustomobject]@{
                    Scope=$definition.Scope;Store=$definition.Store
                    Thumbprint=$failedThumbprint
                    Message=$certificateError
                })
            }
        }
        $status=if($storeIssueCount){'Partial'}else{'Success'}
        $message=if($usedFallback){'PowerShell certificate provider failed; read-only X509Store fallback succeeded. Original error: '+$providerError}else{''}
        if($storeIssueCount){
            if($message){$message+=' | '}
            $message+="$storeIssueCount certificate record(s) could not be normalized; see Integration\Certificate-Read-Issues.csv."
            if($definition.Scope -eq 'CurrentUser' -and $definition.Store -eq 'My'){
                Set-PCCollectorPartial 'One or more CurrentUser personal certificates could not be normalized.'
            }else{Set-PCCollectorWarning $message}
        }
        [void]$storeRows.Add([pscustomobject]@{
            Scope=$definition.Scope;Store=$definition.Store;Status=$status;Records=$storeCount;Message=$message
        })
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\Certificates.csv') -Rows $rows.ToArray() -Columns @(
        'Scope','Store','Thumbprint','Subject','Issuer','NotBefore','NotAfter','HasPrivateKey','FriendlyName','EnhancedKeyUsage'
    )
    Export-PCCsv -Path (Join-Path $capture 'Integration\Certificate-Store-Status.csv') -Rows $storeRows.ToArray() -Columns @(
        'Scope','Store','Status','Records','Message'
    )
    Export-PCCsv -Path (Join-Path $capture 'Integration\Certificate-Read-Issues.csv') -Rows $certificateIssues.ToArray() -Columns @(
        'Scope','Store','Thumbprint','Message'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.ODBC' -Script {
    $rows=New-Object System.Collections.ArrayList
    if(Get-Command Get-OdbcDsn -ErrorAction SilentlyContinue){
        foreach($platform in @('32-bit','64-bit')){
            foreach($type in @('User','System')){
                try{
                    foreach($dsn in @(Get-OdbcDsn -DsnType $type -Platform $platform -ErrorAction Stop)){
                        $attributes=@($dsn.Attribute|ForEach-Object {
                            $text=[string]$_
                            if($text -match '(?i)password|pwd|token|secret'){'[REDACTED]'}else{$text}
                        })
                        [void]$rows.Add([pscustomobject]@{
                            Name=[string]$dsn.Name;DsnType=$type;Platform=$platform
                            DriverName=[string]$dsn.DriverName;Attributes=($attributes -join '; ')
                        })
                    }
                }catch{Set-PCCollectorPartial "ODBC $type $platform inventory was unavailable."}
            }
        }
    }else{Set-PCCollectorPartial 'Wdac ODBC cmdlets unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\ODBC-DSNs.csv') -Rows $rows.ToArray() -Columns @('Name','DsnType','Platform','DriverName','Attributes')
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.Firewall' -Script {
    $rows=@()
    if(Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue){
        try{
            $rows=@(Get-NetFirewallRule -ErrorAction Stop|ForEach-Object {
                [pscustomobject]@{
                    Name=[string]$_.Name
                    DisplayName=[string]$_.DisplayName
                    DisplayGroup=[string]$_.DisplayGroup
                    Enabled=[string]$_.Enabled
                    Direction=[string]$_.Direction
                    Action=[string]$_.Action
                    Profile=[string]$_.Profile
                    PolicyStoreSourceType=[string]$_.PolicyStoreSourceType
                }
            })
        }catch{Set-PCCollectorPartial 'Firewall rules could not be fully enumerated.'}
    }else{Set-PCCollectorPartial 'NetSecurity firewall cmdlets unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\Firewall-Rules.csv') -Rows $rows -Columns @(
        'Name','DisplayName','DisplayGroup','Enabled','Direction','Action','Profile','PolicyStoreSourceType'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.SharesGroups' -Script {
    $shares=New-Object System.Collections.ArrayList
    if(Get-Command Get-SmbShare -ErrorAction SilentlyContinue){
        try{
            foreach($share in @(Get-SmbShare -ErrorAction Stop)){
                if($share.Name -in @('ADMIN$','IPC$','C$')){continue}
                $access=@()
                try{$access=@(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop|ForEach-Object {$_.AccountName+'|'+$_.AccessControlType+'|'+$_.AccessRight})}catch{}
                [void]$shares.Add([pscustomobject]@{
                    Name=[string]$share.Name;Path=ConvertTo-PCTokenPath ([string]$share.Path)
                    Description=[string]$share.Description;ScopeName=[string]$share.ScopeName
                    EncryptData=[string]$share.EncryptData;FolderEnumerationMode=[string]$share.FolderEnumerationMode
                    Access=($access -join '; ')
                    NtfsAclSddl=if($share.Path -and (Test-Path -LiteralPath $share.Path)){
                        try{[string](Get-Acl -LiteralPath $share.Path -ErrorAction Stop).Sddl}catch{''}
                    }else{''}
                })
            }
        }catch{Set-PCCollectorPartial 'SMB shares/access could not be fully enumerated.'}
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\SMB-Shares.csv') -Rows $shares.ToArray() -Columns @(
        'Name','Path','Description','ScopeName','EncryptData','FolderEnumerationMode','Access','NtfsAclSddl'
    )
    $memberships=@()
    if(Get-Command Get-LocalGroup -ErrorAction SilentlyContinue){
        try{
            $membershipRows=New-Object System.Collections.ArrayList
            foreach($group in @(Get-LocalGroup -ErrorAction Stop)){
                foreach($member in @(Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue)){
                    [void]$membershipRows.Add([pscustomobject]@{Group=$group.Name;Member=[string]$member.Name;ObjectClass=[string]$member.ObjectClass;PrincipalSource=[string]$member.PrincipalSource})
                }
            }
            $memberships=$membershipRows.ToArray()
        }catch{Set-PCCollectorPartial 'Local group membership inventory was incomplete.'}
    }else{Set-PCCollectorPartial 'Microsoft.PowerShell.LocalAccounts cmdlets unavailable in this process architecture.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\Local-Group-Memberships.csv') -Rows $memberships -Columns @('Group','Member','ObjectClass','PrincipalSource')
    return ($shares.Count+$memberships.Count)
}

Invoke-PCCaptureCollector -Name 'Integration.PowerConfiguration' -Script {
    $powercfg=Join-Path $env:SystemRoot 'System32\powercfg.exe'
    if(-not [IO.File]::Exists($powercfg)){Set-PCCollectorPartial 'powercfg.exe unavailable.';return 0}
    $list=Invoke-PCNativeProcess -FilePath $powercfg -Arguments '/list'
    $query=Invoke-PCNativeProcess -FilePath $powercfg -Arguments '/query'
    Write-PCText -Path (Join-Path $capture 'Integration\Power-Plans.txt') -Text $list.StdOut
    Write-PCText -Path (Join-Path $capture 'Integration\Active-Power-Plan-Settings.txt') -Text $query.StdOut
    if($list.ExitCode -ne 0 -or $query.ExitCode -ne 0){Set-PCCollectorPartial 'One or more powercfg queries failed.'}
    $activeRows=New-Object System.Collections.ArrayList
    $activeLine=@($list.StdOut -split '\r?\n'|Where-Object {$_ -match '\*\s*$'}|Select-Object -First 1)
    if($activeLine.Count){
        $guid='';$name=''
        if($activeLine[0] -match '(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'){$guid=$matches[1]}
        if($activeLine[0] -match '\(([^()]*)\)'){$name=$matches[1]}
        [void]$activeRows.Add([pscustomobject]@{SchemeGuid=$guid;Name=$name;Raw=$activeLine[0].Trim()})
    }elseif($list.ExitCode -eq 0){Set-PCCollectorPartial 'The active power scheme could not be parsed from powercfg output.'}
    Export-PCCsv -Path (Join-Path $capture 'Integration\Active-Power-Scheme.csv') -Rows $activeRows.ToArray() -Columns @('SchemeGuid','Name','Raw')
    return @($list.StdOut -split '\r?\n'|Where-Object {$_ -match 'Power Scheme GUID'}).Count
}

Invoke-PCCaptureCollector -Name 'Integration.SystemFiles' -Script {
    $rows=New-Object System.Collections.ArrayList
    foreach($path in @(
        (Join-Path $env:WINDIR 'System32\drivers\etc\hosts')
    )){
        if(-not [IO.File]::Exists($path)){continue}
        $payload=''
        if($CaptureSettingsPayload){
            $payload=Copy-PCPayloadFile -Source $path -RelativePayloadPath ('SystemFiles\'+[IO.Path]::GetFileName($path))
        }
        $file=Get-Item -LiteralPath $path
        [void]$rows.Add([pscustomobject]@{
            DestinationPath=ConvertTo-PCTokenPath $path
            Length=$file.Length
            LastWriteTimeUtc=$file.LastWriteTimeUtc.ToString('o')
            SHA256=Get-PCSha256File $path
            PayloadRelativePath=$payload
            Risk='High'
        })
    }
    Export-PCCsv -Path (Join-Path $capture 'Integration\System-Files.csv') -Rows $rows.ToArray() -Columns @(
        'DestinationPath','Length','LastWriteTimeUtc','SHA256','PayloadRelativePath','Risk'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'Integration.DevelopmentTools' -Script {
    $directory=Join-Path $capture 'Integration\Development';New-PCDirectory $directory
    $rows=New-Object System.Collections.ArrayList
    foreach($name in @('pwsh.exe','dotnet.exe','git.exe','code.cmd','code.exe','python.exe','py.exe','cmake.exe','g++.exe','clang.exe','ffmpeg.exe','docker.exe','wsl.exe')){
        $command=Get-Command $name -ErrorAction SilentlyContinue|Select-Object -First 1
        if($null -eq $command){continue}
        $path=[string](Get-PCProperty $command 'Source' '')
        if(-not $path){$path=[string](Get-PCProperty $command 'Path' '')}
        $version=''
        if($path -and [IO.File]::Exists($path)){try{$version=[string](Get-Item -LiteralPath $path).VersionInfo.ProductVersion}catch{}}
        [void]$rows.Add([pscustomobject]@{Name=$name;Path=ConvertTo-PCTokenPath $path;Version=$version;CommandType=[string]$command.CommandType})
    }
    Export-PCCsv -Path (Join-Path $directory 'Tool-Commands.csv') -Rows $rows.ToArray() -Columns @('Name','Path','Version','CommandType')

    $dotnet=Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if($null -ne $dotnet){
        $sdks=Invoke-PCNativeProcess -FilePath $dotnet.Source -Arguments '--list-sdks'
        $runtimes=Invoke-PCNativeProcess -FilePath $dotnet.Source -Arguments '--list-runtimes'
        Write-PCText -Path (Join-Path $directory 'DotNet-SDKs.txt') -Text $sdks.StdOut
        Write-PCText -Path (Join-Path $directory 'DotNet-Runtimes.txt') -Text $runtimes.StdOut
        if($sdks.ExitCode -ne 0 -or $runtimes.ExitCode -ne 0){Set-PCCollectorPartial 'One or more dotnet inventory commands failed.'}
    }
    $code=Get-Command -Name @('code.cmd','code.exe') -ErrorAction SilentlyContinue|Select-Object -First 1
    if($null -ne $code){
        $extensions=Invoke-PCNativeProcess -FilePath $code.Source -Arguments '--list-extensions --show-versions'
        Write-PCText -Path (Join-Path $directory 'VSCode-Extensions.txt') -Text $extensions.StdOut
        if($extensions.ExitCode -ne 0){Set-PCCollectorPartial 'VS Code extension inventory failed.'}
    }
    $wsl=Get-Command wsl.exe -ErrorAction SilentlyContinue
    if($null -ne $wsl){
        $distros=Invoke-PCNativeProcess -FilePath $wsl.Source -Arguments '--list --verbose' -TimeoutSeconds 30
        $wslText=(($distros.StdOut+[Environment]::NewLine+$distros.StdErr) -replace [char]0,'').Trim()
        if($distros.ExitCode -ne 0 -and $wslText -match '(?i)usage:\s*wsl(?:\.exe)?\s+\[argument\]'){
            $legacy=Invoke-PCNativeProcess -FilePath $wsl.Source -Arguments '--list' -TimeoutSeconds 30
            $legacyText=(($legacy.StdOut+[Environment]::NewLine+$legacy.StdErr) -replace [char]0,'').Trim()
            if($legacy.ExitCode -eq 0){
                $distros=$legacy
                $wslText=$legacyText
                Set-PCCollectorWarning 'Legacy wsl.exe does not support verbose distribution listing; distribution names were captured without version/state.'
            }
        }
        Write-PCText -Path (Join-Path $directory 'WSL-Distributions.txt') -Text $wslText
        if($distros.ExitCode -ne 0){
            if($wslText -match '(?i)(no installed distributions|has no installed distributions|windows subsystem for linux has no installed distributions)'){
                Set-PCCollectorWarning 'WSL is available but no distributions are installed.'
            }elseif($wslText -match '(?i)(windows subsystem for linux.*not installed|optional component.*not enabled|enable the.*windows subsystem for linux)'){
                Set-PCCollectorWarning 'wsl.exe is present but the WSL optional component is not enabled; feature inventory records the authoritative state.'
            }else{
                $detail=($wslText -replace '\s+',' ').Trim()
                if($detail.Length -gt 240){$detail=$detail.Substring(0,240)+'...'}
                Set-PCCollectorPartial "WSL distribution inventory returned exit code $($distros.ExitCode): $detail"
            }
        }elseif(-not $wslText){
            Set-PCCollectorWarning 'WSL returned no distribution rows; no installed distribution was detected.'
        }
    }
    $docker=Get-Command docker.exe -ErrorAction SilentlyContinue
    if($null -ne $docker){
        try{
            $contexts=Invoke-PCNativeProcess -FilePath $docker.Source -Arguments 'context ls --format "{{.Name}}|{{.Description}}|{{.DockerEndpoint}}|{{.Current}}"' -TimeoutSeconds 30
            Write-PCText -Path (Join-Path $directory 'Docker-Contexts.txt') -Text $contexts.StdOut
            if($contexts.ExitCode -ne 0){Set-PCCollectorPartial 'Docker context inventory failed.'}
        }catch{Set-PCCollectorPartial 'Docker was installed but context inventory timed out or failed.'}
    }
    $git=Get-Command git.exe -ErrorAction SilentlyContinue
    if($null -ne $git){
        $config=Invoke-PCNativeProcess -FilePath $git.Source -Arguments 'config --global --list --show-origin'
        if($config.ExitCode -ne 0){Set-PCCollectorPartial 'Git global-configuration inventory failed.'}
        $configRows=New-Object System.Collections.ArrayList
        foreach($line in @($config.StdOut -split '\r?\n')){
            if(-not $line){continue}
            $withoutOrigin=$line
            if($line -match '^\S+\s+(.+)$'){$withoutOrigin=$matches[1]}
            $key=$withoutOrigin;$value=''
            if($withoutOrigin -match '^([^=]+)=(.*)$'){$key=$matches[1];$value=$matches[2]}
            $sensitiveGitSetting=($key -match '(?i)credential|token|password|secret|private|url')
            [void]$configRows.Add([pscustomobject]@{
                Key=$key
                ValueSHA256=if($sensitiveGitSetting){''}else{Get-PCSha256Text (ConvertTo-PCNormalizedText $value)}
                Preview=if($sensitiveGitSetting){if($value){'[REDACTED]'}else{''}}else{if($value.Length -gt 160){$value.Substring(0,160)+'...'}else{$value}}
            })
        }
        Export-PCCsv -Path (Join-Path $directory 'Git-Global-Config.csv') -Rows $configRows.ToArray() -Columns @('Key','ValueSHA256','Preview')
    }
    $programFilesX86=[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $vswhere=if($programFilesX86){Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'}else{''}
    if($vswhere -and [IO.File]::Exists($vswhere)){
        $visualStudio=Invoke-PCNativeProcess -FilePath $vswhere -Arguments '-all -products * -format json -utf8'
        Write-PCText -Path (Join-Path $directory 'Visual-Studio-Instances.json') -Text $visualStudio.StdOut
        if($visualStudio.ExitCode -ne 0){Set-PCCollectorPartial 'Visual Studio instance inventory failed.'}
    }
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'SecureManual.CredentialTargets' -Script {
    $rows=New-Object System.Collections.ArrayList
    $cmdkey=Join-Path $env:SystemRoot 'System32\cmdkey.exe'
    if([IO.File]::Exists($cmdkey)){
        $result=Invoke-PCNativeProcess -FilePath $cmdkey -Arguments '/list'
        $target='';$type='';$user=''
        foreach($line in @($result.StdOut -split '\r?\n')){
            if($line -match '^\s*Target:\s*(.+)$'){
                if($target){[void]$rows.Add([pscustomobject]@{Target=$target;Type=$type;UserName=$user;SecretCaptured='False'})}
                $target=$matches[1].Trim();$type='';$user=''
            }elseif($line -match '^\s*Type:\s*(.+)$'){$type=$matches[1].Trim()
            }elseif($line -match '^\s*User:\s*(.+)$'){$user=$matches[1].Trim()}
        }
        if($target){[void]$rows.Add([pscustomobject]@{Target=$target;Type=$type;UserName=$user;SecretCaptured='False'})}
        if($result.ExitCode -ne 0){Set-PCCollectorPartial "cmdkey returned exit code $($result.ExitCode)."}
    }else{Set-PCCollectorPartial 'cmdkey.exe unavailable.'}
    Export-PCCsv -Path (Join-Path $capture 'SecureManual\Credential-Targets.csv') -Rows $rows.ToArray() -Columns @('Target','Type','UserName','SecretCaptured')
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'SecureManual.SecureFileCandidates' -Script {
    $rows=New-Object System.Collections.ArrayList
    if(-not $SearchSecureFileCandidates){
        Set-PCCollectorPartial 'Disabled. Use -SearchSecureFileCandidates on the source to locate vault/key containers.'
    }else{
        $extensions=@('.2fa','.kdbx','.pfx','.p12','.pem','.key','.ppk','.ovpn','.rdp','.1pux')
        foreach($root in @(
            [Environment]::GetFolderPath('Desktop'),
            [Environment]::GetFolderPath('MyDocuments'),
            (Join-Path $env:USERPROFILE 'Downloads')
        )){
            if(-not $root -or -not [IO.Directory]::Exists($root)){continue}
            $secureFiles=@()
            try{$secureFiles=@(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Stop|Where-Object {$extensions -contains $_.Extension.ToLowerInvariant()})}
            catch{Set-PCCollectorPartial "Some secure-file candidates under $root could not be enumerated."}
            foreach($file in $secureFiles){
                [void]$rows.Add([pscustomobject]@{
                    Path=ConvertTo-PCTokenPath $file.FullName
                    Extension=$file.Extension.ToLowerInvariant()
                    Length=$file.Length
                    LastWriteTimeUtc=$file.LastWriteTimeUtc.ToString('o')
                    SHA256=if($file.Length -le ([int64]$MaximumHashedFileMiB*1MB)){Get-PCSha256File $file.FullName}else{''}
                    Copied='False'
                })
            }
        }
    }
    Export-PCCsv -Path (Join-Path $capture 'SecureManual\Secure-File-Candidates.csv') -Rows $rows.ToArray() -Columns @(
        'Path','Extension','Length','LastWriteTimeUtc','SHA256','Copied'
    )
    return $rows.Count
}

Invoke-PCCaptureCollector -Name 'SecureManual.Checklist' -Script {
    $certificates=Import-PCCsv -Path (Join-Path $capture 'Integration\Certificates.csv')
    $apps=Import-PCCsv -Path (Join-Path $capture 'Applications\Desktop-Applications.csv')
    $appx=Import-PCCsv -Path (Join-Path $capture 'Applications\Appx-CurrentUser.csv')
    $names=((@($apps|ForEach-Object {$_.DisplayName})+@($appx|ForEach-Object {$_.Name})) -join ' | ')
    $rows=New-Object System.Collections.ArrayList
    [void]$rows.Add([pscustomobject]@{Item='Credential Manager and saved network credentials';Detected='Unknown';Action='Re-enter or use the application/service supported sign-in flow.';Reason='Secrets are DPAPI/account bound and are never captured.'})
    [void]$rows.Add([pscustomobject]@{Item='Windows Hello, passkeys, PIN, and biometric enrollment';Detected='Unknown';Action='Re-enroll on the destination.';Reason='Device-bound security material is nonportable.'})
    [void]$rows.Add([pscustomobject]@{Item='Browser cookies, saved passwords, and sign-in tokens';Detected='Likely';Action='Use browser sync/export and reauthenticate; do not copy live profile databases generically.';Reason='Protected and version-sensitive browser state.'})
    [void]$rows.Add([pscustomobject]@{Item='Certificates with private keys';Detected=if(@($certificates|Where-Object {$_.HasPrivateKey -eq 'True'}).Count){'Yes'}else{'No'};Action='Export required certificates as password-protected PFX from the source and import deliberately.';Reason='The inventory records certificates but never private keys.'})
    [void]$rows.Add([pscustomobject]@{Item='2fast authenticator vault';Detected=if($names -match '(?i)2fast'){'Application present'}else{'Not detected'};Action='Locate and securely transfer the user-selected .2fa file, then verify codes before retiring the source.';Reason='Reinstalling the Store app does not restore the vault file.'})
    [void]$rows.Add([pscustomobject]@{Item='Keeper or other password-manager session';Detected=if($names -match '(?i)keeper|1password|bitwarden|dashlane'){'Application present'}else{'Not detected'};Action='Install the destination app/extension and sign in; retain recovery material.';Reason='Session, vault cache, Hello, and DPAPI state are not transplanted.'})
    [void]$rows.Add([pscustomobject]@{Item='Application licenses and activations';Detected='Unknown';Action='Deactivate source seats where required, then reactivate using vendor-supported licensing.';Reason='Licenses may be machine-bound or contract-limited.'})
    [void]$rows.Add([pscustomobject]@{Item='EFS, BitLocker recovery, SSH/GPG, VPN, and code-signing keys';Detected='Unknown';Action='Verify independent recovery-key/private-key backups before decommissioning the source.';Reason='Loss can make encrypted data permanently inaccessible.'})
    [void]$rows.Add([pscustomobject]@{Item='Store application data';Detected=if($appx.Count){'Yes'}else{'No'};Action='Reinstall packages, sign in, and use app-supported export/sync for data.';Reason='Generic LocalState/AppRepository transplantation is unsafe and unsupported.'})
    Export-PCCsv -Path (Join-Path $capture 'SecureManual\Manual-Secure-Checklist.csv') -Rows $rows.ToArray() -Columns @('Item','Detected','Action','Reason')
    return $rows.Count
}

$captureStopwatch.Stop()
Export-PCCsv -Path (Join-Path $capture 'Diagnostics\Registry-Read-Issues.csv') -Rows $script:PCRegistryReadIssueRows.ToArray() -Columns @(
    'Hive','View','Root','Key','Operation','Message'
)
Export-PCCsv -Path (Join-Path $capture 'Diagnostics\Policy-Exclusions.csv') -Rows $script:PCPolicyExclusionRows.ToArray() -Columns @(
    'Category','Scope','Path','Reason'
)
Export-PCCsv -Path (Join-Path $capture 'Diagnostics\Service-State-Changes.csv') -Rows $script:PCServiceStateRows.ToArray() -Columns @(
    'Name','DisplayName','RequestedAction','StatusBefore','TransitionResult','RestoreResult','Message'
)
Export-PCCsv -Path (Join-Path $capture 'Capture-Status.csv') -Rows $statusRows.ToArray() -Columns @(
    'Collector','Status','Records','ElapsedSeconds','Message'
)
$failed=@($statusRows|Where-Object {$_.Status -eq 'Failed'}).Count
$partial=@($statusRows|Where-Object {$_.Status -eq 'Partial'}).Count
$warnings=@($statusRows|Where-Object {$_.Status -eq 'Success' -and $_.Message}).Count
$summary=@(
    'PCMigration Reconciliation v4.0.0 capture',
    ('Computer:             '+$meta.ComputerName),
    ('User:                 '+$meta.UserName),
    ('Windows build:        '+$meta.WindowsBuild),
    ('Inventory mode:       '+$InventoryMode),
    ('Collectors:           '+$statusRows.Count),
    ('Failed collectors:    '+$failed),
    ('Partial collectors:   '+$partial),
    ('Successful w/warning: '+$warnings),
    ('Policy exclusions:    '+$script:PCPolicyExclusionRows.Count),
    ('Payload bytes:        '+$script:PCPayloadBytes),
    ('Elapsed seconds:      '+[Math]::Round($captureStopwatch.Elapsed.TotalSeconds,2)),
    '',
    'Review Capture-Status.csv before comparison. A failed/partial collector is',
    'reported as unknown coverage and must not be interpreted as an absent item.'
) -join [Environment]::NewLine
Write-PCText -Path (Join-Path $capture 'Capture-Summary.txt') -Text $summary
[void](New-PCCaptureManifest -CapturePath $capture)

Write-Host ''
Write-Host $summary
Write-Host ''
Write-Host "Capture complete: $capture" -ForegroundColor Green
if(-not $meta.IsAdministrator){Write-Warning 'Capture was not elevated. Review Partial collectors and repeat elevated if complete machine-state coverage is required.'}

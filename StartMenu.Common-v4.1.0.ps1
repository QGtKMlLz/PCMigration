#requires -version 5.1
# Shared helpers for the Windows 10 Start-menu workflow. Do not run directly.
Set-StrictMode -Version 2.0
$script:PCStartCloudSub='Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount'
$script:PCStartPolicySub='SOFTWARE\Policies\Microsoft\Windows\Explorer'
$script:PCStartPolicyNames=@('LockedStartLayout','StartLayoutFile','ReapplyStartLayoutEveryLogon')

function Assert-PCStartHost {
    if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess){
        throw 'Use 64-bit Windows PowerShell 5.1 as the intended interactive user.'
    }
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if([int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 10240 -or [int]$os.BuildNumber -ge 22000){
        throw 'The Start-menu module is limited to Windows 10 clients. Windows 11 pins and Windows Server are not supported.'
    }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')){throw 'Run in the migrated user session, not a service account.'}
    return $os
}

function Test-PCStartChild {
    param([string]$Name)
    return (-not [string]::IsNullOrWhiteSpace($Name) -and
        $Name.IndexOfAny([char[]]@('\','/',"`r","`n",'[',']')) -lt 0 -and
        $Name -like '*start.tilegrid*' -and
        $Name -like '*windows.data.curatedtilecollection.tilecollection*')
}

function Get-PCStartKeys {
    $root=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PCStartCloudSub,$false)
    try{
        if($null -eq $root){return}
        foreach($name in $root.GetSubKeyNames()){
            if(-not (Test-PCStartChild $name)){continue}
            $current=$root.OpenSubKey($name+'\Current',$false)
            try{
                $hasData=($null -ne $current -and $current.GetValueNames() -contains 'Data')
                [pscustomobject]@{ChildName=$name;HasData=$hasData}
            }finally{if($null -ne $current){$current.Dispose()}}
        }
    }finally{if($null -ne $root){$root.Dispose()}}
}

function Get-PCStartHash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Write-PCStartJson {
    param([string]$Path,$Value)
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($true)))
}

function Write-PCStartManifest {
    param([string]$Directory)
    $lines=@(Get-ChildItem -LiteralPath $Directory -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
        if($_.Name -ne 'SHA256SUMS.txt'){
            $rel=$_.FullName.Substring($Directory.TrimEnd('\').Length).TrimStart('\')
            (Get-PCStartHash $_.FullName)+'  '+$rel
        }
    })
    [IO.File]::WriteAllLines((Join-Path $Directory 'SHA256SUMS.txt'),[string[]]$lines,(New-Object Text.UTF8Encoding($true)))
}

function Get-PCStartContainedFile {
    param([string]$Directory,[string]$Relative)
    if([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative) -or $Relative.Contains(':')){
        throw "Invalid capture-relative path: $Relative"
    }
    $root=[IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $path=[IO.Path]::GetFullPath((Join-Path $root $Relative))
    if(-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw "Capture path escapes its root: $Relative"}
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if($item.PSIsContainer){throw "Expected a capture file: $Relative"}
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Reparse point in capture path: $Relative"}
    $cursor=$item.Directory
    while($null -ne $cursor -and $cursor.FullName.Length -ge $root.Length){
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Reparse point in capture path: $Relative"}
        $cursor=$cursor.Parent
    }
    return $path
}

function Assert-PCStartManifest {
    param([string]$Directory,[switch]$AllowLegacy)
    $mf=Join-Path $Directory 'SHA256SUMS.txt'
    if(-not [IO.File]::Exists($mf)){
        if($AllowLegacy){Write-Warning 'Legacy capture has no checksum manifest. Use only your trusted original capture.';return $null}
        throw "Capture manifest missing: $mf"
    }
    $listed=@{}
    foreach($line in [IO.File]::ReadAllLines($mf)){
        if(-not $line.Trim()){continue}
        if($line -notmatch '^([0-9a-fA-F]{64})  (.+)$'){throw 'Malformed capture manifest.'}
        $hash=$matches[1];$rel=$matches[2]
        if($listed.ContainsKey($rel)){throw "Duplicate capture manifest path: $rel"}
        $path=Get-PCStartContainedFile $Directory $rel
        if((Get-PCStartHash $path) -ne $hash){throw "Capture hash mismatch: $rel"}
        $listed[$rel]=$hash
    }
    return $listed
}

function Read-PCStartMeta {
    param([string]$Directory)
    $path=Get-PCStartContainedFile $Directory 'Meta.json'
    $meta=[IO.File]::ReadAllText($path)|ConvertFrom-Json
    $schema=[string]$meta.SchemaVersion
    if($schema -notin @('StartMenu-1.0','2.5.4')){
        throw 'Use a separate Capture-StartMenu capture (StartMenu-1.0 or legacy 2.5.4). Core reconciliation captures are not tile captures.'
    }
    $manifest=Assert-PCStartManifest $Directory -AllowLegacy:($schema -eq '2.5.4')
    Assert-PCStartListed $manifest 'Meta.json'
    [pscustomobject]@{Meta=$meta;Manifest=$manifest}
}

function Assert-PCStartListed {
    param($Manifest,[string]$Relative)
    if($null -ne $Manifest -and -not $Manifest.ContainsKey($Relative)){throw "File is not authorized by capture manifest: $Relative"}
}

function Read-PCStartXml {
    param([string]$Path)
    # Respect the declaration/BOM, including UTF-8 without a BOM. Never decode via Get-Content.
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    try{
        $doc=New-Object Xml.XmlDocument
        $doc.XmlResolver=$null
        $doc.PreserveWhitespace=$true
        $doc.Load($reader)
        return ,$doc
    }finally{$reader.Dispose()}
}

function Convert-PCStartReg {
    param([string]$Text,[string]$SourceChild,[string]$DestinationChild)
    if(-not (Test-PCStartChild $SourceChild) -or -not (Test-PCStartChild $DestinationChild)){throw 'Invalid tile-grid child name.'}
    $src='HKEY_CURRENT_USER\'+$script:PCStartCloudSub+'\'+$SourceChild
    $dst='HKEY_CURRENT_USER\'+$script:PCStartCloudSub+'\'+$DestinationChild
    $lines=@($Text -split "`r?`n")
    if($lines[0].Trim([char]0xFEFF).Trim() -ne 'Windows Registry Editor Version 5.00'){throw 'Invalid registry export signature.'}
    $headers=0;$rootFound=$false;$output=New-Object System.Collections.ArrayList
    foreach($line in $lines){
        $trim=$line.Trim()
        if($trim.StartsWith('[')){
            if(-not $trim.EndsWith(']') -or $trim.StartsWith('[-')){throw 'Invalid/deletion registry header.'}
            $key=$trim.Substring(1,$trim.Length-2)
            if($key.Equals($src,[StringComparison]::OrdinalIgnoreCase)){$rootFound=$true}
            elseif(-not $key.StartsWith($src+'\',[StringComparison]::OrdinalIgnoreCase)){throw "Registry header outside authorized tile-grid: $key"}
            [void]$output.Add('['+$dst+$key.Substring($src.Length)+']')
            $headers++
        }else{
            # Only header paths change. Value strings/binary data remain untouched.
            [void]$output.Add($line)
        }
    }
    if($headers -eq 0 -or -not $rootFound){throw 'Tile-grid root header missing.'}
    return ($output.ToArray() -join "`r`n")
}

function Invoke-PCStartReg {
    param([string[]]$Arguments)
    # ArgumentList is a command-line string on Windows PowerShell 5.1.
    $quoted=@(foreach($a in $Arguments){
        if($a.Contains('"') -or $a.Contains("`r") -or $a.Contains("`n")){throw 'Invalid native registry argument.'}
        '"'+$a+'"'
    })
    $p=Start-Process -FilePath "$env:SystemRoot\System32\reg.exe" -ArgumentList $quoted -Wait -PassThru -WindowStyle Hidden
    if($p.ExitCode -ne 0){throw "reg.exe failed (exit $($p.ExitCode)): $($Arguments[0])"}
}

function Get-PCStartPolicyState {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PCStartPolicySub,$false)
    try{
        foreach($name in $script:PCStartPolicyNames){
            $present=($null -ne $key -and $key.GetValueNames() -contains $name)
            $kind='';$value=$null
            if($present){
                $kind=[string]$key.GetValueKind($name)
                if($kind -notin @('DWord','String','ExpandString')){throw "Unexpected Start policy value type: $name ($kind)"}
                $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
            [pscustomobject]@{Name=$name;Present=$present;Kind=$kind;Value=$value}
        }
    }finally{if($null -ne $key){$key.Dispose()}}
}

function Set-PCStartPolicyState {
    param([object[]]$Rows)
    $rowsArray=@($Rows)
    if($rowsArray.Count -ne 3){throw 'Invalid Start policy snapshot.'}
    $seen=@{}
    foreach($row in $rowsArray){
        if($row.Name -notin $script:PCStartPolicyNames -or $seen.ContainsKey([string]$row.Name)){throw 'Invalid Start policy snapshot name.'}
        $seen[[string]$row.Name]=$true
        if($row.Present -and $row.Kind -notin @('DWord','String','ExpandString')){throw 'Invalid Start policy snapshot kind.'}
    }
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:PCStartPolicySub)
    try{
        foreach($row in $rowsArray){
            if($row.Present){
                $kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$row.Kind)
                $value=if($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord){[int]$row.Value}else{[string]$row.Value}
                $key.SetValue([string]$row.Name,$value,$kind)
            }else{$key.DeleteValue([string]$row.Name,$false)}
        }
    }finally{$key.Dispose()}
}

function Clear-PCStartPolicy {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PCStartPolicySub,$true)
    try{if($null -ne $key){foreach($name in $script:PCStartPolicyNames){$key.DeleteValue($name,$false)}}}
    finally{if($null -ne $key){$key.Dispose()}}
}

function New-PCStartBackupDirectory {
    param([string]$Label)
    $desktop=[Environment]::GetFolderPath('DesktopDirectory')
    if(-not $desktop){throw 'Cannot resolve the current user Desktop folder.'}
    $path=Join-Path $desktop ($Label+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}

function Stop-PCStartShell {
    $session=(Get-Process -Id $PID).SessionId
    foreach($name in @('StartMenuExperienceHost','ShellExperienceHost','explorer')){
        Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session} |
            Stop-Process -Force -ErrorAction Stop
    }
    Start-Sleep -Seconds 1
}

function Remove-PCStartTileKey {
    param([string]$Child)
    if(-not (Test-PCStartChild $Child)){throw 'Invalid tile-grid deletion target.'}
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:PCStartCloudSub+'\'+$Child,$false)
}

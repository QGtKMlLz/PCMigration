#requires -version 5.1
<#
Shared implementation for PCMigration Reconciliation v4.0.0.

This file intentionally uses only Windows PowerShell 5.1 and inbox .NET APIs.
It does not import third-party modules and does not use a temporary database.
#>

Set-StrictMode -Version 2.0

$script:PCMigrationSchemaVersion='4.0'
$script:PCMigrationUtf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:PCRegistryReadErrorCount = 0
$script:PCRegistryReadIssueRows = New-Object System.Collections.ArrayList
$script:PCPolicyExclusionRows = New-Object System.Collections.ArrayList
$script:PCPolicyExclusionIndex = @{}

function Add-PCPolicyExclusion {
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Scope,
        [AllowEmptyString()][string]$Path='',
        [Parameter(Mandatory=$true)][string]$Reason
    )
    $identity=($Category+'|'+$Scope+'|'+$Path).ToLowerInvariant()
    if($script:PCPolicyExclusionIndex.ContainsKey($identity)){return}
    $script:PCPolicyExclusionIndex[$identity]=$true
    [void]$script:PCPolicyExclusionRows.Add([pscustomobject]@{
        Category=$Category
        Scope=$Scope
        Path=$Path
        Reason=$Reason
    })
}

function Add-PCRegistryReadIssue {
    param(
        [string]$Hive,
        [Microsoft.Win32.RegistryView]$View=[Microsoft.Win32.RegistryView]::Default,
        [string]$Root,
        [string]$Key,
        [string]$Operation,
        [string]$Message
    )
    $script:PCRegistryReadErrorCount++
    [void]$script:PCRegistryReadIssueRows.Add([pscustomobject]@{
        Hive=$Hive
        View=[string]$View
        Root=$Root
        Key=$Key
        Operation=$Operation
        Message=$Message
    })
}

function New-PCDirectory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not [IO.Directory]::Exists($Path)){
        [void][IO.Directory]::CreateDirectory($Path)
    }
}

function Write-PCText {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [AllowEmptyString()][string]$Text=''
    )
    $parent=[IO.Path]::GetDirectoryName($Path)
    if($parent){New-PCDirectory $parent}
    [IO.File]::WriteAllText($Path,$Text,$script:PCMigrationUtf8Bom)
}

function Write-PCJson {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$Value,
        [int]$Depth=10
    )
    Write-PCText -Path $Path -Text ($Value|ConvertTo-Json -Depth $Depth)
}

function Read-PCJson {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not [IO.File]::Exists($Path)){return $null}
    try{return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)}catch{return $null}
}

function Import-PCCsv {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not [IO.File]::Exists($Path)){return @()}
    try{return @(Import-Csv -LiteralPath $Path)}catch{return @()}
}

function Export-PCCsv {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        $Rows,
        [Parameter(Mandatory=$true)][string[]]$Columns
    )
    $parent=[IO.Path]::GetDirectoryName($Path)
    if($parent){New-PCDirectory $parent}
    $items=@($Rows)
    if($items.Count -gt 0){
        $items|Select-Object -Property $Columns|Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        return
    }
    $header=(($Columns|ForEach-Object {'"'+($_ -replace '"','""')+'"'}) -join ',')+"`r`n"
    Write-PCText -Path $Path -Text $header
}

function Get-PCProperty {
    param($Object,[Parameter(Mandatory=$true)][string]$Name,$Default='')
    if($null -eq $Object){return $Default}
    $property=$Object.PSObject.Properties[$Name]
    if($null -eq $property -or $null -eq $property.Value){return $Default}
    return $property.Value
}

function Get-PCScheduledTaskTriggerType {
    param($Trigger)
    if($null -eq $Trigger){return ''}
    $type=[string](Get-PCProperty $Trigger 'TriggerType' '')
    if(-not $type){
        $cimClass=Get-PCProperty $Trigger 'CimClass' $null
        $type=[string](Get-PCProperty $cimClass 'CimClassName' '')
    }
    if(-not $type -and $Trigger.PSObject.TypeNames.Count -gt 0){$type=[string]$Trigger.PSObject.TypeNames[0]}
    if(-not $type){$type=$Trigger.GetType().FullName}
    return $type
}

function Test-PCAdministrator {
    try{
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }catch{return $false}
}

function Get-PCSafeFileName {
    param([Parameter(Mandatory=$true)][string]$Text,[int]$MaxLength=120)
    $safe=($Text -replace '[^A-Za-z0-9._-]','_').Trim('_')
    if(-not $safe){$safe='item'}
    if($safe.Length -gt $MaxLength){$safe=$safe.Substring(0,$MaxLength)}
    return $safe
}

function Get-PCSha256Text {
    param([AllowEmptyString()][string]$Text='')
    $sha=[Security.Cryptography.SHA256]::Create()
    try{
        $bytes=[Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes)|ForEach-Object {$_.ToString('x2')}) -join '')
    }finally{$sha.Dispose()}
}

function Get-PCSha256File {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateRange(0,10)][int]$RetryCount=2,
        [ValidateRange(0,5000)][int]$RetryDelayMilliseconds=200,
        [switch]$ThrowOnFailure
    )
    $lastError=$null
    for($attempt=0;$attempt -le $RetryCount;$attempt++){
        $stream=$null;$sha=$null
        try{
            $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
            $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
            $sha=[Security.Cryptography.SHA256]::Create()
            return (($sha.ComputeHash($stream)|ForEach-Object {$_.ToString('x2')}) -join '')
        }catch{
            $lastError=$_
            if($attempt -lt $RetryCount -and $RetryDelayMilliseconds -gt 0){
                Start-Sleep -Milliseconds $RetryDelayMilliseconds
            }
        }finally{
            if($null -ne $sha){$sha.Dispose()}
            if($null -ne $stream){$stream.Dispose()}
        }
    }
    if($ThrowOnFailure -and $null -ne $lastError){throw $lastError}
    return ''
}

function Invoke-PCNativeProcess {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [AllowEmptyString()][string]$Arguments='',
        [int]$TimeoutSeconds=0
    )
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$FilePath
    $start.Arguments=$Arguments
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$start
    try{
        if(-not $process.Start()){throw "Could not start: $FilePath"}
        $stdoutTask=$process.StandardOutput.ReadToEndAsync()
        $stderrTask=$process.StandardError.ReadToEndAsync()
        if($TimeoutSeconds -gt 0){
            if(-not $process.WaitForExit($TimeoutSeconds*1000)){
                try{$process.Kill()}catch{}
                throw "Process timed out after $TimeoutSeconds seconds: $FilePath $Arguments"
            }
            $process.WaitForExit()
        }else{$process.WaitForExit()}
        return [pscustomobject]@{
            ExitCode=$process.ExitCode
            StdOut=[string]$stdoutTask.Result
            StdErr=[string]$stderrTask.Result
        }
    }finally{$process.Dispose()}
}

function Get-PCPathRoots {
    $roots=New-Object System.Collections.ArrayList
    $definitions=@(
        @('LOCALAPPDATA',$env:LOCALAPPDATA),
        @('APPDATA',$env:APPDATA),
        @('USERPROFILE',$env:USERPROFILE),
        @('PROGRAMFILESX86',${env:ProgramFiles(x86)}),
        @('PROGRAMFILES',$env:ProgramFiles),
        @('PROGRAMDATA',$env:ProgramData),
        @('PUBLIC',$env:PUBLIC),
        @('WINDIR',$env:WINDIR)
    )
    foreach($definition in $definitions){
        if(-not $definition[1]){continue}
        $value=[IO.Path]::GetFullPath([string]$definition[1]).TrimEnd('\')
        [void]$roots.Add([pscustomobject]@{Token=[string]$definition[0];Path=$value})
    }
    return @($roots.ToArray()|Sort-Object {$_.Path.Length} -Descending)
}

function ConvertTo-PCTokenPath {
    param([AllowEmptyString()][string]$Path='')
    if(-not $Path){return ''}
    $value=[Environment]::ExpandEnvironmentVariables($Path)
    foreach($root in @(Get-PCPathRoots)){
        if($value.Equals($root.Path,[StringComparison]::OrdinalIgnoreCase)){
            return ('%'+$root.Token+'%')
        }
        $prefix=$root.Path+'\'
        if($value.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){
            return ('%'+$root.Token+'%\'+$value.Substring($prefix.Length))
        }
    }
    return $Path
}

function ConvertTo-PCNormalizedText {
    param([AllowEmptyString()][string]$Text='')
    if(-not $Text){return ''}
    $result=$Text
    foreach($root in @(Get-PCPathRoots)){
        $result=[Text.RegularExpressions.Regex]::Replace(
            $result,[Text.RegularExpressions.Regex]::Escape($root.Path),('%'+$root.Token+'%'),
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }
    return $result
}

function ConvertTo-PCUnicodeStableText {
    <#
    Normalizes text to Unicode Form C for deterministic comparison while
    preserving distinct legal Windows characters. In particular, the micro
    sign (U+00B5, µ) and Greek small letter mu (U+03BC, μ) are not collapsed.
    File operations always use the original literal path, not this value.
    #>
    param([AllowEmptyString()][string]$Text='')
    if($null -eq $Text){return ''}
    return $Text.Normalize([Text.NormalizationForm]::FormC)
}

function Get-PCShortcutRelativeLocation {
    param(
        [Parameter(Mandatory=$true)][string]$RootId,
        [AllowEmptyString()][string]$RelativePath=''
    )
    $prefix=switch($RootId){
        'UserStartMenu' {'Start Menu (current user)'}
        'CommonStartMenu' {'Start Menu (all users)'}
        'UserDesktop' {'Desktop (current user)'}
        'CommonDesktop' {'Desktop (all users)'}
        'UserStartup' {'Startup (current user)'}
        'CommonStartup' {'Startup (all users)'}
        'UserPinned' {'Pinned shortcuts (current user)'}
        default {$RootId}
    }
    if($RelativePath){return ($prefix+'\'+$RelativePath)}
    return $prefix
}

function Get-PCShortcutSemanticDigest {
    param(
        [AllowEmptyString()][string]$Extension='',
        [AllowEmptyString()][string]$TargetPath='',
        [AllowEmptyString()][string]$Arguments='',
        [AllowEmptyString()][string]$WorkingDirectory='',
        [AllowEmptyString()][string]$IconLocation='',
        [AllowEmptyString()][string]$Description=''
    )
    $stableExtension=(ConvertTo-PCUnicodeStableText $Extension).ToLowerInvariant()
    $stableTarget=ConvertTo-PCUnicodeStableText $TargetPath
    $stableWorking=ConvertTo-PCUnicodeStableText $WorkingDirectory
    if($stableExtension -eq '.lnk'){
        # Local Windows paths are case-insensitive. Arguments remain case-exact.
        $stableTarget=$stableTarget.ToLowerInvariant()
        $stableWorking=$stableWorking.ToLowerInvariant()
    }
    # Icon and description are intentionally excluded. Installers commonly
    # regenerate them while preserving identical launch behavior.
    $parts=@(
        'Extension='+$stableExtension
        'TargetPath='+$stableTarget
        'Arguments='+(ConvertTo-PCUnicodeStableText $Arguments)
        'WorkingDirectory='+$stableWorking
    )
    return (Get-PCSha256Text ($parts -join "`n"))
}

function Resolve-PCTokenPath {
    param([Parameter(Mandatory=$true)][string]$TokenPath)
    if($TokenPath -notmatch '^%([A-Z0-9_]+)%(?:\\(.*))?$'){
        throw "Path is not a supported token path: $TokenPath"
    }
    $token=$matches[1]
    $relative=[string]$matches[2]
    if($relative -and (($relative -split '\\') -contains '..')){throw "Parent traversal is not allowed: $TokenPath"}
    $root=switch($token){
        'LOCALAPPDATA' {$env:LOCALAPPDATA}
        'APPDATA' {$env:APPDATA}
        'USERPROFILE' {$env:USERPROFILE}
        'PROGRAMFILESX86' {${env:ProgramFiles(x86)}}
        'PROGRAMFILES' {$env:ProgramFiles}
        'PROGRAMDATA' {$env:ProgramData}
        'PUBLIC' {$env:PUBLIC}
        'WINDIR' {$env:WINDIR}
        default {throw "Unsupported path token: $token"}
    }
    if(-not $root){throw "Destination root is unavailable for token: $token"}
    if($relative){return (Join-Path $root $relative)}
    return $root
}

function Get-PCRegistryBase {
    param(
        [ValidateSet('HKCU','HKLM')][string]$Hive,
        [Microsoft.Win32.RegistryView]$View=[Microsoft.Win32.RegistryView]::Default
    )
    $registryHive=if($Hive -eq 'HKCU'){
        [Microsoft.Win32.RegistryHive]::CurrentUser
    }else{[Microsoft.Win32.RegistryHive]::LocalMachine}
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($registryHive,$View)
}

function Test-PCRegistryKey {
    param(
        [ValidateSet('HKCU','HKLM')][string]$Hive,
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Microsoft.Win32.RegistryView]$View=[Microsoft.Win32.RegistryView]::Default
    )
    $base=$null;$key=$null
    try{
        $base=Get-PCRegistryBase -Hive $Hive -View $View
        $key=$base.OpenSubKey($SubKey,$false)
        return ($null -ne $key)
    }catch{
        Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key '' -Operation 'OpenKey' -Message $_.Exception.Message
        return $false
    }
    finally{
        if($null -ne $key){$key.Dispose()}
        if($null -ne $base){$base.Dispose()}
    }
}

function Export-PCRegistryKey {
    param(
        [ValidateSet('HKCU','HKLM')][string]$Hive,
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Parameter(Mandatory=$true)][string]$Path
    )
    if(-not (Test-PCRegistryKey -Hive $Hive -SubKey $SubKey)){return $false}
    $parent=[IO.Path]::GetDirectoryName($Path)
    if($parent){New-PCDirectory $parent}
    $reg=Join-Path $env:SystemRoot 'System32\reg.exe'
    $result=Invoke-PCNativeProcess -FilePath $reg -Arguments ('export "'+$Hive+'\'+$SubKey+'" "'+$Path+'" /y')
    if($result.ExitCode -ne 0){throw "Registry export failed for $Hive\$($SubKey): $($result.StdErr.Trim())"}
    return $true
}

function ConvertTo-PCRegistryText {
    param($Value)
    if($null -eq $Value){return ''}
    if($Value -is [byte[]]){return (($Value|ForEach-Object {$_.ToString('X2')}) -join '')}
    if($Value -is [string[]]){return ($Value -join [char]0x241F)}
    return (ConvertTo-PCNormalizedText -Text ([string]$Value))
}

function Get-PCRegistryValueManifest {
    param(
        [ValidateSet('HKCU','HKLM')][string]$Hive,
        [Parameter(Mandatory=$true)][string]$SubKey,
        [Microsoft.Win32.RegistryView]$View=[Microsoft.Win32.RegistryView]::Default,
        [string[]]$ExcludeRelativePatterns=@(),
        [int]$MaximumDepth=64
    )
    $rows=New-Object System.Collections.ArrayList
    $base=$null;$root=$null
    try{
        $base=Get-PCRegistryBase -Hive $Hive -View $View
        $root=$base.OpenSubKey($SubKey,$false)
        if($null -eq $root){return @()}
        function Read-PCRegistryManifestKey {
            param([Microsoft.Win32.RegistryKey]$Key,[string]$Relative,[int]$Depth)
            if($Depth -gt $MaximumDepth){return}
            foreach($pattern in $ExcludeRelativePatterns){
                if($Relative -match $pattern){
                    Add-PCPolicyExclusion -Category 'Registry' -Scope ($Hive+'|'+[string]$View+'|'+$SubKey) `
                        -Path $Relative -Reason 'Protected, credential-bearing, volatile, or machine-bound registry state is intentionally not inventoried or migrated.'
                    return
                }
            }
            $valueNames=@()
            try{$valueNames=@($Key.GetValueNames())}
            catch{
                Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key $Relative -Operation 'EnumerateValues' -Message $_.Exception.Message
            }
            foreach($name in $valueNames){
                try{
                    $value=$Key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $text=ConvertTo-PCRegistryText -Value $value
                    $identity=if($name){$name}else{'(Default)'}
                    $sensitive=(($Relative+'\'+$identity) -match '(?i)password|passwd|secret|token|cookie|credential|private|seed|vault|oauth|session|autofill|webauthn|hello')
                    if(-not $sensitive -and -not ($value -is [byte[]])){
                        $sensitive=Test-PCSensitiveText -Text $text
                    }
                    $preview=''
                    if(-not $sensitive -and -not ($value -is [byte[]])){
                        $preview=$text
                        if($preview.Length -gt 240){$preview=$preview.Substring(0,240)+'...'}
                    }elseif($sensitive){$preview='[REDACTED]'}
                    [void]$rows.Add([pscustomobject]@{
                        Hive=$Hive
                        View=[string]$View
                        Root=$SubKey
                        Key=$Relative
                        Name=$identity
                        Kind=[string]$Key.GetValueKind($name)
                        DataLength=$text.Length
                        DataSHA256=if($sensitive){''}else{Get-PCSha256Text -Text $text}
                        Preview=$preview
                        Sensitive=$sensitive
                    })
                }catch{
                    $identity=if($name){$name}else{'(Default)'}
                    Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key ($Relative+'\'+$identity).TrimStart('\') -Operation 'ReadValue' -Message $_.Exception.Message
                }
            }
            $childNames=@()
            try{$childNames=@($Key.GetSubKeyNames())}
            catch{
                Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key $Relative -Operation 'EnumerateSubKeys' -Message $_.Exception.Message
            }
            foreach($childName in $childNames){
                $child=$null
                try{
                    $child=$Key.OpenSubKey($childName,$false)
                    if($null -ne $child){
                        $childRelative=if($Relative){$Relative+'\'+$childName}else{$childName}
                        Read-PCRegistryManifestKey -Key $child -Relative $childRelative -Depth ($Depth+1)
                    }
                }catch{
                    $childRelative=if($Relative){$Relative+'\'+$childName}else{$childName}
                    Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key $childRelative -Operation 'OpenSubKey' -Message $_.Exception.Message
                }
                finally{if($null -ne $child){$child.Dispose()}}
            }
        }
        Read-PCRegistryManifestKey -Key $root -Relative '' -Depth 0
        return $rows.ToArray()
    }catch{
        Add-PCRegistryReadIssue -Hive $Hive -View $View -Root $SubKey -Key '' -Operation 'OpenRoot' -Message $_.Exception.Message
        return $rows.ToArray()
    }finally{
        if($null -ne $root){$root.Dispose()}
        if($null -ne $base){$base.Dispose()}
    }
}

function Get-PCRegistryRootDigest {
    param($Rows)
    $groups=@($Rows|Group-Object {
        $key=[string]$_.Key
        if($key -match '^([^\\]+)'){return $matches[1]}
        return '(Root)'
    })
    $result=New-Object System.Collections.ArrayList
    foreach($group in $groups){
        $lines=@($group.Group|Sort-Object Key,Name|ForEach-Object {
            '{0}|{1}|{2}|{3}' -f $_.Key,$_.Name,$_.Kind,$_.DataSHA256
        })
        [void]$result.Add([pscustomobject]@{
            Name=$group.Name
            ValueCount=$group.Count
            Digest=Get-PCSha256Text -Text ($lines -join "`n")
        })
    }
    return $result.ToArray()
}

function Get-PCRegistryManifestDigest {
    param($Rows)
    $lines=@($Rows|Sort-Object Key,Name|ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.Key,$_.Name,$_.Kind,$_.DataSHA256
    })
    return (Get-PCSha256Text -Text ($lines -join "`n"))
}

function Get-PCFileClassification {
    param([Parameter(Mandatory=$true)][string]$Path)
    $name=[IO.Path]::GetFileName($Path).ToLowerInvariant()
    $extension=[IO.Path]::GetExtension($Path).ToLowerInvariant()
    if($extension -in @('.pfx','.p12','.pem','.key','.ppk','.kdbx','.2fa','.ovpn','.rdp')){return 'SecureContainer'}
    if($extension -in @('.db','.sqlite','.sqlite3','.edb','.mdb','.accdb')){return 'Database'}
    if($extension -in @('.ps1','.psm1','.psd1','.bat','.cmd','.reg','.vbs','.js')){return 'Script'}
    if($extension -in @('.ini','.json','.xml','.yaml','.yml','.toml','.cfg','.conf','.config','.settings','.prefs','.properties','.hlsl','.pbk')){return 'Configuration'}
    if($name -in @('preferences','secure preferences','bookmarks','profiles.ini','extensions.json','hosts')){return 'Configuration'}
    return 'Other'
}

function Test-PCVolatileStatePath {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    return ($RelativePath -match '(?i)(^|\\)(cache|caches|code cache|gpucache|temp|tmp|logs?|crashpad|crashes|dumps?|shadercache|service worker\\cache(storage)?|inetcache|webcache|thumbcache|npm-cache|nuget\\v3-cache|packages\\.*\\ac\\temp)(\\|$)')
}

function Get-PCFilePolicyExclusionReason {
    param(
        [Parameter(Mandatory=$true)][string]$RootToken,
        [Parameter(Mandatory=$true)][string]$RelativePath
    )
    if($RootToken -eq 'LOCALAPPDATA'){
        if($RelativePath -match '(?i)^Packages\\Microsoft\.Windows\.Search_[^\\]+\\AppData\\(?:Indexed DB|CacheStorage)(?:\\|$)'){
            return 'Windows Search package index databases are volatile and are rebuilt on the destination.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Windows\\Notifications\\wpndatabase\.db$'){
            return 'The Windows notification database is live, account-bound operating-system state.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Windows\\Explorer\\(?:iconcache|thumbcache)[^\\]*\.db$'){
            return 'Explorer icon and thumbnail databases are disposable caches rebuilt by Windows.'
        }
        if($RelativePath -match '(?i)^ConnectedDevicesPlatform\\[^\\]+\\ActivitiesCache\.db$'){
            return 'Connected Devices activity history is live account/device-bound state and is not generically portable.'
        }
    }
    if($RootToken -eq 'PROGRAMDATA'){
        if($RelativePath -match '(?i)^Microsoft\\Windows Defender Advanced Threat Protection(?:\\|$)'){
            return 'Microsoft Defender for Endpoint protected runtime data must not be copied or unlocked.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Windows Defender\\Scans(?:\\|$)'){
            return 'Microsoft Defender scan databases are protected runtime state and are rebuilt locally.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Windows\\SystemData(?:\\|$)'){
            return 'Windows SystemData is protected shell/system state and is not a portable settings payload.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Search\\Data(?:\\|$)'){
            return 'The Windows Search index is volatile and is rebuilt on the destination.'
        }
        if($RelativePath -match '(?i)^Microsoft\\Diagnosis(?:\\|$)'){
            return 'Windows diagnostic event databases are volatile telemetry state.'
        }
        if($RelativePath -match '(?i)^Kaspersky Lab\\[^\\]+\\(?:Report\\Database|Data)(?:\\|$)'){
            return 'Kaspersky live databases are protected/version-bound; reinstall Kaspersky and import supported settings or exclusions separately.'
        }
    }
    return ''
}

function Test-PCSensitiveStatePath {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    return ($RelativePath -match '(?i)(password|credential|cookies?$|login data|web data|token|secret|vault|wallet|seed|private|keyring|webauthn|passkeys?|windows hello|protect\\|crypto\\|credentials\\|ngc\\|keeper|1password|bitwarden)')
}

function Test-PCSensitiveText {
    param([AllowEmptyString()][string]$Text='')
    if(-not $Text){return $false}
    return (
        $Text -match '(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----' -or
        $Text -match '(?i)\b(password|passwd|secret|access[_-]?token|refresh[_-]?token|api[_-]?key|private[_-]?key|client[_-]?secret|mnemonic|seed|credential|cookie)\b[^\r\n]{0,24}[:=]'
    )
}

function Test-PCSensitiveFileContent {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [int64]$MaximumBytes=8MB
    )
    try{
        $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if($file.Length -gt $MaximumBytes){return $true}
        return (Test-PCSensitiveText -Text ([IO.File]::ReadAllText($file.FullName)))
    }catch{
        # Fail closed: unreadable text is never placed into a generic payload.
        return $true
    }
}

function New-PCCaptureManifest {
    param([Parameter(Mandatory=$true)][string]$CapturePath)
    $rows=New-Object System.Collections.ArrayList
    foreach($file in @(Get-ChildItem -LiteralPath $CapturePath -File -Recurse -Force -ErrorAction Stop|Sort-Object FullName)){
        if($file.Name -eq 'Capture-Manifest.csv'){continue}
        $relative=$file.FullName.Substring($CapturePath.TrimEnd('\').Length).TrimStart('\')
        [void]$rows.Add([pscustomobject]@{
            RelativePath=$relative
            Length=$file.Length
            SHA256=Get-PCSha256File -Path $file.FullName
        })
    }
    Export-PCCsv -Path (Join-Path $CapturePath 'Capture-Manifest.csv') -Rows $rows.ToArray() -Columns @('RelativePath','Length','SHA256')
    return $rows.Count
}

function Test-PCCaptureManifest {
    param([Parameter(Mandatory=$true)][string]$CapturePath)
    $manifest=Import-PCCsv -Path (Join-Path $CapturePath 'Capture-Manifest.csv')
    if($manifest.Count -eq 0){throw "Capture manifest is missing or empty: $CapturePath"}
    $failures=New-Object System.Collections.ArrayList
    foreach($item in $manifest){
        $path=Join-Path $CapturePath $item.RelativePath
        if(-not [IO.File]::Exists($path)){
            [void]$failures.Add("Missing: $($item.RelativePath)")
            continue
        }
        $hash=Get-PCSha256File -Path $path
        if($hash -ne ([string]$item.SHA256).ToLowerInvariant()){
            [void]$failures.Add("Hash mismatch: $($item.RelativePath)")
        }
    }
    return $failures.ToArray()
}

function Get-PCCollectorStatus {
    param([Parameter(Mandatory=$true)][string]$CapturePath,[Parameter(Mandatory=$true)][string]$Name)
    $rows=Import-PCCsv -Path (Join-Path $CapturePath 'Capture-Status.csv')
    $match=@($rows|Where-Object {$_.Collector -eq $Name}|Select-Object -First 1)
    if($match.Count -eq 0){return 'NotRecorded'}
    return [string]$match[0].Status
}

function Normalize-PCApplicationName {
    param([AllowEmptyString()][string]$Name='')
    if(-not $Name){return ''}
    $value=$Name.ToLowerInvariant()
    $value=$value -replace '(?i)\b(version|ver\.?|build)\s*\d+(?:\.\d+){0,5}\b',' '
    $value=$value -replace '(?i)(?<=\s)\d+(?:\.\d+){1,5}(?=\s|$)',' '
    $value=$value -replace '(?i)\((x64|x86|64-bit|32-bit|machine-wide|user)\)',' '
    $value=$value -replace '(?i)\b(x64|x86|64-bit|32-bit)\b',' '
    $value=$value -replace '[^a-z0-9]+',' '
    return (($value -replace '\s+',' ').Trim())
}

function Get-PCWingetPackages {
    param([Parameter(Mandatory=$true)][string]$CapturePath)
    $json=Read-PCJson (Join-Path $CapturePath 'Applications\Winget-Export.json')
    if($null -eq $json){return @()}
    $rows=New-Object System.Collections.ArrayList
    foreach($sourceObject in @(Get-PCProperty $json 'Sources' @())){
        $details=Get-PCProperty $sourceObject 'SourceDetails' $null
        foreach($package in @(Get-PCProperty $sourceObject 'Packages' @())){
            [void]$rows.Add([pscustomobject]@{
                PackageIdentifier=[string](Get-PCProperty $package 'PackageIdentifier' '')
                Version=[string](Get-PCProperty $package 'Version' '')
                SourceName=[string](Get-PCProperty $details 'Name' '')
                SourceIdentifier=[string](Get-PCProperty $details 'Identifier' '')
            })
        }
    }
    return $rows.ToArray()
}

#requires -version 5.1
<# Validates PowerShell syntax and the package SHA256 manifest. Read-only. #>
[CmdletBinding()]
param(
    [string]$PackagePath=$PSScriptRoot,
    [switch]$StrictPackageContents
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($PackagePath)
$manifest=Join-Path $root 'SHA256SUMS.txt'
if(-not [IO.File]::Exists($manifest)){throw "SHA256SUMS.txt not found: $root"}

$failures=New-Object System.Collections.ArrayList
$warnings=New-Object System.Collections.ArrayList
$listed=@{}
foreach($line in [IO.File]::ReadAllLines($manifest)){
    if(-not $line.Trim()){continue}
    if($line -notmatch '^([0-9a-fA-F]{64})  (.+)$'){
        [void]$failures.Add("Malformed manifest line: $line")
        continue
    }
    $expected=$matches[1].ToLowerInvariant()
    $relative=$matches[2]
    if($listed.ContainsKey($relative.ToLowerInvariant())){
        [void]$failures.Add("Duplicate manifest path: $relative")
        continue
    }
    $listed[$relative.ToLowerInvariant()]=$true
    $file=[IO.Path]::GetFullPath((Join-Path $root $relative))
    if(-not $file.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
        [void]$failures.Add("Manifest path escapes package: $relative")
        continue
    }
    if(-not [IO.File]::Exists($file)){
        [void]$failures.Add("Manifest file missing: $relative")
        continue
    }
    $actual=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if($actual -ne $expected){[void]$failures.Add("Hash mismatch: $relative")}
}

foreach($script in @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File -Recurse -ErrorAction Stop)){
    $relative=$script.FullName.Substring($root.TrimEnd('\').Length).TrimStart('\')
    if(-not $listed.ContainsKey($relative.ToLowerInvariant())){continue}
    $tokens=$null;$errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$errors)
    foreach($error in @($errors)){
        [void]$failures.Add("Parser: $($script.Name):$($error.Extent.StartLineNumber): $($error.Message)")
    }
}

foreach($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction Stop)){
    if($file.FullName -eq $manifest){continue}
    $relative=$file.FullName.Substring($root.TrimEnd('\').Length).TrimStart('\')
    if(-not $listed.ContainsKey($relative.ToLowerInvariant())){
        if($StrictPackageContents){
            [void]$failures.Add("File is not listed in SHA256SUMS.txt: $relative")
        }else{
            [void]$warnings.Add("Unlisted file ignored (use -StrictPackageContents to reject it): $relative")
        }
    }
}

try{
    . (Join-Path $root 'PCMigration.Common-v4.0.0.ps1')
    $present=$true
    $singleRows=@()
    if($present){$singleRows=@([pscustomobject]@{Key='';Name='OnlyValue';Kind='String';DataSHA256='test'})}
    if($singleRows.Count -ne 1){[void]$failures.Add('Regression: single-record registry arrays are not count-safe.')}
    $digest=Get-PCRegistryManifestDigest -Rows $singleRows
    if(-not $digest){[void]$failures.Add('Regression: single-record registry digest was empty.')}
    $trigger=[pscustomobject]@{StartBoundary='2026-01-01T00:00:00';Enabled=$true}
    $triggerType=Get-PCScheduledTaskTriggerType -Trigger $trigger
    if(-not $triggerType){[void]$failures.Add('Regression: scheduled-task trigger without CimClass has no safe type fallback.')}
    $commonPath=Join-Path $root 'PCMigration.Common-v4.0.0.ps1'
    $expectedHash=(Get-FileHash -LiteralPath $commonPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sharedReadHash=Get-PCSha256File -Path $commonPath -ThrowOnFailure
    if($sharedReadHash -ne $expectedHash){[void]$failures.Add('Regression: shared-read SHA256 hashing returned an incorrect digest.')}
    $defenderReason=Get-PCFilePolicyExclusionReason -RootToken 'PROGRAMDATA' -RelativePath 'Microsoft\Windows Defender Advanced Threat Protection\SenseNDR'
    if(-not $defenderReason){[void]$failures.Add('Regression: Defender protected data is not covered by the file-exclusion policy.')}
    $kasperskyReason=Get-PCFilePolicyExclusionReason -RootToken 'PROGRAMDATA' -RelativePath 'Kaspersky Lab\AVP21.26\Data\reports.db'
    if(-not $kasperskyReason){[void]$failures.Add('Regression: Kaspersky runtime databases are not covered by the file-exclusion policy.')}
    $ordinaryDatabaseReason=Get-PCFilePolicyExclusionReason -RootToken 'PROGRAMDATA' -RelativePath 'App_Service\App_Service.db'
    if($ordinaryDatabaseReason){[void]$failures.Add('Regression: an ordinary third-party database was incorrectly policy-excluded.')}
    $bodyFragments=@('<h1>Regression</h1>','<p>PowerShell 5.1 requires one Body string.</p>')
    $bodyText=(@($bodyFragments|ForEach-Object {[string]$_}) -join [Environment]::NewLine)
    $html=(ConvertTo-Html -Title 'PCMigration HTML regression' -Body $bodyText) -join [Environment]::NewLine
    if($html -notmatch '<h1>Regression</h1>'){[void]$failures.Add('Regression: HTML report body fragments were not joined correctly.')}
    $micro=[string][char]0x00B5
    $greekMu=[string][char]0x03BC
    $microPath='Tools\'+$micro+'Torrent\settings.json'
    $greekPath='Tools\'+$greekMu+'Torrent\settings.json'
    $roundTrip=(([pscustomobject]@{Path=$microPath}|ConvertTo-Json)|ConvertFrom-Json).Path
    if($roundTrip -cne $microPath){[void]$failures.Add('Regression: the Unicode micro sign did not survive JSON round-trip.')}
    if((ConvertTo-PCUnicodeStableText $microPath) -ceq (ConvertTo-PCUnicodeStableText $greekPath)){
        [void]$failures.Add('Regression: U+00B5 micro sign and U+03BC Greek mu were incorrectly collapsed.')
    }
    $shortcutA=Get-PCShortcutSemanticDigest -Extension '.lnk' -TargetPath '%PROGRAMFILES%\Vendor\App.exe' -Arguments '--mode safe' -WorkingDirectory '%PROGRAMFILES%\Vendor'
    $shortcutB=Get-PCShortcutSemanticDigest -Extension '.LNK' -TargetPath '%programfiles%\vendor\app.EXE' -Arguments '--mode safe' -WorkingDirectory '%ProgramFiles%\Vendor'
    $shortcutC=Get-PCShortcutSemanticDigest -Extension '.lnk' -TargetPath '%PROGRAMFILES%\Vendor\App.exe' -Arguments '--mode changed' -WorkingDirectory '%PROGRAMFILES%\Vendor'
    if($shortcutA -ne $shortcutB){[void]$failures.Add('Regression: equivalent Windows shortcut paths produced different semantic digests.')}
    if($shortcutA -eq $shortcutC){[void]$failures.Add('Regression: different shortcut arguments produced the same semantic digest.')}
    . (Join-Path $root 'RegistryBackup-v4.0.0.ps1')
    if(-not (Get-Command Invoke-PCMigrationRegistryBackup -ErrorAction SilentlyContinue)){
        [void]$failures.Add('Regression: integrated registry safety-backup function is unavailable.')
    }
}catch{
    [void]$failures.Add('Regression self-test failed: '+$_.Exception.Message)
}

if($failures.Count){
    $failures|ForEach-Object {Write-Host $_ -ForegroundColor Red}
    throw "Package validation failed with $($failures.Count) error(s)."
}
if($warnings.Count){$warnings|ForEach-Object {Write-Warning $_}}
Write-Host 'Package validation passed: PowerShell parser, SHA256 manifest, and v4.0.0 regression checks.' -ForegroundColor Green

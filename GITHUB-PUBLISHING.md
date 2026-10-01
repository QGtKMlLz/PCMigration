#requires -version 5.1
<#
.SYNOPSIS
Compares source and destination v4.0.0 captures and creates a risk-ranked gap ledger.

.DESCRIPTION
The comparison is offline and non-mutating. It validates capture integrity, checks
collector completeness, correlates independent application evidence, compares
file/value-level settings, and generates an editable Repair-Plan.csv. A missing
item is not asserted when the destination collector failed or was incomplete.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceCapture,
    [Parameter(Mandatory=$true)][string]$DestinationCapture,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$SkipCaptureHashValidation,
    [switch]$IncludeExpectedMachineDifferences
)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PCMigration.Common-v4.0.0.ps1')

$source=[IO.Path]::GetFullPath($SourceCapture)
$destination=[IO.Path]::GetFullPath($DestinationCapture)
$report=[IO.Path]::GetFullPath($OutputPath)
foreach($path in @($source,$destination)){
    if(-not [IO.File]::Exists((Join-Path $path 'Meta.json'))){throw "Not a compatible v4.0 capture: $path"}
}
if([IO.Directory]::Exists($report) -and @(Get-ChildItem -LiteralPath $report -Force -ErrorAction SilentlyContinue).Count -gt 0){
    throw "OutputPath must be new or empty so reports cannot be mixed: $report"
}
New-PCDirectory $report

$sourceMeta=Read-PCJson (Join-Path $source 'Meta.json')
$destinationMeta=Read-PCJson (Join-Path $destination 'Meta.json')
if([string](Get-PCProperty $sourceMeta 'SchemaVersion' '') -ne '4.0'){throw 'Source capture schema is not 4.0.'}
if([string](Get-PCProperty $destinationMeta 'SchemaVersion' '') -ne '4.0'){throw 'Destination capture schema is not 4.0.'}
if(-not $SkipCaptureHashValidation){
    $sourceFailures=@(Test-PCCaptureManifest -CapturePath $source)
    $destinationFailures=@(Test-PCCaptureManifest -CapturePath $destination)
    if($sourceFailures.Count -or $destinationFailures.Count){
        throw ("Capture-integrity validation failed."+[Environment]::NewLine+
            (($sourceFailures|ForEach-Object {'SOURCE: '+$_})+($destinationFailures|ForEach-Object {'DESTINATION: '+$_}) -join [Environment]::NewLine))
    }
}

$differences=New-Object System.Collections.ArrayList
$applicationGaps=New-Object System.Collections.ArrayList
$settingsGaps=New-Object System.Collections.ArrayList
$windowsGaps=New-Object System.Collections.ArrayList
$manualActions=New-Object System.Collections.ArrayList
$repairPlan=New-Object System.Collections.ArrayList
$differenceNumber=0
$actionNumber=0

function Add-PCDifference {
    param(
        [int]$Priority,
        [string]$Category,
        [string]$Subcategory,
        [string]$Item,
        [string]$Status,
        [string]$Confidence,
        [string]$Risk,
        [string]$SourceValue,
        [string]$DestinationValue,
        [string]$Evidence,
        [string]$Recommendation,
        [bool]$MigrationGap=$true,
        [bool]$Repairable=$false,
        [string]$RepairMethod=''
    )
    $script:differenceNumber++
    $id=('D{0:D6}' -f $script:differenceNumber)
    [void]$script:differences.Add([pscustomobject]@{
        DifferenceId=$id;Priority=$Priority;Category=$Category;Subcategory=$Subcategory
        Item=$Item;Status=$Status;Confidence=$Confidence;Risk=$Risk
        SourceValue=$SourceValue;DestinationValue=$DestinationValue;Evidence=$Evidence
        Recommendation=$Recommendation;MigrationGap=$MigrationGap
        Repairable=$Repairable;RepairMethod=$RepairMethod
    })
    return $id
}

function Add-PCRepairAction {
    param(
        [string]$DifferenceId,
        [int]$Priority,
        [string]$Category,
        [string]$Item,
        [string]$Method,
        [string]$Risk,
        [string]$Confidence,
        [bool]$RequiresAdmin=$false,
        [string]$SourceArtifact='',
        [string]$DestinationTarget='',
        [string]$PackageId='',
        [string]$PackageSource='',
        [string]$FeatureName='',
        [string]$CapabilityName='',
        [string]$ExpectedSourceSHA256='',
        [string]$Precondition='',
        [string]$Recommendation=''
    )
    $script:actionNumber++
    [void]$script:repairPlan.Add([pscustomobject]@{
        ActionId=('A{0:D5}' -f $script:actionNumber)
        Approved='NO'
        DifferenceId=$DifferenceId
        Priority=$Priority
        Category=$Category
        Item=$Item
        Method=$Method
        Risk=$Risk
        Confidence=$Confidence
        RequiresAdmin=$RequiresAdmin
        SourceArtifact=$SourceArtifact
        DestinationTarget=$DestinationTarget
        PackageId=$PackageId
        PackageSource=$PackageSource
        FeatureName=$FeatureName
        CapabilityName=$CapabilityName
        ExpectedSourceSHA256=$ExpectedSourceSHA256
        Precondition=$Precondition
        Recommendation=$Recommendation
    })
}

function Add-PCApplicationGap {
    param(
        [string]$Name,[string]$Identity,[string]$EvidenceType,[string]$SourceVersion,
        [string]$Publisher,[string]$Confidence,[string]$InstallMethod,[string]$PackageId,
        [string]$PackageSource,[string]$Recommendation,[string]$DifferenceId
    )
    [void]$script:applicationGaps.Add([pscustomobject]@{
        Name=$Name;Identity=$Identity;EvidenceType=$EvidenceType;SourceVersion=$SourceVersion
        Publisher=$Publisher;Confidence=$Confidence;InstallMethod=$InstallMethod
        PackageId=$PackageId;PackageSource=$PackageSource;Recommendation=$Recommendation
        DifferenceId=$DifferenceId
    })
}

function Add-PCSettingsGap {
    param(
        [string]$Scope,[string]$Identity,[string]$Status,[string]$Classification,
        [string]$SourceSHA256,[string]$DestinationSHA256,[string]$Sensitive,
        [string]$Payload,[string]$Recommendation,[string]$DifferenceId
    )
    [void]$script:settingsGaps.Add([pscustomobject]@{
        Scope=$Scope;Identity=$Identity;Status=$Status;Classification=$Classification
        SourceSHA256=$SourceSHA256;DestinationSHA256=$DestinationSHA256
        Sensitive=$Sensitive;PayloadRelativePath=$Payload
        Recommendation=$Recommendation;DifferenceId=$DifferenceId
    })
}

function Add-PCWindowsGap {
    param(
        [string]$Category,[string]$Identity,[string]$Status,[string]$SourceValue,
        [string]$DestinationValue,[string]$Confidence,[string]$Recommendation,[string]$DifferenceId
    )
    [void]$script:windowsGaps.Add([pscustomobject]@{
        Category=$Category;Identity=$Identity;Status=$Status;SourceValue=$SourceValue
        DestinationValue=$DestinationValue;Confidence=$Confidence
        Recommendation=$Recommendation;DifferenceId=$DifferenceId
    })
}

function Add-PCManualAction {
    param([string]$Category,[string]$Item,[string]$Detected,[string]$Action,[string]$Reason,[string]$DifferenceId='')
    [void]$script:manualActions.Add([pscustomobject]@{
        Category=$Category;Item=$Item;Detected=$Detected;Action=$Action;Reason=$Reason;DifferenceId=$DifferenceId
    })
}

function Get-PCWingetPackages {
    param([string]$CapturePath)
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

function Get-PCDefaultAssociations {
    param([string]$CapturePath)
    $path=Join-Path $CapturePath 'UserState\Default-App-Associations.xml'
    if(-not [IO.File]::Exists($path)){return @()}
    try{
        $document=New-Object Xml.XmlDocument
        $document.Load($path)
        return @($document.SelectNodes('//Association')|ForEach-Object {
            [pscustomobject]@{
                Identifier=[string]$_.GetAttribute('Identifier')
                ProgId=[string]$_.GetAttribute('ProgId')
                ApplicationName=[string]$_.GetAttribute('ApplicationName')
            }
        })
    }catch{return @()}
}

function New-PCIndex {
    param($Rows,[Parameter(Mandatory=$true)][scriptblock]$Key)
    $index=@{}
    foreach($row in @($Rows)){
        $identity=[string](& $Key $row)
        if($identity){$index[$identity.ToLowerInvariant()]=$row}
    }
    return $index
}

function Test-PCDestinationComplete {
    param([string]$Collector)
    return ((Get-PCCollectorStatus -CapturePath $destination -Name $Collector) -eq 'Success')
}

function Compare-PCValueRows {
    param($SourceRows,$DestinationRows,[string]$KeyPrefix='')
    $index=@{}
    foreach($row in @($DestinationRows)){
        $key=($KeyPrefix+[string]$row.StateId+'|'+[string]$row.Key+'|'+[string]$row.Name).ToLowerInvariant()
        $index[$key]=$row
    }
    $result=New-Object System.Collections.ArrayList
    foreach($row in @($SourceRows)){
        $key=($KeyPrefix+[string]$row.StateId+'|'+[string]$row.Key+'|'+[string]$row.Name).ToLowerInvariant()
        if(-not $index.ContainsKey($key)){
            [void]$result.Add([pscustomobject]@{Source=$row;Destination=$null;Status='Missing'})
        }else{
            $other=$index[$key]
            if([string]$row.Kind -ne [string]$other.Kind -or [string]$row.DataSHA256 -ne [string]$other.DataSHA256){
                [void]$result.Add([pscustomobject]@{Source=$row;Destination=$other;Status='Different'})
            }
        }
    }
    return $result.ToArray()
}

# Capture coverage is part of the answer, not merely diagnostic metadata.
$sourceStatus=Import-PCCsv (Join-Path $source 'Capture-Status.csv')
$destinationStatus=Import-PCCsv (Join-Path $destination 'Capture-Status.csv')
$sourceStatusIndex=New-PCIndex -Rows $sourceStatus -Key {param($row) $row.Collector}
$destinationStatusIndex=New-PCIndex -Rows $destinationStatus -Key {param($row) $row.Collector}
$collectors=@(($sourceStatus.Collector+$destinationStatus.Collector)|Where-Object {$_}|Sort-Object -Unique)
$coverageRows=New-Object System.Collections.ArrayList
foreach($collector in $collectors){
    $key=$collector.ToLowerInvariant()
    $sourceRow=if($sourceStatusIndex.ContainsKey($key)){$sourceStatusIndex[$key]}else{$null}
    $destinationRow=if($destinationStatusIndex.ContainsKey($key)){$destinationStatusIndex[$key]}else{$null}
    $sourceState=if($null -ne $sourceRow){[string]$sourceRow.Status}else{'NotRecorded'}
    $destinationState=if($null -ne $destinationRow){[string]$destinationRow.Status}else{'NotRecorded'}
    $comparable=($destinationState -eq 'Success')
    [void]$coverageRows.Add([pscustomobject]@{
        Collector=$collector;SourceStatus=$sourceState;DestinationStatus=$destinationState
        ComparableForMissing=$comparable
        SourceRecords=if($null -ne $sourceRow){$sourceRow.Records}else{''}
        DestinationRecords=if($null -ne $destinationRow){$destinationRow.Records}else{''}
        SourceMessage=if($null -ne $sourceRow){$sourceRow.Message}else{''}
        DestinationMessage=if($null -ne $destinationRow){$destinationRow.Message}else{''}
    })
    if(-not $comparable){
        [void](Add-PCDifference -Priority 1 -Category 'Capture coverage' -Subcategory $collector -Item $collector `
            -Status 'Unknown' -Confidence 'High' -Risk 'None' -SourceValue $sourceState -DestinationValue $destinationState `
            -Evidence 'Destination collector was not fully successful.' `
            -Recommendation 'Repeat the destination capture elevated or resolve the collector error before treating items as missing.' `
            -MigrationGap $false)
    }
}
Export-PCCsv -Path (Join-Path $report 'Capture-Coverage.csv') -Rows $coverageRows.ToArray() -Columns @(
    'Collector','SourceStatus','DestinationStatus','ComparableForMissing','SourceRecords',
    'DestinationRecords','SourceMessage','DestinationMessage'
)
$policyExclusions=New-Object System.Collections.ArrayList
foreach($definition in @(
    @{Side='Source';Path=(Join-Path $source 'Diagnostics\Policy-Exclusions.csv')},
    @{Side='Destination';Path=(Join-Path $destination 'Diagnostics\Policy-Exclusions.csv')}
)){
    foreach($item in @(Import-PCCsv $definition.Path)){
        [void]$policyExclusions.Add([pscustomobject]@{
            Side=$definition.Side;Category=$item.Category;Scope=$item.Scope;Path=$item.Path;Reason=$item.Reason
        })
    }
}
Export-PCCsv -Path (Join-Path $report 'Capture-Policy-Exclusions.csv') -Rows $policyExclusions.ToArray() -Columns @(
    'Side','Category','Scope','Path','Reason'
)

$modeRank=@{Fast=0;Standard=1;Deep=2}
$sourceMode=[string](Get-PCProperty $sourceMeta 'InventoryMode' 'Fast')
$destinationMode=[string](Get-PCProperty $destinationMeta 'InventoryMode' 'Fast')
$fileInventoryComparable=($modeRank.ContainsKey($sourceMode) -and $modeRank.ContainsKey($destinationMode) -and $modeRank[$destinationMode] -ge $modeRank[$sourceMode])
if(-not $fileInventoryComparable){
    [void](Add-PCDifference -Priority 1 -Category 'Capture coverage' -Subcategory 'ApplicationState.Files' -Item 'Inventory modes' `
        -Status 'Unknown' -Confidence 'High' -Risk 'None' -SourceValue $sourceMode -DestinationValue $destinationMode `
        -Evidence 'Destination file-inventory depth is lower than source.' `
        -Recommendation "Recapture destination using -InventoryMode $sourceMode or Deep." -MigrationGap $false)
}
if([string]$sourceMeta.WindowsBuild -ne [string]$destinationMeta.WindowsBuild){
    [void](Add-PCDifference -Priority 2 -Category 'Compatibility' -Subcategory 'Windows build' -Item 'Windows build mismatch' `
        -Status 'Different' -Confidence 'High' -Risk 'Medium' -SourceValue ([string]$sourceMeta.WindowsBuild) `
        -DestinationValue ([string]$destinationMeta.WindowsBuild) -Evidence 'Meta.json' `
        -Recommendation 'Treat binary state, drivers, Store package state, and version-specific settings as manual until compatibility is verified.' `
        -MigrationGap $false)
}

# Applications: winget, AppX, uninstall registrations, Start identities,
# shortcuts, and portable executable footprints are compared independently.
$sourceWinget=@(Get-PCWingetPackages $source)
$destinationWinget=@(Get-PCWingetPackages $destination)
$destinationWingetIndex=New-PCIndex -Rows $destinationWinget -Key {param($row) $row.PackageIdentifier}
$missingWinget=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.Winget'){
    foreach($package in $sourceWinget){
        if(-not $package.PackageIdentifier){continue}
        $key=$package.PackageIdentifier.ToLowerInvariant()
        if($destinationWingetIndex.ContainsKey($key)){continue}
        [void]$missingWinget.Add($package)
        $recommendation='Install by exact source package ID, then recapture before restoring its settings.'
        $id=Add-PCDifference -Priority 1 -Category 'Applications' -Subcategory 'winget package' `
            -Item $package.PackageIdentifier -Status 'Missing' -Confidence 'High' -Risk 'Low' `
            -SourceValue $package.Version -DestinationValue '' -Evidence ('winget export; source='+$package.SourceName) `
            -Recommendation $recommendation -MigrationGap $true -Repairable $true -RepairMethod 'WingetInstall'
        Add-PCApplicationGap -Name $package.PackageIdentifier -Identity $package.PackageIdentifier -EvidenceType 'Winget' `
            -SourceVersion $package.Version -Publisher '' -Confidence 'High' -InstallMethod 'WingetInstall' `
            -PackageId $package.PackageIdentifier -PackageSource $package.SourceName -Recommendation $recommendation -DifferenceId $id
        Add-PCRepairAction -DifferenceId $id -Priority 1 -Category 'Applications' -Item $package.PackageIdentifier `
            -Method 'WingetInstall' -Risk 'Low' -Confidence 'High' -PackageId $package.PackageIdentifier `
            -PackageSource $package.SourceName -Precondition 'Review package ID and publisher; network access required.' `
            -Recommendation $recommendation
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Winget-Packages.csv') -Rows $missingWinget.ToArray() -Columns @(
    'PackageIdentifier','Version','SourceName','SourceIdentifier'
)
$wingetVersionDifferences=New-Object System.Collections.ArrayList
foreach($package in $sourceWinget){
    if(-not $package.PackageIdentifier -or -not $destinationWingetIndex.ContainsKey($package.PackageIdentifier.ToLowerInvariant())){continue}
    $other=$destinationWingetIndex[$package.PackageIdentifier.ToLowerInvariant()]
    if(-not $package.Version -or -not $other.Version -or $package.Version -eq $other.Version){continue}
    [void]$wingetVersionDifferences.Add([pscustomobject]@{
        PackageIdentifier=$package.PackageIdentifier;SourceVersion=$package.Version
        DestinationVersion=$other.Version;SourceName=$package.SourceName
    })
    [void](Add-PCDifference -Priority 4 -Category 'Compatibility' -Subcategory 'winget package version' `
        -Item $package.PackageIdentifier -Status 'Different' -Confidence 'High' -Risk 'Low' `
        -SourceValue $package.Version -DestinationValue $other.Version -Evidence 'winget export' `
        -Recommendation 'Keep a compatible/current destination version unless the application requires exact version parity; do not downgrade automatically.' `
        -MigrationGap $false)
}
Export-PCCsv -Path (Join-Path $report 'Winget-Version-Differences.csv') -Rows $wingetVersionDifferences.ToArray() -Columns @(
    'PackageIdentifier','SourceVersion','DestinationVersion','SourceName'
)

$sourceAppx=@(Import-PCCsv (Join-Path $source 'Applications\Appx-CurrentUser.csv')|Where-Object {$_.IsFramework -ne 'True' -and $_.IsResourcePackage -ne 'True'})
$destinationAppx=@(Import-PCCsv (Join-Path $destination 'Applications\Appx-CurrentUser.csv'))
$destinationAppxIndex=New-PCIndex -Rows $destinationAppx -Key {param($row) $row.PackageFamilyName}
$missingAppx=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.AppxCurrentUser'){
    foreach($package in $sourceAppx){
        if(-not $package.PackageFamilyName){continue}
        if($destinationAppxIndex.ContainsKey($package.PackageFamilyName.ToLowerInvariant())){continue}
        [void]$missingAppx.Add($package)
        $priority=if($package.Publisher -match '(?i)CN=Microsoft'){3}else{1}
        $recommendation='Reinstall from Microsoft Store or an exact verified winget/msstore ID; do not copy WindowsApps or AppRepository.'
        $id=Add-PCDifference -Priority $priority -Category 'Applications' -Subcategory 'AppX/MSIX current user' `
            -Item $package.Name -Status 'Missing' -Confidence 'High' -Risk 'Low' `
            -SourceValue $package.PackageFamilyName -DestinationValue '' -Evidence 'Get-AppxPackage current user' `
            -Recommendation $recommendation -MigrationGap $true
        Add-PCApplicationGap -Name $package.Name -Identity $package.PackageFamilyName -EvidenceType 'AppX' `
            -SourceVersion $package.Version -Publisher $package.Publisher -Confidence 'High' -InstallMethod 'StoreOrWingetLookup' `
            -PackageId '' -PackageSource 'msstore' -Recommendation $recommendation -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Appx-Packages.csv') -Rows $missingAppx.ToArray() -Columns @(
    'Name','PackageFamilyName','Version','Architecture','Publisher','SignatureKind','NonRemovable'
)
$appxVersionDifferences=New-Object System.Collections.ArrayList
foreach($package in $sourceAppx){
    if(-not $package.PackageFamilyName -or -not $destinationAppxIndex.ContainsKey($package.PackageFamilyName.ToLowerInvariant())){continue}
    $other=$destinationAppxIndex[$package.PackageFamilyName.ToLowerInvariant()]
    if(-not $package.Version -or -not $other.Version -or $package.Version -eq $other.Version){continue}
    [void]$appxVersionDifferences.Add([pscustomobject]@{
        Name=$package.Name;PackageFamilyName=$package.PackageFamilyName
        SourceVersion=$package.Version;DestinationVersion=$other.Version
    })
    [void](Add-PCDifference -Priority 4 -Category 'Compatibility' -Subcategory 'AppX/MSIX version' `
        -Item $package.Name -Status 'Different' -Confidence 'High' -Risk 'Low' `
        -SourceValue $package.Version -DestinationValue $other.Version -Evidence $package.PackageFamilyName `
        -Recommendation 'Prefer the current compatible Store version; review settings/database compatibility before restoring state.' `
        -MigrationGap $false)
}
Export-PCCsv -Path (Join-Path $report 'Appx-Version-Differences.csv') -Rows $appxVersionDifferences.ToArray() -Columns @(
    'Name','PackageFamilyName','SourceVersion','DestinationVersion'
)

$sourceDesktop=@(Import-PCCsv (Join-Path $source 'Applications\Desktop-Applications.csv')|Where-Object {
    $_.SystemComponent -ne '1' -and $_.ReleaseType -notmatch '(?i)update|hotfix|security'
})
$destinationDesktop=@(Import-PCCsv (Join-Path $destination 'Applications\Desktop-Applications.csv')|Where-Object {$_.SystemComponent -ne '1'})
$destinationDesktopExact=New-PCIndex -Rows $destinationDesktop -Key {param($row) ([string]$row.KeyName+'|'+[string]$row.Publisher)}
$destinationDesktopName=New-PCIndex -Rows $destinationDesktop -Key {param($row) ([string]$row.NormalizedName+'|'+(Normalize-PCApplicationName ([string]$row.Publisher)))}
$missingDesktop=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.DesktopRegistrations'){
    foreach($app in $sourceDesktop){
        $exact=([string]$app.KeyName+'|'+[string]$app.Publisher).ToLowerInvariant()
        $normal=([string]$app.NormalizedName+'|'+(Normalize-PCApplicationName ([string]$app.Publisher))).ToLowerInvariant()
        if($destinationDesktopExact.ContainsKey($exact) -or ($normal -ne '|' -and $destinationDesktopName.ContainsKey($normal))){continue}
        [void]$missingDesktop.Add($app)
        $recommendation='Reinstall from the original publisher or a reviewed winget package; application binaries and registrations should not be copied.'
        $id=Add-PCDifference -Priority 1 -Category 'Applications' -Subcategory 'Desktop registration' `
            -Item $app.DisplayName -Status 'Missing' -Confidence 'High' -Risk 'Low' `
            -SourceValue $app.DisplayVersion -DestinationValue '' -Evidence ('Uninstall registry '+$app.Hive+' '+$app.View) `
            -Recommendation $recommendation -MigrationGap $true
        Add-PCApplicationGap -Name $app.DisplayName -Identity $app.KeyName -EvidenceType 'UninstallRegistry' `
            -SourceVersion $app.DisplayVersion -Publisher $app.Publisher -Confidence 'High' -InstallMethod 'PublisherOrWingetLookup' `
            -PackageId '' -PackageSource '' -Recommendation $recommendation -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Desktop-Applications.csv') -Rows $missingDesktop.ToArray() -Columns @(
    'DisplayName','DisplayVersion','Publisher','KeyName','InstallLocation','Hive','View'
)
$desktopVersionDifferences=New-Object System.Collections.ArrayList
foreach($app in $sourceDesktop){
    $exact=([string]$app.KeyName+'|'+[string]$app.Publisher).ToLowerInvariant()
    $normal=([string]$app.NormalizedName+'|'+(Normalize-PCApplicationName ([string]$app.Publisher))).ToLowerInvariant()
    $other=if($destinationDesktopExact.ContainsKey($exact)){$destinationDesktopExact[$exact]}elseif($normal -ne '|' -and $destinationDesktopName.ContainsKey($normal)){$destinationDesktopName[$normal]}else{$null}
    if($null -eq $other -or -not $app.DisplayVersion -or -not $other.DisplayVersion -or $app.DisplayVersion -eq $other.DisplayVersion){continue}
    [void]$desktopVersionDifferences.Add([pscustomobject]@{
        DisplayName=$app.DisplayName;Publisher=$app.Publisher
        SourceVersion=$app.DisplayVersion;DestinationVersion=$other.DisplayVersion
    })
    [void](Add-PCDifference -Priority 4 -Category 'Compatibility' -Subcategory 'Desktop application version' `
        -Item $app.DisplayName -Status 'Different' -Confidence 'High' -Risk 'Low' `
        -SourceValue $app.DisplayVersion -DestinationValue $other.DisplayVersion -Evidence 'Uninstall registrations' `
        -Recommendation 'Confirm destination version compatibility with any settings being restored; do not downgrade automatically.' `
        -MigrationGap $false)
}
Export-PCCsv -Path (Join-Path $report 'Desktop-Application-Version-Differences.csv') -Rows $desktopVersionDifferences.ToArray() -Columns @(
    'DisplayName','Publisher','SourceVersion','DestinationVersion'
)

$sourceStart=@(Import-PCCsv (Join-Path $source 'Applications\Start-Apps.csv'))
$destinationStart=@(Import-PCCsv (Join-Path $destination 'Applications\Start-Apps.csv'))
$destinationStartIndex=New-PCIndex -Rows $destinationStart -Key {param($row) $row.AppID}
$missingStart=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.StartApps'){
    foreach($app in $sourceStart){
        if(-not $app.AppID -or $destinationStartIndex.ContainsKey($app.AppID.ToLowerInvariant())){continue}
        [void]$missingStart.Add($app)
        $id=Add-PCDifference -Priority 2 -Category 'Applications' -Subcategory 'Start-visible identity' `
            -Item $app.Name -Status 'Missing' -Confidence 'Medium' -Risk 'None' -SourceValue $app.AppID `
            -DestinationValue '' -Evidence 'Get-StartApps' `
            -Recommendation 'Correlate with AppX, desktop registrations, and shortcuts; this identity alone is not an installer.' `
            -MigrationGap $true
        Add-PCApplicationGap -Name $app.Name -Identity $app.AppID -EvidenceType 'StartApps' -SourceVersion '' `
            -Publisher '' -Confidence 'Medium' -InstallMethod 'CorrelateEvidence' -PackageId '' -PackageSource '' `
            -Recommendation 'Correlate with package and shortcut evidence.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Start-Apps.csv') -Rows $missingStart.ToArray() -Columns @('Name','AppID')

$sourceShortcuts=@(Import-PCCsv (Join-Path $source 'Applications\Shortcuts.csv'))
$destinationShortcuts=@(Import-PCCsv (Join-Path $destination 'Applications\Shortcuts.csv'))
$destinationShortcutIndex=New-PCIndex -Rows $destinationShortcuts -Key {param($row) ([string]$row.RootId+'|'+[string]$row.RelativePath)}
$sourceShortcutIndex=New-PCIndex -Rows $sourceShortcuts -Key {param($row) ([string]$row.RootId+'|'+[string]$row.RelativePath)}
$shortcutGaps=New-Object System.Collections.ArrayList
$shortcutEquivalentBinaryDifferences=New-Object System.Collections.ArrayList
$shortcutReconciliation=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.Shortcuts'){
    foreach($shortcut in $sourceShortcuts){
        $identity=([string]$shortcut.RootId+'|'+[string]$shortcut.RelativePath)
        $relativeLocation=[string](Get-PCProperty $shortcut 'RelativeLocation' '')
        if(-not $relativeLocation){$relativeLocation=Get-PCShortcutRelativeLocation -RootId $shortcut.RootId -RelativePath $shortcut.RelativePath}
        $other=if($destinationShortcutIndex.ContainsKey($identity.ToLowerInvariant())){$destinationShortcutIndex[$identity.ToLowerInvariant()]}else{$null}
        $sourceSemantic=[string](Get-PCProperty $shortcut 'SemanticSHA256' $shortcut.SHA256)
        $destinationSemantic=if($null -ne $other){[string](Get-PCProperty $other 'SemanticSHA256' $other.SHA256)}else{''}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($sourceSemantic -ne $destinationSemantic){$status='Different'}
        $functionalStatus=if($status){$status}else{'Equivalent'}
        $binaryStatus=if($null -eq $other){'Destination missing'}elseif($shortcut.SHA256 -eq $other.SHA256){'Identical'}else{'Different'}
        [void]$shortcutReconciliation.Add([pscustomobject]@{
            RootId=$shortcut.RootId;RelativePath=$shortcut.RelativePath;RelativeLocation=$relativeLocation
            Name=$shortcut.Name;Extension=$shortcut.Extension;DestinationPresent=($null -ne $other)
            FunctionalStatus=$functionalStatus;BinaryStatus=$binaryStatus
            SourceTarget=$shortcut.TargetPath;DestinationTarget=if($null -ne $other){$other.TargetPath}else{''}
            SourceArguments=$shortcut.Arguments;DestinationArguments=if($null -ne $other){$other.Arguments}else{''}
            SourceWorkingDirectory=$shortcut.WorkingDirectory
            DestinationWorkingDirectory=if($null -ne $other){$other.WorkingDirectory}else{''}
            Risk=if($shortcut.RootId -in @('CommonStartMenu','CommonDesktop','CommonStartup')){'High'}else{'Medium'}
        })
        if(-not $status){
            if($null -ne $other -and $shortcut.SHA256 -ne $other.SHA256){
                [void]$shortcutEquivalentBinaryDifferences.Add([pscustomobject]@{
                    RootId=$shortcut.RootId;RelativePath=$shortcut.RelativePath;RelativeLocation=$relativeLocation
                    Name=$shortcut.Name;Extension=$shortcut.Extension;TargetPath=$shortcut.TargetPath
                    SourceSHA256=$shortcut.SHA256;DestinationSHA256=$other.SHA256
                    SemanticSHA256=$sourceSemantic;Status='Functionally equivalent'
                    Reason='The binary files differ, but launch target, arguments, and working directory match.'
                })
            }
            continue
        }
        [void]$shortcutGaps.Add([pscustomobject]@{
            RootId=$shortcut.RootId;RelativePath=$shortcut.RelativePath;RelativeLocation=$relativeLocation;Name=$shortcut.Name
            Extension=$shortcut.Extension;TargetPath=$shortcut.TargetPath;TargetExists=$shortcut.TargetExists
            Arguments=$shortcut.Arguments;Status=$status;DestinationPresent=($null -ne $other)
            SourceSemanticSHA256=$sourceSemantic;DestinationSemanticSHA256=$destinationSemantic;SourceSHA256=$shortcut.SHA256
            DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            PayloadRelativePath=$shortcut.PayloadRelativePath
        })
        $repairable=([string]$shortcut.PayloadRelativePath -ne '')
        $machineShortcut=($shortcut.RootId -in @('CommonStartMenu','CommonDesktop','CommonStartup'))
        $shortcutRisk=if($machineShortcut){'High'}else{'Medium'}
        $id=Add-PCDifference -Priority 2 -Category 'Applications' -Subcategory 'Shortcut' -Item $relativeLocation `
            -Status $status -Confidence 'High' -Risk $shortcutRisk -SourceValue ($relativeLocation+' -> '+$shortcut.TargetPath) `
            -DestinationValue $(if($null -ne $other){$relativeLocation+' -> '+[string]$other.TargetPath}else{'Not present'}) `
            -Evidence ('Functional shortcut comparison; target: '+$shortcut.TargetPath) `
            -Recommendation 'Install the target application first; review target/arguments and restore only if the captured shortcut is still correct.' `
            -MigrationGap $true -Repairable $repairable -RepairMethod $(if($repairable){'CopyShortcut'}else{''})
        if($repairable){
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'Shortcuts' -Item $relativeLocation `
                -Method 'CopyShortcut' -Risk $shortcutRisk -Confidence 'High' -RequiresAdmin $machineShortcut -SourceArtifact $shortcut.PayloadRelativePath `
                -DestinationTarget $identity -ExpectedSourceSHA256 $shortcut.SHA256 `
                -Precondition ('Target must exist: '+$shortcut.TargetPath) `
                -Recommendation 'Restore the captured shortcut after installing its target application.'
        }
    }
    foreach($destinationShortcut in $destinationShortcuts){
        $destinationIdentity=([string]$destinationShortcut.RootId+'|'+[string]$destinationShortcut.RelativePath)
        if($sourceShortcutIndex.ContainsKey($destinationIdentity.ToLowerInvariant())){continue}
        $destinationLocation=[string](Get-PCProperty $destinationShortcut 'RelativeLocation' '')
        if(-not $destinationLocation){$destinationLocation=Get-PCShortcutRelativeLocation -RootId $destinationShortcut.RootId -RelativePath $destinationShortcut.RelativePath}
        [void]$shortcutReconciliation.Add([pscustomobject]@{
            RootId=$destinationShortcut.RootId;RelativePath=$destinationShortcut.RelativePath;RelativeLocation=$destinationLocation
            Name=$destinationShortcut.Name;Extension=$destinationShortcut.Extension;DestinationPresent=$true
            FunctionalStatus='Destination-only';BinaryStatus='Destination-only'
            SourceTarget='';DestinationTarget=$destinationShortcut.TargetPath
            SourceArguments='';DestinationArguments=$destinationShortcut.Arguments
            SourceWorkingDirectory='';DestinationWorkingDirectory=$destinationShortcut.WorkingDirectory
            Risk='None'
        })
    }
}
Export-PCCsv -Path (Join-Path $report 'Shortcut-Reconciliation.csv') -Rows $shortcutReconciliation.ToArray() -Columns @(
    'RootId','RelativePath','RelativeLocation','Name','Extension','DestinationPresent','FunctionalStatus','BinaryStatus',
    'SourceTarget','DestinationTarget','SourceArguments','DestinationArguments','SourceWorkingDirectory',
    'DestinationWorkingDirectory','Risk'
)
Export-PCCsv -Path (Join-Path $report 'Shortcut-Gaps.csv') -Rows $shortcutGaps.ToArray() -Columns @(
    'RootId','RelativePath','RelativeLocation','Name','Extension','TargetPath','TargetExists','Arguments','Status',
    'DestinationPresent','SourceSemanticSHA256','DestinationSemanticSHA256','SourceSHA256','DestinationSHA256','PayloadRelativePath'
)
Export-PCCsv -Path (Join-Path $report 'Shortcut-Equivalent-Binary-Differences.csv') -Rows $shortcutEquivalentBinaryDifferences.ToArray() -Columns @(
    'RootId','RelativePath','RelativeLocation','Name','Extension','TargetPath','SourceSHA256','DestinationSHA256',
    'SemanticSHA256','Status','Reason'
)

$sourcePortable=@(Import-PCCsv (Join-Path $source 'Applications\Portable-Executables.csv'))
$destinationPortable=@(Import-PCCsv (Join-Path $destination 'Applications\Portable-Executables.csv'))
$destinationPortableIndex=New-PCIndex -Rows $destinationPortable -Key {param($row) $row.Path}
$missingPortable=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Applications.PortableExecutables'){
    foreach($executable in $sourcePortable){
        if(-not $executable.Path -or $destinationPortableIndex.ContainsKey($executable.Path.ToLowerInvariant())){continue}
        [void]$missingPortable.Add($executable)
        $name=if($executable.ProductName){$executable.ProductName}else{$executable.FileName}
        $id=Add-PCDifference -Priority 2 -Category 'Applications' -Subcategory 'Portable executable' -Item $name `
            -Status 'Missing' -Confidence 'Medium' -Risk 'Medium' -SourceValue $executable.Path -DestinationValue '' `
            -Evidence 'Executable footprint in a user/explicit portable root' `
            -Recommendation 'Review provenance, then reinstall or copy the complete portable application directory—not only the EXE.' `
            -MigrationGap $true
        Add-PCApplicationGap -Name $name -Identity $executable.Path -EvidenceType 'PortableExecutable' `
            -SourceVersion $executable.ProductVersion -Publisher $executable.CompanyName -Confidence 'Medium' `
            -InstallMethod 'ManualPortableDirectory' -PackageId '' -PackageSource '' `
            -Recommendation 'Restore the complete trusted portable application directory.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Portable-Executables.csv') -Rows $missingPortable.ToArray() -Columns @(
    'Root','Path','FileName','ProductName','ProductVersion','CompanyName','Length','SHA256'
)

# File-level application settings.
$sourceFiles=@(Import-PCCsv (Join-Path $source 'ApplicationState\Settings-Files.csv'))
$destinationFiles=@(Import-PCCsv (Join-Path $destination 'ApplicationState\Settings-Files.csv'))
$destinationFileIndex=New-PCIndex -Rows $destinationFiles -Key {param($row) ([string]$row.RootToken+'|'+[string]$row.RelativePath)}
$fileGaps=New-Object System.Collections.ArrayList
if((Test-PCDestinationComplete 'ApplicationState.Files') -and $fileInventoryComparable){
    foreach($file in $sourceFiles){
        $identity=[string]$file.RootToken+'|'+[string]$file.RelativePath
        $key=$identity.ToLowerInvariant()
        $other=if($destinationFileIndex.ContainsKey($key)){$destinationFileIndex[$key]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'
        }elseif($file.SHA256 -and $other.SHA256 -and $file.SHA256 -ne $other.SHA256){$status='Different'
        }elseif([string]$file.Length -ne [string]$other.Length){$status='Different'}
        if(-not $status){continue}
        [void]$fileGaps.Add([pscustomobject]@{
            RootToken=$file.RootToken;RelativePath=$file.RelativePath;TopLevelRoot=$file.TopLevelRoot
            Classification=$file.Classification;Sensitive=$file.Sensitive;Status=$status
            SourceLength=$file.Length;DestinationLength=if($null -ne $other){$other.Length}else{''}
            SourceSHA256=$file.SHA256;DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            PayloadRelativePath=$file.PayloadRelativePath
        })
        $sensitive=([string]$file.Sensitive -eq 'True')
        $machinePath=($file.RootToken -in @('PROGRAMDATA','PROGRAMFILES','PROGRAMFILESX86','WINDIR'))
        $risk=if($sensitive -or $file.Classification -eq 'Database' -or $machinePath){'High'}else{'Medium'}
        $specializedPayload=($identity -match '(?i)^(APPDATA|LOCALAPPDATA)\|(MPC-HC|Icaros|K-Lite Codec Pack)\\' -or
            $identity -match '(?i)^LOCALAPPDATA\|(Packages\\Microsoft\.WindowsTerminal[^\\]*\\LocalState|Microsoft\\Windows Terminal)\\settings\.json$')
        $repairable=(-not $sensitive -and -not $specializedPayload -and $file.Classification -in @('Configuration','Script') -and [string]$file.PayloadRelativePath)
        $recommendation=if($sensitive){
            'Use the application-supported sign-in, sync, export, or import path; protected state is not copied generically.'
        }elseif($file.Classification -eq 'Database'){
            'Close the application and use its supported backup/import process; do not overwrite a live or version-mismatched database.'
        }else{'Install and close the matching application, inspect old paths/version compatibility, then restore this configuration file if approved.'}
        $id=Add-PCDifference -Priority 2 -Category 'Application settings' -Subcategory 'File state' `
            -Item $identity -Status $status -Confidence 'High' -Risk $risk -SourceValue $file.SHA256 `
            -DestinationValue $(if($null -ne $other){$other.SHA256}else{''}) -Evidence $file.Classification `
            -Recommendation $recommendation -MigrationGap $true -Repairable $repairable `
            -RepairMethod $(if($repairable){'CopyFile'}else{''})
        Add-PCSettingsGap -Scope 'File' -Identity $identity -Status $status -Classification $file.Classification `
            -SourceSHA256 $file.SHA256 -DestinationSHA256 $(if($null -ne $other){$other.SHA256}else{''}) `
            -Sensitive $file.Sensitive -Payload $file.PayloadRelativePath -Recommendation $recommendation -DifferenceId $id
        if($repairable){
            $target='%'+$file.RootToken+'%\'+$file.RelativePath
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'Application settings file' -Item $identity `
                -Method 'CopyFile' -Risk $risk -Confidence 'High' -RequiresAdmin $machinePath -SourceArtifact $file.PayloadRelativePath `
                -DestinationTarget $target -ExpectedSourceSHA256 $file.SHA256 `
                -Precondition 'Matching application installed and closed; destination file reviewed/backed up automatically.' `
                -Recommendation $recommendation
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'Application-File-Gaps.csv') -Rows $fileGaps.ToArray() -Columns @(
    'RootToken','RelativePath','TopLevelRoot','Classification','Sensitive','Status',
    'SourceLength','DestinationLength','SourceSHA256','DestinationSHA256','PayloadRelativePath'
)

$sourceRoots=@(Import-PCCsv (Join-Path $source 'ApplicationState\State-Roots.csv'))
$destinationRoots=@(Import-PCCsv (Join-Path $destination 'ApplicationState\State-Roots.csv'))
$destinationRootIndex=New-PCIndex -Rows $destinationRoots -Key {param($row) ([string]$row.RootToken+'|'+[string]$row.Name)}
$rootGaps=New-Object System.Collections.ArrayList
if((Test-PCDestinationComplete 'ApplicationState.Files') -and $fileInventoryComparable){
    foreach($root in $sourceRoots){
        $identity=[string]$root.RootToken+'|'+[string]$root.Name
        $key=$identity.ToLowerInvariant()
        $other=if($destinationRootIndex.ContainsKey($key)){$destinationRootIndex[$key]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'
        }elseif([int64]$root.CandidateCount -ne [int64]$other.CandidateCount){$status='Different candidate count'}
        if(-not $status){continue}
        [void]$rootGaps.Add([pscustomobject]@{
            RootToken=$root.RootToken;Name=$root.Name;Status=$status
            SourceFileCount=$root.FileCount;DestinationFileCount=if($null -ne $other){$other.FileCount}else{''}
            SourceCandidateCount=$root.CandidateCount;DestinationCandidateCount=if($null -ne $other){$other.CandidateCount}else{''}
            SourceBytes=$root.Bytes;DestinationBytes=if($null -ne $other){$other.Bytes}else{''}
        })
        [void](Add-PCDifference -Priority 3 -Category 'Application settings' -Subcategory 'State root summary' `
            -Item $identity -Status $status -Confidence 'Medium' -Risk 'Medium' -SourceValue ([string]$root.CandidateCount) `
            -DestinationValue $(if($null -ne $other){[string]$other.CandidateCount}else{'0'}) `
            -Evidence 'Recursive nonvolatile file summary' `
            -Recommendation 'Use Application-File-Gaps.csv to identify specific configuration items; do not bulk-copy the whole root.' `
            -MigrationGap $true)
    }
}
Export-PCCsv -Path (Join-Path $report 'Application-State-Root-Gaps.csv') -Rows $rootGaps.ToArray() -Columns @(
    'RootToken','Name','Status','SourceFileCount','DestinationFileCount','SourceCandidateCount',
    'DestinationCandidateCount','SourceBytes','DestinationBytes'
)

# Deep registry value comparison. Only hashes are required; sensitive previews
# were redacted during capture.
$sourceUserRegistry=@(Import-PCCsv (Join-Path $source 'ApplicationState\Registry-HKCU-Software.csv'))
$destinationUserRegistry=@(Import-PCCsv (Join-Path $destination 'ApplicationState\Registry-HKCU-Software.csv'))
$destinationUserRegistryIndex=New-PCIndex -Rows $destinationUserRegistry -Key {param($row) ([string]$row.Key+'|'+[string]$row.Name)}
$registryGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'ApplicationState.RegistryCurrentUser'){
    foreach($value in $sourceUserRegistry){
        $identity=[string]$value.Key+'|'+[string]$value.Name
        $key=$identity.ToLowerInvariant()
        $other=if($destinationUserRegistryIndex.ContainsKey($key)){$destinationUserRegistryIndex[$key]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'
        }elseif($value.Kind -ne $other.Kind -or $value.DataSHA256 -ne $other.DataSHA256){$status='Different'}
        if(-not $status){continue}
        [void]$registryGaps.Add([pscustomobject]@{
            Hive='HKCU';View=$value.View;Key=$value.Key;Name=$value.Name;Kind=$value.Kind
            Sensitive=$value.Sensitive;Status=$status;SourceSHA256=$value.DataSHA256
            DestinationSHA256=if($null -ne $other){$other.DataSHA256}else{''}
            SourcePreview=$value.Preview;DestinationPreview=if($null -ne $other){$other.Preview}else{''}
        })
        $risk=if($value.Sensitive -eq 'True'){'High'}else{'Medium'}
        $recommendation='Correlate this key with its installed application and use a reviewed app-specific export/restore; never import HKCU\Software wholesale.'
        $id=Add-PCDifference -Priority 3 -Category 'Application settings' -Subcategory 'HKCU registry value' `
            -Item $identity -Status $status -Confidence 'High' -Risk $risk -SourceValue $value.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Evidence ('SHA256 '+$value.DataSHA256) `
            -Recommendation $recommendation -MigrationGap $true
        Add-PCSettingsGap -Scope 'Registry HKCU' -Identity $identity -Status $status -Classification $value.Kind `
            -SourceSHA256 $value.DataSHA256 -DestinationSHA256 $(if($null -ne $other){$other.DataSHA256}else{''}) `
            -Sensitive $value.Sensitive -Payload '' -Recommendation $recommendation -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Registry-State-Gaps.csv') -Rows $registryGaps.ToArray() -Columns @(
    'Hive','View','Key','Name','Kind','Sensitive','Status','SourceSHA256','DestinationSHA256','SourcePreview','DestinationPreview'
)

# Machine registry is summarized by vendor/root digest to avoid producing a
# misleading blanket-import plan.
$machineRootGaps=New-Object System.Collections.ArrayList
foreach($view in @('HKLM64','HKLM32')){
    $collector=if($view -eq 'HKLM64'){'ApplicationState.RegistryMachine64'}else{'ApplicationState.RegistryMachine32'}
    if(-not (Test-PCDestinationComplete $collector)){continue}
    $sourceMachine=@(Import-PCCsv (Join-Path $source ('ApplicationState\Registry-'+$view+'-Software-Roots.csv')))
    $destinationMachine=@(Import-PCCsv (Join-Path $destination ('ApplicationState\Registry-'+$view+'-Software-Roots.csv')))
    $destinationMachineIndex=New-PCIndex -Rows $destinationMachine -Key {param($row) $row.Name}
    foreach($root in $sourceMachine){
        $other=if($destinationMachineIndex.ContainsKey($root.Name.ToLowerInvariant())){$destinationMachineIndex[$root.Name.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($root.Digest -ne $other.Digest){$status='Different'}
        if(-not $status){continue}
        [void]$machineRootGaps.Add([pscustomobject]@{
            View=$view;Name=$root.Name;Status=$status;SourceValueCount=$root.ValueCount
            DestinationValueCount=if($null -ne $other){$other.ValueCount}else{''}
            SourceDigest=$root.Digest;DestinationDigest=if($null -ne $other){$other.Digest}else{''}
        })
        [void](Add-PCDifference -Priority 3 -Category 'Application settings' -Subcategory ('Machine registry '+$view) `
            -Item $root.Name -Status $status -Confidence 'Medium' -Risk 'High' -SourceValue $root.Digest `
            -DestinationValue $(if($null -ne $other){$other.Digest}else{''}) -Evidence 'Registry vendor/root digest' `
            -Recommendation 'Install the matching software first; review specific machine settings and hardware compatibility. Never import HKLM\SOFTWARE wholesale.' `
            -MigrationGap $true)
    }
}
Export-PCCsv -Path (Join-Path $report 'Machine-Registry-Root-Gaps.csv') -Rows $machineRootGaps.ToArray() -Columns @(
    'View','Name','Status','SourceValueCount','DestinationValueCount','SourceDigest','DestinationDigest'
)

# Grouped, explicitly captured registry payloads are the only registry items
# eligible for an automated plan.
$sourceCatalog=@(Import-PCCsv (Join-Path $source 'ApplicationState\Registry-Payload-Catalog.csv'))
$destinationCatalog=@(Import-PCCsv (Join-Path $destination 'ApplicationState\Registry-Payload-Catalog.csv'))
$destinationCatalogIndex=New-PCIndex -Rows $destinationCatalog -Key {param($row) $row.Id}
$registryPayloadGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'ApplicationState.RepairableRegistryPayload'){
    foreach($item in $sourceCatalog){
        if($item.Present -ne 'True'){continue}
        $other=if($destinationCatalogIndex.ContainsKey($item.Id.ToLowerInvariant())){$destinationCatalogIndex[$item.Id.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other -or $other.Present -ne 'True'){$status='Missing'
        }elseif($item.StateDigest -ne $other.StateDigest){$status='Different'}
        if(-not $status){continue}
        [void]$registryPayloadGaps.Add([pscustomobject]@{
            Id=$item.Id;Hive=$item.Hive;SubKey=$item.SubKey;Status=$status;Risk=$item.Risk
            RequiresApp=$item.RequiresApp;AutoMethod=$item.AutoMethod
            ValueCount=$item.ValueCount;StateDigest=$item.StateDigest;Artifact=$item.Artifact;SHA256=$item.SHA256
        })
        $repairable=($item.AutoMethod -eq 'ImportRegistry' -and [string]$item.Artifact)
        $recommendation=if($repairable){
            'Review this narrowly scoped registry export, ensure any required application is installed/closed, then approve its single plan row.'
        }else{'Review manually; this category is intentionally excluded from generic registry import.'}
        $id=Add-PCDifference -Priority 2 -Category 'User state' -Subcategory 'Scoped registry payload' `
            -Item $item.Id -Status $status -Confidence 'High' -Risk $item.Risk `
            -SourceValue ($item.Hive+'\'+$item.SubKey) -DestinationValue '' -Evidence $item.Artifact `
            -Recommendation $recommendation -MigrationGap $true -Repairable $repairable `
            -RepairMethod $(if($repairable){'ImportRegistry'}else{''})
        if($repairable){
            $precondition='Destination key will be backed up.'
            if($item.RequiresApp){$precondition=$item.RequiresApp+' must be installed and closed; '+$precondition}
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'Scoped registry state' -Item $item.Id `
                -Method 'ImportRegistry' -Risk $item.Risk -Confidence 'High' -SourceArtifact $item.Artifact `
                -DestinationTarget ($item.Hive+'\'+$item.SubKey) -ExpectedSourceSHA256 $item.SHA256 `
                -Precondition $precondition -Recommendation $recommendation
        }else{Add-PCManualAction -Category 'Registry state' -Item $item.Id -Detected $status -Action $recommendation -Reason ($item.Hive+'\'+$item.SubKey) -DifferenceId $id}
    }
}
Export-PCCsv -Path (Join-Path $report 'Scoped-Registry-Payload-Gaps.csv') -Rows $registryPayloadGaps.ToArray() -Columns @(
    'Id','Hive','SubKey','Status','Risk','RequiresApp','AutoMethod','ValueCount','StateDigest','Artifact','SHA256'
)

# User shell and operating-system state.
$sourceUserState=@(Import-PCCsv (Join-Path $source 'UserState\Registry-Values.csv'))
$destinationUserState=@(Import-PCCsv (Join-Path $destination 'UserState\Registry-Values.csv'))
$userStateDifferences=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.RegistryValues'){
    foreach($pair in @(Compare-PCValueRows -SourceRows $sourceUserState -DestinationRows $destinationUserState)){
        $row=$pair.Source;$other=$pair.Destination
        $identity=$row.StateId+'|'+$row.Key+'|'+$row.Name
        [void]$userStateDifferences.Add([pscustomobject]@{
            StateId=$row.StateId;Key=$row.Key;Name=$row.Name;Kind=$row.Kind;Status=$pair.Status
            SourceSHA256=$row.DataSHA256;DestinationSHA256=if($null -ne $other){$other.DataSHA256}else{''}
            SourcePreview=$row.Preview;DestinationPreview=if($null -ne $other){$other.Preview}else{''}
            Sensitive=$row.Sensitive
        })
        $risk=if($row.Sensitive -eq 'True'){'High'}else{'Medium'}
        $recommendation='Use the matching scoped registry-payload row where available; otherwise review and restore this setting family manually.'
        $id=Add-PCDifference -Priority 2 -Category 'Windows user state' -Subcategory $row.StateId -Item $identity `
            -Status $pair.Status -Confidence 'High' -Risk $risk -SourceValue $row.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Evidence ('Registry hash '+$row.DataSHA256) `
            -Recommendation $recommendation -MigrationGap $true
        Add-PCWindowsGap -Category $row.StateId -Identity $identity -Status $pair.Status -SourceValue $row.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Confidence 'High' `
            -Recommendation $recommendation -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'User-State-Registry-Gaps.csv') -Rows $userStateDifferences.ToArray() -Columns @(
    'StateId','Key','Name','Kind','Status','SourceSHA256','DestinationSHA256','SourcePreview','DestinationPreview','Sensitive'
)

$sourceRegional=Read-PCJson (Join-Path $source 'UserState\Regional-Language.json')
$destinationRegional=Read-PCJson (Join-Path $destination 'UserState\Regional-Language.json')
$regionalGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.RegionalLanguage'){
    foreach($name in @('CultureName','ShortDatePattern','LongDatePattern','ShortTimePattern','LongTimePattern','FirstDayOfWeek','TimeZoneId','SystemLocale','HomeGeoId','DefaultInputMethodOverride')){
        $sourceValue=[string](Get-PCProperty $sourceRegional $name '')
        $destinationValue=[string](Get-PCProperty $destinationRegional $name '')
        if($sourceValue -eq $destinationValue){continue}
        [void]$regionalGaps.Add([pscustomobject]@{Name=$name;SourceValue=$sourceValue;DestinationValue=$destinationValue;Status='Different'})
        $risk=if($name -eq 'TimeZoneId' -or $name -eq 'SystemLocale'){'Medium'}else{'Low'}
        $id=Add-PCDifference -Priority 1 -Category 'Windows user state' -Subcategory 'Regional/language' -Item $name `
            -Status 'Different' -Confidence 'High' -Risk $risk -SourceValue $sourceValue -DestinationValue $destinationValue `
            -Evidence 'Regional-Language.json' -Recommendation 'Restore the scoped regional state; sign out/in before judging shell/clock rendering.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Regional/language' -Identity $name -Status 'Different' -SourceValue $sourceValue `
            -DestinationValue $destinationValue -Confidence 'High' `
            -Recommendation 'Restore scoped regional state and sign out/in.' -DifferenceId $id
        if($name -eq 'TimeZoneId' -and $sourceValue){
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'System time zone' -Item $sourceValue `
                -Method 'SetTimeZone' -Risk 'Medium' -Confidence 'High' -RequiresAdmin $true `
                -DestinationTarget $sourceValue -Precondition 'Confirm the source time zone is correct for the destination location.' `
                -Recommendation 'Set the destination system time zone to the source ID.'
        }
    }
    $sourceLanguages=@(Get-PCProperty $sourceRegional 'UserLanguages' @())
    $destinationLanguages=@(Get-PCProperty $destinationRegional 'UserLanguages' @())
    $sourceLanguageText=($sourceLanguages|ForEach-Object {$_.LanguageTag+'|'+$_.InputMethodTips}) -join '; '
    $destinationLanguageText=($destinationLanguages|ForEach-Object {$_.LanguageTag+'|'+$_.InputMethodTips}) -join '; '
    if($sourceLanguageText -ne $destinationLanguageText){
        [void]$regionalGaps.Add([pscustomobject]@{Name='UserLanguages';SourceValue=$sourceLanguageText;DestinationValue=$destinationLanguageText;Status='Different'})
        $languageId=Add-PCDifference -Priority 2 -Category 'Windows user state' -Subcategory 'Regional/language' -Item 'User language and input-method list' `
            -Status 'Different' -Confidence 'High' -Risk 'Medium' -SourceValue $sourceLanguageText -DestinationValue $destinationLanguageText `
            -Evidence 'Get-WinUserLanguageList' `
            -Recommendation 'Review language order and input method tips; restore with Windows language settings rather than raw registry transplantation.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Language/input' -Item 'User language and input-method list' -Detected 'Different' `
            -Action 'Review and recreate through Windows language settings.' -Reason $sourceLanguageText -DifferenceId $languageId
    }
    $sourceShort=[string](Get-PCProperty $sourceRegional 'ShortTimePattern' '')
    $sourceLong=[string](Get-PCProperty $sourceRegional 'LongTimePattern' '')
    $destinationShort=[string](Get-PCProperty $destinationRegional 'ShortTimePattern' '')
    $destinationLong=[string](Get-PCProperty $destinationRegional 'LongTimePattern' '')
    if(($sourceShort -match 'H' -or $sourceLong -match 'H') -and ($destinationShort -notmatch 'H' -or $destinationLong -notmatch 'H')){
        $id=Add-PCDifference -Priority 1 -Category 'Windows user state' -Subcategory 'Clock' -Item '24-hour taskbar/locale clock' `
            -Status 'Different' -Confidence 'High' -Risk 'Low' -SourceValue ($sourceShort+' | '+$sourceLong) `
            -DestinationValue ($destinationShort+' | '+$destinationLong) -Evidence 'Source uses 24-hour H patterns.' `
            -Recommendation 'Set sShortTime=HH:mm, sTimeFormat=HH:mm:ss, iTime=1, and iTLZero=1.' `
            -MigrationGap $true -Repairable $true -RepairMethod 'Set24HourClock'
        Add-PCRepairAction -DifferenceId $id -Priority 1 -Category 'Regional clock' -Item '24-hour clock' `
            -Method 'Set24HourClock' -Risk 'Low' -Confidence 'High' `
            -Precondition 'Current user only; sign out/in may be required for the taskbar.' `
            -Recommendation 'Apply HH:mm and HH:mm:ss 24-hour formats.'
    }
}
Export-PCCsv -Path (Join-Path $report 'Regional-Language-Gaps.csv') -Rows $regionalGaps.ToArray() -Columns @('Name','SourceValue','DestinationValue','Status')

$sourceProfiles=@(Import-PCCsv (Join-Path $source 'UserState\PowerShell\Profiles.csv'))
$destinationProfiles=@(Import-PCCsv (Join-Path $destination 'UserState\PowerShell\Profiles.csv'))
$destinationProfileIndex=New-PCIndex -Rows $destinationProfiles -Key {param($row) $row.Id}
$profileGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.PowerShell'){
    foreach($profile in $sourceProfiles){
        $other=if($destinationProfileIndex.ContainsKey($profile.Id.ToLowerInvariant())){$destinationProfileIndex[$profile.Id.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($profile.SHA256 -ne $other.SHA256){$status='Different'}
        if(-not $status){continue}
        [void]$profileGaps.Add([pscustomobject]@{
            Id=$profile.Id;Scope=$profile.Scope;DestinationPath=$profile.DestinationPath;Status=$status
            SourceSHA256=$profile.SHA256;DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            PayloadRelativePath=$profile.PayloadRelativePath
        })
        $repairable=([string]$profile.PayloadRelativePath -ne '')
        $risk=if($profile.Scope -eq 'AllUsers'){'High'}else{'Medium'}
        $recommendation='Review the profile for obsolete paths, commands, and secrets before restoring it.'
        $id=Add-PCDifference -Priority 2 -Category 'PowerShell' -Subcategory 'Profile' -Item $profile.Id `
            -Status $status -Confidence 'High' -Risk $risk -SourceValue $profile.SHA256 `
            -DestinationValue $(if($null -ne $other){$other.SHA256}else{''}) -Evidence $profile.DestinationPath `
            -Recommendation $recommendation -MigrationGap $true -Repairable $repairable `
            -RepairMethod $(if($repairable){'CopyFile'}else{''})
        if($repairable){
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'PowerShell profile' -Item $profile.Id `
                -Method 'CopyFile' -Risk $risk -Confidence 'High' -RequiresAdmin ($profile.Scope -eq 'AllUsers') `
                -SourceArtifact $profile.PayloadRelativePath -DestinationTarget $profile.DestinationPath `
                -ExpectedSourceSHA256 $profile.SHA256 -Precondition 'Review profile text; close affected PowerShell hosts.' `
                -Recommendation $recommendation
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'PowerShell-Profile-Gaps.csv') -Rows $profileGaps.ToArray() -Columns @(
    'Id','Scope','DestinationPath','Status','SourceSHA256','DestinationSHA256','PayloadRelativePath'
)

$sourceModules=@(Import-PCCsv (Join-Path $source 'UserState\PowerShell\Modules.csv'))
$destinationModules=@(Import-PCCsv (Join-Path $destination 'UserState\PowerShell\Modules.csv'))
$destinationModuleIndex=New-PCIndex -Rows $destinationModules -Key {param($row) ([string]$row.Name+'|'+[string]$row.Version)}
$missingModules=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.PowerShell'){
    foreach($module in $sourceModules){
        $identity=[string]$module.Name+'|'+[string]$module.Version
        if($destinationModuleIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingModules.Add($module)
        $id=Add-PCDifference -Priority 3 -Category 'PowerShell' -Subcategory 'Module' -Item $identity `
            -Status 'Missing' -Confidence 'High' -Risk 'Medium' -SourceValue $module.Path -DestinationValue '' `
            -Evidence 'Get-Module -ListAvailable' `
            -Recommendation 'Reinstall from the original trusted repository/installer; do not copy a module whose provenance or native dependencies are unknown.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'PowerShell' -Item $identity -Detected 'Missing' `
            -Action 'Reinstall from the original trusted repository or installer.' -Reason $module.Path -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-PowerShell-Modules.csv') -Rows $missingModules.ToArray() -Columns @('Name','Version','ModuleType','Guid','Path')

$sourcePolicies=@(Import-PCCsv (Join-Path $source 'UserState\PowerShell\Execution-Policy.csv'))
$destinationPolicies=@(Import-PCCsv (Join-Path $destination 'UserState\PowerShell\Execution-Policy.csv'))
$destinationPolicyIndex=New-PCIndex -Rows $destinationPolicies -Key {param($row) $row.Scope}
$policyGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.PowerShell'){
    foreach($policy in $sourcePolicies){
        $other=if($destinationPolicyIndex.ContainsKey($policy.Scope.ToLowerInvariant())){$destinationPolicyIndex[$policy.Scope.ToLowerInvariant()]}else{$null}
        $destinationValue=if($null -ne $other){[string]$other.ExecutionPolicy}else{''}
        if($policy.ExecutionPolicy -eq $destinationValue){continue}
        [void]$policyGaps.Add([pscustomobject]@{
            Scope=$policy.Scope;SourceExecutionPolicy=$policy.ExecutionPolicy
            DestinationExecutionPolicy=$destinationValue;Status='Different'
        })
        $id=Add-PCDifference -Priority 3 -Category 'PowerShell' -Subcategory 'Execution policy' -Item $policy.Scope `
            -Status 'Different' -Confidence 'High' -Risk 'High' -SourceValue $policy.ExecutionPolicy `
            -DestinationValue $destinationValue -Evidence 'Get-ExecutionPolicy -List' `
            -Recommendation 'Review policy ownership and security intent; do not weaken destination execution policy merely to match the source.' `
            -MigrationGap $false
        Add-PCManualAction -Category 'PowerShell security' -Item ('Execution policy '+$policy.Scope) -Detected 'Different' `
            -Action 'Review only; preserve the stricter or policy-managed setting unless a deliberate change is required.' `
            -Reason ($policy.ExecutionPolicy+' -> '+$destinationValue) -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'PowerShell-Execution-Policy-Gaps.csv') -Rows $policyGaps.ToArray() -Columns @(
    'Scope','SourceExecutionPolicy','DestinationExecutionPolicy','Status'
)

$sourceTerminal=@(Import-PCCsv (Join-Path $source 'UserState\Windows-Terminal.csv'))
$destinationTerminal=@(Import-PCCsv (Join-Path $destination 'UserState\Windows-Terminal.csv'))
$destinationTerminalIndex=New-PCIndex -Rows $destinationTerminal -Key {param($row) $row.DestinationPath}
$terminalGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.WindowsTerminal'){
    foreach($item in $sourceTerminal){
        $other=if($destinationTerminalIndex.ContainsKey($item.DestinationPath.ToLowerInvariant())){$destinationTerminalIndex[$item.DestinationPath.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($item.SHA256 -ne $other.SHA256){$status='Different'}
        if(-not $status){continue}
        [void]$terminalGaps.Add([pscustomobject]@{
            Id=$item.Id;DestinationPath=$item.DestinationPath;Status=$status
            SourceSHA256=$item.SHA256;DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            PayloadRelativePath=$item.PayloadRelativePath
        })
        $repairable=([string]$item.PayloadRelativePath -ne '')
        $recommendation='Close Windows Terminal, review profile command paths and GUIDs, then restore settings.json.'
        $id=Add-PCDifference -Priority 2 -Category 'Windows Terminal' -Subcategory 'settings.json' -Item $item.Id `
            -Status $status -Confidence 'High' -Risk 'Medium' -SourceValue $item.SHA256 `
            -DestinationValue $(if($null -ne $other){$other.SHA256}else{''}) -Evidence $item.DestinationPath `
            -Recommendation $recommendation -MigrationGap $true -Repairable $repairable `
            -RepairMethod $(if($repairable){'CopyFile'}else{''})
        if($repairable){
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'Windows Terminal' -Item $item.Id `
                -Method 'CopyFile' -Risk 'Medium' -Confidence 'High' -SourceArtifact $item.PayloadRelativePath `
                -DestinationTarget $item.DestinationPath -ExpectedSourceSHA256 $item.SHA256 `
                -Precondition 'Windows Terminal closed; source profile executables installed.' -Recommendation $recommendation
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'Windows-Terminal-Gaps.csv') -Rows $terminalGaps.ToArray() -Columns @(
    'Id','DestinationPath','Status','SourceSHA256','DestinationSHA256','PayloadRelativePath'
)

$sourceExtensions=@(Import-PCCsv (Join-Path $source 'ApplicationState\Browser-Extensions.csv'))
$destinationExtensions=@(Import-PCCsv (Join-Path $destination 'ApplicationState\Browser-Extensions.csv'))
$destinationExtensionIndex=New-PCIndex -Rows $destinationExtensions -Key {param($row) ([string]$row.Browser+'|'+[string]$row.Profile+'|'+[string]$row.Id)}
$missingExtensions=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'ApplicationState.Browsers'){
    foreach($extension in $sourceExtensions){
        $identity=$extension.Browser+'|'+$extension.Profile+'|'+$extension.Id
        if($destinationExtensionIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingExtensions.Add($extension)
        $id=Add-PCDifference -Priority 3 -Category 'Browser state' -Subcategory 'Extension' -Item $identity `
            -Status 'Missing' -Confidence 'Medium' -Risk 'Medium' -SourceValue ($extension.Name+' '+$extension.Version) `
            -DestinationValue '' -Evidence 'Browser extension manifest' `
            -Recommendation 'Install through the browser store/sync and review extension permissions; do not transplant browser profile databases.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Browser extension' -Item $identity -Detected 'Missing' `
            -Action 'Install through browser sync/store and verify permissions.' -Reason 'Profile databases and tokens are not copied.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Browser-Extensions.csv') -Rows $missingExtensions.ToArray() -Columns @('Browser','Profile','Id','Name','Version','Type')

$sourceFonts=@(Import-PCCsv (Join-Path $source 'UserState\Fonts.csv'))
$destinationFonts=@(Import-PCCsv (Join-Path $destination 'UserState\Fonts.csv'))
$destinationFontIndex=New-PCIndex -Rows $destinationFonts -Key {param($row) ([string]$row.Scope+'|'+[string]$row.Name)}
$missingFonts=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.Fonts'){
    foreach($font in $sourceFonts){
        $identity=$font.Scope+'|'+$font.Name
        if($destinationFontIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingFonts.Add($font)
        $id=Add-PCDifference -Priority 3 -Category 'Windows user state' -Subcategory 'Font' -Item $identity `
            -Status 'Missing' -Confidence 'High' -Risk 'Medium' -SourceValue $font.Version -DestinationValue '' `
            -Evidence 'Font file inventory' -Recommendation 'Reinstall from the original licensed/trusted font file; restart applications afterward.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Font' -Item $identity -Detected 'Missing' `
            -Action 'Reinstall from the original licensed/trusted font source.' -Reason 'Font binaries are inventory-only.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Fonts.csv') -Rows $missingFonts.ToArray() -Columns @('Scope','Name','Length','Version','SHA256')

$sourceAssociations=@(Get-PCDefaultAssociations $source)
$destinationAssociations=@(Get-PCDefaultAssociations $destination)
$destinationAssociationIndex=New-PCIndex -Rows $destinationAssociations -Key {param($row) $row.Identifier}
$associationGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'UserState.DefaultApplications'){
    foreach($association in $sourceAssociations){
        $other=if($destinationAssociationIndex.ContainsKey($association.Identifier.ToLowerInvariant())){$destinationAssociationIndex[$association.Identifier.ToLowerInvariant()]}else{$null}
        if($null -ne $other -and $association.ProgId -eq $other.ProgId){continue}
        [void]$associationGaps.Add([pscustomobject]@{
            Identifier=$association.Identifier;SourceProgId=$association.ProgId
            SourceApplicationName=$association.ApplicationName
            DestinationProgId=if($null -ne $other){$other.ProgId}else{''}
            DestinationApplicationName=if($null -ne $other){$other.ApplicationName}else{''}
            Status=if($null -eq $other){'Missing'}else{'Different'}
        })
        $id=Add-PCDifference -Priority 3 -Category 'Windows user state' -Subcategory 'Default application' -Item $association.Identifier `
            -Status $(if($null -eq $other){'Missing'}else{'Different'}) -Confidence 'High' -Risk 'Medium' `
            -SourceValue $association.ProgId -DestinationValue $(if($null -ne $other){$other.ProgId}else{''}) `
            -Evidence 'DISM default-app associations' `
            -Recommendation 'Install the target application and assign the default through Windows Settings; protected UserChoice hashes are not imported.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Default application' -Identity $association.Identifier `
            -Status $(if($null -eq $other){'Missing'}else{'Different'}) -SourceValue $association.ProgId `
            -DestinationValue $(if($null -ne $other){$other.ProgId}else{''}) -Confidence 'High' `
            -Recommendation 'Assign through Windows Settings.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Default-Application-Gaps.csv') -Rows $associationGaps.ToArray() -Columns @(
    'Identifier','SourceProgId','SourceApplicationName','DestinationProgId','DestinationApplicationName','Status'
)

# Services and scheduled tasks are powerful evidence for applications that do
# not register cleanly in Add/Remove Programs.
$sourceServices=@(Import-PCCsv (Join-Path $source 'Integration\Services.csv'))
$destinationServices=@(Import-PCCsv (Join-Path $destination 'Integration\Services.csv'))
$destinationServiceIndex=New-PCIndex -Rows $destinationServices -Key {param($row) $row.Name}
$missingServices=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.Services'){
    foreach($service in $sourceServices){
        if(-not $IncludeExpectedMachineDifferences -and $service.PathName -match '(?i)%WINDIR%\\(?:System32|SysWOW64)\\(?:svchost|lsass|services|spoolsv|SearchIndexer|MsMpEng)\.exe'){continue}
        if($destinationServiceIndex.ContainsKey($service.Name.ToLowerInvariant())){continue}
        [void]$missingServices.Add($service)
        $id=Add-PCDifference -Priority 2 -Category 'System integration' -Subcategory 'Service' -Item $service.Name `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue $service.PathName -DestinationValue '' `
            -Evidence ('Win32_Service; '+$service.StartMode) `
            -Recommendation 'Install/repair the owning application or driver; never recreate an unknown service from a command line alone.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Service' -Identity $service.Name -Status 'Missing' -SourceValue $service.PathName `
            -DestinationValue '' -Confidence 'High' -Recommendation 'Reinstall the owning application/driver.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Services.csv') -Rows $missingServices.ToArray() -Columns @(
    'Name','DisplayName','State','StartMode','StartName','PathName','Description'
)
$serviceConfigurationGaps=New-Object System.Collections.ArrayList
foreach($service in $sourceServices){
    if(-not $service.Name -or -not $destinationServiceIndex.ContainsKey($service.Name.ToLowerInvariant())){continue}
    $other=$destinationServiceIndex[$service.Name.ToLowerInvariant()]
    $sourceConfiguration=$service.StartMode+'|'+$service.StartName+'|'+$service.PathName
    $destinationConfiguration=$other.StartMode+'|'+$other.StartName+'|'+$other.PathName
    if($sourceConfiguration -eq $destinationConfiguration){continue}
    [void]$serviceConfigurationGaps.Add([pscustomobject]@{
        Name=$service.Name;DisplayName=$service.DisplayName
        SourceStartMode=$service.StartMode;DestinationStartMode=$other.StartMode
        SourceStartName=$service.StartName;DestinationStartName=$other.StartName
        SourcePathName=$service.PathName;DestinationPathName=$other.PathName
    })
    $id=Add-PCDifference -Priority 3 -Category 'System integration' -Subcategory 'Service configuration' -Item $service.Name `
        -Status 'Different' -Confidence 'High' -Risk 'High' -SourceValue $sourceConfiguration `
        -DestinationValue $destinationConfiguration -Evidence 'Win32_Service' `
        -Recommendation 'Confirm application/driver versions before changing service path, account, or start mode.' -MigrationGap $true
    Add-PCWindowsGap -Category 'Service configuration' -Identity $service.Name -Status 'Different' `
        -SourceValue $sourceConfiguration -DestinationValue $destinationConfiguration -Confidence 'High' `
        -Recommendation 'Confirm owning software/version and repair through its installer.' -DifferenceId $id
}
Export-PCCsv -Path (Join-Path $report 'Service-Configuration-Gaps.csv') -Rows $serviceConfigurationGaps.ToArray() -Columns @(
    'Name','DisplayName','SourceStartMode','DestinationStartMode','SourceStartName',
    'DestinationStartName','SourcePathName','DestinationPathName'
)

$sourceTasks=@(Import-PCCsv (Join-Path $source 'Integration\Scheduled-Tasks.csv')|Where-Object {$IncludeExpectedMachineDifferences -or $_.TaskPath -notlike '\Microsoft\*'})
$destinationTasks=@(Import-PCCsv (Join-Path $destination 'Integration\Scheduled-Tasks.csv'))
$destinationTaskIndex=New-PCIndex -Rows $destinationTasks -Key {param($row) ([string]$row.TaskPath+'|'+[string]$row.TaskName)}
$missingTasks=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.ScheduledTasks'){
    foreach($task in $sourceTasks){
        $identity=$task.TaskPath+'|'+$task.TaskName
        if($destinationTaskIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingTasks.Add($task)
        $id=Add-PCDifference -Priority 2 -Category 'System integration' -Subcategory 'Scheduled task' -Item $identity `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue $task.Actions -DestinationValue '' `
            -Evidence ('ScheduledTasks; '+$task.Triggers) `
            -Recommendation 'Reinstall the owning application or recreate only after reviewing principal, actions, triggers, and credentials.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Scheduled task' -Identity $identity -Status 'Missing' -SourceValue $task.Actions `
            -DestinationValue '' -Confidence 'High' -Recommendation 'Reinstall owner or recreate after security review.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Scheduled-Tasks.csv') -Rows $missingTasks.ToArray() -Columns @(
    'TaskPath','TaskName','State','Author','Description','UserId','RunLevel','Actions','Triggers','Enabled','Hidden'
)
$taskConfigurationGaps=New-Object System.Collections.ArrayList
foreach($task in $sourceTasks){
    $identity=$task.TaskPath+'|'+$task.TaskName
    if(-not $destinationTaskIndex.ContainsKey($identity.ToLowerInvariant())){continue}
    $other=$destinationTaskIndex[$identity.ToLowerInvariant()]
    $sourceConfiguration=$task.UserId+'|'+$task.RunLevel+'|'+$task.Actions+'|'+$task.Triggers+'|'+$task.Enabled
    $destinationConfiguration=$other.UserId+'|'+$other.RunLevel+'|'+$other.Actions+'|'+$other.Triggers+'|'+$other.Enabled
    if($sourceConfiguration -eq $destinationConfiguration){continue}
    [void]$taskConfigurationGaps.Add([pscustomobject]@{
        TaskPath=$task.TaskPath;TaskName=$task.TaskName
        SourceConfiguration=$sourceConfiguration;DestinationConfiguration=$destinationConfiguration
    })
    $id=Add-PCDifference -Priority 3 -Category 'System integration' -Subcategory 'Scheduled task configuration' -Item $identity `
        -Status 'Different' -Confidence 'High' -Risk 'High' -SourceValue $sourceConfiguration `
        -DestinationValue $destinationConfiguration -Evidence 'ScheduledTasks' `
        -Recommendation 'Review principal/actions/triggers and repair through the owning application or a deliberate task export/import.' `
        -MigrationGap $true
    Add-PCWindowsGap -Category 'Scheduled task configuration' -Identity $identity -Status 'Different' `
        -SourceValue $sourceConfiguration -DestinationValue $destinationConfiguration -Confidence 'High' `
        -Recommendation 'Review and repair through the owning application.' -DifferenceId $id
}
Export-PCCsv -Path (Join-Path $report 'Scheduled-Task-Configuration-Gaps.csv') -Rows $taskConfigurationGaps.ToArray() -Columns @(
    'TaskPath','TaskName','SourceConfiguration','DestinationConfiguration'
)

$sourceMachineState=@(Import-PCCsv (Join-Path $source 'Integration\Machine-Environment-Startup.csv'))
$destinationMachineState=@(Import-PCCsv (Join-Path $destination 'Integration\Machine-Environment-Startup.csv'))
$machineStateGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.MachineEnvironmentStartup'){
    foreach($pair in @(Compare-PCValueRows -SourceRows $sourceMachineState -DestinationRows $destinationMachineState)){
        $row=$pair.Source;$other=$pair.Destination;$identity=$row.StateId+'|'+$row.Name
        [void]$machineStateGaps.Add([pscustomobject]@{
            StateId=$row.StateId;Key=$row.Key;Name=$row.Name;Kind=$row.Kind;Status=$pair.Status
            SourceSHA256=$row.DataSHA256;DestinationSHA256=if($null -ne $other){$other.DataSHA256}else{''}
            SourcePreview=$row.Preview;DestinationPreview=if($null -ne $other){$other.Preview}else{''}
        })
        $id=Add-PCDifference -Priority 3 -Category 'System integration' -Subcategory $row.StateId -Item $identity `
            -Status $pair.Status -Confidence 'High' -Risk 'High' -SourceValue $row.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Evidence 'Machine registry value hash' `
            -Recommendation 'Restore only after validating the referenced application/path; machine PATH, Run, and RunOnce are never imported wholesale.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category $row.StateId -Identity $identity -Status $pair.Status -SourceValue $row.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Confidence 'High' `
            -Recommendation 'Validate the referenced application/path and repair selectively.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Machine-Environment-Startup-Gaps.csv') -Rows $machineStateGaps.ToArray() -Columns @(
    'StateId','Key','Name','Kind','Status','SourceSHA256','DestinationSHA256','SourcePreview','DestinationPreview'
)

$sourcePrinters=@(Import-PCCsv (Join-Path $source 'Integration\Printers.csv'))
$destinationPrinters=@(Import-PCCsv (Join-Path $destination 'Integration\Printers.csv'))
$destinationPrinterIndex=New-PCIndex -Rows $destinationPrinters -Key {param($row) $row.Name}
$missingPrinters=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.Printers'){
    foreach($printer in $sourcePrinters){
        if($destinationPrinterIndex.ContainsKey($printer.Name.ToLowerInvariant())){continue}
        [void]$missingPrinters.Add($printer)
        $id=Add-PCDifference -Priority 2 -Category 'Devices and network' -Subcategory 'Printer' -Item $printer.Name `
            -Status 'Missing' -Confidence 'High' -Risk 'Medium' -SourceValue ($printer.DriverName+' | '+$printer.PortName) `
            -DestinationValue '' -Evidence 'Printer/driver/port inventory' `
            -Recommendation 'Install the current destination-compatible driver, then add the printer/port or reconnect the shared printer.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Printer' -Identity $printer.Name -Status 'Missing' `
            -SourceValue ($printer.DriverName+' | '+$printer.PortName) -DestinationValue '' -Confidence 'High' `
            -Recommendation 'Install compatible driver and recreate/reconnect printer.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Printers.csv') -Rows $missingPrinters.ToArray() -Columns @(
    'Name','DriverName','PortName','Type','Shared','ShareName','Published','ComputerName','Default'
)
$printerConfigurationGaps=New-Object System.Collections.ArrayList
foreach($printer in $sourcePrinters){
    if(-not $printer.Name -or -not $destinationPrinterIndex.ContainsKey($printer.Name.ToLowerInvariant())){continue}
    $other=$destinationPrinterIndex[$printer.Name.ToLowerInvariant()]
    $sourceConfiguration=$printer.DriverName+'|'+$printer.PortName+'|'+$printer.Default
    $destinationConfiguration=$other.DriverName+'|'+$other.PortName+'|'+$other.Default
    if($sourceConfiguration -eq $destinationConfiguration){continue}
    [void]$printerConfigurationGaps.Add([pscustomobject]@{
        Name=$printer.Name;SourceDriver=$printer.DriverName;DestinationDriver=$other.DriverName
        SourcePort=$printer.PortName;DestinationPort=$other.PortName
        SourceDefault=$printer.Default;DestinationDefault=$other.Default
    })
    $id=Add-PCDifference -Priority 3 -Category 'Devices and network' -Subcategory 'Printer configuration' -Item $printer.Name `
        -Status 'Different' -Confidence 'High' -Risk 'Medium' -SourceValue $sourceConfiguration `
        -DestinationValue $destinationConfiguration -Evidence 'Printer inventory' `
        -Recommendation 'Review driver/port compatibility and set the intended default printer through Windows.' -MigrationGap $true
    Add-PCWindowsGap -Category 'Printer configuration' -Identity $printer.Name -Status 'Different' `
        -SourceValue $sourceConfiguration -DestinationValue $destinationConfiguration -Confidence 'High' `
        -Recommendation 'Review driver/port and default-printer intent.' -DifferenceId $id
}
Export-PCCsv -Path (Join-Path $report 'Printer-Configuration-Gaps.csv') -Rows $printerConfigurationGaps.ToArray() -Columns @(
    'Name','SourceDriver','DestinationDriver','SourcePort','DestinationPort','SourceDefault','DestinationDefault'
)

function Compare-PCSimpleMissing {
    param(
        [string]$Collector,[string]$SourceFile,[string]$DestinationFile,[scriptblock]$Key,
        [string]$Category,[string]$Subcategory,[string]$Recommendation,[string[]]$Columns,
        [string]$OutputFile,[int]$Priority=3,[string]$Risk='Medium',[bool]$MigrationGap=$true
    )
    $sourceRows=@(Import-PCCsv (Join-Path $source $SourceFile))
    $destinationRows=@(Import-PCCsv (Join-Path $destination $DestinationFile))
    $destinationIndex=New-PCIndex -Rows $destinationRows -Key $Key
    $missing=New-Object System.Collections.ArrayList
    if(Test-PCDestinationComplete $Collector){
        foreach($row in $sourceRows){
            $identity=[string](& $Key $row)
            if(-not $identity -or $destinationIndex.ContainsKey($identity.ToLowerInvariant())){continue}
            [void]$missing.Add($row)
            $id=Add-PCDifference -Priority $Priority -Category $Category -Subcategory $Subcategory -Item $identity `
                -Status 'Missing' -Confidence 'High' -Risk $Risk -SourceValue (($row|Out-String).Trim()) `
                -DestinationValue '' -Evidence $SourceFile -Recommendation $Recommendation -MigrationGap $MigrationGap
            Add-PCWindowsGap -Category $Subcategory -Identity $identity -Status 'Missing' -SourceValue '' `
                -DestinationValue '' -Confidence 'High' -Recommendation $Recommendation -DifferenceId $id
        }
    }
    Export-PCCsv -Path (Join-Path $report $OutputFile) -Rows $missing.ToArray() -Columns $Columns
    return $missing.ToArray()
}

$missingMappings=@(Compare-PCSimpleMissing -Collector 'Integration.NetworkMappingsVpnWifi' `
    -SourceFile 'Integration\Network-Mappings.csv' -DestinationFile 'Integration\Network-Mappings.csv' `
    -Key {param($row) ([string]$row.Type+'|'+[string]$row.LocalPath+'|'+[string]$row.RemotePath)} `
    -Category 'Devices and network' -Subcategory 'Network mapping' `
    -Recommendation 'Reconnect using the destination credential context; passwords are not captured.' `
    -Columns @('Type','LocalPath','RemotePath','Status','UserName') -OutputFile 'Missing-Network-Mappings.csv' -Priority 2)

$missingVpn=@(Compare-PCSimpleMissing -Collector 'Integration.NetworkMappingsVpnWifi' `
    -SourceFile 'Integration\VPN-Connections.csv' -DestinationFile 'Integration\VPN-Connections.csv' `
    -Key {param($row) ([string]$row.Scope+'|'+[string]$row.Name)} -Category 'Devices and network' -Subcategory 'VPN connection' `
    -Recommendation 'Recreate/import with the provider-supported method, then re-enter credentials/certificates and verify routing.' `
    -Columns @('Scope','Name','ServerAddress','TunnelType','AuthenticationMethod','EncryptionLevel','SplitTunneling','RememberCredential') `
    -OutputFile 'Missing-VPN-Connections.csv' -Priority 2 -Risk 'High')

$missingWifi=@(Compare-PCSimpleMissing -Collector 'Integration.NetworkMappingsVpnWifi' `
    -SourceFile 'Integration\WiFi-Profiles.csv' -DestinationFile 'Integration\WiFi-Profiles.csv' `
    -Key {param($row) $row.Name} -Category 'Devices and network' -Subcategory 'Wi-Fi profile' `
    -Recommendation 'Reconnect and enter the network key; credentials were intentionally not exported.' `
    -Columns @('Name','Scope','CredentialCaptured') -OutputFile 'Missing-WiFi-Profiles.csv' -Priority 3 -Risk 'Medium')

$sourceFeatures=@(Import-PCCsv (Join-Path $source 'Integration\Enabled-Optional-Features.csv'))
$destinationFeatures=@(Import-PCCsv (Join-Path $destination 'Integration\Enabled-Optional-Features.csv'))
$destinationFeatureIndex=New-PCIndex -Rows $destinationFeatures -Key {param($row) $row.FeatureName}
$missingFeatures=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.FeaturesCapabilities'){
    foreach($feature in $sourceFeatures){
        if($destinationFeatureIndex.ContainsKey($feature.FeatureName.ToLowerInvariant())){continue}
        [void]$missingFeatures.Add($feature)
        $recommendation='Review whether the feature is still required; enabling can add components and may require a restart.'
        $id=Add-PCDifference -Priority 3 -Category 'Windows components' -Subcategory 'Optional feature' -Item $feature.FeatureName `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue 'Enabled' -DestinationValue '' `
            -Evidence 'Get-WindowsOptionalFeature' -Recommendation $recommendation -MigrationGap $true `
            -Repairable $true -RepairMethod 'EnableFeature'
        Add-PCRepairAction -DifferenceId $id -Priority 3 -Category 'Windows optional feature' -Item $feature.FeatureName `
            -Method 'EnableFeature' -Risk 'High' -Confidence 'High' -RequiresAdmin $true -FeatureName $feature.FeatureName `
            -Precondition 'Review feature purpose and restart implications.' -Recommendation $recommendation
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Optional-Features.csv') -Rows $missingFeatures.ToArray() -Columns @('FeatureName','State')

$sourceCapabilities=@(Import-PCCsv (Join-Path $source 'Integration\Installed-Capabilities.csv'))
$destinationCapabilities=@(Import-PCCsv (Join-Path $destination 'Integration\Installed-Capabilities.csv'))
$destinationCapabilityIndex=New-PCIndex -Rows $destinationCapabilities -Key {param($row) $row.Name}
$missingCapabilities=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.FeaturesCapabilities'){
    foreach($capability in $sourceCapabilities){
        if($destinationCapabilityIndex.ContainsKey($capability.Name.ToLowerInvariant())){continue}
        [void]$missingCapabilities.Add($capability)
        $recommendation='Review whether the capability is required; installation may contact Windows Update.'
        $id=Add-PCDifference -Priority 3 -Category 'Windows components' -Subcategory 'Capability' -Item $capability.Name `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue 'Installed' -DestinationValue '' `
            -Evidence 'Get-WindowsCapability' -Recommendation $recommendation -MigrationGap $true `
            -Repairable $true -RepairMethod 'AddCapability'
        Add-PCRepairAction -DifferenceId $id -Priority 3 -Category 'Windows capability' -Item $capability.Name `
            -Method 'AddCapability' -Risk 'High' -Confidence 'High' -RequiresAdmin $true -CapabilityName $capability.Name `
            -Precondition 'Review capability purpose, source availability, and restart implications.' -Recommendation $recommendation
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Windows-Capabilities.csv') -Rows $missingCapabilities.ToArray() -Columns @('Name','State')

$sourceSystemFiles=@(Import-PCCsv (Join-Path $source 'Integration\System-Files.csv'))
$destinationSystemFiles=@(Import-PCCsv (Join-Path $destination 'Integration\System-Files.csv'))
$destinationSystemFileIndex=New-PCIndex -Rows $destinationSystemFiles -Key {param($row) $row.DestinationPath}
$systemFileGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.SystemFiles'){
    foreach($file in $sourceSystemFiles){
        $other=if($destinationSystemFileIndex.ContainsKey($file.DestinationPath.ToLowerInvariant())){$destinationSystemFileIndex[$file.DestinationPath.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($file.SHA256 -ne $other.SHA256){$status='Different'}
        if(-not $status){continue}
        [void]$systemFileGaps.Add([pscustomobject]@{
            DestinationPath=$file.DestinationPath;Status=$status;SourceSHA256=$file.SHA256
            DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            PayloadRelativePath=$file.PayloadRelativePath;Risk=$file.Risk
        })
        $repairable=([string]$file.PayloadRelativePath -ne '')
        $id=Add-PCDifference -Priority 2 -Category 'System integration' -Subcategory 'System configuration file' -Item $file.DestinationPath `
            -Status $status -Confidence 'High' -Risk 'High' -SourceValue $file.SHA256 `
            -DestinationValue $(if($null -ne $other){$other.SHA256}else{''}) -Evidence 'System-Files.csv' `
            -Recommendation 'Review the complete source and destination content; merge deliberate entries when appropriate instead of automatically discarding destination changes.' `
            -MigrationGap $true -Repairable $repairable -RepairMethod $(if($repairable){'CopyFile'}else{''})
        if($repairable){
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'System configuration file' -Item $file.DestinationPath `
                -Method 'CopyFile' -Risk 'High' -Confidence 'High' -RequiresAdmin $true `
                -SourceArtifact $file.PayloadRelativePath -DestinationTarget $file.DestinationPath `
                -ExpectedSourceSHA256 $file.SHA256 -Precondition 'Review/merge content; administrative access required.' `
                -Recommendation 'Restore only after confirming destination-specific entries are not needed.'
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'System-File-Gaps.csv') -Rows $systemFileGaps.ToArray() -Columns @(
    'DestinationPath','Status','SourceSHA256','DestinationSHA256','PayloadRelativePath','Risk'
)

$sourcePower=@(Import-PCCsv (Join-Path $source 'Integration\Active-Power-Scheme.csv')|Select-Object -First 1)
$destinationPower=@(Import-PCCsv (Join-Path $destination 'Integration\Active-Power-Scheme.csv')|Select-Object -First 1)
$powerGaps=New-Object System.Collections.ArrayList
if((Test-PCDestinationComplete 'Integration.PowerConfiguration') -and $sourcePower.Count){
    $other=if($destinationPower.Count){$destinationPower[0]}else{$null}
    $sourceIdentity=$sourcePower[0].SchemeGuid+'|'+$sourcePower[0].Name
    $destinationIdentity=if($null -ne $other){$other.SchemeGuid+'|'+$other.Name}else{''}
    if($sourceIdentity -ne $destinationIdentity){
        [void]$powerGaps.Add([pscustomobject]@{
            SourceSchemeGuid=$sourcePower[0].SchemeGuid;SourceName=$sourcePower[0].Name
            DestinationSchemeGuid=if($null -ne $other){$other.SchemeGuid}else{''}
            DestinationName=if($null -ne $other){$other.Name}else{''};Status='Different'
        })
        $id=Add-PCDifference -Priority 3 -Category 'Windows system state' -Subcategory 'Active power scheme' -Item 'Active power scheme' `
            -Status 'Different' -Confidence 'High' -Risk 'Medium' -SourceValue $sourceIdentity -DestinationValue $destinationIdentity `
            -Evidence 'powercfg /list active marker' `
            -Recommendation 'Review destination hardware and recreate/select the intended power plan with powercfg or Power Options.' `
            -MigrationGap $true
        Add-PCWindowsGap -Category 'Power configuration' -Identity 'Active power scheme' -Status 'Different' `
            -SourceValue $sourceIdentity -DestinationValue $destinationIdentity -Confidence 'High' `
            -Recommendation 'Review hardware compatibility and select/recreate the intended power plan.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Power-Configuration-Gaps.csv') -Rows $powerGaps.ToArray() -Columns @(
    'SourceSchemeGuid','SourceName','DestinationSchemeGuid','DestinationName','Status'
)

$sourceDrivers=@(Import-PCCsv (Join-Path $source 'Integration\PnP-Signed-Drivers.csv'))
$destinationDrivers=@(Import-PCCsv (Join-Path $destination 'Integration\PnP-Signed-Drivers.csv'))
$destinationDriverIndex=New-PCIndex -Rows $destinationDrivers -Key {param($row) ([string]$row.DeviceClass+'|'+[string]$row.DriverProviderName+'|'+[string]$row.DriverVersion)}
$missingDrivers=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.DriversDevices'){
    foreach($driver in $sourceDrivers){
        $identity=[string]$driver.DeviceClass+'|'+[string]$driver.DriverProviderName+'|'+[string]$driver.DriverVersion
        if($destinationDriverIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingDrivers.Add($driver)
        $id=Add-PCDifference -Priority 4 -Category 'Hardware context' -Subcategory 'Driver' -Item $driver.DeviceName `
            -Status 'Not matched' -Confidence 'Low' -Risk 'High' -SourceValue ($driver.DriverProviderName+' '+$driver.DriverVersion) `
            -DestinationValue '' -Evidence $driver.InfName `
            -Recommendation 'Install only if the destination has the corresponding hardware; prefer its current vendor/OEM driver.' `
            -MigrationGap $false
        Add-PCManualAction -Category 'Driver review' -Item $driver.DeviceName -Detected 'Source driver not matched' `
            -Action 'Confirm destination hardware, then use current OEM/vendor driver if needed.' -Reason $driver.InfName -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Unmatched-Source-Drivers.csv') -Rows $missingDrivers.ToArray() -Columns @(
    'DeviceName','DeviceClass','Manufacturer','DriverProviderName','DriverVersion','DriverDate','InfName','IsSigned','Signer','DeviceID'
)

$sourceCertificates=@(Import-PCCsv (Join-Path $source 'Integration\Certificates.csv')|Where-Object {$_.Scope -eq 'CurrentUser' -and $_.Store -eq 'My'})
$destinationCertificates=@(Import-PCCsv (Join-Path $destination 'Integration\Certificates.csv'))
$destinationCertificateIndex=New-PCIndex -Rows $destinationCertificates -Key {param($row) ([string]$row.Scope+'|'+[string]$row.Store+'|'+[string]$row.Thumbprint)}
$missingCertificates=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.Certificates'){
    foreach($certificate in $sourceCertificates){
        $identity=$certificate.Scope+'|'+$certificate.Store+'|'+$certificate.Thumbprint
        if($destinationCertificateIndex.ContainsKey($identity.ToLowerInvariant())){continue}
        [void]$missingCertificates.Add($certificate)
        $recommendation=if($certificate.HasPrivateKey -eq 'True'){
            'Export the required source certificate as a password-protected PFX and import it deliberately; verify private-key access.'
        }else{'Export/import only if this personal certificate is still required; verify the trust chain and purpose.'}
        $id=Add-PCDifference -Priority 1 -Category 'Security/manual' -Subcategory 'Personal certificate' -Item $certificate.Subject `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue $certificate.Thumbprint -DestinationValue '' `
            -Evidence ('HasPrivateKey='+$certificate.HasPrivateKey) -Recommendation $recommendation -MigrationGap $true
        Add-PCManualAction -Category 'Certificate' -Item $certificate.Subject -Detected 'Missing' -Action $recommendation `
            -Reason ('Thumbprint '+$certificate.Thumbprint) -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Personal-Certificates.csv') -Rows $missingCertificates.ToArray() -Columns @(
    'Scope','Store','Thumbprint','Subject','Issuer','NotBefore','NotAfter','HasPrivateKey','FriendlyName','EnhancedKeyUsage'
)

$missingOdbc=@(Compare-PCSimpleMissing -Collector 'Integration.ODBC' -SourceFile 'Integration\ODBC-DSNs.csv' `
    -DestinationFile 'Integration\ODBC-DSNs.csv' -Key {param($row) ([string]$row.DsnType+'|'+[string]$row.Platform+'|'+[string]$row.Name)} `
    -Category 'System integration' -Subcategory 'ODBC DSN' `
    -Recommendation 'Install the matching 32/64-bit driver, recreate the DSN, and re-enter credentials; review redacted attributes.' `
    -Columns @('Name','DsnType','Platform','DriverName','Attributes') -OutputFile 'Missing-ODBC-DSNs.csv' -Priority 2 -Risk 'High')

$sourceFirewall=@(Import-PCCsv (Join-Path $source 'Integration\Firewall-Rules.csv')|Where-Object {
    $IncludeExpectedMachineDifferences -or ($_.PolicyStoreSourceType -eq 'Local' -and -not $_.DisplayGroup)
})
$destinationFirewall=@(Import-PCCsv (Join-Path $destination 'Integration\Firewall-Rules.csv'))
$destinationFirewallIndex=New-PCIndex -Rows $destinationFirewall -Key {param($row) $row.Name}
$missingFirewall=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.Firewall'){
    foreach($rule in $sourceFirewall){
        if(-not $rule.Name -or $destinationFirewallIndex.ContainsKey($rule.Name.ToLowerInvariant())){continue}
        [void]$missingFirewall.Add($rule)
        $id=Add-PCDifference -Priority 2 -Category 'Security/manual' -Subcategory 'Firewall rule' -Item $rule.DisplayName `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue ($rule.Direction+' '+$rule.Action+' '+$rule.Profile) `
            -DestinationValue '' -Evidence $rule.Name `
            -Recommendation 'Use the dedicated backed-up firewall policy workflow or recreate only after reviewing program, ports, scope, direction, and profile.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Firewall' -Item $rule.DisplayName -Detected 'Missing' `
            -Action 'Use the dedicated firewall restore/verification workflow or recreate after review.' -Reason $rule.Name -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Firewall-Rules.csv') -Rows $missingFirewall.ToArray() -Columns @(
    'Name','DisplayName','DisplayGroup','Enabled','Direction','Action','Profile','PolicyStoreSourceType'
)

$missingShares=@(Compare-PCSimpleMissing -Collector 'Integration.SharesGroups' -SourceFile 'Integration\SMB-Shares.csv' `
    -DestinationFile 'Integration\SMB-Shares.csv' -Key {param($row) $row.Name} -Category 'System integration' -Subcategory 'SMB share' `
    -Recommendation 'Verify the destination path and ACLs, then recreate the share and explicitly review share permissions.' `
    -Columns @('Name','Path','Description','ScopeName','EncryptData','FolderEnumerationMode','Access','NtfsAclSddl') `
    -OutputFile 'Missing-SMB-Shares.csv' -Priority 2 -Risk 'High')

$sourceTools=@(Import-PCCsv (Join-Path $source 'Integration\Development\Tool-Commands.csv'))
$destinationTools=@(Import-PCCsv (Join-Path $destination 'Integration\Development\Tool-Commands.csv'))
$destinationToolIndex=New-PCIndex -Rows $destinationTools -Key {param($row) $row.Name}
$missingTools=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.DevelopmentTools'){
    foreach($tool in $sourceTools){
        if($destinationToolIndex.ContainsKey($tool.Name.ToLowerInvariant())){continue}
        [void]$missingTools.Add($tool)
        $id=Add-PCDifference -Priority 2 -Category 'Development environment' -Subcategory 'Tool command' -Item $tool.Name `
            -Status 'Missing' -Confidence 'High' -Risk 'Medium' -SourceValue ($tool.Version+' | '+$tool.Path) `
            -DestinationValue '' -Evidence 'Command discovery' `
            -Recommendation 'Install the matching architecture/version through its official installer or package manager, then restore settings/extensions.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Development tool' -Item $tool.Name -Detected 'Missing' `
            -Action 'Install from official source/package manager and verify PATH.' -Reason $tool.Path -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Development-Tools.csv') -Rows $missingTools.ToArray() -Columns @('Name','Path','Version','CommandType')

$sourceGit=@(Import-PCCsv (Join-Path $source 'Integration\Development\Git-Global-Config.csv'))
$destinationGit=@(Import-PCCsv (Join-Path $destination 'Integration\Development\Git-Global-Config.csv'))
$destinationGitIndex=New-PCIndex -Rows $destinationGit -Key {param($row) $row.Key}
$gitGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.DevelopmentTools'){
    foreach($setting in $sourceGit){
        $other=if($destinationGitIndex.ContainsKey($setting.Key.ToLowerInvariant())){$destinationGitIndex[$setting.Key.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($setting.ValueSHA256 -ne $other.ValueSHA256){$status='Different'}
        if(-not $status){continue}
        [void]$gitGaps.Add([pscustomobject]@{
            Key=$setting.Key;Status=$status;SourcePreview=$setting.Preview
            DestinationPreview=if($null -ne $other){$other.Preview}else{''}
            SourceSHA256=$setting.ValueSHA256;DestinationSHA256=if($null -ne $other){$other.ValueSHA256}else{''}
        })
        $id=Add-PCDifference -Priority 3 -Category 'Development environment' -Subcategory 'Git global config' -Item $setting.Key `
            -Status $status -Confidence 'High' -Risk 'Medium' -SourceValue $setting.Preview `
            -DestinationValue $(if($null -ne $other){$other.Preview}else{''}) -Evidence 'Hashed git global config value' `
            -Recommendation 'Review and recreate with git config --global; credential/token/URL values are redacted and should be reauthorized.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Git configuration' -Item $setting.Key -Detected $status `
            -Action 'Review and recreate with git config --global.' -Reason 'Values may contain machine paths or credentials.' -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Git-Global-Config-Gaps.csv') -Rows $gitGaps.ToArray() -Columns @(
    'Key','Status','SourcePreview','DestinationPreview','SourceSHA256','DestinationSHA256'
)

$sourceVisualStudio=@(Read-PCJson (Join-Path $source 'Integration\Development\Visual-Studio-Instances.json'))
$destinationVisualStudio=@(Read-PCJson (Join-Path $destination 'Integration\Development\Visual-Studio-Instances.json'))
$destinationVsIndex=New-PCIndex -Rows $destinationVisualStudio -Key {param($row) [string](Get-PCProperty $row 'productId' '')}
$visualStudioGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.DevelopmentTools'){
    foreach($instance in $sourceVisualStudio){
        if($null -eq $instance){continue}
        $productId=[string](Get-PCProperty $instance 'productId' '')
        if(-not $productId){continue}
        $sourceVersion=[string](Get-PCProperty $instance 'installationVersion' '')
        $other=if($destinationVsIndex.ContainsKey($productId.ToLowerInvariant())){$destinationVsIndex[$productId.ToLowerInvariant()]}else{$null}
        $destinationVersion=if($null -ne $other){[string](Get-PCProperty $other 'installationVersion' '')}else{''}
        $status=if($null -eq $other){'Missing'}elseif($sourceVersion -ne $destinationVersion){'Different version'}else{''}
        if(-not $status){continue}
        [void]$visualStudioGaps.Add([pscustomobject]@{
            ProductId=$productId;DisplayName=[string](Get-PCProperty $instance 'displayName' '')
            Status=$status;SourceVersion=$sourceVersion;DestinationVersion=$destinationVersion
        })
        $id=Add-PCDifference -Priority 2 -Category 'Development environment' -Subcategory 'Visual Studio instance' -Item $productId `
            -Status $status -Confidence 'High' -Risk 'Medium' -SourceValue $sourceVersion -DestinationValue $destinationVersion `
            -Evidence 'vswhere instance inventory' `
            -Recommendation 'Use Visual Studio Installer to match required edition/workloads/components; avoid copying installation directories.' `
            -MigrationGap ($status -eq 'Missing')
        Add-PCManualAction -Category 'Visual Studio' -Item $productId -Detected $status `
            -Action 'Use Visual Studio Installer to review edition, workloads, and components.' -Reason ($sourceVersion+' -> '+$destinationVersion) -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Visual-Studio-Instance-Gaps.csv') -Rows $visualStudioGaps.ToArray() -Columns @(
    'ProductId','DisplayName','Status','SourceVersion','DestinationVersion'
)

function Compare-PCTextLineSet {
    param([string]$RelativePath,[string]$Category,[string]$Subcategory,[int]$Priority=3)
    if(-not (Test-PCDestinationComplete 'Integration.DevelopmentTools')){return @()}
    $sourceFile=Join-Path $source $RelativePath;$destinationFile=Join-Path $destination $RelativePath
    if(-not [IO.File]::Exists($sourceFile)){return @()}
    $sourceLines=@([IO.File]::ReadAllLines($sourceFile)|ForEach-Object {$_.Trim()}|Where-Object {$_})
    $destinationLines=if([IO.File]::Exists($destinationFile)){@([IO.File]::ReadAllLines($destinationFile)|ForEach-Object {$_.Trim()}|Where-Object {$_})}else{@()}
    $destinationIndex=@{};foreach($line in $destinationLines){$destinationIndex[$line.ToLowerInvariant()]=$true}
    $missing=New-Object System.Collections.ArrayList
    foreach($line in $sourceLines){
        if($destinationIndex.ContainsKey($line.ToLowerInvariant())){continue}
        [void]$missing.Add([pscustomobject]@{Item=$line})
        $id=Add-PCDifference -Priority $Priority -Category $Category -Subcategory $Subcategory -Item $line `
            -Status 'Missing' -Confidence 'Medium' -Risk 'Medium' -SourceValue $line -DestinationValue '' `
            -Evidence $RelativePath -Recommendation 'Reinstall/recreate through the owning tool after reviewing version compatibility.' `
            -MigrationGap $true
        Add-PCManualAction -Category $Subcategory -Item $line -Detected 'Missing' `
            -Action 'Reinstall/recreate through the owning tool.' -Reason $RelativePath -DifferenceId $id
    }
    return $missing.ToArray()
}

$sourceVsCodeFile=Join-Path $source 'Integration\Development\VSCode-Extensions.txt'
$destinationVsCodeFile=Join-Path $destination 'Integration\Development\VSCode-Extensions.txt'
$sourceVsCodeLines=if([IO.File]::Exists($sourceVsCodeFile)){@([IO.File]::ReadAllLines($sourceVsCodeFile)|Where-Object {$_.Trim()})}else{@()}
$destinationVsCodeLines=if([IO.File]::Exists($destinationVsCodeFile)){@([IO.File]::ReadAllLines($destinationVsCodeFile)|Where-Object {$_.Trim()})}else{@()}
$destinationVsCodeIndex=@{}
foreach($line in $destinationVsCodeLines){
    $parts=$line.Trim() -split '@',2
    $destinationVsCodeIndex[$parts[0].ToLowerInvariant()]=if($parts.Count -gt 1){$parts[1]}else{''}
}
$missingVsCode=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'Integration.DevelopmentTools'){
    foreach($line in $sourceVsCodeLines){
        $parts=$line.Trim() -split '@',2;$extensionId=$parts[0];$sourceVersion=if($parts.Count -gt 1){$parts[1]}else{''}
        if(-not $extensionId){continue}
        if(-not $destinationVsCodeIndex.ContainsKey($extensionId.ToLowerInvariant())){
            [void]$missingVsCode.Add([pscustomobject]@{ExtensionId=$extensionId;SourceVersion=$sourceVersion;DestinationVersion='';Status='Missing'})
            $id=Add-PCDifference -Priority 3 -Category 'Development environment' -Subcategory 'VS Code extension' -Item $extensionId `
                -Status 'Missing' -Confidence 'High' -Risk 'Medium' -SourceValue $sourceVersion -DestinationValue '' `
                -Evidence 'code --list-extensions --show-versions' `
                -Recommendation 'Install the extension by exact ID through VS Code, then review its trust and settings.' -MigrationGap $true
            Add-PCManualAction -Category 'VS Code extension' -Item $extensionId -Detected 'Missing' `
                -Action 'Install by exact extension ID through VS Code.' -Reason $sourceVersion -DifferenceId $id
        }elseif($sourceVersion -and $destinationVsCodeIndex[$extensionId.ToLowerInvariant()] -ne $sourceVersion){
            [void]$missingVsCode.Add([pscustomobject]@{
                ExtensionId=$extensionId;SourceVersion=$sourceVersion
                DestinationVersion=$destinationVsCodeIndex[$extensionId.ToLowerInvariant()];Status='Different version'
            })
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'VSCode-Extension-Gaps.csv') -Rows $missingVsCode.ToArray() -Columns @('ExtensionId','SourceVersion','DestinationVersion','Status')
$missingDotNetSdks=@(Compare-PCTextLineSet -RelativePath 'Integration\Development\DotNet-SDKs.txt' -Category 'Development environment' -Subcategory '.NET SDK' -Priority 2)
Export-PCCsv -Path (Join-Path $report 'Missing-DotNet-SDKs.csv') -Rows $missingDotNetSdks -Columns @('Item')
$missingDotNetRuntimes=@(Compare-PCTextLineSet -RelativePath 'Integration\Development\DotNet-Runtimes.txt' -Category 'Development environment' -Subcategory '.NET runtime' -Priority 2)
Export-PCCsv -Path (Join-Path $report 'Missing-DotNet-Runtimes.csv') -Rows $missingDotNetRuntimes -Columns @('Item')
$missingWsl=@(Compare-PCTextLineSet -RelativePath 'Integration\Development\WSL-Distributions.txt' -Category 'Development environment' -Subcategory 'WSL distribution' -Priority 2)
Export-PCCsv -Path (Join-Path $report 'Missing-WSL-Distributions.csv') -Rows $missingWsl -Columns @('Item')

# Secure/manual items are deliberately carried forward even when source and
# destination appear similar, because presence is not proof that secrets work.
foreach($item in @(Import-PCCsv (Join-Path $source 'SecureManual\Manual-Secure-Checklist.csv'))){
    Add-PCManualAction -Category 'Security/manual' -Item $item.Item -Detected $item.Detected -Action $item.Action -Reason $item.Reason
}
$sourceCredentialTargets=@(Import-PCCsv (Join-Path $source 'SecureManual\Credential-Targets.csv'))
$destinationCredentialTargets=@(Import-PCCsv (Join-Path $destination 'SecureManual\Credential-Targets.csv'))
$destinationCredentialIndex=New-PCIndex -Rows $destinationCredentialTargets -Key {param($row) $row.Target}
if(Test-PCDestinationComplete 'SecureManual.CredentialTargets'){
    foreach($credential in $sourceCredentialTargets){
        if($destinationCredentialIndex.ContainsKey($credential.Target.ToLowerInvariant())){continue}
        $id=Add-PCDifference -Priority 2 -Category 'Security/manual' -Subcategory 'Credential target' -Item $credential.Target `
            -Status 'Missing' -Confidence 'Medium' -Risk 'High' -SourceValue $credential.UserName -DestinationValue '' `
            -Evidence 'cmdkey target metadata; no secret captured' `
            -Recommendation 'Re-enter through the owning application/service; do not attempt DPAPI registry/file transplantation.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Credential target' -Item $credential.Target -Detected 'Missing' `
            -Action 'Re-enter through the owning application/service.' -Reason 'Secret was not captured.' -DifferenceId $id
    }
}
$sourceSecureFiles=@(Import-PCCsv (Join-Path $source 'SecureManual\Secure-File-Candidates.csv'))
$destinationSecureFiles=@(Import-PCCsv (Join-Path $destination 'SecureManual\Secure-File-Candidates.csv'))
$destinationSecureIndex=New-PCIndex -Rows $destinationSecureFiles -Key {param($row) $row.Path}
$missingSecureFiles=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'SecureManual.SecureFileCandidates'){
    foreach($file in $sourceSecureFiles){
        if($destinationSecureIndex.ContainsKey($file.Path.ToLowerInvariant())){continue}
        [void]$missingSecureFiles.Add($file)
        $id=Add-PCDifference -Priority 1 -Category 'Security/manual' -Subcategory 'Secure file candidate' -Item $file.Path `
            -Status 'Missing' -Confidence 'High' -Risk 'High' -SourceValue $file.SHA256 -DestinationValue '' `
            -Evidence $file.Extension -Recommendation 'Transfer through a secure, verified path and test before retiring the source; this tool never copies it.' `
            -MigrationGap $true
        Add-PCManualAction -Category 'Secure file' -Item $file.Path -Detected 'Missing' `
            -Action 'Securely transfer, preserve passwords/recovery data, and verify usability.' -Reason $file.Extension -DifferenceId $id
    }
}
Export-PCCsv -Path (Join-Path $report 'Missing-Secure-File-Candidates.csv') -Rows $missingSecureFiles.ToArray() -Columns @(
    'Path','Extension','Length','LastWriteTimeUtc','SHA256','Copied'
)

# K-Lite/MPC-HC remains a regression case, but uses the same generic plan model.
$sourceKLite=@(Import-PCCsv (Join-Path $source 'ApplicationState\KLite-Files.csv'))
$destinationKLite=@(Import-PCCsv (Join-Path $destination 'ApplicationState\KLite-Files.csv'))
$destinationKLiteIndex=New-PCIndex -Rows $destinationKLite -Key {param($row) ([string]$row.RootToken+'|'+[string]$row.RootRelativePath+'|'+[string]$row.RelativePath)}
$kliteGaps=New-Object System.Collections.ArrayList
if(Test-PCDestinationComplete 'ApplicationState.KLiteRegression'){
    foreach($file in $sourceKLite){
        $identity=$file.RootToken+'|'+$file.RootRelativePath+'|'+$file.RelativePath
        $other=if($destinationKLiteIndex.ContainsKey($identity.ToLowerInvariant())){$destinationKLiteIndex[$identity.ToLowerInvariant()]}else{$null}
        $status=''
        if($null -eq $other){$status='Missing'}elseif($file.SHA256 -and $other.SHA256 -and $file.SHA256 -ne $other.SHA256){$status='Different'}
        if(-not $status){continue}
        [void]$kliteGaps.Add([pscustomobject]@{
            RootToken=$file.RootToken;RootRelativePath=$file.RootRelativePath;RelativePath=$file.RelativePath
            Status=$status;SourceSHA256=$file.SHA256;DestinationSHA256=if($null -ne $other){$other.SHA256}else{''}
            Sensitive=$file.Sensitive;PayloadRelativePath=$file.PayloadRelativePath
        })
        $repairable=($file.Sensitive -ne 'True' -and [string]$file.PayloadRelativePath)
        $machinePath=($file.RootToken -in @('PROGRAMDATA','PROGRAMFILES','PROGRAMFILESX86','WINDIR'))
        $kliteRisk=if($machinePath){'High'}else{'Medium'}
        $id=Add-PCDifference -Priority 2 -Category 'Application settings' -Subcategory 'K-Lite/MPC-HC regression' -Item $identity `
            -Status $status -Confidence 'High' -Risk $kliteRisk -SourceValue $file.SHA256 `
            -DestinationValue $(if($null -ne $other){$other.SHA256}else{''}) -Evidence 'Dedicated regression inventory' `
            -Recommendation 'Install K-Lite first, close MPC-HC/codec tools, then restore only reviewed compatible settings.' `
            -MigrationGap $true -Repairable $repairable -RepairMethod $(if($repairable){'CopyFile'}else{''})
        Add-PCSettingsGap -Scope 'K-Lite/MPC-HC file' -Identity $identity -Status $status -Classification 'Configuration' `
            -SourceSHA256 $file.SHA256 -DestinationSHA256 $(if($null -ne $other){$other.SHA256}else{''}) `
            -Sensitive $file.Sensitive -Payload $file.PayloadRelativePath `
            -Recommendation 'Install K-Lite first, close its tools, and restore only reviewed compatible settings.' -DifferenceId $id
        if($repairable){
            $target='%'+$file.RootToken+'%\'+$file.RootRelativePath
            if($file.RelativePath){$target+='\'+$file.RelativePath}
            Add-PCRepairAction -DifferenceId $id -Priority 2 -Category 'K-Lite/MPC-HC settings' -Item $identity `
                -Method 'CopyFile' -Risk $kliteRisk -Confidence 'High' -RequiresAdmin $machinePath -SourceArtifact $file.PayloadRelativePath `
                -DestinationTarget $target -ExpectedSourceSHA256 $file.SHA256 `
                -Precondition 'K-Lite installed; MPC-HC, Codec Tweak Tool, and Icaros closed.' `
                -Recommendation 'Restore reviewed compatible file setting.'
        }
    }
}
Export-PCCsv -Path (Join-Path $report 'KLite-MPCHC-File-Gaps.csv') -Rows $kliteGaps.ToArray() -Columns @(
    'RootToken','RootRelativePath','RelativePath','Status','SourceSHA256','DestinationSHA256','Sensitive','PayloadRelativePath'
)

# Named examples are regression tests only; the reports above are the scope.
function Test-PCAppPresent {
    param([string]$CapturePath,[string]$Pattern)
    $desktop=@(Import-PCCsv (Join-Path $CapturePath 'Applications\Desktop-Applications.csv'))
    $appx=@(Import-PCCsv (Join-Path $CapturePath 'Applications\Appx-CurrentUser.csv'))
    $start=@(Import-PCCsv (Join-Path $CapturePath 'Applications\Start-Apps.csv'))
    $winget=@(Get-PCWingetPackages $CapturePath)
    $values=New-Object System.Collections.ArrayList
    foreach($item in $desktop){[void]$values.Add([string]$item.DisplayName)}
    foreach($item in $appx){[void]$values.Add(([string]$item.Name+' '+[string]$item.PackageFamilyName))}
    foreach($item in $start){[void]$values.Add(([string]$item.Name+' '+[string]$item.AppID))}
    foreach($item in $winget){[void]$values.Add([string]$item.PackageIdentifier)}
    foreach($value in $values){
        if([string]$value -match $Pattern){return $true}
    }
    return $false
}

$regression=New-Object System.Collections.ArrayList
$sourceRegressionCatalog=@(Import-PCCsv (Join-Path $source 'Applications\Regression-Package-Catalog.csv'))
$sourceRegressionCatalogIndex=New-PCIndex -Rows $sourceRegressionCatalog -Key {param($row) $row.Name}
foreach($definition in @(
    @{Name='2fast installation';CatalogName='2fast';Pattern='(?i)2fast|9P9D81GLH89Q';Required=@('Applications.AppxCurrentUser','Applications.StartApps')},
    @{Name='Keeper installation';CatalogName='Keeper';Pattern='(?i)keeper|9N040SRQ0S8C';Required=@('Applications.AppxCurrentUser','Applications.StartApps')},
    @{Name='K-Lite/MPC-HC installation';CatalogName='K-Lite Codec Pack Full';Pattern='(?i)K[\s-]?Lite|MPC[\s-]?HC|CodecGuide\.K-Lite';Required=@('Applications.DesktopRegistrations','Applications.StartApps')}
)){
    $onSource=Test-PCAppPresent -CapturePath $source -Pattern $definition.Pattern
    $onDestination=Test-PCAppPresent -CapturePath $destination -Pattern $definition.Pattern
    $destinationEvidenceComplete=$true
    foreach($collector in $definition.Required){if(-not (Test-PCDestinationComplete $collector)){$destinationEvidenceComplete=$false}}
    $status=if(-not $onSource){'NotApplicable'}elseif($onDestination){'Pass'}elseif(-not $destinationEvidenceComplete){'Unknown'}else{'Fail'}
    [void]$regression.Add([pscustomobject]@{
        Check=$definition.Name;SourceDetected=$onSource;DestinationDetected=$onDestination
        Status=$status;Evidence='AppX + desktop + StartApps + winget'
    })
    if($status -eq 'Fail' -and $sourceRegressionCatalogIndex.ContainsKey($definition.CatalogName.ToLowerInvariant())){
        $mapping=$sourceRegressionCatalogIndex[$definition.CatalogName.ToLowerInvariant()]
        $alreadyPlanned=@($repairPlan|Where-Object {$_.Method -eq 'WingetInstall' -and $_.PackageId -eq $mapping.PackageIdentifier}).Count -gt 0
        if(-not $alreadyPlanned){
            $recommendation='Install using the exact regression package mapping retained from the supplied v2.7 source, then recapture before restoring settings.'
            $id=Add-PCDifference -Priority 1 -Category 'Applications' -Subcategory 'Verified regression package mapping' `
                -Item $mapping.Name -Status 'Missing' -Confidence 'High' -Risk 'Low' `
                -SourceValue $mapping.PackageIdentifier -DestinationValue '' -Evidence $mapping.DetectedEvidence `
                -Recommendation $recommendation -MigrationGap $true -Repairable $true -RepairMethod 'WingetInstall'
            Add-PCApplicationGap -Name $mapping.Name -Identity $mapping.PackageIdentifier -EvidenceType 'RegressionPackageCatalog' `
                -SourceVersion '' -Publisher '' -Confidence 'High' -InstallMethod 'WingetInstall' `
                -PackageId $mapping.PackageIdentifier -PackageSource $mapping.SourceName -Recommendation $recommendation -DifferenceId $id
            Add-PCRepairAction -DifferenceId $id -Priority 1 -Category 'Applications' -Item $mapping.Name `
                -Method 'WingetInstall' -Risk 'Low' -Confidence 'High' -PackageId $mapping.PackageIdentifier `
                -PackageSource $mapping.SourceName -Precondition 'Review exact package ID and publisher; network access required.' `
                -Recommendation $recommendation
        }
    }
}
$consoleComparable=Test-PCDestinationComplete 'UserState.RegistryValues'
$consoleGapCount=@($userStateDifferences|Where-Object {$_.StateId -eq 'Console'}).Count
$sourceConsoleCount=@($sourceUserState|Where-Object {$_.StateId -eq 'Console'}).Count
$consoleStatus=if(-not $consoleComparable){'Unknown'}elseif($sourceConsoleCount -eq 0){'NotApplicable'}elseif($consoleGapCount -eq 0){'Pass'}else{'Fail'}
[void]$regression.Add([pscustomobject]@{
    Check='CMD/PowerShell Console Host layout';SourceDetected=($sourceConsoleCount -gt 0)
    DestinationDetected=($consoleGapCount -eq 0);Status=$consoleStatus
    Evidence='HKCU\Console value-level comparison'
})
$sourceShortTime=[string](Get-PCProperty $sourceRegional 'ShortTimePattern' '')
$sourceLongTime=[string](Get-PCProperty $sourceRegional 'LongTimePattern' '')
$destinationShortTime=[string](Get-PCProperty $destinationRegional 'ShortTimePattern' '')
$destinationLongTime=[string](Get-PCProperty $destinationRegional 'LongTimePattern' '')
$source24=($sourceShortTime -match 'H' -and $sourceLongTime -match 'H')
$destination24=($destinationShortTime -match 'H' -and $destinationLongTime -match 'H')
$clockStatus=if(-not (Test-PCDestinationComplete 'UserState.RegionalLanguage')){'Unknown'}elseif(-not $source24){'NotApplicable'}elseif($destination24){'Pass'}else{'Fail'}
[void]$regression.Add([pscustomobject]@{
    Check='24-hour clock';SourceDetected=$source24;DestinationDetected=$destination24
    Status=$clockStatus;Evidence=($sourceShortTime+' / '+$destinationShortTime)
})
$broadStatus=if(-not $fileInventoryComparable -or -not (Test-PCDestinationComplete 'ApplicationState.Files') -or -not (Test-PCDestinationComplete 'ApplicationState.RegistryCurrentUser')){'Unknown'}else{'Pass'}
[void]$regression.Add([pscustomobject]@{
    Check='Broad file/value settings audit operational';SourceDetected='True'
    DestinationDetected=($broadStatus -eq 'Pass');Status=$broadStatus
    Evidence='ApplicationState.Files + RegistryCurrentUser collector coverage'
})
$shortcutComparisonStatus=if(-not (Test-PCDestinationComplete 'Applications.Shortcuts')){'Unknown'}else{'Pass'}
[void]$regression.Add([pscustomobject]@{
    Check='Shortcut semantic comparison operational';SourceDetected=($sourceShortcuts.Count -gt 0)
    DestinationDetected=($shortcutComparisonStatus -eq 'Pass');Status=$shortcutComparisonStatus
    Evidence=($shortcutGaps.Count.ToString()+' functional gap(s); '+$shortcutEquivalentBinaryDifferences.Count.ToString()+' binary-only difference(s) suppressed from repair')
})
Export-PCCsv -Path (Join-Path $report 'Regression-Checks.csv') -Rows $regression.ToArray() -Columns @(
    'Check','SourceDetected','DestinationDetected','Status','Evidence'
)

$orderedDifferences=@($differences|Sort-Object Priority,Category,Subcategory,Item)
$likelyGaps=@($orderedDifferences|Where-Object {
    [string]$_.MigrationGap -eq 'True' -and $_.Status -in @('Missing','Different','Different candidate count','Not matched')
})
$orderedApplications=@($applicationGaps|Sort-Object Confidence,Name,EvidenceType)
$orderedSettings=@($settingsGaps|Sort-Object Scope,Identity)
$orderedWindows=@($windowsGaps|Sort-Object Category,Identity)
$orderedManual=@($manualActions|Sort-Object Category,Item -Unique)
$orderedPlan=@($repairPlan|Sort-Object Priority,Risk,Category,Item)

Export-PCCsv -Path (Join-Path $report 'All-Differences.csv') -Rows $orderedDifferences -Columns @(
    'DifferenceId','Priority','Category','Subcategory','Item','Status','Confidence','Risk',
    'SourceValue','DestinationValue','Evidence','Recommendation','MigrationGap','Repairable','RepairMethod'
)
Export-PCCsv -Path (Join-Path $report 'Likely-Migration-Gaps.csv') -Rows $likelyGaps -Columns @(
    'DifferenceId','Priority','Category','Subcategory','Item','Status','Confidence','Risk',
    'SourceValue','DestinationValue','Evidence','Recommendation','Repairable','RepairMethod'
)
Export-PCCsv -Path (Join-Path $report 'Missing-Applications.csv') -Rows $orderedApplications -Columns @(
    'Name','Identity','EvidenceType','SourceVersion','Publisher','Confidence','InstallMethod',
    'PackageId','PackageSource','Recommendation','DifferenceId'
)
Export-PCCsv -Path (Join-Path $report 'Application-Settings-Gaps.csv') -Rows $orderedSettings -Columns @(
    'Scope','Identity','Status','Classification','SourceSHA256','DestinationSHA256',
    'Sensitive','PayloadRelativePath','Recommendation','DifferenceId'
)
Export-PCCsv -Path (Join-Path $report 'Windows-State-Gaps.csv') -Rows $orderedWindows -Columns @(
    'Category','Identity','Status','SourceValue','DestinationValue','Confidence','Recommendation','DifferenceId'
)
Export-PCCsv -Path (Join-Path $report 'Manual-Secure-Actions.csv') -Rows $orderedManual -Columns @(
    'Category','Item','Detected','Action','Reason','DifferenceId'
)
Export-PCCsv -Path (Join-Path $report 'Repair-Plan.csv') -Rows $orderedPlan -Columns @(
    'ActionId','Approved','DifferenceId','Priority','Category','Item','Method','Risk','Confidence',
    'RequiresAdmin','SourceArtifact','DestinationTarget','PackageId','PackageSource','FeatureName',
    'CapabilityName','ExpectedSourceSHA256','Precondition','Recommendation'
)

$categoryCounts=@($likelyGaps|Group-Object Category|Sort-Object Count -Descending|ForEach-Object {
    [pscustomobject]@{Category=$_.Name;Count=$_.Count}
})
$failedRegression=@($regression|Where-Object {$_.Status -eq 'Fail'}).Count
$unknownCoverage=@($coverageRows|Where-Object {-not $_.ComparableForMissing}).Count
$summaryLines=@(
    'PCMigration Reconciliation v4.0.0 comparison',
    ('Generated:             '+(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')),
    ('Source:                '+[string]$sourceMeta.ComputerName+' / '+[string]$sourceMeta.UserName),
    ('Destination:           '+[string]$destinationMeta.ComputerName+' / '+[string]$destinationMeta.UserName),
    ('Windows builds:        '+[string]$sourceMeta.WindowsBuild+' -> '+[string]$destinationMeta.WindowsBuild),
    ('All differences:       '+$orderedDifferences.Count),
    ('Likely migration gaps: '+$likelyGaps.Count),
    ('Application evidence:  '+$orderedApplications.Count),
    ('Settings gaps:         '+$orderedSettings.Count),
    ('Windows-state gaps:    '+$orderedWindows.Count),
    ('Manual/secure actions: '+$orderedManual.Count),
    ('Repair-plan actions:   '+$orderedPlan.Count),
    ('Shortcut binary-only:  '+$shortcutEquivalentBinaryDifferences.Count),
    ('Coverage not complete: '+$unknownCoverage),
    ('Policy exclusions:     '+$policyExclusions.Count),
    ('Regression failures:   '+$failedRegression),
    '',
    'Open Summary.html, then Likely-Migration-Gaps.csv and Missing-Applications.csv.',
    'Repair-Plan.csv defaults every Approved field to NO. Review and approve individual',
    'rows only; Invoke-PCMigrationRepair-v4.0.0.ps1 remains preview-only without -Apply.'
)
Write-PCText -Path (Join-Path $report 'Summary.txt') -Text ($summaryLines -join [Environment]::NewLine)

$css=@'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937;background:#f8fafc}
h1,h2{color:#0f3b5d} .cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:white;border:1px solid #cbd5e1;border-radius:8px;padding:12px 16px;min-width:150px}
.n{font-size:26px;font-weight:700;color:#0f609b}.warn{color:#9a3412;font-weight:600}
table{border-collapse:collapse;width:100%;background:white;margin-bottom:24px;font-size:12px}
th,td{border:1px solid #cbd5e1;padding:6px;text-align:left;vertical-align:top}
th{background:#dbeafe}tr:nth-child(even){background:#f8fafc}
</style>
'@
$cards='<div class="cards">'+
    '<div class="card"><div class="n">'+$likelyGaps.Count+'</div>likely gaps</div>'+
    '<div class="card"><div class="n">'+$orderedApplications.Count+'</div>application evidence</div>'+
    '<div class="card"><div class="n">'+$orderedSettings.Count+'</div>settings gaps</div>'+
    '<div class="card"><div class="n">'+$orderedPlan.Count+'</div>reviewable repairs</div>'+
    '<div class="card"><div class="n">'+$unknownCoverage+'</div>coverage warnings</div>'+
    '<div class="card"><div class="n">'+$shortcutEquivalentBinaryDifferences.Count+'</div>shortcut binary-only differences</div></div>'
$coverageHtml=@($coverageRows|Where-Object {-not $_.ComparableForMissing}|Select-Object Collector,SourceStatus,DestinationStatus,DestinationMessage|ConvertTo-Html -Fragment)
$policyHtml=@($policyExclusions|Select-Object Side,Category,Scope,Path,Reason|ConvertTo-Html -Fragment)
$categoryHtml=@($categoryCounts|ConvertTo-Html -Fragment)
$regressionHtml=@($regression|ConvertTo-Html -Fragment)
$topHtml=@($likelyGaps|Select-Object -First 250 Priority,Category,Subcategory,Item,Status,Confidence,Risk,Recommendation|ConvertTo-Html -Fragment)
$body=@(
    '<h1>PCMigration Reconciliation v4.0.0</h1>',
    '<p>Source <b>'+[string]$sourceMeta.ComputerName+'</b> to destination <b>'+[string]$destinationMeta.ComputerName+'</b>.</p>',
    $cards,
    '<h2>Regression checks</h2>',$regressionHtml,
    '<h2>Incomplete comparison coverage</h2>',$coverageHtml,
    '<h2>Intentional policy exclusions</h2>',$policyHtml,
    '<h2>Likely gaps by category</h2>',$categoryHtml,
    '<h2>Highest-priority gaps (first 250)</h2>',$topHtml,
    '<p class="warn">Repair-Plan.csv is inert until individual Approved values are changed from NO and the repair script is run with -Apply.</p>'
)
$bodyText=(@($body|ForEach-Object {[string]$_}) -join [Environment]::NewLine)
$html=(ConvertTo-Html -Title 'PCMigration Reconciliation v4.0.0' -Head $css -Body $bodyText) -join [Environment]::NewLine
Write-PCText -Path (Join-Path $report 'Summary.html') -Text $html
Write-PCJson -Path (Join-Path $report 'Comparison-Meta.json') -Value ([ordered]@{
    SchemaVersion='4.0';GeneratedAt=(Get-Date).ToString('o')
    SourceCapture=$source;DestinationCapture=$destination
    SourceComputer=[string]$sourceMeta.ComputerName;DestinationComputer=[string]$destinationMeta.ComputerName
    DifferenceCount=$orderedDifferences.Count;LikelyGapCount=$likelyGaps.Count
    RepairActionCount=$orderedPlan.Count;CoverageWarningCount=$unknownCoverage
}) -Depth 5

Write-Host ''
Write-Host ($summaryLines -join [Environment]::NewLine)
Write-Host ''
Write-Host "Comparison complete: $report" -ForegroundColor Green

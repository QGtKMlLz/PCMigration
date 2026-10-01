#requires -version 5.1
# Pure logic/encoding regression checks; no shell, policy, or registry changes.
[CmdletBinding()]
param([string]$PackagePath=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
. (Join-Path $PackagePath 'StartMenu.Common-v4.1.0.ps1')
$child='test-guid$start.tilegrid$windows.data.curatedtilecollection.tilecollection'
$other='destination-guid$start.tilegrid$windows.data.curatedtilecollection.tilecollection'
$root='HKEY_CURRENT_USER\'+$script:PCStartCloudSub+'\'+$child
$dest='HKEY_CURRENT_USER\'+$script:PCStartCloudSub+'\'+$other
$text="Windows Registry Editor Version 5.00`r`n`r`n[$root]`r`n`"Marker`"=`"$root`"`r`n`r`n[$root\Current]`r`n`"Data`"=hex:01,02`r`n"
$mapped=Convert-PCStartReg $text $child $other
if(-not $mapped.Contains('['+$dest+'\Current]')){throw 'Regression: child registry headers were not mapped.'}
if(-not $mapped.Contains('"Marker"="'+$root+'"')){throw 'Regression: mapping modified value data.'}
$same=Convert-PCStartReg $text $child $child
if($same -cne $text){throw 'Regression: identical source/destination identity is not accepted unchanged.'}
foreach($bad in @(
    ($text+"`r`n[HKEY_LOCAL_MACHINE\SOFTWARE\Injected]`r`n`"Data`"=dword:00000001"),
    ($text+"`r`n[-$root]"),
    ($text+"`r`n[$root-sibling]"),
    $text.Replace($root,'HKEY_CURRENT_USER\Software\Outside')
)){
    $rejected=$false
    try{[void](Convert-PCStartReg $bad $child $other)}catch{$rejected=$true}
    if(-not $rejected){throw 'Regression: an unauthorized registry header was accepted.'}
}
if(Test-PCStartChild ($child+'\Injected')){throw 'Regression: a child name containing a path separator was accepted.'}

$directory=Join-Path $env:TEMP ('PCMigration-StartLogic-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
try{
    $xml=Join-Path $directory 'Encoding.xml'
    $micro=[string][char]0x00B5
    $data='<?xml version="1.0" encoding="UTF-8"?><Root Path="'+$micro+'Torrent" />'
    [IO.File]::WriteAllText($xml,$data,(New-Object Text.UTF8Encoding($false)))
    $doc=Read-PCStartXml $xml
    if($doc.DocumentElement.GetAttribute('Path') -cne ($micro+'Torrent')){throw 'Regression: BOM-less UTF-8 XML damaged the micro sign.'}
    [IO.File]::WriteAllText($xml,'<!DOCTYPE Root [<!ENTITY injected "bad">]><Root>&injected;</Root>')
    $rejected=$false
    try{[void](Read-PCStartXml $xml)}catch{$rejected=$true}
    if(-not $rejected){throw 'Regression: XML DTDs were accepted.'}

    Write-PCStartJson (Join-Path $directory 'Meta.json') @{SchemaVersion='StartMenu-1.0'}
    Write-PCStartManifest $directory
    [void](Assert-PCStartManifest $directory)
    [IO.File]::AppendAllText($xml,'tampered')
    $rejected=$false
    try{[void](Assert-PCStartManifest $directory)}catch{$rejected=$true}
    if(-not $rejected){throw 'Regression: a changed capture file passed hash validation.'}
}finally{Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue}
Write-Host 'Start-menu logic checks passed: scope, mapping, same identity, UTF-8 XML, DTD rejection, and tamper detection.'

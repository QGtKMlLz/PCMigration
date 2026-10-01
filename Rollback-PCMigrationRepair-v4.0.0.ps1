#requires -version 5.1
<#
PCMigration Registry Safety Backup v4.0.0
=========================================
Purpose
-------
Native registry safety-backup implementation used by PCMigration-Reconciliation.

Design:
  * FAST broad forensic backup using native binary registry hive snapshots.
  * KEEP granular targeted .reg exports for known remediation/restore targets.
  * NEVER restore HKCU\Software or HKLM\SOFTWARE wholesale to the destination.
  * Broad .hiv files are backup/forensic sources only.
  * Sequential native saves; do not parallelize them.
  * PowerShell 5.1 compatible; no external modules; no temp files.

This file is dot-sourced by Capture-PCMigrationState-v4.0.0.ps1. The snapshot
stage runs only when -CaptureRegistrySafetyBackup is explicitly supplied.

SECURITY / RESTORE RULE
-----------------------
The .hiv snapshots created here MUST NOT be automatically restored wholesale on another PC.
Load them under a temporary key and selectively inspect/extract only approved application state.

Example manual forensic mount:
    reg.exe load HKU\PCMoverBackup "<path>\HKCU-Software.hiv"
    # inspect/export approved branch
    reg.exe unload HKU\PCMoverBackup
#>

Set-StrictMode -Version 2.0

function Invoke-NativeReg {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments
    )

    $reg = Join-Path $env:SystemRoot 'System32\reg.exe'
    $p = Start-Process -FilePath $reg `
        -ArgumentList $Arguments `
        -Wait -PassThru -WindowStyle Hidden

    return [int]$p.ExitCode
}

function Test-NativeRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key
    )

    $rc = Invoke-NativeReg -Arguments @('query', $Key)
    return ($rc -eq 0)
}

function Save-RegistrySubtreeBinary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    if ($parent) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction Stop
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rc = Invoke-NativeReg -Arguments @('save', $Key, $Destination, '/y')
    $sw.Stop()

    $exists = Test-Path -LiteralPath $Destination -PathType Leaf
    $length = if ($exists) { (Get-Item -LiteralPath $Destination).Length } else { 0L }

    [pscustomobject][ordered]@{
        Type         = 'BinaryHiveSnapshot'
        Key          = $Key
        File         = $Destination
        ExitCode     = $rc
        Succeeded    = ($rc -eq 0 -and $exists -and $length -gt 0)
        Bytes        = [int64]$length
        DurationMs   = [int64]$sw.ElapsedMilliseconds
        RestoreScope = 'FORENSIC_ONLY_SELECTIVE_EXTRACTION'
    }
}

function Export-RegistryKeyTargeted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    if ($parent) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    # Missing keys are normal in migration captures.
    if (-not (Test-NativeRegistryKey -Key $Key)) {
        return [pscustomobject][ordered]@{
            Type         = 'TargetedRegExport'
            Key          = $Key
            File         = $Destination
            Present      = $false
            ExitCode     = $null
            Succeeded    = $false
            Bytes        = 0L
            DurationMs   = 0L
            RestoreScope = 'TARGETED'
        }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rc = Invoke-NativeReg -Arguments @('export', $Key, $Destination, '/y')
    $sw.Stop()

    $exists = Test-Path -LiteralPath $Destination -PathType Leaf
    $length = if ($exists) { (Get-Item -LiteralPath $Destination).Length } else { 0L }

    [pscustomobject][ordered]@{
        Type         = 'TargetedRegExport'
        Key          = $Key
        File         = $Destination
        Present      = $true
        ExitCode     = $rc
        Succeeded    = ($rc -eq 0 -and $exists)
        Bytes        = [int64]$length
        DurationMs   = [int64]$sw.ElapsedMilliseconds
        RestoreScope = 'TARGETED'
    }
}

function Get-PCMigrationDefaultTargetedRegistryKeys {
    [CmdletBinding()]
    param()

    # Deliberately small. These remain human-readable / individually restorable.
    # Deliberately separate from repair payloads: these are safety exports.
    @(
        [pscustomobject]@{
            Name = 'Taskband'
            Key  = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband'
        }
        [pscustomobject]@{
            Name = 'CloudStore'
            Key  = 'HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore'
        }
        [pscustomobject]@{
            Name = 'StartPage'
            Key  = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage'
        }
        [pscustomobject]@{
            Name = 'StartPage2'
            Key  = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2'
        }
    )
}

function Invoke-PCMigrationRegistryBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupRoot,

        [Parameter()]
        [object[]]$TargetedKeys,

        [Parameter()]
        [switch]$SkipBinarySnapshots,

        [Parameter()]
        [switch]$SkipTargetedExports
    )

    $registryRoot = Join-Path $BackupRoot 'Registry'
    $rawRoot      = Join-Path $registryRoot 'Raw'
    $targetRoot   = Join-Path $registryRoot 'Targeted'
    $diagRoot     = Join-Path $BackupRoot 'Diagnostics'

    [IO.Directory]::CreateDirectory($registryRoot) | Out-Null
    [IO.Directory]::CreateDirectory($rawRoot)      | Out-Null
    [IO.Directory]::CreateDirectory($targetRoot)   | Out-Null
    [IO.Directory]::CreateDirectory($diagRoot)     | Out-Null

    $results = New-Object System.Collections.ArrayList

    if (-not $SkipBinarySnapshots) {
        Write-Host '    Registry forensic snapshot: HKCU\Software' -ForegroundColor DarkGray
        $r = Save-RegistrySubtreeBinary `
            -Key 'HKCU\Software' `
            -Destination (Join-Path $rawRoot 'HKCU-Software.hiv')
        [void]$results.Add($r)

        if (-not $r.Succeeded) {
            throw "Native registry snapshot failed for HKCU\Software (exit code $($r.ExitCode))."
        }

        # Intentionally sequential. Parallel reg-save operations only contend for
        # registry/I/O resources and provide no consistency advantage.
        Write-Host '    Registry forensic snapshot: HKLM\SOFTWARE' -ForegroundColor DarkGray
        $r = Save-RegistrySubtreeBinary `
            -Key 'HKLM\SOFTWARE' `
            -Destination (Join-Path $rawRoot 'HKLM-Software.hiv')
        [void]$results.Add($r)

        if (-not $r.Succeeded) {
            throw "Native registry snapshot failed for HKLM\SOFTWARE (exit code $($r.ExitCode))."
        }
    }

    if (-not $SkipTargetedExports) {
        if ($null -eq $TargetedKeys -or @($TargetedKeys).Count -eq 0) {
            $TargetedKeys = @(Get-PCMigrationDefaultTargetedRegistryKeys)
        }

        foreach ($item in @($TargetedKeys)) {
            $name = [string]$item.Name
            $key  = [string]$item.Key

            if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($key)) {
                continue
            }

            $safeName = ($name -replace '[^\w\-.]+', '_').Trim('_')
            if ([string]::IsNullOrWhiteSpace($safeName)) {
                $safeName = 'RegistryKey'
            }

            $dest = Join-Path $targetRoot ($safeName + '.reg')
            Write-Host ("    Targeted registry export: {0}" -f $key) -ForegroundColor DarkGray
            $r = Export-RegistryKeyTargeted -Key $key -Destination $dest
            [void]$results.Add($r)

            if ($r.Present -and -not $r.Succeeded) {
                throw "Targeted registry export failed for $key (exit code $($r.ExitCode))."
            }
        }
    }

    $manifest = Join-Path $diagRoot 'Registry-Backup-Manifest.csv'
    @($results) |
        Export-Csv -LiteralPath $manifest -NoTypeInformation -Encoding UTF8

    $policy = [pscustomobject][ordered]@{
        SchemaVersion              = '4.0'
        ToolVersion                = '4.0.0'
        CapturedAt                 = (Get-Date).ToString('o')
        BinarySnapshotPolicy       = 'FORENSIC_ONLY_SELECTIVE_EXTRACTION'
        BroadAutomaticRestore      = $false
        BroadSnapshotsSequential   = $true
        HKCUSoftwareSnapshot       = (-not $SkipBinarySnapshots)
        HKLMSoftwareSnapshot       = (-not $SkipBinarySnapshots)
        TargetedRegExports         = (-not $SkipTargetedExports)
        DestinationWritePerformed  = $false
        Notes = @(
            'Binary .hiv snapshots are comprehensive safety archives only.'
            'Never automatically restore HKCU\Software or HKLM\SOFTWARE wholesale to a destination PC.'
            'Use the comparison/policy logic to select individual application keys/values.'
            'Targeted .reg exports remain available for known narrow remediation targets.'
            'HKLM\SOFTWARE already contains WOW6432Node; no separate 32-bit broad snapshot is required.'
        )
    }

    $policyPath = Join-Path $registryRoot 'Registry-Backup-Policy.json'
    [IO.File]::WriteAllText(
        $policyPath,
        ($policy | ConvertTo-Json -Depth 8),
        (New-Object Text.UTF8Encoding($false))
    )

    return @($results)
}

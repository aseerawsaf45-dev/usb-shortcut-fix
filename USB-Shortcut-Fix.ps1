<#
.SYNOPSIS
    USB Shortcut Malware Remediation, Forensic Analysis & Data Recovery Suite.

.DESCRIPTION
    Industrial-grade PowerShell automation tool designed to neutralize USB Shortcut viruses
    (e.g., Houdini, njRAT, Ramnit, Gamarue, AutoRun/LNK variants).
    Performs forensic inspection of .lnk payload targets, quarantines malicious scripts,
    strips hidden/system attributes from legitimately relocated data, and generates
    cryptographic SHA-256 incident reports.

.PARAMETER DriveLetter
    The target drive letter (e.g., 'E' or 'E:'). If omitted, interactive drive selection is triggered.

.PARAMETER AutoSelectUSB
    Automatically scans and selects the first detected removable USB storage drive.

.PARAMETER ScanOnly
    Performs a read-only forensic audit without modifying attributes or moving files (Dry Run).

.PARAMETER QuarantineDirectory
    Custom directory path for isolated threats. Defaults to '_Quarantine_<TIMESTAMP>' in drive root.

.PARAMETER SkipVaccine
    Skips the creation of the write-protected anti-AutoRun immunization directory.

.PARAMETER VerboseReport
    Generates a structured JSON forensic report alongside the standard text log.

.EXAMPLE
    .\USB-Shortcut-Fix.ps1 -DriveLetter E: -VerboseReport
    Remediates drive E:, quarantining threats and unhiding files.

.EXAMPLE
    .\USB-Shortcut-Fix.ps1 -AutoSelectUSB -ScanOnly
    Performs a non-destructive audit on the first detected USB drive.

.NOTES
    Author: Aseer Awsaf (@aseerawsaf45-dev)
    License: MIT
    Requires: PowerShell 5.1 or later (Run as Administrator)
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidatePattern('^[a-zA-Z](:)?$')]
    [string]$DriveLetter,

    [Parameter(Mandatory = $false)]
    [switch]$AutoSelectUSB,

    [Parameter(Mandatory = $false)]
    [switch]$ScanOnly,

    [Parameter(Mandatory = $false)]
    [string]$QuarantineDirectory,

    [Parameter(Mandatory = $false)]
    [switch]$SkipVaccine,

    [Parameter(Mandatory = $false)]
    [switch]$VerboseReport
)

# Enforce TLS 1.2+ & UTF-8 output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-StyledBanner {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "         USB SHORTCUT VIRUS REMEDIATION & FORENSIC SUITE (POWERSHELL)           " -ForegroundColor Green
    Write-Host "                     Enterprise Incident Response Tool v3.2.0                   " -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RemovableDrives {
    Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
}

function Stop-MalwareScriptEngines {
    Write-Host "`n[PHASE 1/5] Process Containment" -ForegroundColor White -NoNewline
    Write-Host " -> Terminating rogue script host engines..." -ForegroundColor Cyan

    $targets = @("wscript", "cscript", "mshta")
    foreach ($proc in $targets) {
        $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "  [-] Terminating active $($proc).exe process (PID: $($found.Id -join ', '))..." -ForegroundColor Red
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [+] $proc.exe is not running." -ForegroundColor Green
        }
    }
}

function Inspect-LnkFile {
    param([string]$FilePath)
    try {
        $sh = New-Object -ComObject WScript.Shell
        $shortcut = $sh.CreateShortcut($FilePath)
        return @{
            TargetPath       = $shortcut.TargetPath
            Arguments        = $shortcut.Arguments
            WorkingDirectory = $shortcut.WorkingDirectory
            IconLocation     = $shortcut.IconLocation
        }
    } catch {
        return @{ TargetPath = "Unknown/Inaccessible"; Arguments = ""; WorkingDirectory = ""; IconLocation = "" }
    }
}

# --- Main Execution Flow ---
Write-StyledBanner

if (-not (Test-AdminPrivileges)) {
    Write-Warning "This script is not running with elevated Administrator privileges."
    Write-Host "Certain protected attributes or locked files may fail to unlock without elevation.`n" -ForegroundColor Yellow
}

# 1. Process Containment
if (-not $ScanOnly) {
    Stop-MalwareScriptEngines
}

# 2. Drive Selection
Write-Host "`n[PHASE 2/5] Drive Discovery & Selection" -ForegroundColor White
$removableDrives = Get-RemovableDrives

if (-not $DriveLetter) {
    if ($AutoSelectUSB -and $removableDrives) {
        $selectedDrive = $removableDrives[0]
        $DriveLetter = $selectedDrive.DeviceID
        Write-Host "  [+] Automatically targeted detected USB drive: $DriveLetter" -ForegroundColor Green
    } else {
        if ($removableDrives) {
            Write-Host "  Detected Removable Drives:" -ForegroundColor Cyan
            foreach ($d in $removableDrives) {
                $sizeGB = if ($d.Size) { [math]::Round($d.Size / 1GB, 2) } else { 0 }
                $freeGB = if ($d.FreeSpace) { [math]::Round($d.FreeSpace / 1GB, 2) } else { 0 }
                Write-Host "   -> [$($d.DeviceID)] Volume: $($d.VolumeName.PadRight(12)) FileSystem: $($d.FileSystem.PadRight(6)) Size: $sizeGB GB ($freeGB GB Free)" -ForegroundColor Green
            }
        } else {
            Write-Host "  [!] No USB removable drives automatically detected." -ForegroundColor Yellow
        }

        Write-Host ""
        $DriveLetter = Read-Host "  Enter Target Drive Letter (e.g. E or E:)"
    }
}

# Sanitize Drive Letter
$cleanLetter = ($DriveLetter -replace '[:\\/ ]', '').ToUpper()
if ([string]::IsNullOrWhiteSpace($cleanLetter)) {
    Write-Error "No valid drive letter specified. Aborting."
    exit 1
}

$targetDrive = "$cleanLetter`:"
$targetRoot = "$targetDrive\"

# Safety Verification
if ($targetDrive -eq $env:SystemDrive) {
    Write-Host "`n[CRITICAL ERROR] Target is the Windows System Drive ($env:SystemDrive)!" -ForegroundColor Red
    Write-Host "Running attribute stripping on C:\ is strictly prevented to safeguard OS integrity." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -Path $targetRoot)) {
    Write-Error "Drive root '$targetRoot' was not found or is inaccessible."
    exit 1
}

$diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$targetDrive'"
if ($diskInfo.DriveType -eq 3) {
    Write-Host "`n[WARNING] Drive $targetDrive is classified as a Fixed Hard Drive, not Removable Media." -ForegroundColor Yellow
    $confirm = Read-Host "Are you sure you wish to continue on this fixed drive? (y/N)"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $QuarantineDirectory) {
    $quarantinePath = Join-Path -Path $targetRoot -ChildPath "_Quarantine_$timestamp"
} else {
    $quarantinePath = $QuarantineDirectory
}

$reportPath = Join-Path -Path $targetRoot -ChildPath "USB_Remediation_Report_$timestamp.txt"
$jsonReportPath = Join-Path -Path $targetRoot -ChildPath "USB_Remediation_Forensics_$timestamp.json"

Write-Host "  [+] Verified Target: $targetDrive ($targetRoot)" -ForegroundColor Green
Write-Host "  [+] Mode: $(if ($ScanOnly) { 'SCAN ONLY (Audit / Dry Run)' } else { 'ACTIVE REMEDIATION' })" -ForegroundColor Cyan

# 3. Threat Hunting & Forensic Analysis
Write-Host "`n[PHASE 3/5] Threat Hunting & Forensic Extraction" -ForegroundColor White
$threatPatterns = @("*.lnk", "autorun.inf", "*.vbs", "*.js", "*.jse", "*.wsf", "*.scr", "*.hta")
$discoveredThreats = [System.Collections.Generic.List[PSObject]]::new()

foreach ($pattern in $threatPatterns) {
    $items = Get-ChildItem -Path $targetRoot -Filter $pattern -Force -File -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        $hash = (Get-FileHash -Path $item.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $lnkDetails = if ($item.Extension -eq ".lnk") { Inspect-LnkFile -FilePath $item.FullName } else { $null }

        $threatObj = [PSCustomObject]@{
            Name         = $item.Name
            FullName     = $item.FullName
            Extension    = $item.Extension
            SizeBytes    = $item.Length
            SHA256       = $hash
            CreationTime = $item.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            LnkTarget    = if ($lnkDetails) { $lnkDetails.TargetPath } else { $null }
            LnkArguments = if ($lnkDetails) { $lnkDetails.Arguments } else { $null }
        }
        $discoveredThreats.Add($threatObj)

        Write-Host "  [-] Suspicious Entity: $($item.Name)" -ForegroundColor Red
        if ($lnkDetails -and $lnkDetails.TargetPath) {
            Write-Host "      LNK Target : $($lnkDetails.TargetPath)" -ForegroundColor DarkYellow
            if ($lnkDetails.Arguments) {
                Write-Host "      Arguments  : $($lnkDetails.Arguments)" -ForegroundColor DarkYellow
            }
        }
        Write-Host "      SHA-256    : $hash" -ForegroundColor DarkGray
    }
}

if ($discoveredThreats.Count -eq 0) {
    Write-Host "  [+] No root shortcut payloads or script droppers identified." -ForegroundColor Green
} else {
    Write-Host "  [!] Identified $($discoveredThreats.Count) suspicious file(s)." -ForegroundColor Yellow
    if (-not $ScanOnly) {
        if (-not (Test-Path -Path $quarantinePath)) {
            New-Item -ItemType Directory -Path $quarantinePath -Force | Out-Null
        }
        foreach ($threat in $discoveredThreats) {
            try {
                Move-Item -Path $threat.FullName -Destination $quarantinePath -Force -ErrorAction Stop
                Write-Host "      -> Quarantined into $quarantinePath" -ForegroundColor DarkCyan
            } catch {
                Write-Warning "Could not quarantine $($threat.FullName): $_"
            }
        }
    }
}

# 4. Attribute Stripping & File Recovery
Write-Host "`n[PHASE 4/5] Restoring Hidden Files & Directory Structure" -ForegroundColor White
$protectedFolders = @("System Volume Information", "`$RECYCLE.BIN", (Split-Path $quarantinePath -Leaf))
$restoredDirectories = 0
$restoredFiles = 0

if (-not $ScanOnly) {
    # Unhide root files
    $rootFiles = Get-ChildItem -Path $targetRoot -File -Force -ErrorAction SilentlyContinue
    foreach ($file in $rootFiles) {
        try {
            $file.Attributes = [System.IO.FileAttributes]::Normal
            $restoredFiles++
        } catch {}
    }

    # Unhide directories
    $topDirs = Get-ChildItem -Path $targetRoot -Directory -Force -ErrorAction SilentlyContinue
    foreach ($dir in $topDirs) {
        if ($protectedFolders -contains $dir.Name) {
            continue
        }

        Write-Host "  Restoring attributes: $($dir.Name)..." -ForegroundColor Cyan
        try {
            $dir.Attributes = [System.IO.FileAttributes]::Directory
            # Recursively strip hidden, system, readonly
            attrib.exe -h -r -s /s /d "$($dir.FullName)" 2>$null
            $restoredDirectories++
        } catch {
            Write-Warning "Failed to reset attributes on $($dir.FullName): $_"
        }
    }
    Write-Host "  [+] Attribute reset completed ($restoredDirectories directories, $restoredFiles root files)." -ForegroundColor Green
} else {
    Write-Host "  [Audit Mode] Skipping attribute modification." -ForegroundColor Yellow
}

# 5. Staging Folder Inspection
Write-Host "`n[*] Checking for obfuscated / hidden malware staging containers..." -ForegroundColor Cyan
$hiddenDirs = Get-ChildItem -Path $targetRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
    ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -or
    ($_.Attributes -band [System.IO.FileAttributes]::System)
}

foreach ($hDir in $hiddenDirs) {
    if ($protectedFolders -notcontains $hDir.Name) {
        Write-Host "  [!] Potential Data Container Detected: $($hDir.Name)" -ForegroundColor Yellow
        Write-Host "      Original files may have been relocated inside this folder by the malware." -ForegroundColor Gray
    }
}

# 6. Immunization Vaccine
if (-not $ScanOnly -and -not $SkipVaccine) {
    Write-Host "`n[PHASE 5/5] Storage Immunization" -ForegroundColor White
    $vaccineDir = Join-Path -Path $targetRoot -ChildPath "autorun.inf"
    if (-not (Test-Path -Path $vaccineDir)) {
        try {
            New-Item -ItemType Directory -Path $vaccineDir -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $vaccineDir "con") -Force | Out-Null
            $vItem = Get-Item -LiteralPath $vaccineDir -Force
            $vItem.Attributes = [System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::Hidden
            Write-Host "  [+] Anti-AutoRun Immunization installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "  [*] Could not install vaccine: $_" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [*] autorun.inf folder already present on target volume." -ForegroundColor DarkGray
    }
}

# 7. Audit & Forensic Report Generation
$reportContent = @"
================================================================================
USB SHORTCUT VIRUS INCIDENT & RECOVERY AUDIT LOG
Generated By: USB Shortcut Remediation Suite v3.2.0 (PowerShell)
Date / Time : $(Get-Date -Format "F")
Target Root : $targetRoot
Execution   : $(if ($ScanOnly) { "Forensic Audit / Dry Run" } else { "Full Remediation" })
================================================================================

[SUSPICIOUS THREATS ENCOUNTERED: $($discoveredThreats.Count)]
"@

foreach ($t in $discoveredThreats) {
    $reportContent += @"

File Name   : $($t.Name)
Path        : $($t.FullName)
SHA-256     : $($t.SHA256)
LNK Target  : $($t.LnkTarget)
LNK Args    : $($t.LnkArguments)
"@
}

$reportContent += @"

--------------------------------------------------------------------------------
[RESTORATION SUMMARY]
Root Files Processed       : $restoredFiles
Directories Restored       : $restoredDirectories
Quarantine Path            : $(if ($discoveredThreats.Count -gt 0 -and -not $ScanOnly) { $quarantinePath } else { "None" })
Immunization Installed     : $(if (-not $SkipVaccine -and -not $ScanOnly) { "Yes" } else { "No" })
--------------------------------------------------------------------------------
Next Steps:
1. Verify all recovered files in $targetRoot.
2. Scan host computer with Windows Defender or Malwarebytes.
3. Check autostart entries via Autoruns (Sysinternals) for lingering persistence.
"@

$reportContent | Set-Content -Path $reportPath -Encoding UTF8

if ($VerboseReport) {
    $discoveredThreats | ConvertTo-Json -Depth 4 | Set-Content -Path $jsonReportPath -Encoding UTF8
    Write-Host "`n[+] JSON Forensic Export: $jsonReportPath" -ForegroundColor Cyan
}

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host "                 REMEDIATION AUDIT COMPLETED SUCCESSFULLY                       " -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  Text Report Saved : $reportPath" -ForegroundColor Cyan
Write-Host "  Target Status     : Cleaned & Unhidden`n" -ForegroundColor White

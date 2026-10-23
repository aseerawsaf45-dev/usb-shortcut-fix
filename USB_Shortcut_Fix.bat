@echo off
:: ============================================================================
::  USB Shortcut Virus Cleaner & Data Recovery Tool (Enterprise Edition)
::  Version: 3.2.0 | Architecture: Windows Batch / Hybrid PowerShell
::  Description: Detects & purges shortcut malware (.lnk, .vbs, .js, .scr),
::               restores hidden files/directories, and vaccinates USB storage.
:: ============================================================================

setlocal EnableExtensions EnableDelayedExpansion

:: --- 0. Fast CLI Flags (CI / Scripting Support) ---
if /I "%~1"=="--version" (
    echo USB Shortcut Fix v3.2.0
    exit /b 0
)
if /I "%~1"=="--help" (
    echo USB Shortcut Fix v3.2.0
    echo Usage: USB_Shortcut_Fix.bat [DriveLetter]
    echo Example: USB_Shortcut_Fix.bat E:
    exit /b 0
)

:: --- 1. Terminal Configuration & Visual Theme ---
chcp 65001 >nul 2>&1
title USB Shortcut Virus Cleaner ^& Recovery Suite v3.2.0

:: Define ANSI Escape Sequences for Modern Styling
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "CLR_RESET=%ESC%[0m"
set "CLR_BOLD=%ESC%[1m"
set "CLR_RED=%ESC%[91m"
set "CLR_GREEN=%ESC%[92m"
set "CLR_YELLOW=%ESC%[93m"
set "CLR_BLUE=%ESC%[94m"
set "CLR_MAGENTA=%ESC%[95m"
set "CLR_CYAN=%ESC%[96m"
set "CLR_WHITE=%ESC%[97m"
set "CLR_BG_RED=%ESC%[41m%CLR_WHITE%"
set "CLR_BG_BLUE=%ESC%[44m%CLR_WHITE%"

:: --- 2. UAC Self-Elevation (Administrator Privileges) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo %CLR_YELLOW%[!] Administrator privileges required for low-level attribute restoration.%CLR_RESET%
    echo %CLR_CYAN%[*] Requesting User Account Control [UAC] elevation...%CLR_RESET%
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

:: --- 3. Header & Banner Display ---
cls
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_BOLD%%CLR_GREEN%            USB SHORTCUT VIRUS CLEANER ^& DATA RECOVERY SUITE%CLR_RESET%
echo %CLR_WHITE%                     Enterprise Edition  v3.2.0%CLR_RESET%
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_WHITE%  Target Scope:%CLR_RESET%
echo   - Purge malicious shortcut pointers (*.lnk) in root
echo   - Quarantine script droppers (*.vbs, *.js, *.jse, *.wsf, *.scr, *.hta)
echo   - Neutralize rogue AutoRun vectors (autorun.inf)
echo   - Terminate active background script engines (wscript, cscript, mshta)
echo   - Restore hidden user files/directories (System/Hidden/Read-Only strip)
echo   - Immunize storage against autorun re-infection (Vaccine)
echo %CLR_CYAN%--------------------------------------------------------------------------------%CLR_RESET%
echo.

:: --- 4. Process Containment (Kill Rogue Script Hosts) ---
echo %CLR_BOLD%[PHASE 1/5] Process Containment%CLR_RESET%
echo %CLR_CYAN%[*] Checking and suspending rogue Windows script host engines...%CLR_RESET%
taskkill /f /im wscript.exe >nul 2>&1 && (echo   %CLR_RED%[-] Terminated running wscript.exe payload process.%CLR_RESET%) || (echo   %CLR_GREEN%[+] wscript.exe not running.%CLR_RESET%)
taskkill /f /im cscript.exe >nul 2>&1 && (echo   %CLR_RED%[-] Terminated running cscript.exe payload process.%CLR_RESET%) || (echo   %CLR_GREEN%[+] cscript.exe not running.%CLR_RESET%)
taskkill /f /im mshta.exe >nul 2>&1   && (echo   %CLR_RED%[-] Terminated running mshta.exe payload process.%CLR_RESET%)   || (echo   %CLR_GREEN%[+] mshta.exe not running.%CLR_RESET%)
echo.

:: --- 5. USB / Removable Storage Drive Detection ---
echo %CLR_BOLD%[PHASE 2/5] Removable Drive Discovery%CLR_RESET%
echo %CLR_CYAN%[*] Scanning active volumes for removable media...%CLR_RESET%
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | ForEach-Object { " ^
    "  $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }; " ^
    "  $freeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }; " ^
    "  Write-Host ('   Drive [' + $_.DeviceID + ']  Label: ' + ($_.VolumeName.PadRight(15)) + ' FS: ' + ($_.FileSystem.PadRight(6)) + ' Size: ' + $sizeGB + ' GB (Free: ' + $freeGB + ' GB)') -ForegroundColor Green " ^
    "}"

echo.
echo %CLR_YELLOW%[!] Safety Guardrail: Fixed system drives (C:\) are strictly protected.%CLR_RESET%
echo.

:: --- 6. Drive Letter Input and Validation ---
:PROMPT_DRIVE
set "USER_INPUT=%~1"
if "%USER_INPUT%"=="" (
    set /p "USER_INPUT=%CLR_BOLD%Enter Target Drive Letter (e.g., E or E:): %CLR_RESET%"
)

if "%USER_INPUT%"=="" (
    echo %CLR_RED%[ERROR] No drive letter entered. Operation aborted.%CLR_RESET%
    goto :PROMPT_DRIVE
)

:: Sanitize input: strip quotes, spaces, backslashes, colons
set "CLEAN_DRIVE=%USER_INPUT:"=%"
set "CLEAN_DRIVE=%CLEAN_DRIVE: =%"
set "CLEAN_DRIVE=%CLEAN_DRIVE:\=%"
set "CLEAN_DRIVE=%CLEAN_DRIVE::=%"

:: Extract the first character and uppercase it
set "DRV_LETTER=%CLEAN_DRIVE:~0,1%"
for %%A in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if /I "%DRV_LETTER%"=="%%A" set "DRV_LETTER=%%A"
)

set "TARGET_DRIVE=%DRV_LETTER%:"
set "TARGET_ROOT=%TARGET_DRIVE%\"

:: Safety Check 1: System Drive Protection
if /I "%TARGET_DRIVE%"=="%SystemDrive%" (
    echo.
    echo %CLR_BG_RED% [FATAL REJECTED] %CLR_RESET% %CLR_RED%Target %TARGET_DRIVE% is the active Windows System Drive!%CLR_RESET%
    echo %CLR_YELLOW%Stripping system attributes from C:\ can break operating system stability.%CLR_RESET%
    echo %CLR_YELLOW%Please specify a removable USB drive letter.%CLR_RESET%
    echo.
    set "USER_INPUT="
    goto :PROMPT_DRIVE
)

:: Safety Check 2: Existence Check
if not exist "%TARGET_ROOT%" (
    echo.
    echo %CLR_RED%[ERROR] Drive %TARGET_DRIVE% does not exist or is not connected.%CLR_RESET%
    echo %CLR_YELLOW%Please verify the connection in File Explorer and re-enter.%CLR_RESET%
    echo.
    set "USER_INPUT="
    goto :PROMPT_DRIVE
)

:: Safety Check 3: Drive Type Warning
for /f "tokens=*" %%T in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"%TARGET_DRIVE%\"').DriveType"') do set "DETECTED_TYPE=%%T"

if "%DETECTED_TYPE%"=="3" (
    echo.
    echo %CLR_YELLOW%[WARNING] %TARGET_DRIVE% appears to be an internal Fixed Hard Disk, not a Removable USB drive.%CLR_RESET%
    choice /C YN /N /M "%CLR_YELLOW%Are you absolutely sure you want to proceed on this drive? [Y/N]: %CLR_RESET%"
    if errorlevel 2 (
        set "USER_INPUT="
        goto :PROMPT_DRIVE
    )
)

echo.
echo %CLR_GREEN%[+] Target Verified: %TARGET_DRIVE% (Root: %TARGET_ROOT%)%CLR_RESET%
echo.

:: --- 7. Confirmation & Options ---
choice /C YN /N /M "%CLR_BOLD%Begin threat quarantine and file unhiding on %TARGET_DRIVE%? [Y/N]: %CLR_RESET%"
if errorlevel 2 (
    echo %CLR_YELLOW%[*] Operation cancelled by user.%CLR_RESET%
    goto :EXIT_SCRIPT
)

echo.
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_BOLD%[PHASE 3/5] Threat Quarantine & Purge%CLR_RESET%
echo %CLR_CYAN%================================================================================%CLR_RESET%

:: Generate timestamp for quarantine folder and report
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set "LDT=%%I"
if not defined LDT (
    set "TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
    set "TIMESTAMP=!TIMESTAMP: =0!"
) else (
    set "TIMESTAMP=%LDT:~0,8%_%LDT:~8,6%"
)

set "QUARANTINE_DIR=%TARGET_ROOT%_Quarantine_%TIMESTAMP%"
set "REPORT_FILE=%TARGET_ROOT%USB_Shortcut_Fix_Report_%TIMESTAMP%.txt"

echo USB SHORTCUT FIX LOG REPORT > "%REPORT_FILE%"
echo Date/Time: %DATE% %TIME% >> "%REPORT_FILE%"
echo Target Drive: %TARGET_DRIVE% >> "%REPORT_FILE%"
echo ------------------------------------------------------------ >> "%REPORT_FILE%"

set "FOUND_THREATS=0"

:: Helper macro to quarantine files safely
call :QUARANTINE_EXT "*.lnk" "Malicious Shortcut File"
call :QUARANTINE_EXT "autorun.inf" "AutoRun Configuration Script"
call :QUARANTINE_EXT "*.vbs" "VBScript Payload"
call :QUARANTINE_EXT "*.js" "JavaScript Payload"
call :QUARANTINE_EXT "*.jse" "Encoded JScript Payload"
call :QUARANTINE_EXT "*.wsf" "Windows Script File Payload"
call :QUARANTINE_EXT "*.scr" "Screensaver / Disguised Executable"
call :QUARANTINE_EXT "*.hta" "HTML Application Payload"

if %FOUND_THREATS% equ 0 (
    echo   %CLR_GREEN%[+] No common root script droppers or shortcut threats found.%CLR_RESET%
    echo No root script droppers found. >> "%REPORT_FILE%"
) else (
    echo.
    echo   %CLR_YELLOW%[!] Suspicious files were isolated in: %QUARANTINE_DIR%%CLR_RESET%
    echo Isolated files located in: %QUARANTINE_DIR% >> "%REPORT_FILE%"
)

echo.
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_BOLD%[PHASE 4/5] Restoring Hidden Files & Directory Attributes%CLR_RESET%
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_WHITE%[*] Stripping System, Hidden, and Read-Only flags from user items...%CLR_RESET%
echo %CLR_YELLOW%[*] Note: Skipping protected OS system folders ('System Volume Information', '$RECYCLE.BIN')...%CLR_RESET%
echo.

:: 1. Unhide Root Files
echo   Unhiding root files on %TARGET_DRIVE%...
attrib -h -r -s "%TARGET_ROOT%*.*" >nul 2>&1

:: 2. Unhide User Directories safely without hitting locked system directories
set "DIR_COUNT=0"
for /d %%D in ("%TARGET_ROOT%*") do (
    set "DIR_NAME=%%~nxD"
    set "SKIP_DIR=0"
    if /I "!DIR_NAME!"=="System Volume Information" set "SKIP_DIR=1"
    if /I "!DIR_NAME!"=="$RECYCLE.BIN" set "SKIP_DIR=1"
    if /I "!DIR_NAME!"=="_Quarantine_%TIMESTAMP%" set "SKIP_DIR=1"

    if "!SKIP_DIR!"=="0" (
        set /a DIR_COUNT+=1
        echo   Restoring folder: %CLR_CYAN%!DIR_NAME!%CLR_RESET%
        attrib -h -r -s /s /d "%%D" >nul 2>&1
        echo Restored folder attributes: !DIR_NAME! >> "%REPORT_FILE%"
    )
)

echo.
echo %CLR_GREEN%[+] Restored attributes for root files and !DIR_COUNT! top-level directories.%CLR_RESET%

:: 3. Check for Suspicious Nameless or Hidden Malware Staging Directories
echo.
echo %CLR_CYAN%[*] Inspecting drive root for obfuscated malware containers...%CLR_RESET%
for /d %%F in ("%TARGET_ROOT%*") do (
    set "FOLDER_NAME=%%~nxF"
    set "IS_PROTECTED=0"
    if /I "!FOLDER_NAME!"=="System Volume Information" set "IS_PROTECTED=1"
    if /I "!FOLDER_NAME!"=="$RECYCLE.BIN" set "IS_PROTECTED=1"
    if /I "!FOLDER_NAME!"=="_Quarantine_%TIMESTAMP%" set "IS_PROTECTED=1"

    if "!IS_PROTECTED!"=="0" (
        attrib "%%F" | findstr /I " H S " >nul
        if not errorlevel 1 (
            echo   %CLR_YELLOW%[!] Obfuscated / Hidden System directory detected: %%~nxF%CLR_RESET%
            echo Warning: Hidden System directory detected: %%~nxF >> "%REPORT_FILE%"
            echo       Your original files may have been relocated inside this folder by the malware.
        )
    )
)

echo.
echo %CLR_CYAN%================================================================================%CLR_RESET%
echo %CLR_BOLD%[PHASE 5/5] Immunization & Final Health Check%CLR_RESET%
echo %CLR_CYAN%================================================================================%CLR_RESET%

choice /C YN /N /M "%CLR_BOLD%Install USB Immunization Vaccine (prevents unauthorized autorun.inf creation)? [Y/N]: %CLR_RESET%"
if errorlevel 2 (
    echo %CLR_WHITE%[*] Skipped immunization vaccine.%CLR_RESET%
) else (
    if not exist "%TARGET_ROOT%autorun.inf" (
        mkdir "%TARGET_ROOT%autorun.inf" >nul 2>&1
        mkdir "%TARGET_ROOT%autorun.inf\con\" >nul 2>&1
        attrib +r +s +h "%TARGET_ROOT%autorun.inf" >nul 2>&1
        echo   %CLR_GREEN%[+] Immunization directory installed at %TARGET_ROOT%autorun.inf%CLR_RESET%
        echo Immunization directory installed. >> "%REPORT_FILE%"
    ) else (
        echo   %CLR_YELLOW%[*] autorun.inf already exists on target.%CLR_RESET%
    )
)

echo.
echo %CLR_GREEN%================================================================================%CLR_RESET%
echo %CLR_BOLD%%CLR_GREEN%                       CLEANUP ^& RECOVERY COMPLETE!%CLR_RESET%
echo %CLR_GREEN%================================================================================%CLR_RESET%
echo.
echo %CLR_WHITE%Summary of Actions:%CLR_RESET%
echo   - Malware script engines contained
echo   - Malicious root shortcuts and scripts safely quarantined
echo   - Hidden and system attributes stripped from files and folders
echo   - Audit log saved to: %CLR_CYAN%%REPORT_FILE%%CLR_RESET%
echo.
echo %CLR_BOLD%Mandatory Post-Clean Steps:%CLR_RESET%
echo   1. Open %TARGET_DRIVE% in File Explorer and verify your recovered files.
echo   2. Check inside any single-character or obscure folders (e.g., '_', ' ')
echo      if files were relocated by the virus.
echo   3. Run a Full Antivirus Scan with Windows Security or Malwarebytes on both
echo      the USB drive and your host PC to remove any lingering host registry hooks.
echo.
pause
goto :EXIT_SCRIPT

:: --- Subroutine: Quarantine by Pattern ---
:QUARANTINE_EXT
set "PATTERN=%~1"
set "THREAT_DESC=%~2"
for %%I in ("%TARGET_ROOT%%PATTERN%") do (
    if exist "%%I" (
        if not exist "%QUARANTINE_DIR%" mkdir "%QUARANTINE_DIR%" >nul 2>&1
        echo   %CLR_RED%[-] Detected: %%~nxI (%THREAT_DESC%)%CLR_RESET%
        move /y "%%I" "%QUARANTINE_DIR%\" >nul 2>&1
        echo Quarantined: %%~nxI (%THREAT_DESC%) >> "%REPORT_FILE%"
        set /a FOUND_THREATS+=1
    )
)
exit /b

:EXIT_SCRIPT
endlocal

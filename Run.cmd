@ECHO OFF
CD /D "%~dp0"

REM Paste the path to the ISO/WIM below, then run this script as an administrator.
SET "SourcePath=E:\Windows 10\CCCOMA_X64FRE_EN-US_DV9.iso"
SET "SavePath=E:\Windows 10 Images"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    ECHO Running as Administrator.
    TIMEOUT /T 2 >NUL
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\ConvertTo-PfW.ps1 -SourcePath "%SourcePath%"
)
PAUSE
EXIT

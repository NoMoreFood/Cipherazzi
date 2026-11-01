@ECHO OFF
SETLOCAL
WHERE pwsh.exe >NUL 2>&1
IF ERRORLEVEL 1 (
    ECHO PowerShell 7 is required to build Cipherazzi.
    EXIT /B 1
)
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build.ps1" %*
EXIT /B %ERRORLEVEL%

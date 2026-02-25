@echo off
echo Checking PowerShell ExecutionPolicy...

for /f "delims=" %%i in ('powershell -Command "Get-ExecutionPolicy -Scope CurrentUser"') do set POLICY=%%i

echo Current ExecutionPolicy: %POLICY%

if "%POLICY%"=="Restricted" (
    echo.
    echo ExecutionPolicy is Restricted.
    echo Please run as admin:
    echo   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
    echo.
    exit /b 1
)

echo Policy OK. Running setup...
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1


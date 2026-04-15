@echo off
:: CyberGuard Windows Collector Installer
:: Run as Administrator
:: Usage: set AGENT_TOKEN=<token> && set DEVICE_ID=<id> && set BACKEND_URL=<url> && install.bat

setlocal enabledelayedexpansion

set SERVICE_NAME=CyberGuardCollector
set INSTALL_DIR=%ProgramData%\CyberGuard
set PYTHON_PATH=python

echo === CyberGuard Windows Collector Installer ===

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Must run as Administrator
    exit /b 1
)

:: Validate required vars
if "%AGENT_TOKEN%"=="" (
    echo ERROR: AGENT_TOKEN environment variable is required
    exit /b 1
)
if "%DEVICE_ID%"=="" (
    echo ERROR: DEVICE_ID environment variable is required
    exit /b 1
)
if "%BACKEND_URL%"=="" (
    set BACKEND_URL=https://api.cyberguard.example.com
)

echo [1/4] Creating install directory...
mkdir "%INSTALL_DIR%" 2>nul
copy /Y "%~dp0collector.py" "%INSTALL_DIR%\collector.py"
copy /Y "%~dp0requirements.txt" "%INSTALL_DIR%\requirements.txt"

echo [2/4] Installing Python dependencies...
%PYTHON_PATH% -m pip install psutil httpx --quiet

echo [3/4] Creating Windows environment file...
(
echo CYBERGUARD_BACKEND_URL=%BACKEND_URL%
echo CYBERGUARD_AGENT_TOKEN=%AGENT_TOKEN%
echo CYBERGUARD_DEVICE_ID=%DEVICE_ID%
echo CYBERGUARD_INTERVAL=60
) > "%INSTALL_DIR%\.env"

echo [4/4] Installing Windows Service using NSSM...
:: Install NSSM if not present (or use sc.exe)
where nssm >nul 2>&1
if %errorLevel%==0 (
    nssm install %SERVICE_NAME% %PYTHON_PATH% "%INSTALL_DIR%\collector.py"
    nssm set %SERVICE_NAME% AppEnvironmentExtra "CYBERGUARD_BACKEND_URL=%BACKEND_URL%" "CYBERGUARD_AGENT_TOKEN=%AGENT_TOKEN%" "CYBERGUARD_DEVICE_ID=%DEVICE_ID%" "CYBERGUARD_INTERVAL=60"
    nssm set %SERVICE_NAME% Description "CyberGuard Security Telemetry Collector"
    nssm set %SERVICE_NAME% Start SERVICE_AUTO_START
    nssm start %SERVICE_NAME%
) else (
    echo NSSM not found. Starting as scheduled task...
    schtasks /create /tn "CyberGuardCollector" /tr "%PYTHON_PATH% %INSTALL_DIR%\collector.py" /sc ONSTART /ru SYSTEM /f
    :: Set environment via registry for scheduled task
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v CYBERGUARD_AGENT_TOKEN /t REG_SZ /d "%AGENT_TOKEN%" /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v CYBERGUARD_DEVICE_ID /t REG_SZ /d "%DEVICE_ID%" /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v CYBERGUARD_BACKEND_URL /t REG_SZ /d "%BACKEND_URL%" /f >nul
    schtasks /run /tn "CyberGuardCollector"
)

echo.
echo === Installation Complete ===
echo Logs: %INSTALL_DIR%\collector.log
echo.

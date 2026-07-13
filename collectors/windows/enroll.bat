@echo off
:: CyberGuard Windows Collector Enrollment Script
:: Run as Administrator
:: Usage: set ENROLLMENT_CODE=<code> && set BACKEND_URL=<url> && enroll.bat

setlocal enabledelayedexpansion

set SERVICE_NAME=CyberGuardCollector
set INSTALL_DIR=%ProgramData%\CyberGuard
set PYTHON_PATH=python

echo === CyberGuard Windows Collector Enrollment ===

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Must run as Administrator
    exit /b 1
)

:: Validate required vars
if "%ENROLLMENT_CODE%"=="" (
    echo ERROR: ENROLLMENT_CODE environment variable is required
    echo Usage: set ENROLLMENT_CODE=<code> && set BACKEND_URL=<url> && enroll.bat
    exit /b 1
)
if "%BACKEND_URL%"=="" (
    set BACKEND_URL=https://api.cyberguard.example.com
)

echo [1/5] Creating install directory...
mkdir "%INSTALL_DIR%" 2>nul
copy /Y "%~dp0collector.py" "%INSTALL_DIR%\collector.py"
copy /Y "%~dp0requirements.txt" "%INSTALL_DIR%\requirements.txt"

echo [2/5] Installing Python dependencies...
%PYTHON_PATH% -m pip install psutil httpx --quiet

echo [3/5] Exchanging enrollment code for agent token...
set ENROLL_CMD=import sys,json,urllib.request; req=urllib.request.Request("%BACKEND_URL%/api/v1/devices/enroll", data=json.dumps({"enrollment_code": "%ENROLLMENT_CODE%"}).encode(), headers={"Content-Type": "application/json"}); resp=urllib.request.urlopen(req); print(json.load(resp)["agent_token"]); print(json.load(resp)["device_id"])
for /f "tokens=1* delims=" %%a in ('%PYTHON_PATH% -c "%ENROLL_CMD%" 2^>nul') do (
    if not defined AGENT_TOKEN (
        set AGENT_TOKEN=%%a
    ) else if not defined DEVICE_ID (
        set DEVICE_ID=%%a
    )
)

if "%AGENT_TOKEN%"=="" (
    echo ERROR: Failed to exchange enrollment code
    exit /b 1
)
if "%DEVICE_ID%"=="" (
    echo ERROR: Invalid enrollment response
    exit /b 1
)

echo [4/5] Creating Windows environment file...
(
echo CYBERGUARD_BACKEND_URL=%BACKEND_URL%
echo CYBERGUARD_AGENT_TOKEN=%AGENT_TOKEN%
echo CYBERGUARD_DEVICE_ID=%DEVICE_ID%
echo CYBERGUARD_INTERVAL=60
) > "%INSTALL_DIR%\.env"

echo [5/5] Installing Windows Service using NSSM...
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
echo === Enrollment Complete ===
echo Logs: %INSTALL_DIR%\collector.log
echo.
@echo off
REM CyberTrace setup - creates venv, installs everything, verifies. Safe to re-run.
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Enable ANSI colors on Windows 10+ terminals.
for /f %%e in ('echo prompt $E ^| cmd') do set "ESC=%%e"
set "R=%ESC%[0m"
set "B=%ESC%[1m"
set "DIM=%ESC%[2m"
set "CYAN=%ESC%[36m"
set "GREEN=%ESC%[32m"
set "YELLOW=%ESC%[33m"
set "RED=%ESC%[31m"
set "AMBER=%ESC%[38;5;214m"

echo.
echo %CYAN%%B%    ______      __             ______                    %R%
echo %CYAN%%B%   / ____/_  __/ /_  ___  ____/_  __/________ _________  %R%
echo %CYAN%%B%  / /   / / / / __ \/ _ \/ ___// / / ___/ __ `/ ___/ _ \ %R%
echo %CYAN%%B% / /___/ /_/ / /_/ /  __/ /   / / / /  / /_/ / /__/  __/ %R%
echo %CYAN%%B% \____/\__, /_.___/\___/_/   /_/ /_/   \__,_/\___/\___/  %R%
echo %CYAN%%B%      /____/                                             %R%
echo %DIM%  Multi-Layer OSINT Investigation Tool - Surface . Deep . Dark%R%
echo.
echo %AMBER%%B%  ----------------[  A N U B H A V   M O H A N D A S  ]----------------%R%
echo.

echo %CYAN%%B%^> Checking Python%R%
where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>nul
if errorlevel 1 (
    echo   %RED%[X] Python 3.10+ required and must be on PATH.%R%
    exit /b 1
)
for /f "delims=" %%v in ('%PY% -V 2^>^&1') do echo   %GREEN%[OK] %%v%R%

echo %CYAN%%B%^> Setting up virtual environment%R%
if exist venv (
    echo   %GREEN%[OK] venv already exists - reusing%R%
) else (
    %PY% -m venv venv || exit /b 1
    echo   %GREEN%[OK] Created .\venv%R%
)

echo %CYAN%%B%^> Installing CyberTrace + OSINT tools%R%
echo %DIM%     maigret . sherlock . holehe . phonenumbers . Tor/SOCKS support%R%
echo %DIM%     ^(first run pulls ~200MB, grab a coffee^)%R%
venv\Scripts\python.exe -m pip install --upgrade --quiet pip || exit /b 1
venv\Scripts\pip.exe install --quiet -e ".[dev]" || exit /b 1
echo   %GREEN%[OK] Dependencies installed%R%

echo %CYAN%%B%^> Configuring environment%R%
if exist .env (
    echo   %GREEN%[OK] .env already present - left untouched%R%
) else (
    copy /y .env.example .env >nul
    echo   %GREEN%[OK] Created .env from .env.example%R%
    echo %DIM%     All API keys are optional; CyberTrace degrades gracefully without them.%R%
)

echo %CYAN%%B%^> Verifying installation%R%
set FAILED=0
for %%t in (cybertrace maigret sherlock holehe) do (
    if exist "venv\Scripts\%%t.exe" (
        echo   %GREEN%[OK] %%t%R%
    ) else (
        echo   %RED%[X] %%t missing%R%
        set FAILED=1
    )
)
where exiftool >nul 2>&1 && (echo   %GREEN%[OK] exiftool ^(full EXIF extraction^)%R%) || (echo   %YELLOW%[!] exiftool not found - image module falls back to Pillow%R%)

if "%FAILED%"=="1" (
    echo   %RED%[X] Some tools failed to install. Re-run setup.bat%R%
    exit /b 1
)

echo.
echo %GREEN%%B%  Setup complete!%R%
echo.
echo %B%  Start investigating:%R%
echo.
echo      %CYAN%venv\Scripts\activate%R%
echo      %CYAN%cybertrace search "user@example.com"%R%
echo.
echo %DIM%  Try also:  cybertrace search "torvalds" -t username%R%
echo %DIM%             cybertrace search "example.com" -o rich%R%
echo %DIM%             cybertrace modules%R%
echo.
echo %AMBER%%B%  ----------------[  A N U B H A V   M O H A N D A S  ]----------------%R%
echo %DIM%           Use responsibly - authorized targets only%R%
echo %B%              ^<3  I  L O V E  Y O U U U U U  ^<3%R%
echo.

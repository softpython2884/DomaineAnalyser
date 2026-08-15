@echo off
setlocal EnableDelayedExpansion
rem ---------------------------------------------------------------------------
rem  Installation de DomaineAnalyser (Windows).
rem
rem  Idempotent : relancer le script ne casse rien et ne reinstalle que ce qui
rem  manque. Rien n'est ecrit hors du repertoire du projet, a l'exception des
rem  binaires systeme optionnels installes via winget ou Chocolatey.
rem
rem  Options :
rem    --no-system-tools   n'installe pas les binaires optionnels (whois)
rem    --dev               installe aussi les outils de developpement
rem ---------------------------------------------------------------------------

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
set "VENV_DIR=%PROJECT_DIR%\.venv"
set "EXTRAS=ai"
set "WITH_SYSTEM_TOOLS=1"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--no-system-tools" set "WITH_SYSTEM_TOOLS=0" & shift & goto parse_args
if /i "%~1"=="--dev"             set "EXTRAS=ai,dev"       & shift & goto parse_args
if /i "%~1"=="-h"                goto usage
if /i "%~1"=="--help"            goto usage
echo   [x] Option inconnue : %~1
exit /b 64
:args_done

echo.
echo ==^> Verification de Python

rem ---------------------------------------------------------------------------
rem  Le lanceur " py " est privilegie : sur Windows, " python " peut renvoyer
rem  vers l'alias du Microsoft Store, qui ouvre une page web au lieu de
rem  s'executer. " py -3 " ne souffre pas de ce probleme.
rem ---------------------------------------------------------------------------
set "PYTHON="
for %%C in ("py -3" "python" "python3") do (
    if not defined PYTHON (
        %%~C -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
        if !errorlevel! equ 0 set "PYTHON=%%~C"
    )
)

if not defined PYTHON (
    echo   [x] Python 3.10 ou superieur est requis et n'a pas ete trouve.
    echo.
    echo       Installation : winget install Python.Python.3.12
    echo       ou telechargement sur https://www.python.org/downloads/
    exit /b 1
)

for /f "delims=" %%V in ('%PYTHON% --version 2^>^&1') do echo     [ok] %%V

echo.
echo ==^> Environnement virtuel

if exist "%VENV_DIR%\Scripts\python.exe" (
    echo     [ok] deja present, reutilise
) else (
    %PYTHON% -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo   [x] Creation de l'environnement virtuel impossible.
        exit /b 1
    )
    echo     [ok] cree dans .venv
)

set "VENV_PY=%VENV_DIR%\Scripts\python.exe"

echo.
echo ==^> Dependances Python

"%VENV_PY%" -m pip install --quiet --upgrade pip
if !errorlevel! neq 0 (
    echo   [x] Mise a jour de pip impossible.
    exit /b 1
)
echo     [ok] pip a jour

"%VENV_PY%" -m pip install --quiet -e "%PROJECT_DIR%[%EXTRAS%]"
if !errorlevel! neq 0 (
    echo   [x] Installation des dependances impossible.
    exit /b 1
)
echo     [ok] domaine-analyser installe (extras : %EXTRAS%)

echo.
echo ==^> Cache de la Public Suffix List

rem  Amorce maintenant plutot qu'au premier audit : sans lui, la determination
rem  du domaine organisationnel - donc l'heritage DMARC - reposerait sur une
rem  liste embarquee potentiellement datee.
"%VENV_PY%" -c "import tldextract; tldextract.TLDExtract().update()" >nul 2>&1
if !errorlevel! equ 0 (
    echo     [ok] liste a jour
) else (
    echo     [--] mise a jour impossible ; la liste embarquee sera utilisee
)

echo.
echo ==^> Configuration locale

if exist "%PROJECT_DIR%\.env" (
    echo     [ok] .env deja present, laisse intact
) else (
    copy /y "%PROJECT_DIR%\.env.example" "%PROJECT_DIR%\.env" >nul
    echo     [ok] .env cree depuis .env.example
)

echo.
echo ==^> Binaires systeme optionnels

where whois >nul 2>&1
if !errorlevel! equ 0 (
    echo     [ok] whois deja present
    goto system_tools_done
)

if "%WITH_SYSTEM_TOOLS%"=="0" (
    echo     [--] whois absent ^(installation desactivee par --no-system-tools^)
    goto system_tools_done
)

set "INSTALLED=0"

where winget >nul 2>&1
if !errorlevel! equ 0 (
    echo     installation de whois via winget...
    winget install --id Microsoft.Sysinternals.Whois -e --silent ^
        --accept-source-agreements --accept-package-agreements >nul 2>&1
    if !errorlevel! equ 0 set "INSTALLED=1"
)

if "!INSTALLED!"=="0" (
    where choco >nul 2>&1
    if !errorlevel! equ 0 (
        echo     installation de whois via Chocolatey...
        choco install whois -y --limit-output >nul 2>&1
        if !errorlevel! equ 0 set "INSTALLED=1"
    )
)

if "!INSTALLED!"=="1" (
    echo     [ok] whois installe
) else (
    rem  Volontairement non bloquant : ce binaire enrichit la sortie WHOIS
    rem  brute mais n'est jamais necessaire. L'outil embarque son propre
    rem  client WHOIS en TCP/43 et n'utilise pas dig.
    echo     [--] installation impossible ^(droits insuffisants ?^) - sans consequence :
    echo         l'outil embarque son propre client WHOIS
)

:system_tools_done

echo.
echo ==^> Verification
echo.
"%VENV_DIR%\Scripts\da.exe" doctor

echo.
echo Installation terminee.
echo.
echo   Activer l'environnement :   .venv\Scripts\activate
echo   Premier audit :             da domain example.com
echo   Rapport complet :           da domain example.com --output rapport.md
echo.
echo Sans activer l'environnement, utiliser directement .venv\Scripts\da.exe
echo.
exit /b 0

:usage
echo.
echo Installation de DomaineAnalyser.
echo.
echo   install.cmd [--no-system-tools] [--dev]
echo.
echo   --no-system-tools   n'installe pas les binaires optionnels (whois)
echo   --dev               installe aussi les outils de developpement
echo.
exit /b 0

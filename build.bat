@echo off
REM SharkPy - build standalone exe
REM Run from a NORMAL (non-Administrator) Command Prompt.

cd /d "%~dp0"

echo.
echo [SharkPy] Preparing build environment...
echo.

REM Force-reinstall PyQt5 with all sub-packages so dist-info metadata is correct.
REM PyInstaller's PyQt5 hook reads the installed version via importlib.metadata;
REM if metadata is missing or broken it crashes with "got NoneType".
echo [*] Reinstalling PyQt5 (fixes metadata used by PyInstaller hook)...
python -m pip install --force-reinstall --no-cache-dir PyQt5 PyQt5-Qt5 PyQt5-sip
if errorlevel 1 (
    echo [-] PyQt5 reinstall failed.
    goto :fail
)

REM Clean PyInstaller's analysis cache so it picks up the fresh metadata.
echo [*] Clearing PyInstaller build cache...
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist

echo.
echo [*] Building SharkPy.exe (this may take a few minutes)...
echo.
pyinstaller SharkPy.spec --noconfirm --clean
if errorlevel 1 goto :fail

echo.
if exist "dist\SharkPy.exe" (
    echo [+] Success:  dist\SharkPy.exe
    echo.
    echo     The exe requests UAC elevation automatically at launch.
    echo     Npcap must be installed on any machine that runs it.
    goto :done
)

:fail
echo.
echo [-] Build failed.  Common causes on Python 3.13:
echo.
echo   1. PyQt5 metadata still broken:
echo        python -m pip install --force-reinstall "PyQt5==5.15.11" PyQt5-Qt5 PyQt5-sip
echo.
echo   2. Python 3.13 / PyInstaller incompatibility:
echo      Use Python 3.11 or 3.12 to build the exe.
echo      Both can be installed alongside 3.13 from https://www.python.org/downloads/
echo      Then: py -3.12 -m pip install pyinstaller PyQt5 ... and py -3.12 -m PyInstaller SharkPy.spec

:done
echo.
pause

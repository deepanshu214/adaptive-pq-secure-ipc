@echo off
rem Builds the Adaptive Security Policy Engine on Windows with MinGW g++
rem (no make or CMake needed). Usage:  build.bat          build only
rem                                   build.bat run      build, test and run all phases
setlocal
cd /d "%~dp0"

where g++ >nul 2>nul
if errorlevel 1 (
  echo g++ not found. Install MinGW-w64 or MSYS2 and add its bin folder to PATH.
  exit /b 1
)

if not exist build mkdir build

echo Building build\aspe.exe ...
g++ -std=c++14 -O2 -Wall -Wextra -Wpedantic -Iinclude src\*.cpp apps\aspe_main.cpp -o build\aspe.exe
if errorlevel 1 exit /b 1

echo Building build\aspe_tests.exe ...
g++ -std=c++14 -O2 -Wall -Wextra -Wpedantic -Iinclude src\*.cpp tests\test_main.cpp -o build\aspe_tests.exe
if errorlevel 1 exit /b 1

echo Build complete.

if /I "%~1"=="run" (
  build\aspe_tests.exe || exit /b 1
  build\aspe.exe all || exit /b 1
)
endlocal

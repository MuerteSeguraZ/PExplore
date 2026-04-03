@echo off

for /f %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"

set "BOLD_RED=%ESC%[1;31m"
set "BOLD_BLUE=%ESC%[1;34m"
set "BOLD_GREEN=%ESC%[1;32m"
set "RESET=%ESC%[0m"

if "%1"=="run" (
    echo Running PExplorer..
    .\build\Release\PExplore.exe
    exit /b 1
)

echo %BOLD_RED%Running the first CMake step...%RESET%
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
echo %BOLD_RED%Running the last CMake step...%RESET%
cmake --build build --config Release

if errorlevel 1 (
    echo %BOLD_BLUE%[:c]%RESET% Compilation %BOLD_RED%failed!%RESET%
    pause
    exit /b 1
)

echo %BOLD_GREEN%Compilation successful!%RESET%
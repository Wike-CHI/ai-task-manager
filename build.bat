@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
if not exist build mkdir build

rc /nologo /fo "build\app.res" "app.rc"
if errorlevel 1 (
  echo [RES FAILED]
  exit /b 1
)

cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 ^
   /Fo:build\ ^
   src\main.cpp ^
   build\app.res ^
   /Fe:AITaskManager.exe ^
   user32.lib gdi32.lib comctl32.lib psapi.lib shell32.lib dwmapi.lib msimg32.lib advapi32.lib

if errorlevel 1 (
  echo [BUILD FAILED]
  exit /b 1
)
echo [BUILD OK] AITaskManager.exe

@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

msbuild multibind-fix.sln /p:Configuration=Release /p:Platform=x64 /t:Rebuild /nologo
msbuild injector\injector.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /nologo

mkdir release 2>nul
copy /Y x64\Release\multibind-fix.dll release\
copy /Y injector\x64\Release\injector.exe release\

echo.
echo [+] release files in .\release\
dir release\

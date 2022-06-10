REM Change dumpbin_path according to your system
REM This script will store all the functions inside a DLL in exports.log
REM Written by nop

@echo off

set dumpbin_path="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.30.30705\bin\Hostx64\x86\dumpbin.exe"
set /P library="Enter library path: "

%dumpbin_path% %library% /exports >> exports.log

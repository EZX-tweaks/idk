@echo off
chcp 65001 >nul
title Windows Optimizer Pro - 50 Tweak Edition

:: ANSI Colors
set "purple=[95m"
set "blue=[94m"
set "cyan=[96m"
set "reset=[0m"

:MENU
cls
echo %purple%=====================================================%reset%
echo           %cyan%WINDOWS OPTIMIZER PRO - MAIN MENU%reset%
echo %purple%=====================================================%reset%
echo.
echo %blue%[1] Internet Tweaks (20)%reset%
echo %blue%[2] Delay & Latency Tweaks (20)%reset%
echo %blue%[3] Extra Registry Tweaks (10)%reset%
echo %blue%[0] Kilépés%reset%
echo.
set /p choice="Válassz egy opciót: "

if "%choice%"=="1" goto INTERNET
if "%choice%"=="2" goto DELAY
if "%choice%"=="3" goto REGEXTRA
if "%choice%"=="0" exit
goto MENU


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                INTERNET TWEAKS (20)                       ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:INTERNET
cls
echo %purple%=== INTERNET TWEAKS FUTTATÁSA ===%reset%
echo %cyan%20 optimalizálás indul...%reset%
echo.

:: --- Internet Tweaks 1–10 ---
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rsc=enabled
netsh int tcp set global pacingprofile=off
ipconfig /flushdns
ipconfig /registerdns
nbtstat -R

:: --- Internet Tweaks 11–20 ---
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
netsh int tcp set heuristics disabled
netsh int tcp set supplemental internet congestionprovider=dctcp
netsh winsock reset
netsh int ip reset
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v TCPNoDelay /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v MaxConnectionsPerServer /t REG_DWORD /d 10 /f

echo.
echo %cyan%Internet optimalizálás kész!%reset%
pause
goto MENU


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                 DELAY / LATENCY TWEAKS (20)               ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:DELAY
cls
echo %purple%=== DELAY & LATENCY TWEAKS FUTTATÁSA ===%reset%
echo %cyan%20 optimalizálás indul...%reset%
echo.

:: --- Delay Tweaks 1–10 ---
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v TcpAckFrequency /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v TCPNoDelay /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DisableHardwareAcceleration /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisablePreviewDesktop /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_DWORD /d 1000 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 1000 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v IRQ8Priority /t REG_DWORD /d 1 /f

:: --- Delay Tweaks 11–20 ---
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v GPU Priority /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
powercfg -setactive scheme_current
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v TimerResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f

echo.
echo %cyan%Delay csökkentő optimalizálás kész!%reset%
pause
goto MENU


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::                    EXTRA REGISTRY TWEAKS (10)             ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:REGEXTRA
cls
echo %purple%=== EXTRA REGISTRY TWEAKS ===%reset%
echo %cyan%10 extra rendszer tweak alkalmazása...%reset%
echo.

:: --- Extra Registry Tweaks 1–10 ---
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v OverlayTestMode /t REG_DWORD /d 5 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisallowShaking /t REG_DWORD /d 1 /f

echo.
echo %cyan%Extra registry optimalizálás kész!%reset%
pause
goto MENU


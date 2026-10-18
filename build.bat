@echo off
chcp 65001 >nul 2>&1
title Peertopeer P2P VPN - Derleme Araci
color 0A

echo =======================================================
echo   Peertopeer P2P VPN - Derleme Araci
echo   Gelistirici: Bekir Alisoglu
echo =======================================================
echo.

:: Gerekli bagimliliklari kontrol et
echo [*] Bagimliliklar kontrol ediliyor...
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [!] PyInstaller bulunamadi, yukleniyor...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo [HATA] PyInstaller yuklenemedi!
        pause
        exit /b 1
    )
)

python -m pip show cryptography >nul 2>&1
if errorlevel 1 (
    echo [!] cryptography bulunamadi, yukleniyor...
    python -m pip install cryptography
)

echo [OK] Tum bagimliliklar hazir.
echo.

:MENU
echo -------------------------------------------------------
echo   Platform Secimi:
echo -------------------------------------------------------
echo.
echo   [1] Windows  (.exe)
echo   [2] Linux    (ELF binary)
echo   [3] Her ikisi
echo   [4] Cikis
echo.
set /p choice="  Seciminiz (1-4): "

if "%choice%"=="1" goto BUILD_WINDOWS
if "%choice%"=="2" goto BUILD_LINUX
if "%choice%"=="3" goto BUILD_BOTH
if "%choice%"=="4" goto END
echo [!] Gecersiz secim, tekrar deneyin.
goto MENU

:: =======================================================
::  WINDOWS DERLEME
:: =======================================================
:BUILD_WINDOWS
echo.
echo =======================================================
echo   [*] Windows icin derleniyor...
echo =======================================================
echo.

:: dist/windows klasorunu olustur
if not exist "dist\windows" mkdir "dist\windows"

python -m PyInstaller ^
    --onefile ^
    --console ^
    --name "PertoperVPN" ^
    --icon "%~dp0pertoper_vpn.ico" ^
    --distpath "dist\windows" ^
    --workpath "build\windows" ^
    --specpath "build" ^
    --clean ^
    --noconfirm ^
    pertoper_vpn.py

if errorlevel 1 (
    echo.
    echo [HATA] Windows derlemesi basarisiz!
    pause
    goto MENU
)

echo.
echo =======================================================
echo   [OK] Windows derlemesi tamamlandi!
echo   Cikti: dist\windows\PertoperVPN.exe
echo =======================================================
echo.

if "%choice%"=="3" goto BUILD_LINUX
goto DONE

:: =======================================================
::  LINUX DERLEME
:: =======================================================
:BUILD_LINUX
echo.
echo =======================================================
echo   [*] Linux icin derleniyor...
echo =======================================================
echo.
echo   [NOT] Linux derlemesi icin iki yontem mevcuttur:
echo.
echo   (a) WSL (Windows Subsystem for Linux) kullanarak
echo   (b) Docker kullanarak
echo   (c) Sadece Linux dosyalarini hazirla (derleme yok)
echo.

set /p lmethod="  Yontem secin (a/b/c): "

if /i "%lmethod%"=="a" goto LINUX_WSL
if /i "%lmethod%"=="b" goto LINUX_DOCKER
if /i "%lmethod%"=="c" goto LINUX_PREPARE
echo [!] Gecersiz secim.
goto BUILD_LINUX

:LINUX_WSL
echo.
echo [*] WSL ile Linux derlemesi baslatiliyor...

:: WSL kontrol
wsl --status >nul 2>&1
if errorlevel 1 (
    echo [HATA] WSL yuklu degil veya erisilemiyor!
    echo        WSL kurulumu icin: wsl --install
    pause
    goto MENU
)

:: dist/linux klasorunu olustur
if not exist "dist\linux" mkdir "dist\linux"

:: WSL ile derleme komutu
wsl bash -c "cd /mnt/%CD:~0,1%/%CD:~3% 2>/dev/null || cd \"$(wslpath '%CD%')\" && \
    pip3 install pyinstaller cryptography 2>/dev/null && \
    python3 -m PyInstaller \
        --onefile \
        --name PertoperVPN \
        --distpath dist/linux \
        --workpath build/linux \
        --specpath build \
        --clean \
        --noconfirm \
        pertoper_vpn.py"

if errorlevel 1 (
    echo.
    echo [HATA] WSL Linux derlemesi basarisiz!
    echo        WSL'de Python3 ve pip3 kurulu oldugundan emin olun.
    pause
    goto MENU
)

echo.
echo =======================================================
echo   [OK] Linux derlemesi tamamlandi!
echo   Cikti: dist\linux\PertoperVPN
echo =======================================================
echo.
goto DONE

:LINUX_DOCKER
echo.
echo [*] Docker ile Linux derlemesi baslatiliyor...

:: Docker kontrol
docker --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Docker yuklu degil veya calismiyor!
    pause
    goto MENU
)

:: dist/linux klasorunu olustur
if not exist "dist\linux" mkdir "dist\linux"

docker run --rm -v "%CD%:/src" -w /src python:3.11-slim bash -c "\
    apt-get update && apt-get install -y binutils > /dev/null 2>&1 && \
    pip install pyinstaller cryptography > /dev/null 2>&1 && \
    pyinstaller \
        --onefile \
        --name PertoperVPN \
        --distpath dist/linux \
        --workpath build/linux \
        --specpath build \
        --clean \
        --noconfirm \
        pertoper_vpn.py"

if errorlevel 1 (
    echo.
    echo [HATA] Docker Linux derlemesi basarisiz!
    pause
    goto MENU
)

echo.
echo =======================================================
echo   [OK] Linux derlemesi (Docker) tamamlandi!
echo   Cikti: dist\linux\PertoperVPN
echo =======================================================
echo.
goto DONE

:LINUX_PREPARE
echo.
echo [*] Linux derleme dosyalari hazirlaniyor...

if not exist "dist\linux" mkdir "dist\linux"

:: Linux icin derleme betigi olustur
(
echo #!/bin/bash
echo # =======================================================
echo # Pertoper P2P VPN - Linux Derleme Betigi
echo # Gelistirici: Bekir Alisoglu
echo # =======================================================
echo.
echo echo "Pertoper P2P VPN - Linux Derleme"
echo echo "========================================"
echo echo ""
echo.
echo # Bagimliliklar
echo echo "[*] Bagimliliklar yukleniyor..."
echo pip3 install pyinstaller cryptography
echo.
echo # Derleme
echo echo "[*] Derleniyor..."
echo python3 -m PyInstaller \
echo     --onefile \
echo     --name PertoperVPN \
echo     --distpath dist \
echo     --workpath build \
echo     --clean \
echo     --noconfirm \
echo     pertoper_vpn.py
echo.
echo if [ $? -eq 0 ]; then
echo     echo ""
echo     echo "[OK] Derleme tamamlandi!"
echo     echo "Cikti: dist/PertoperVPN"
echo     chmod +x dist/PertoperVPN
echo else
echo     echo "[HATA] Derleme basarisiz!"
echo     exit 1
echo fi
) > "dist\linux\build_linux.sh"

:: Kaynak dosyalari kopyala
copy /Y "pertoper_vpn.py"  "dist\linux\" >nul 2>&1
copy /Y "pertoper_vpn.ico" "dist\linux\" >nul 2>&1
copy /Y "pertoper_vpn.png" "dist\linux\" >nul 2>&1
copy /Y "requirements.txt" "dist\linux\" >nul 2>&1

echo.
echo =======================================================
echo   [OK] Linux dosyalari hazirlandi!
echo.
echo   Dosyalar: dist\linux\
echo     - pertoper_vpn.py
echo     - pertoper_vpn.ico
echo     - pertoper_vpn.png
echo     - requirements.txt
echo     - build_linux.sh
echo.
echo   Linux makinede calistirin:
echo     chmod +x build_linux.sh ^&^& ./build_linux.sh
echo =======================================================
echo.
goto DONE

:: =======================================================
::  HER IKISI
:: =======================================================
:BUILD_BOTH
set choice=3
goto BUILD_WINDOWS

:: =======================================================
:DONE
echo.
echo -------------------------------------------------------
echo   Islem tamamlandi!
echo -------------------------------------------------------
echo.
set /p again="  Baska bir derleme yapmak ister misiniz? (e/h): "
if /i "%again%"=="e" goto MENU

:END
echo.
echo   Pertoper P2P VPN Derleme Araci kapatiliyor...
echo.
pause

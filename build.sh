#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "==============================================="
echo "  Pertoper P2P VPN - Linux Derleme"
echo "==============================================="

BUILD_DIR="$PROJECT_DIR"
TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# PyInstaller collects shared libraries from the output of `ldd`, and its
# parser truncates every path at the first whitespace. A space anywhere in the
# build path (e.g. "Peertopeer_Vpn (kopya 8)") therefore corrupts the resolved
# library paths and the build later crashes with an IsADirectoryError.
# Work around it by building from a whitespace-free temporary directory.
if [[ "$PROJECT_DIR" == *[[:space:]]* ]]; then
    echo "[!] Derleme yolu bosluk iceriyor:"
    echo "    $PROJECT_DIR"
    echo "[*] PyInstaller bu yolda hata verdigi icin gecici bir dizinde derleniyor..."
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pertoper-build.XXXXXXXX")"
    BUILD_DIR="$TMP_DIR/pertoper"
    mkdir -p "$BUILD_DIR"
    if [[ -d "$PROJECT_DIR/.venv" ]]; then
        cp -a "$PROJECT_DIR/.venv" "$BUILD_DIR/.venv"
    fi
    for f in pertoper_vpn.py pertoper_vpn.ico pertoper_vpn.png requirements.txt; do
        if [[ -e "$PROJECT_DIR/$f" ]]; then
            cp -a "$PROJECT_DIR/$f" "$BUILD_DIR/"
        fi
    done
fi

PYTHON="python3"
if [[ -x "$BUILD_DIR/.venv/bin/python" ]]; then
    PYTHON="$BUILD_DIR/.venv/bin/python"
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "[HATA] Python 3 bulunamadi."
    exit 1
fi

if [[ "$BUILD_DIR" == "$PROJECT_DIR" ]] || [[ ! -x "$BUILD_DIR/.venv/bin/python" ]]; then
    echo "[*] Bagimliliklar kontrol ediliyor..."
    "$PYTHON" -m pip install -r "$PROJECT_DIR/requirements.txt" pyinstaller
fi

cd "$BUILD_DIR"

echo "[*] Eski derleme dosyalari temizleniyor..."
rm -rf build/linux dist/linux
mkdir -p dist/linux

echo "[*] Linux binary dosyasi olusturuluyor..."
"$PYTHON" -m PyInstaller \
    --onefile \
    --name PertoperVPN \
    --distpath dist/linux \
    --workpath build/linux \
    --specpath build \
    --clean \
    --noconfirm \
    pertoper_vpn.py

chmod +x dist/linux/PertoperVPN

if [[ "$BUILD_DIR" != "$PROJECT_DIR" ]]; then
    mkdir -p "$PROJECT_DIR/dist/linux"
    cp -a "$BUILD_DIR/dist/linux/PertoperVPN" "$PROJECT_DIR/dist/linux/PertoperVPN"
fi

echo
echo "[OK] Linux derlemesi tamamlandi."
echo "[OK] Cikti: $PROJECT_DIR/dist/linux/PertoperVPN"

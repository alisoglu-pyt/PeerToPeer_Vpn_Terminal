#!/usr/bin/env bash
# =======================================================
#  Pertoper P2P VPN - Linux AppImage Derleme Betigi
#  Gelistirici: Bekir Alisoglu
#
#  PyInstaller ile tek dosya binary olusturur, bir AppDir
#  hazirlar ve appimagetool ile .AppImage paketini uretir.
#
#  Kullanim:
#    ./build_appimage.sh
#
#  Gereksinimler: python3 + pip, curl, file
#  Cikti: dist/appimage/PertoperVPN-<surum>-x86_64.AppImage
# =======================================================
set -Eeuo pipefail

APP_NAME="PertoperVPN"
VERSION="$(grep -oP '^VERSION = "\K[^"]+' pertoper_vpn.py 2>/dev/null || echo "3.4")"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="$PROJECT_DIR/build/appimage"
APPDIR="$BUILD_ROOT/${APP_NAME}.AppDir"
PYI_DIST="$BUILD_ROOT/pyinstaller"
TOOLS_DIR="$BUILD_ROOT/tools"
DIST_DIR="$PROJECT_DIR/dist/appimage"
TOOL="${TOOLS_DIR}/appimagetool-x86_64.AppImage"
TOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"

# PyInstaller, `ldd` ciktisindeki yollari ilk boslukta kestigi icin bosluk
# iceren yollarda hata verir; proje yolu boslukluysa gecici dizinde derle.
SOURCE_DIR="$PROJECT_DIR"
TMP_DIR=""
cleanup() { [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; }
trap cleanup EXIT
if [[ "$PROJECT_DIR" == *[[:space:]]* ]]; then
    echo "[!] Yol bosluk iceriyor, gecici dizinde derleniyor..."
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pertoper-appimage.XXXXXX")"
    SOURCE_DIR="$TMP_DIR/src"
    mkdir -p "$SOURCE_DIR"
    cp -a "$PROJECT_DIR/pertoper_vpn.py" "$SOURCE_DIR/" 2>/dev/null || true
    cp -a "$PROJECT_DIR/pertoper_vpn.png" "$SOURCE_DIR/" 2>/dev/null || true
fi

PYTHON="python3"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "[HATA] python3 bulunamadi."
    exit 1
fi

echo "==============================================="
echo "  Pertoper P2P VPN - AppImage Derleme (v$VERSION)"
echo "==============================================="

echo "[*] Bagimliliklar kuruluyor..."
"$PYTHON" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
"$PYTHON" -m pip install --quiet pyinstaller cryptography

echo "[*] Eski ciktilar temizleniyor..."
rm -rf "$APPDIR" "$PYI_DIST" "$PROJECT_DIR/build/${APP_NAME}" \
       "$PROJECT_DIR/${APP_NAME}.spec"
mkdir -p "$APPDIR/usr/bin" "$DIST_DIR" "$TOOLS_DIR"

# ── 1) PyInstaller tek dosya binary ──
echo "[*] Tek dosya binary olusturuluyor (PyInstaller)..."
cd "$SOURCE_DIR"
"$PYTHON" -m PyInstaller \
    --onefile \
    --console \
    --name "$APP_NAME" \
    --distpath "$PYI_DIST" \
    --workpath "$BUILD_ROOT/work" \
    --specpath "$BUILD_ROOT" \
    --clean \
    --noconfirm \
    pertoper_vpn.py

install -m 0755 "$PYI_DIST/$APP_NAME" "$APPDIR/usr/bin/$APP_NAME"

# ── 2) AppDir icerigi ──
echo "[*] AppDir hazirlaniyor..."
# Uygulama simgesi (AppImage: ust duzeyde <isim>.png + .DirIcon)
if [[ -f "$SOURCE_DIR/pertoper_vpn.png" ]]; then
    cp -a "$SOURCE_DIR/pertoper_vpn.png" "$APPDIR/$APP_NAME.png"
    cp -a "$SOURCE_DIR/pertoper_vpn.png" "$APPDIR/.DirIcon"
else
    # Simge yoksa appimagetool'un hata vermemesi icin gecici bir ikon uret
    printf '' > "$APPDIR/$APP_NAME.png"
    cp -a "$APPDIR/$APP_NAME.png" "$APPDIR/.DirIcon"
fi

cat > "$APPDIR/$APP_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Peertopeer P2P VPN
GenericName=Peer-to-Peer VPN
Comment=Sunucusuz P2P VPN istemcisi (komut satiri)
Exec=$APP_NAME
Icon=$APP_NAME
Terminal=true
Categories=Network;Security;
Keywords=vpn;p2p;peer;tunnel;
EOF

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
# AppImage giris noktasi: gomulu binary'yi calistirir.
HERE="$(dirname "$(readlink -f "${0}")")"
exec "${HERE}/usr/bin/PertoperVPN" "$@"
EOF
chmod 0755 "$APPDIR/AppRun"

# ── 3) appimagetool ──
if [[ ! -x "$TOOL" ]]; then
    echo "[*] appimagetool indiriliyor..."
    curl -fsSL -o "$TOOL" "$TOOL_URL"
    chmod 0755 "$TOOL"
fi

echo "[*] .AppImage paketleniyor..."
OUT="$DIST_DIR/${APP_NAME}-${VERSION}-x86_64.AppImage"
# appimagetool bir AppImage'dir; FUSE olmayan ortamlarda (konteyner/CI)
# kendini acip calistirmasi icin bu ortam degiskeni kullanilir.
export APPIMAGE_EXTRACT_AND_RUN=1
cd "$BUILD_ROOT"
ARCH=x86_64 "$TOOL" --no-appstream "$APPDIR" "$OUT"
chmod 0755 "$OUT"

echo
echo "==============================================="
echo "[OK] AppImage hazir:"
echo "     $OUT"
echo
echo "Calistirma (TUN icin root/pkexec onerilir):"
echo "     ./$(basename "$OUT")"
echo "     sudo ./$(basename "$OUT")"
echo "==============================================="

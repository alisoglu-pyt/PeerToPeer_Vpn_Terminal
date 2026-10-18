#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Peertopeer P2P VPN v3.4 — Komut Satırı (CLI) + Peer-to-Peer VPN
===============================================================
• VPS sunucusu gerektirmez — doğrudan peer-to-peer bağlantı
• CGNat bypass — STUN + UDP Hole Punching
• Komut satırı arayüzü (argümanlar + interaktif kabuk)
• Tek dosya — hem dinleyici (serve) hem bağlanan (connect)
• AES-256-GCM şifreleme
• TUN sanal ağ adaptörü (gerçek VPN tüneli)

Gereksinimler:
  pip install cryptography
  Windows: wintun.dll dosyasını aynı dizine koyun (https://www.wintun.net)
  Admin/root yetkisi gerekir (TUN adaptörü için)
"""

import argparse
import socket
import struct
import threading
import json
import os
import sys
import time
import queue
import ctypes
import platform
import socketserver
import subprocess
import secrets
import logging
import hashlib
import locale
import urllib.request
from typing import Optional, Tuple
from datetime import datetime

# ── Encoding düzeltmesi (Windows terminal) ────────────────────────────
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── Kriptografi bağımlılığı, çeviri kataloğundan sonra kontrol edilir ─


# ═══════════════════════════════════════════════════════════════════════
#  VPN SABİTLERİ
# ═══════════════════════════════════════════════════════════════════════

VERSION = "3.4"
PROTO_VER = "3"


STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 3478),
    ("stun.sipgate.net", 3478),
    ("stun.ekiga.net", 3478),
]
STUN_MAGIC = 0x2112A442
STUN_TIMEOUT = 3.0  # saniye

MTU           = 1400
KEEPALIVE_SEC = 15
PUNCH_TRIES   = 200     # Agresif delme: çok deneme, yüksek başarı şansı
PUNCH_DELAY   = 0.08    # Denemeler arası bekleme (s) — yüksek paket frekansı
PUNCH_RECV_TIMEOUT = 0.01  # Deneme başına yanıt dinleme penceresi (s)
PUNCH_MAX_SECONDS = 15.0   # İlk delme denemesinin azami süresi (s) — relay'e hızlı düş
PEER_TIMEOUT  = 90
IP_GRACE_SEC  = 600       # Peer düşse de aynı VPN IP'sini bu süre boyunca geri ver
MQTT_STALE_SEC = 90       # Broker'dan bu süre boyunca bayt gelmezse bağlantı kopuk sayılır
MQTT_RECONNECT_MIN = 2.0  # Yeniden bağlanma beklemesi (alt sınır)
MQTT_RECONNECT_MAX = 60.0 # Yeniden bağlanma beklemesi (üst sınır)

VPN_NET    = "10.8.0"
SERVE_IP   = f"{VPN_NET}.1"
CLIENT_IP  = f"{VPN_NET}.2"
HUB_IP     = SERVE_IP                 # Dinleyici (hub) VPN adresi
HUB_PEER_ID = "hub"                   # Hub'ın sabit peer kimliği
IP_POOL_START = 2                     # Peer'lere dağıtılacak ilk son oktet
IP_POOL_END   = 254                   # Peer'lere dağıtılacak son son oktet
NETMASK    = "255.255.255.0"
MQTT_BASE  = "peertopeer_vpn_v3"
KDF_SALT   = b"PeertopeerVPN_P2P_v3_2024"

MSG_HELLO             = b"Peertopeer_HELLO_v3"
MSG_ACK               = b"Peertopeer_ACK_v3"
MSG_ASSIGN            = b"Peertopeer_ASSIGN_v3"
MSG_ROSTER            = b"Peertopeer_ROSTER_v3"
MSG_KA                = b"Peertopeer_KEEPALIVE"
MSG_RELAY_DATA        = b"Peertopeer_RELAY_DATA"
MSG_RELAY_BATCH       = b"Peertopeer_RELAY_BATCH"
MSG_RELAY_DIRECT_PING = b"Peertopeer_RELAY_DPING"
MSG_RELAY_DIRECT_ACK  = b"Peertopeer_RELAY_DACK"

ROSTER_INTERVAL = 3.0   # Hub peer listesini kaç saniyede bir yayınlar (doğrudan UDP)
ROSTER_RELAY_INTERVAL = 15.0  # Relay peer'lerine daha seyrek yayın (veri kanalını rahatlatır)
RELAY_BATCH_INTERVAL  = 0.008      # Relay paketlerini biriktirme penceresi (s)
RELAY_BATCH_MAX_BYTES = 32 * 1024  # Tek MQTT yayınındaki azami yük (byte)

# Kullanıcının peer'lere verdiği takma isimler (diskte kalıcı)
PEER_NAMES_FILE = os.path.join(os.path.expanduser("~"), ".peertopeer_vpn_names.json")

# Kullanıcı tercihleri (Hakkında penceresi dili vb.)
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".peertopeer_vpn_settings.json")

log = logging.getLogger("Peertopeer")


# ═══════════════════════════════════════════════════════════════════════
#  YARDIMCILAR
# ═══════════════════════════════════════════════════════════════════════

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_public_ip_http(timeout: float = 4.0, limit: int = 2) -> Optional[str]:
    """HTTP API üzerinden public IP tespit eder (STUN başarısız olunca yedek).

    Yalnızca STUN sonucu kullanılamadığında çağrıldığı için servis sayısı ve
    zaman aşımı sınırlı tutulur; aksi halde başlangıç gereksiz yere gecikir.
    """
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://api.my-ip.io/v2/ip.txt",
    ]
    for url in services[:max(1, limit)]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PeertopeerVPN/3.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode("utf-8").strip()
                # Basit IP formatı doğrulaması
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return ip
        except Exception:
            continue
    return None


def _is_private_ip(ip: str) -> bool:
    """Adres yerel/özel bir aralıkta mı (RFC1918 + loopback + link-local)?"""
    try:
        parts = [int(p) for p in ip.strip().split(".")]
    except Exception:
        return True
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return True
    a, b = parts[0], parts[1]
    return (a == 0 or a == 10 or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254))


def resolve_public_endpoint(nat_info: dict, local_port: int,
                            upnp_ok: bool = False) -> Tuple[str, int]:
    """Dışarıdan erişilebilir public uç noktayı (ip, port) döndürür.

    STUN başarısız olduğunda NATDetector yerel (LAN) adresi döndürür. Bu adresi
    "public" gibi yayınlamak karşı tarafı erişilemeyen bir adrese yönlendirir:
    peer listesinde yanlış IP görünür ve doğrudan yol hiç kurulamaz. Bu yüzden
    STUN sonucu özel bir adresse HTTP üzerinden gerçek public IP sorulur;
    bulunamazsa uç "yok" olarak bildirilir ve trafik bulut relay'ine kalır.
    """
    ip = str(nat_info.get("public_ip") or "").strip()
    if not ip or _is_private_ip(ip):
        ip = str(get_public_ip_http() or "").strip()
    if not ip or _is_private_ip(ip):
        return "", 0
    port = local_port if upnp_ok else int(nat_info.get("public_port") or 0)
    return (ip, port) if port else ("", 0)


def local_node_name() -> str:
    """Makinenin görünen adı (hostname) — peer'ler arasında paylaşılır.

    HELLO/ACK çerçeveleri "|" ile ayrıldığı için ayırıcı ve yazdırılamayan
    karakterler temizlenir; ad 32 karakterle sınırlanır.
    """
    try:
        name = socket.gethostname().strip()
    except Exception:
        return ""
    name = "".join(ch for ch in name if ch.isprintable() and ch != "|").strip()
    return name[:32]


def tune_socket_buffers(sock, bufsize: int = 4 * 1024 * 1024) -> None:
    """Soketin çekirdek alıcı/gönderici tamponlarını büyütür.

    Varsayılan UDP tamponu (Windows'ta ~64 KB, Linux'ta ~208 KB) yüksek gecikmeli
    hatlarda (BDP) yetersiz kalır; tampon dolunca çekirdek paketi sessizce düşürür
    ve içinden geçen TCP akışı çöker. Bu yüzden veri yolu soketlerinde tamponu
    olabildiğince büyütürüz (işletim sistemi üst sınırına kırpılır).
    """
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, bufsize)
        except Exception:
            pass


def check_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def read_peer_file(path: str) -> Optional[dict]:
    """Peer JSON dosyasını okur; okunamazsa None döner."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def load_peer_names() -> dict:
    """Kayıtlı takma isimleri okur (anahtar: duyurulan hostname, yoksa peer_id)."""
    try:
        with open(PEER_NAMES_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if k and str(v).strip()}
    except Exception:
        pass
    return {}


def save_peer_names(names: dict) -> bool:
    """Takma isimleri diske yazar; başarısız olursa False döner."""
    try:
        with open(PEER_NAMES_FILE, "w", encoding="utf-8") as f:
            json.dump(names, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


# ── Çok dilli arayüz (i18n) ───────────────────────────────────────────
# Katalogdaki her giriş (tr, en, de, fr, es) sırasıyla 5 metin tutar.
# Dil adları kendi dillerinde yazılır; böylece ayrıca çevrilmeleri gerekmez.

LANGUAGES = ("tr", "en", "de", "fr", "es")
_LANG_INDEX = {"tr": 0, "en": 1, "de": 2, "fr": 3, "es": 4}

LANG_NAMES = {
    "tr": "Türkçe",
    "en": "English",
    "de": "Deutsch",
    "fr": "Français",
    "es": "Español",
}

# Windows'ta locale.getlocale() "Turkish_Turkey" gibi adlar döndürür
_LANG_ALIASES = {
    "turkish": "tr", "english": "en", "german": "de", "french": "fr", "spanish": "es",
}

_TEXTS = {
    # Başlık / tepsi
    "tray.show":            ("👁  Pencereyi Göster", "👁  Show Window", "👁  Fenster anzeigen", "👁  Afficher la fenêtre", "👁  Mostrar ventana"),
    "tray.connected":       ("Durum: Bağlı", "Status: Connected", "Status: Verbunden", "État : connecté", "Estado: conectado"),
    "tray.disconnected":    ("Durum: Bağlantısız", "Status: Disconnected", "Status: Getrennt", "État : déconnecté", "Estado: desconectado"),
    "tray.stop":            ("⏹  VPN'i Durdur", "⏹  Stop VPN", "⏹  VPN stoppen", "⏹  Arrêter le VPN", "⏹  Detener VPN"),
    "tray.start":           ("▶  VPN'i Başlat", "▶  Start VPN", "▶  VPN starten", "▶  Démarrer le VPN", "▶  Iniciar VPN"),
    "tray.quit":            ("❌  Çıkış", "❌  Exit", "❌  Beenden", "❌  Quitter", "❌  Salir"),

    # Tepsi araç ipucu
    "tip.idle":             ("Peertopeer VPN — Hazır", "Peertopeer VPN — Ready", "Peertopeer VPN — Bereit", "Peertopeer VPN — Prêt", "Peertopeer VPN — Listo"),
    "tip.disconnected":     ("Peertopeer VPN — Bağlantı Kesildi", "Peertopeer VPN — Disconnected", "Peertopeer VPN — Getrennt", "Peertopeer VPN — Déconnecté", "Peertopeer VPN — Desconectado"),
    "tip.error":            ("Peertopeer VPN — Hata", "Peertopeer VPN — Error", "Peertopeer VPN — Fehler", "Peertopeer VPN — Erreur", "Peertopeer VPN — Error"),
    "tip.discovering":      ("Peertopeer VPN — STUN Keşfi...", "Peertopeer VPN — STUN discovery...", "Peertopeer VPN — STUN-Erkennung...", "Peertopeer VPN — Découverte STUN...", "Peertopeer VPN — Descubriendo STUN..."),
    "tip.punching":         ("Peertopeer VPN — Bağlanıyor...", "Peertopeer VPN — Connecting...", "Peertopeer VPN — Verbinden...", "Peertopeer VPN — Connexion...", "Peertopeer VPN — Conectando..."),
    "tip.waiting":          ("Peertopeer VPN — Peer Bekleniyor...", "Peertopeer VPN — Waiting for peer...", "Peertopeer VPN — Warte auf Peer...", "Peertopeer VPN — En attente d'un pair...", "Peertopeer VPN — Esperando par..."),
    "tip.listening":        ("Peertopeer VPN — Dinleniyor / Hub ({ip})", "Peertopeer VPN — Listening / Hub ({ip})", "Peertopeer VPN — Wartet / Hub ({ip})", "Peertopeer VPN — Écoute / Hub ({ip})", "Peertopeer VPN — Escuchando / Hub ({ip})"),
    "tip.connected":        ("Peertopeer VPN — Bağlı ({ip})", "Peertopeer VPN — Connected ({ip})", "Peertopeer VPN — Verbunden ({ip})", "Peertopeer VPN — Connecté ({ip})", "Peertopeer VPN — Conectado ({ip})"),
    "tip.direct":           ("Peertopeer VPN — Doğrudan P2P Bağlı ({ip})", "Peertopeer VPN — Direct P2P connected ({ip})", "Peertopeer VPN — Direkt P2P verbunden ({ip})", "Peertopeer VPN — Connecté en P2P direct ({ip})", "Peertopeer VPN — Conectado P2P directo ({ip})"),
    "tip.relay":            ("Peertopeer VPN — Bulut Relay Aktarma Bağlı ({ip})", "Peertopeer VPN — Connected via cloud relay ({ip})", "Peertopeer VPN — Über Cloud-Relay verbunden ({ip})", "Peertopeer VPN — Connecté via relais cloud ({ip})", "Peertopeer VPN — Conectado por relé en la nube ({ip})"),

    # Bildirimler
    "notif.connected_title":  ("VPN Bağlandı", "VPN Connected", "VPN verbunden", "VPN connecté", "VPN conectada"),
    "notif.connected_body":   ("VPN tüneli aktif ({mode})!\nIP: {ip}", "VPN tunnel is up ({mode})!\nIP: {ip}", "VPN-Tunnel aktiv ({mode})!\nIP: {ip}", "Tunnel VPN actif ({mode}) !\nIP : {ip}", "¡Túnel VPN activo ({mode})!\nIP: {ip}"),
    "notif.disconnected_title": ("VPN Kesildi", "VPN Disconnected", "VPN getrennt", "VPN déconnecté", "VPN desconectada"),
    "notif.disconnected_body":  ("VPN bağlantısı sonlandı.", "VPN connection terminated.", "VPN-Verbindung beendet.", "Connexion VPN terminée.", "Conexión VPN finalizada."),
    "notif.tray_title":       ("Peertopeer P2P VPN", "Peertopeer P2P VPN", "Peertopeer P2P VPN", "Peertopeer P2P VPN", "Peertopeer P2P VPN"),
    "notif.tray_body":        ("Uygulama arka planda sistem tepsisinde çalışıyor.\nGeri açmak için tepsi simgesine tıklayın.", "The app keeps running in the system tray.\nClick the tray icon to bring it back.", "Die App läuft weiter im System-Tray.\nKlicken Sie auf das Tray-Symbol, um sie zu öffnen.", "L'application reste dans la zone de notification.\nCliquez sur l'icône pour la rouvrir.", "La aplicación sigue en la bandeja del sistema.\nHaz clic en el icono para volver a abrirla."),
    "notif.minimized_body":   ("VPN bağlantısı kesilmedi, arka planda çalışmaya devam ediyor.\nTamamen çıkmak için tepsi simgesine sağ tıklayın.", "The VPN stays connected and keeps running in the background.\nRight-click the tray icon to exit completely.", "Die VPN-Verbindung bleibt bestehen und läuft im Hintergrund weiter.\nZum Beenden rechtsklick auf das Tray-Symbol.", "La connexion VPN reste active en arrière-plan.\nClic droit sur l'icône pour quitter complètement.", "La conexión VPN sigue activa en segundo plano.\nHaz clic derecho en el icono para salir del todo."),

    # Üst şerit / mod
    "hdr.about":            ("ℹ Hakkında", "ℹ About", "ℹ Über", "ℹ À propos", "ℹ Acerca de"),
    "hdr.tray":             ("📥 Tepsiye", "📥 To tray", "📥 In den Tray", "📥 Réduire", "📥 A la bandeja"),
    "hdr.offline":          ("Bağlantısız", "Offline", "Offline", "Hors ligne", "Desconectado"),
    "mode.hub":             ("Dinleyici", "Listener", "Listener", "Écouteur", "Receptor"),
    "mode.client":          ("Bağlan", "Connect", "Verbinden", "Se connecter", "Conectar"),
    "mode.hub_label":       ("Hub/Dinleyici", "Hub/Listener", "Hub/Listener", "Hub/Écouteur", "Hub/Receptor"),
    "btn.stun":             ("🔍 STUN Testi", "🔍 STUN Test", "🔍 STUN-Test", "🔍 Test STUN", "🔍 Prueba STUN"),

    # Ayarlar
    "set.title":            ("⚙  Bağlantı Ayarları", "⚙  Connection Settings", "⚙  Verbindungseinstellungen", "⚙  Paramètres de connexion", "⚙  Ajustes de conexión"),
    "set.key":              ("Şifreleme Anahtarı", "Encryption Key", "Verschlüsselungsschlüssel", "Clé de chiffrement", "Clave de cifrado"),
    "set.key_ph":           ("Paylaşılan gizli anahtar", "Shared secret key", "Gemeinsamer geheimer Schlüssel", "Clé secrète partagée", "Clave secreta compartida"),
    "set.port":             ("Port", "Port", "Port", "Port", "Puerto"),
    "set.peer_addr":        ("Peer Adresi (opsiyonel)", "Peer Address (optional)", "Peer-Adresse (optional)", "Adresse du pair (facultatif)", "Dirección del par (opcional)"),
    "set.peer_addr_ph":     ("IP:PORT (opsiyonel — bulut eşleşmesi)", "IP:PORT (optional — cloud matching)", "IP:PORT (optional — Cloud-Abgleich)", "IP:PORT (facultatif — appariement cloud)", "IP:PORT (opcional — emparejamiento en la nube)"),
    "set.peer_addr_ph_auto": ("IP:PORT (opsiyonel — otomatik eşleşme devrede)", "IP:PORT (optional — auto matching enabled)", "IP:PORT (optional — Auto-Abgleich aktiv)", "IP:PORT (facultatif — appariement auto actif)", "IP:PORT (opcional — emparejamiento automático activo)"),
    "set.peer_file":        ("Peer Dosyası (opsiyonel)", "Peer File (optional)", "Peer-Datei (optional)", "Fichier du pair (facultatif)", "Archivo del par (opcional)"),
    "set.peer_file_ph":     ("peer.json (opsiyonel)", "peer.json (optional)", "peer.json (optional)", "peer.json (facultatif)", "peer.json (opcional)"),
    "set.peer_file_ph_hub": ("peer_info.json (şifre dosyadan yüklenir)", "peer_info.json (key loaded from file)", "peer_info.json (Schlüssel aus Datei)", "peer_info.json (clé lue depuis le fichier)", "peer_info.json (clave desde el archivo)"),
    "set.export":           ("Dışa Aktar (opsiyonel)", "Export (optional)", "Exportieren (optional)", "Exporter (facultatif)", "Exportar (opcional)"),
    "set.export_short":     ("Dışa Aktar", "Export", "Exportieren", "Exporter", "Exportar"),
    "set.export_ph":        ("peer_info.json (opsiyonel)", "peer_info.json (optional)", "peer_info.json (optional)", "peer_info.json (facultatif)", "peer_info.json (opcional)"),
    "set.export_ph_key":    ("peer_info.json (şifre dahil)", "peer_info.json (includes key)", "peer_info.json (inkl. Schlüssel)", "peer_info.json (clé incluse)", "peer_info.json (incluye clave)"),
    "set.cgnat_peer":       ("CGNat Peer (opsiyonel)", "CGNAT Peer (optional)", "CGNAT-Peer (optional)", "Pair CGNAT (facultatif)", "Par CGNAT (opcional)"),
    "set.auto":             (" ☁  Otomatik Eşleşme (Aynı anahtarla doğrudan bağlan — dosya gerekmez)", " ☁  Auto matching (connect directly with the same key — no file needed)", " ☁  Auto-Abgleich (direkt mit gleichem Schlüssel verbinden — keine Datei nötig)", " ☁  Appariement auto (connexion directe avec la même clé — aucun fichier requis)", " ☁  Emparejamiento automático (conéctate con la misma clave — sin archivo)"),

    # Butonlar
    "btn.start":            ("▶  BAŞLAT", "▶  START", "▶  STARTEN", "▶  DÉMARRER", "▶  INICIAR"),
    "btn.stop":             ("⏹  DURDUR", "⏹  STOP", "⏹  STOPPEN", "⏹  ARRÊTER", "⏹  DETENER"),
    "btn.peers":            ("☰  Peer'ler ({n})  {arrow}", "☰  Peers ({n})  {arrow}", "☰  Peers ({n})  {arrow}", "☰  Pairs ({n})  {arrow}", "☰  Pares ({n})  {arrow}"),

    # Gösterge kartları
    "stat.public":          ("Public Adres", "Public Address", "Öffentliche Adresse", "Adresse publique", "Dirección pública"),
    "stat.vpn":             ("VPN IP", "VPN IP", "VPN-IP", "IP VPN", "IP de VPN"),
    "stat.tx":              ("↑ Gönderim", "↑ Upload", "↑ Senden", "↑ Envoi", "↑ Subida"),
    "stat.rx":              ("↓ Alım", "↓ Download", "↓ Empfangen", "↓ Réception", "↓ Bajada"),
    "stat.uptime":          ("⏱ Süre", "⏱ Uptime", "⏱ Laufzeit", "⏱ Durée", "⏱ Duración"),

    # Taşıma
    "trn.direct":           ("Doğrudan P2P", "Direct P2P", "Direkt P2P", "P2P direct", "P2P directo"),
    "trn.relay":            ("Bulut Relay", "Cloud Relay", "Cloud-Relay", "Relais cloud", "Relé en la nube"),
    "trn.relay_secure":     ("Bulut Güvenli Relay", "Secure Cloud Relay", "Sicherer Cloud-Relay", "Relais cloud sécurisé", "Relé en la nube seguro"),

    # Peer paneli
    "prs.title":            ("☰  Bağlı Peer'ler ({n})", "☰  Connected Peers ({n})", "☰  Verbundene Peers ({n})", "☰  Pairs connectés ({n})", "☰  Pares conectados ({n})"),
    "prs.close":            ("✕ Kapat", "✕ Close", "✕ Schließen", "✕ Fermer", "✕ Cerrar"),
    "prs.col_name":         ("İsim", "Name", "Name", "Nom", "Nombre"),
    "prs.col_transport":    ("Taşıma", "Transport", "Transport", "Transport", "Transporte"),
    "prs.empty":            ("bağlı peer yok", "no peers connected", "keine Peers verbunden", "aucun pair connecté", "sin pares conectados"),
    "prs.hint_hub":         ("Hub — isim vermek için satıra çift tıkla", "Hub — double-click a row to name a peer", "Hub — Zeile doppelklicken, um einen Peer zu benennen", "Hub — double-cliquez sur une ligne pour nommer un pair", "Hub — haz doble clic en una fila para nombrar un par"),
    "prs.hint_client":      ("{peer} · isim için çift tıkla", "{peer} · double-click to rename", "{peer} · Doppelklick zum Umbenennen", "{peer} · double-cliquez pour renommer", "{peer} · doble clic para renombrar"),
    "prs.hint_default":     ("Hub bağlantısı", "Hub connection", "Hub-Verbindung", "Connexion au hub", "Conexión al hub"),
    "prs.rename_title":     ("Takma isim", "Nickname", "Spitzname", "Surnom", "Alias"),
    "prs.rename_prompt":    ("'{current}' için görünen ad:\n(boş bırakıp OK derseniz takma isim silinir)", "Display name for '{current}':\n(leave empty and press OK to remove the nickname)", "Anzeigename für '{current}':\n(leer lassen und OK drücken, um den Spitznamen zu entfernen)", "Nom affiché pour « {current} » :\n(laissez vide et validez pour supprimer le surnom)", "Nombre para mostrar de '{current}':\n(déjalo vacío y pulsa Aceptar para borrar el alias)"),
    "prs.name_saved":       ("🏷 Peer adı kaydedildi: {name}", "🏷 Peer name saved: {name}", "🏷 Peer-Name gespeichert: {name}", "🏷 Nom du pair enregistré : {name}", "🏷 Nombre del par guardado: {name}"),
    "prs.name_save_failed": ("Ad kaydedilemedi: {path}", "Could not save the name: {path}", "Name konnte nicht gespeichert werden: {path}", "Impossible d'enregistrer le nom : {path}", "No se pudo guardar el nombre: {path}"),

    # Log paneli
    "log.title":            ("📋  Log", "📋  Log", "📋  Log", "📋  Journal", "📋  Registro"),
    "log.clear":            ("🗑 Temizle", "🗑 Clear", "🗑 Leeren", "🗑 Effacer", "🗑 Limpiar"),
    "log.app_started":      ("Peertopeer P2P VPN v{v} başlatıldı", "Peertopeer P2P VPN v{v} started", "Peertopeer P2P VPN v{v} gestartet", "Peertopeer P2P VPN v{v} démarré", "Peertopeer P2P VPN v{v} iniciado"),
    "log.platform":         ("Platform: {os} {arch}", "Platform: {os} {arch}", "Plattform: {os} {arch}", "Plateforme : {os} {arch}", "Plataforma: {os} {arch}"),
    "log.crypto":           ("Şifreleme: AES-256-GCM (PBKDF2)", "Encryption: AES-256-GCM (PBKDF2)", "Verschlüsselung: AES-256-GCM (PBKDF2)", "Chiffrement : AES-256-GCM (PBKDF2)", "Cifrado: AES-256-GCM (PBKDF2)"),
    "log.no_admin":         ("Admin yetkisi yok — TUN için yönetici olarak çalıştırın", "No admin rights — run as administrator for the TUN adapter", "Keine Administratorrechte — für das TUN-Gerät als Administrator ausführen", "Pas de droits administrateur — lancez en tant qu'administrateur pour le TUN", "Sin permisos de administrador — ejecuta como administrador para el TUN"),
    "log.pkexec":           ("pkexec yükseltmesi başarısız/iptal — TUN açılamayabilir. İsterseniz uygulamayı terminalden 'sudo <yol>/PertoperVPN' ile çalıştırın.", "pkexec elevation failed/cancelled — the TUN may not open. If needed, run the app from a terminal with 'sudo <path>/PertoperVPN'.", "pkexec-Erhöhung fehlgeschlagen/abgebrochen — das TUN öffnet eventuell nicht. Starten Sie die App ggf. im Terminal mit 'sudo <Pfad>/PertoperVPN'.", "Élévation pkexec échouée/annulée — le TUN risque de ne pas s'ouvrir. Au besoin, lancez l'application avec « sudo <chemin>/PertoperVPN ».", "Elevación pkexec fallida/cancelada — puede que el TUN no se abra. Si hace falta, ejecuta la app con 'sudo <ruta>/PertoperVPN'."),

    # Durum çubuğu
    "sb.ready":             ("Hazır", "Ready", "Bereit", "Prêt", "Listo"),
    "sb.info":              ("AES-256-GCM  │  {os} {arch}  │  v{v}", "AES-256-GCM  │  {os} {arch}  │  v{v}", "AES-256-GCM  │  {os} {arch}  │  v{v}", "AES-256-GCM  │  {os} {arch}  │  v{v}", "AES-256-GCM  │  {os} {arch}  │  v{v}"),

    # Durum metinleri (üst şerit rozeti + durum çubuğu)
    "st.idle":              ("Bağlantısız", "Offline", "Offline", "Hors ligne", "Desconectado"),
    "st.idle_sb":           ("Hazır", "Ready", "Bereit", "Prêt", "Listo"),
    "st.discovering":       ("STUN & NAT analizi...", "STUN & NAT analysis...", "STUN- & NAT-Analyse...", "Analyse STUN et NAT...", "Análisis STUN y NAT..."),
    "st.discovering_sb":    ("Analiz ediliyor", "Analysing", "Analyse läuft", "Analyse en cours", "Analizando"),
    "st.waiting":           ("Peer bekleniyor...", "Waiting for peer...", "Warte auf Peer...", "En attente d'un pair...", "Esperando par..."),
    "st.waiting_sb":        ("Bekleniyor", "Waiting", "Warten", "En attente", "Esperando"),
    "st.listening":         ("Dinleniyor (Hub)", "Listening (hub)", "Wartet (Hub)", "Écoute (hub)", "Escuchando (hub)"),
    "st.listening_sb":      ("VPN Aktif (Hub)", "VPN active (hub)", "VPN aktiv (Hub)", "VPN actif (hub)", "VPN activa (hub)"),
    "st.punching":          ("Hole Punch...", "Hole punching...", "Hole Punching...", "Hole punching...", "Hole punching..."),
    "st.punching_sb":       ("Bağlanıyor", "Connecting", "Verbinden", "Connexion", "Conectando"),
    "st.connected_direct":  ("Bağlı (Doğrudan P2P)", "Connected (direct P2P)", "Verbunden (direkt P2P)", "Connecté (P2P direct)", "Conectado (P2P directo)"),
    "st.connected_direct_sb": ("VPN Aktif (P2P)", "VPN active (P2P)", "VPN aktiv (P2P)", "VPN actif (P2P)", "VPN activa (P2P)"),
    "st.connected_relay":   ("Bağlı (Bulut Relay)", "Connected (cloud relay)", "Verbunden (Cloud-Relay)", "Connecté (relais cloud)", "Conectado (relé en la nube)"),
    "st.connected_relay_sb": ("VPN Aktif (Relay)", "VPN active (relay)", "VPN aktiv (Relay)", "VPN actif (relais)", "VPN activa (relé)"),
    "st.disconnected":      ("Bağlantı kesildi", "Disconnected", "Getrennt", "Déconnecté", "Desconectado"),
    "st.disconnected_sb":   ("Kesildi", "Disconnected", "Getrennt", "Déconnecté", "Desconectado"),
    "st.error":             ("Hata", "Error", "Fehler", "Erreur", "Error"),
    "st.error_sb":          ("Hata", "Error", "Fehler", "Erreur", "Error"),

    # Doğrulama ve diyaloglar
    "err.key_required":     ("Şifreleme anahtarı gerekli!", "Encryption key is required!", "Verschlüsselungsschlüssel erforderlich!", "Clé de chiffrement requise !", "¡Se requiere la clave de cifrado!"),
    "err.bad_port":         ("Geçersiz port numarası!", "Invalid port number!", "Ungültige Portnummer!", "Numéro de port invalide !", "¡Número de puerto no válido!"),
    "err.cgnat_format":     ("CGNat peer formatı: IP:PORT", "CGNAT peer format: IP:PORT", "CGNAT-Peer-Format: IP:PORT", "Format du pair CGNAT : IP:PORT", "Formato del par CGNAT: IP:PORT"),
    "err.peer_required":    ("Peer adresi/dosyası girin veya Otomatik Eşleşmeyi açık bırakın!", "Enter a peer address/file or keep Auto matching enabled!", "Peer-Adresse/-Datei angeben oder Auto-Abgleich aktiviert lassen!", "Saisissez une adresse/un fichier de pair ou laissez l'appariement auto activé !", "Introduce una dirección/archivo de par o deja el emparejamiento automático activado."),
    "err.peer_format":      ("Peer adresi formatı: IP:PORT", "Peer address format: IP:PORT", "Peer-Adressformat: IP:PORT", "Format de l'adresse du pair : IP:PORT", "Formato de dirección del par: IP:PORT"),
    "err.peer_file_missing": ("Peer dosyası bulunamadı!", "Peer file not found!", "Peer-Datei nicht gefunden!", "Fichier du pair introuvable !", "¡Archivo del par no encontrado!"),
    "dlg.peer_file_title":  ("Peer Dosyası Seç", "Select Peer File", "Peer-Datei wählen", "Choisir le fichier du pair", "Seleccionar archivo del par"),
    "dlg.filetype_all":     ("Tümü", "All", "Alle", "Tous", "Todos"),
    "dlg.save_peer_title":  ("Peer Bilgilerini Kaydet", "Save Peer Info", "Peer-Infos speichern", "Enregistrer les infos du pair", "Guardar información del par"),
    "dlg.tray_title":       ("Sistem Tepsisi", "System Tray", "System-Tray", "Zone de notification", "Bandeja del sistema"),
    "dlg.tray_body":        ("Sistem tepsisi (pystray) modülü yüklenemediği için arka plana gizlenemiyor.{detail}", "Cannot hide to the background because the system tray (pystray) module failed to load.{detail}", "Das Ausblenden in den Hintergrund ist nicht möglich, weil das System-Tray-Modul (pystray) nicht geladen werden konnte.{detail}", "Impossible de réduire en arrière-plan : le module de zone de notification (pystray) n'a pas pu être chargé.{detail}", "No se puede ocultar en segundo plano porque el módulo de bandeja (pystray) no se pudo cargar.{detail}"),
    "dlg.tray_detail":      ("\n\nHata detayı: {err}", "\n\nError details: {err}", "\n\nFehlerdetails: {err}", "\n\nDétails de l'erreur : {err}", "\n\nDetalles del error: {err}"),
    "dlg.close_title":      ("Peertopeer VPN", "Peertopeer VPN", "Peertopeer VPN", "Peertopeer VPN", "Peertopeer VPN"),
    "dlg.quit_confirm":     ("Uygulamadan tamamen çıkılsın mı?\n\n(Arka planda sistem tepsisinde çalıştırmak için 'Hayır'ı seçin)", "Exit the application completely?\n\n(Choose 'No' to keep it running in the system tray)", "Anwendung vollständig beenden?\n\n('Nein' wählen, um sie im System-Tray weiterlaufen zu lassen)", "Quitter complètement l'application ?\n\n(Choisissez « Non » pour la laisser dans la zone de notification)", "¿Salir completamente de la aplicación?\n\n(Elige 'No' para dejarla en la bandeja del sistema)"),
    "dlg.stop_confirm":     ("VPN bağlantısı aktif.\nKapatmak istediğinizden emin misiniz?", "The VPN connection is active.\nAre you sure you want to close?", "Die VPN-Verbindung ist aktiv.\nMöchten Sie wirklich schließen?", "La connexion VPN est active.\nVoulez-vous vraiment fermer ?", "La conexión VPN está activa.\n¿Seguro que quieres cerrar?"),
    "dep.title":            ("Eksik Bağımlılık", "Missing Dependency", "Fehlende Abhängigkeit", "Dépendance manquante", "Dependencia faltante"),
    "dep.body":             ("'cryptography' paketi gerekli!\n\nYüklemek için:\npip install cryptography", "'cryptography' package is required!\n\nTo install:\npip install cryptography", "Das Paket 'cryptography' wird benötigt!\n\nInstallation:\npip install cryptography", "Le paquet 'cryptography' est requis !\n\nPour l'installer :\npip install cryptography", "¡Se requiere el paquete 'cryptography'!\n\nPara instalarlo:\npip install cryptography"),

    # STUN / anahtar yardımcıları
    "stun.starting":        ("STUN, NAT tipi ve UPnP analizi başlatılıyor...", "Starting STUN, NAT type and UPnP analysis...", "STUN-, NAT- und UPnP-Analyse wird gestartet...", "Démarrage de l'analyse STUN, NAT et UPnP...", "Iniciando el análisis de STUN, NAT y UPnP..."),
    "stun.public":          ("Public IP: {ip}", "Public IP: {ip}", "Öffentliche IP: {ip}", "IP publique : {ip}", "IP pública: {ip}"),
    "stun.local":           ("Yerel IP: {ip}", "Local IP: {ip}", "Lokale IP: {ip}", "IP locale : {ip}", "IP local: {ip}"),
    "stun.nat":             ("Ağ / NAT Tipi: {info}", "Network / NAT type: {info}", "Netzwerk-/NAT-Typ: {info}", "Type de réseau / NAT : {info}", "Tipo de red / NAT: {info}"),
    "stun.port_behavior":   ("Port Davranışı: {info}", "Port behaviour: {info}", "Portverhalten: {info}", "Comportement du port : {info}", "Comportamiento del puerto: {info}"),
    "stun.failed":          ("STUN / NAT tespiti başarısız!", "STUN / NAT detection failed!", "STUN-/NAT-Erkennung fehlgeschlagen!", "Échec de la détection STUN / NAT !", "¡Falló la detección de STUN / NAT!"),
    "stun.upnp_yes":        ("✅ UPnP Desteği: VAR ({service})", "✅ UPnP support: YES ({service})", "✅ UPnP-Unterstützung: JA ({service})", "✅ Prise en charge UPnP : OUI ({service})", "✅ Compatibilidad UPnP: SÍ ({service})"),
    "stun.upnp_no":         ("ℹ UPnP Desteği: Yok (STUN + Delme / Güvenli Relay kullanılır)", "ℹ UPnP support: none (STUN + punching / secure relay is used)", "ℹ UPnP-Unterstützung: keine (STUN + Punching / sicherer Relay wird genutzt)", "ℹ Prise en charge UPnP : aucune (STUN + perforation / relais sécurisé utilisé)", "ℹ Compatibilidad UPnP: ninguna (se usa STUN + perforación / relé seguro)"),
    "stun.nat_result":      ("Ağ Tipi: {info}", "Network type: {info}", "Netzwerktyp: {info}", "Type de réseau : {info}", "Tipo de red: {info}"),
    "key.generated":        ("Rastgele anahtar üretildi ve panoya kopyalandı ({n} karakter)", "Random key generated and copied to the clipboard ({n} characters)", "Zufälliger Schlüssel erzeugt und in die Zwischenablage kopiert ({n} Zeichen)", "Clé aléatoire générée et copiée dans le presse-papiers ({n} caractères)", "Clave aleatoria generada y copiada al portapapeles ({n} caracteres)"),
    "desktop.comment":      ("Sunucusuz P2P VPN istemcisi", "Serverless P2P VPN client", "Serverloser P2P-VPN-Client", "Client VPN P2P sans serveur", "Cliente VPN P2P sin servidor"),
    "key.loaded_file":      ("Şifreleme anahtarı peer dosyasından yüklendi.", "Encryption key loaded from the peer file.", "Verschlüsselungsschlüssel aus der Peer-Datei geladen.", "Clé de chiffrement chargée depuis le fichier du pair.", "Clave de cifrado cargada desde el archivo del par."),

    # Motor logları
    "eng.cloud_room":       ("Bulut eşleşme odası: {room}...", "Cloud match room: {room}...", "Cloud-Abgleichraum: {room}...", "Salle d'appariement cloud : {room}...", "Sala de emparejamiento en la nube: {room}..."),
    "eng.cloud_connected":  ("✅ Bulut sunucusuna bağlandı — Eşleşme kanalı hazır.", "✅ Connected to the cloud server — matching channel ready.", "✅ Mit dem Cloud-Server verbunden — Abgleichkanal bereit.", "✅ Connecté au serveur cloud — canal d'appariement prêt.", "✅ Conectado al servidor en la nube — canal de emparejamiento listo."),
    "eng.cloud_unreachable": ("Bulut sunucusuna ulaşılamadı — Manuel mod devrede.", "Cloud server unreachable — manual mode is active.", "Cloud-Server nicht erreichbar — manueller Modus aktiv.", "Serveur cloud injoignable — mode manuel actif.", "Servidor en la nube inaccesible — modo manual activo."),
    "eng.port_fail":        ("Port {port} bağlanamadı: {err}", "Could not bind port {port}: {err}", "Port {port} konnte nicht gebunden werden: {err}", "Impossible de lier le port {port} : {err}", "No se pudo enlazar el puerto {port}: {err}"),
    "eng.listening":        ("UDP port {port} dinleniyor", "Listening on UDP port {port}", "Warte auf UDP-Port {port}", "Écoute sur le port UDP {port}", "Escuchando en el puerto UDP {port}"),
    "eng.firewall":         ("Windows Güvenlik Duvarı kuralı eklendi (Port {port})", "Windows Firewall rule added (port {port})", "Windows-Firewall-Regel hinzugefügt (Port {port})", "Règle de pare-feu Windows ajoutée (port {port})", "Regla de firewall de Windows añadida (puerto {port})"),
    "eng.firewall_linux":   ("Linux güvenlik duvarı kuralı eklendi (UDP {port})", "Linux firewall rule added (UDP {port})", "Linux-Firewall-Regel hinzugefügt (UDP {port})", "Règle de pare-feu Linux ajoutée (UDP {port})", "Regla de firewall de Linux añadida (UDP {port})"),
    "eng.firewall_icmp":    ("Windows Güvenlik Duvarı ICMP (ping) kuralı eklendi (VPN {net})", "Windows Firewall ICMP (ping) rule added (VPN {net})", "Windows-Firewall-ICMP-Regel (Ping) hinzugefügt (VPN {net})", "Règle ICMP (ping) du pare-feu Windows ajoutée (VPN {net})", "Regla ICMP (ping) del firewall de Windows añadida (VPN {net})"),
    "eng.firewall_subnet":  ("Windows Güvenlik Duvarı VPN alt ağı erişim kuralı eklendi (VPN {net})", "Windows Firewall VPN subnet access rule added (VPN {net})", "Windows-Firewall-Zugriffsregel für VPN-Subnetz hinzugefügt (VPN {net})", "Règle d'accès au sous-réseau VPN du pare-feu Windows ajoutée (VPN {net})", "Regla de acceso a la subred VPN del firewall de Windows añadida (VPN {net})"),
    "eng.net_private_ok":   ("Windows ağ profili 'Özel' yapıldı — peer'ler arası ping/erişim açık ({iface})", "Windows network profile set to 'Private' — peer-to-peer ping/access enabled ({iface})", "Windows-Netzwerkprofil auf 'Privat' gesetzt — Ping/Zugriff zwischen Peers aktiviert ({iface})", "Profil réseau Windows défini sur « Privé » — ping/accès entre pairs activé ({iface})", "Perfil de red de Windows establecido en 'Privada' — ping/acceso entre pares activado ({iface})"),
    "eng.net_private_fail": ("Windows ağ profili 'Özel' yapılamadı — peer'ler arası ping/erişim engellenebilir ({iface})", "Could not set the Windows network profile to 'Private' — peer-to-peer ping/access may be blocked ({iface})", "Windows-Netzwerkprofil konnte nicht auf 'Privat' gesetzt werden — Ping/Zugriff zwischen Peers evtl. blockiert ({iface})", "Impossible de définir le profil réseau Windows sur « Privé » — ping/accès entre pairs peut être bloqué ({iface})", "No se pudo establecer el perfil de red de Windows en 'Privada' — el ping/acceso entre pares puede estar bloqueado ({iface})"),
    "eng.upnp_trying":      ("Router UPnP port yönlendirmesi deneniyor...", "Trying UPnP port forwarding on the router...", "UPnP-Portweiterleitung am Router wird versucht...", "Tentative de redirection de port UPnP sur le routeur...", "Probando el reenvío de puertos UPnP en el router..."),
    "eng.upnp_ok":          ("✅ UPnP: Router'da port {port} otomatik açıldı (Firewall aşıldı!)", "✅ UPnP: port {port} opened automatically on the router (firewall bypassed!)", "✅ UPnP: Port {port} am Router automatisch geöffnet (Firewall umgangen!)", "✅ UPnP : port {port} ouvert automatiquement sur le routeur (pare-feu contourné !)", "✅ UPnP: puerto {port} abierto automáticamente en el router (¡firewall superado!)"),
    "eng.upnp_no":          ("UPnP yanıt vermedi — STUN + UDP Hole Punching devrede.", "UPnP did not respond — STUN + UDP hole punching is active.", "UPnP hat nicht geantwortet — STUN + UDP-Hole-Punching aktiv.", "UPnP n'a pas répondu — STUN + perforation UDP actifs.", "UPnP no respondió — STUN + UDP hole punching activos."),
    "eng.nat_analyzing":    ("NAT tipi ve dış port davranışı analiz ediliyor...", "Analysing NAT type and external port behaviour...", "NAT-Typ und externes Portverhalten werden analysiert...", "Analyse du type de NAT et du comportement de port externe...", "Analizando el tipo de NAT y el comportamiento del puerto externo..."),
    "eng.nat_result":       ("NAT Tipi: {info}", "NAT type: {info}", "NAT-Typ: {info}", "Type de NAT : {info}", "Tipo de NAT: {info}"),
    "eng.public_stun":      ("Public Adres (STUN): {addr}", "Public address (STUN): {addr}", "Öffentliche Adresse (STUN): {addr}", "Adresse publique (STUN) : {addr}", "Dirección pública (STUN): {addr}"),
    "eng.public_unknown":   ("Public adres belirlenemedi — doğrudan yol kurulamaz, bulut relay kullanılacak.", "Could not determine a public address — no direct path, cloud relay will be used.", "Öffentliche Adresse nicht ermittelbar — kein direkter Pfad, Cloud-Relay wird genutzt.", "Adresse publique introuvable — pas de chemin direct, le relais cloud sera utilisé.", "No se pudo determinar una dirección pública — sin ruta directa, se usará el relé en la nube."),
    "eng.peer_saved":       ("Peer bilgileri kaydedildi: {file}", "Peer info saved: {file}", "Peer-Infos gespeichert: {file}", "Infos du pair enregistrées : {file}", "Información del par guardada: {file}"),
    "eng.key_in_file":      ("Şifreleme anahtarı da dosyaya eklendi — dosyayı güvenli kanaldan paylaşın.", "The encryption key was added to the file too — share it over a secure channel.", "Der Verschlüsselungsschlüssel wurde ebenfalls in die Datei geschrieben — teilen Sie sie über einen sicheren Kanal.", "La clé de chiffrement a aussi été ajoutée au fichier — partagez-le via un canal sécurisé.", "La clave de cifrado también se añadió al archivo — compártelo por un canal seguro."),
    "eng.file_write_fail":  ("Dosya yazılamadı: {err}", "Could not write the file: {err}", "Datei konnte nicht geschrieben werden: {err}", "Impossible d'écrire le fichier : {err}", "No se pudo escribir el archivo: {err}"),
    "eng.punch_start":      ("Hole punch başlatılıyor → {addr}", "Starting hole punch → {addr}", "Hole Punching wird gestartet → {addr}", "Démarrage de la perforation → {addr}", "Iniciando hole punching → {addr}"),
    "eng.hub_ready":        ("Dinleyici hazır — peer bağlantıları bekleniyor...", "Listener ready — waiting for peer connections...", "Listener bereit — warte auf Peer-Verbindungen...", "Écouteur prêt — en attente des connexions...", "Receptor listo — esperando conexiones de pares..."),
    "eng.sock_fail":        ("Socket hatası: {err}", "Socket error: {err}", "Socket-Fehler: {err}", "Erreur de socket : {err}", "Error de socket: {err}"),
    "eng.local_port":       ("Yerel port: {port}", "Local port: {port}", "Lokaler Port: {port}", "Port local : {port}", "Puerto local: {port}"),
    "eng.peer_id":          ("Peer kimliği: {id}", "Peer ID: {id}", "Peer-ID: {id}", "Identifiant du pair : {id}", "ID del par: {id}"),
    "eng.client_public":    ("İstemci Public Adres: {addr}", "Client public address: {addr}", "Öffentliche Client-Adresse: {addr}", "Adresse publique du client : {addr}", "Dirección pública del cliente: {addr}"),
    "eng.wait_hub":         ("Hub'ın bulut üzerinden eşleşmesi bekleniyor...", "Waiting for the hub to match over the cloud...", "Warte auf den Hub-Abgleich über die Cloud...", "En attente de l'appariement du hub via le cloud...", "Esperando el emparejamiento del hub por la nube..."),
    "eng.target":           ("Hedef: {addr}", "Target: {addr}", "Ziel: {addr}", "Cible : {addr}", "Destino: {addr}"),
    "eng.relay_wait":       ("Doğrudan UDP açılamadı — bulut relay ataması bekleniyor...", "Direct UDP failed — waiting for a cloud relay assignment...", "Direktes UDP fehlgeschlagen — warte auf Cloud-Relay-Zuweisung...", "UDP direct impossible — en attente d'une attribution de relais cloud...", "UDP directo no disponible — esperando la asignación del relé en la nube..."),
    "eng.assign_timeout":   ("Bulut eşleşmesi/ataması zaman aşımına uğradı!", "Cloud match/assignment timed out!", "Cloud-Abgleich/-Zuweisung hat das Zeitlimit überschritten!", "Délai dépassé pour l'appariement/l'attribution cloud !", "¡Se agotó el tiempo del emparejamiento/asignación en la nube!"),
    "eng.connect_fail":     ("Bağlantı kurulamadı!", "Could not establish a connection!", "Verbindung konnte nicht hergestellt werden!", "Impossible d'établir la connexion !", "¡No se pudo establecer la conexión!"),
    "eng.tunnel_active":    ("Tünel aktif: {vpn} ↔ {hub} ({transport})", "Tunnel active: {vpn} ↔ {hub} ({transport})", "Tunnel aktiv: {vpn} ↔ {hub} ({transport})", "Tunnel actif : {vpn} ↔ {hub} ({transport})", "Túnel activo: {vpn} ↔ {hub} ({transport})"),
    "eng.file_not_found":   ("Dosya bulunamadı: {path}", "File not found: {path}", "Datei nicht gefunden: {path}", "Fichier introuvable : {path}", "Archivo no encontrado: {path}"),
    "eng.peer_file_fail":   ("Peer dosyası okunamadı: {path}", "Could not read the peer file: {path}", "Peer-Datei konnte nicht gelesen werden: {path}", "Impossible de lire le fichier du pair : {path}", "No se pudo leer el archivo del par: {path}"),
    "eng.file_no_endpoint": ("Dosyada public_ip/public_port bulunamadı!", "public_ip/public_port not found in the file!", "public_ip/public_port in der Datei nicht gefunden!", "public_ip/public_port introuvables dans le fichier !", "¡No se encontró public_ip/public_port en el archivo!"),
    "eng.file_read":        ("Dosyadan okundu: {addr}", "Read from file: {addr}", "Aus Datei gelesen: {addr}", "Lu depuis le fichier : {addr}", "Leído del archivo: {addr}"),
    "eng.capacity_full":    ("Peer kapasitesi dolu (maks 253) — yeni bağlantı reddedildi.", "Peer capacity is full (max 253) — new connection rejected.", "Peer-Kapazität voll (max. 253) — neue Verbindung abgelehnt.", "Capacité de pairs atteinte (max 253) — nouvelle connexion refusée.", "Capacidad de pares llena (máx. 253) — conexión nueva rechazada."),
    "eng.capacity_full_relay": ("Peer kapasitesi dolu — yeni relay peer reddedildi.", "Peer capacity is full — new relay peer rejected.", "Peer-Kapazität voll — neuer Relay-Peer abgelehnt.", "Capacité de pairs atteinte — nouveau pair relais refusé.", "Capacidad de pares llena — par de relé nuevo rechazado."),
    "eng.peer_joined":      ("✅ Yeni peer bağlandı: {peer} → VPN {ip} ({addr})", "✅ New peer connected: {peer} → VPN {ip} ({addr})", "✅ Neuer Peer verbunden: {peer} → VPN {ip} ({addr})", "✅ Nouveau pair connecté : {peer} → VPN {ip} ({addr})", "✅ Nuevo par conectado: {peer} → VPN {ip} ({addr})"),
    "eng.punch_aggressive": ("Agresif UDP Hole Punch başlatıldı ({tries} paket, frekans {delay}s)...", "Aggressive UDP hole punch started ({tries} packets, {delay}s interval)...", "Aggressives UDP-Hole-Punching gestartet ({tries} Pakete, {delay}s Intervall)...", "Perforation UDP agressive démarrée ({tries} paquets, intervalle {delay}s)...", "Hole punching UDP agresivo iniciado ({tries} paquetes, intervalo {delay}s)..."),
    "eng.punch_direct_ok":  ("✅ Doğrudan P2P bağlantı sağlandı: {addr}", "✅ Direct P2P connection established: {addr}", "✅ Direkte P2P-Verbindung hergestellt: {addr}", "✅ Connexion P2P directe établie : {addr}", "✅ Conexión P2P directa establecida: {addr}"),
    "eng.punch_trying":     ("UDP Hole Punch deneniyor ({i}/{n})...", "Trying UDP hole punch ({i}/{n})...", "UDP-Hole-Punching wird versucht ({i}/{n})...", "Tentative de perforation UDP ({i}/{n})...", "Probando hole punching UDP ({i}/{n})..."),
    "eng.no_admin_tun":     ("Admin yetkisi yok — TUN adaptörü oluşturulamayabilir!", "No admin rights — the TUN adapter may fail to open!", "Keine Administratorrechte — das TUN-Gerät öffnet eventuell nicht!", "Pas de droits administrateur — le TUN risque de ne pas s'ouvrir !", "Sin permisos de administrador — ¡puede que el TUN no se abra!"),
    "eng.tun_fail":         ("TUN hatası: {err}", "TUN error: {err}", "TUN-Fehler: {err}", "Erreur TUN : {err}", "Error de TUN: {err}"),
    "eng.tun_open":         ("TUN adaptörü açıldı: {ip}", "TUN adapter opened: {ip}", "TUN-Gerät geöffnet: {ip}", "TUN ouvert : {ip}", "TUN abierto: {ip}"),
    "eng.direct_upgrade":   ("✅ Doğrudan P2P UDP yolu açıldı ({addr}).", "✅ Direct P2P UDP path opened ({addr}).", "✅ Direkter P2P-UDP-Pfad geöffnet ({addr}).", "✅ Chemin UDP P2P direct ouvert ({addr}).", "✅ Ruta UDP P2P directa abierta ({addr})."),
    "eng.hub_found":        ("✅ Hub bulut üzerinden bulundu: {addr}", "✅ Hub found over the cloud: {addr}", "✅ Hub über die Cloud gefunden: {addr}", "✅ Hub trouvé via le cloud : {addr}", "✅ Hub encontrado por la nube: {addr}"),
    "eng.assign_received":  ("☁ Bulut ataması alındı: VPN IP {ip} (Hub: {hub})", "☁ Cloud assignment received: VPN IP {ip} (hub: {hub})", "☁ Cloud-Zuweisung erhalten: VPN-IP {ip} (Hub: {hub})", "☁ Attribution cloud reçue : IP VPN {ip} (hub : {hub})", "☁ Asignación en la nube recibida: IP VPN {ip} (hub: {hub})"),
    "eng.relay_match":      ("☁ Bulut eşleşmesi: {peer} → VPN {ip}", "☁ Cloud match: {peer} → VPN {ip}", "☁ Cloud-Abgleich: {peer} → VPN {ip}", "☁ Appariement cloud : {peer} → VPN {ip}", "☁ Emparejamiento en la nube: {peer} → VPN {ip}"),
    "eng.peer_left":        ("⚠️ Peer ayrıldı: {peer} ({ip})", "⚠️ Peer left: {peer} ({ip})", "⚠️ Peer getrennt: {peer} ({ip})", "⚠️ Pair parti : {peer} ({ip})", "⚠️ Par desconectado: {peer} ({ip})"),
    "eng.roster_joined":    ("☰ Peer listesine eklendi: {name} → VPN {ip}", "☰ Added to the peer list: {name} → VPN {ip}", "☰ Zur Peer-Liste hinzugefügt: {name} → VPN {ip}", "☰ Ajouté à la liste des pairs : {name} → VPN {ip}", "☰ Añadido a la lista de pares: {name} → VPN {ip}"),
    "eng.roster_left":      ("⚠️ Peer listesinden çıktı: {name} ({ip})", "⚠️ Removed from the peer list: {name} ({ip})", "⚠️ Aus der Peer-Liste entfernt: {name} ({ip})", "⚠️ Retiré de la liste des pairs : {name} ({ip})", "⚠️ Eliminado de la lista de pares: {name} ({ip})"),
    "eng.stopped":          ("VPN durduruldu.", "VPN stopped.", "VPN gestoppt.", "VPN arrêté.", "VPN detenida."),
    "eng.hub_silent":       ("⚠️ Hub yanıt vermiyor — bağlantı yeniden kuruluyor...", "⚠️ Hub is not responding — re-establishing the connection...", "⚠️ Hub antwortet nicht — Verbindung wird wiederhergestellt...", "⚠️ Le hub ne répond pas — rétablissement de la connexion...", "⚠️ El hub no responde — restableciendo la conexión..."),
    "eng.recovered":        ("✅ Bağlantı yeniden kuruldu.", "✅ Connection re-established.", "✅ Verbindung wiederhergestellt.", "✅ Connexion rétablie.", "✅ Conexión restablecida."),
    "eng.mqtt_lost":        ("☁ Bulut bağlantısı koptu — yeniden bağlanılıyor...", "☁ Cloud connection lost — reconnecting...", "☁ Cloud-Verbindung verloren — Neuverbindung...", "☁ Connexion cloud perdue — reconnexion...", "☁ Conexión en la nube perdida — reconectando..."),
    "eng.mqtt_back":        ("✅ Bulut bağlantısı yeniden kuruldu.", "✅ Cloud connection re-established.", "✅ Cloud-Verbindung wiederhergestellt.", "✅ Connexion cloud rétablie.", "✅ Conexión en la nube restablecida."),
    "eng.tun_unsupported":  ("Desteklenmeyen OS: {os}", "Unsupported OS: {os}", "Nicht unterstütztes Betriebssystem: {os}", "Système non pris en charge : {os}", "Sistema no compatible: {os}"),
    "eng.wintun_missing":   ("wintun.dll bulunamadı!\n\n1. https://www.wintun.net adresinden indirin\n2. wintun.dll dosyasını script dizinine kopyalayın\n3. Admin olarak çalıştırın", "wintun.dll not found!\n\n1. Download it from https://www.wintun.net\n2. Copy wintun.dll next to the script\n3. Run as administrator", "wintun.dll nicht gefunden!\n\n1. Von https://www.wintun.net herunterladen\n2. wintun.dll neben das Skript kopieren\n3. Als Administrator ausführen", "wintun.dll introuvable !\n\n1. Téléchargez-la sur https://www.wintun.net\n2. Copiez wintun.dll à côté du script\n3. Lancez en administrateur", "¡wintun.dll no encontrada!\n\n1. Descárgala de https://www.wintun.net\n2. Copia wintun.dll junto al script\n3. Ejecuta como administrador"),
    "eng.tun_create_fail":  ("TUN adaptör oluşturulamadı — Admin yetkisi gerekli!", "Could not create the TUN adapter — administrator rights required!", "TUN-Gerät konnte nicht erstellt werden — Administratorrechte erforderlich!", "Impossible de créer le TUN — droits administrateur requis !", "No se pudo crear el TUN — ¡se requieren permisos de administrador!"),
    "eng.tun_session_fail": ("TUN session başlatılamadı!", "Could not start the TUN session!", "TUN-Sitzung konnte nicht gestartet werden!", "Impossible de démarrer la session TUN !", "¡No se pudo iniciar la sesión TUN!"),
    "eng.tun_addr_fail":    ("TUN adaptörüne VPN IP'si atanamadı — yönetici olarak çalıştırın. ({err})", "Could not assign the VPN IP to the TUN adapter — run as administrator. ({err})", "VPN-IP konnte dem TUN-Gerät nicht zugewiesen werden — als Administrator ausführen. ({err})", "Impossible d'attribuer l'IP VPN au TUN — lancez en administrateur. ({err})", "No se pudo asignar la IP VPN al TUN — ejecuta como administrador. ({err})"),
    "eng.route_fail":       ("VPN rotası eklenemedi ({dest}) — trafik tünele giremez: {err}", "Could not add the VPN route ({dest}) — traffic cannot enter the tunnel: {err}", "VPN-Route konnte nicht hinzugefügt werden ({dest}) — Verkehr kann nicht in den Tunnel: {err}", "Impossible d'ajouter la route VPN ({dest}) — le trafic ne peut pas entrer dans le tunnel : {err}", "No se pudo añadir la ruta VPN ({dest}) — el tráfico no puede entrar en el túnel: {err}"),

    # NAT tipi açıklamaları
    "nat.unknown_type":     ("Bilinmiyor (STUN Yanıtsız)", "Unknown (no STUN reply)", "Unbekannt (keine STUN-Antwort)", "Inconnu (pas de réponse STUN)", "Desconocido (sin respuesta STUN)"),
    "nat.unknown_details":  ("STUN sunucularına ulaşılamadı", "STUN servers unreachable", "STUN-Server nicht erreichbar", "Serveurs STUN injoignables", "Servidores STUN inaccesibles"),
    "nat.open_type":        ("Açık İnternet (NAT Yok)", "Open Internet (no NAT)", "Offenes Internet (kein NAT)", "Internet ouvert (sans NAT)", "Internet abierto (sin NAT)"),
    "nat.open_details":     ("Doğrudan Public IP atanmış", "Direct public IP assigned", "Direkte öffentliche IP zugewiesen", "IP publique directe attribuée", "IP pública directa asignada"),
    "nat.cone_type":        ("Cone NAT (Hole Punch Uyumlu)", "Cone NAT (hole-punch friendly)", "Cone-NAT (Hole-Punch-fähig)", "NAT cone (compatible perforation)", "NAT cónico (compatible con hole punching)"),
    "nat.cone_details":     ("Sabit Port Korundu: {port}", "Port kept stable: {port}", "Port blieb stabil: {port}", "Port resté stable : {port}", "Puerto estable: {port}"),
    "nat.sym_type":         ("Simetrik NAT / CGNat", "Symmetric NAT / CGNAT", "Symmetrisches NAT / CGNAT", "NAT symétrique / CGNAT", "NAT simétrico / CGNAT"),
    "nat.sym_details":      ("Değişken Portlar: {ports} (Delta: {delta:+d})", "Varying ports: {ports} (delta: {delta:+d})", "Wechselnde Ports: {ports} (Delta: {delta:+d})", "Ports variables : {ports} (delta : {delta:+d})", "Puertos variables: {ports} (delta: {delta:+d})"),
    "nat.unknown":          ("Bilinmiyor", "Unknown", "Unbekannt", "Inconnu", "Desconocido"),

    # Hakkında penceresi
    "about.window":         ("Hakkında — Peertopeer P2P VPN", "About — Peertopeer P2P VPN", "Über — Peertopeer P2P VPN", "À propos — Peertopeer P2P VPN", "Acerca de — Peertopeer P2P VPN"),
    "about.version":        ("Sürüm {v}", "Version {v}", "Version {v}", "Version {v}", "Versión {v}"),
    "about.tagline":        ("Peer-to-Peer VPN Çözümü", "Peer-to-Peer VPN Solution", "Peer-to-Peer-VPN-Lösung", "Solution VPN pair-à-pair", "Solución VPN entre pares"),
    "about.feat1":          ("VPS gerektirmez • AES-256-GCM Şifreleme", "No VPS required • AES-256-GCM encryption", "Kein VPS erforderlich • AES-256-GCM-Verschlüsselung", "Aucun VPS requis • Chiffrement AES-256-GCM", "Sin VPS • Cifrado AES-256-GCM"),
    "about.feat2":          ("UDP Hole Punching • CGNat Desteği", "UDP hole punching • CGNAT support", "UDP-Hole-Punching • CGNAT-Unterstützung", "UDP hole punching • Prise en charge CGNAT", "UDP hole punching • Compatibilidad con CGNAT"),
    "about.developer":      ("Geliştirici", "Developer", "Entwickler", "Développeur", "Desarrollador"),
    "about.language":       ("Dil", "Language", "Sprache", "Langue", "Idioma"),
    "about.ok":             ("Tamam", "OK", "OK", "OK", "Aceptar"),

    # ── Ana menü (deneyimsiz kullanıcı için numaralı yönlendirme) ──
    "menu.opt_start":     ("VPN'i başlat (adım adım)", "Start the VPN (step by step)", "VPN starten (Schritt für Schritt)", "Démarrer le VPN (étape par étape)", "Iniciar el VPN (paso a paso)"),
    "menu.opt_stop":      ("VPN'i durdur", "Stop the VPN", "VPN stoppen", "Arrêter le VPN", "Detener el VPN"),
    "menu.opt_status":    ("Durum ve istatistikler", "Status and statistics", "Status und Statistiken", "État et statistiques", "Estado y estadísticas"),
    "menu.opt_peers":     ("Bağlı cihazlar", "Connected devices", "Verbundene Geräte", "Appareils connectés", "Dispositivos conectados"),
    "menu.opt_log":       ("Kayıtlar (log)", "Logs", "Protokolle (Log)", "Journaux", "Registros (log)"),
    "menu.opt_settings":  ("Ayarlar", "Settings", "Einstellungen", "Paramètres", "Ajustes"),
    "menu.opt_stun":      ("Ağ testi (STUN/NAT)", "Network test (STUN/NAT)", "Netzwerktest (STUN/NAT)", "Test réseau (STUN/NAT)", "Prueba de red (STUN/NAT)"),
    "menu.opt_lang":      ("Dil değiştir", "Change language", "Sprache ändern", "Changer la langue", "Cambiar idioma"),
    "menu.opt_about":     ("Program hakkında", "About", "Über das Programm", "À propos", "Acerca de"),
    "menu.opt_advanced":  ("Gelişmiş komut satırı", "Advanced command line", "Erweiterte Kommandozeile", "Ligne de commande avancée", "Línea de comandos avanzada"),
    "menu.opt_auto":      ("Otomatik eşleşme", "Automatic matching", "Automatischer Abgleich", "Appariement auto", "Emparejamiento automático"),
    "menu.opt_back":      ("Geri", "Back", "Zurück", "Retour", "Atrás"),
    "menu.opt_quit":      ("Çıkış", "Quit", "Beenden", "Quitter", "Salir"),
    "menu.choice":        ("Seçiminiz", "Your choice", "Ihre Auswahl", "Votre choix", "Su elección"),
    "menu.invalid":       ("Geçersiz seçim, tekrar deneyin.", "Invalid choice, try again.", "Ungültige Auswahl, bitte erneut versuchen.", "Choix invalide, réessayez.", "Opción no válida, inténtelo de nuevo."),
    "menu.press_enter":   ("Devam etmek için Enter'a basın...", "Press Enter to continue...", "Zum Fortfahren Enter drücken...", "Appuyez sur Entrée pour continuer...", "Pulse Enter para continuar..."),
    "menu.back_hint":     ("Ana menüye dönmek için 'menu' yazın.", "Type 'menu' to return to the main menu.", "Geben Sie 'menu' ein, um zum Hauptmenü zurückzukehren.", "Tapez « menu » pour revenir au menu principal.", "Escriba 'menu' para volver al menú principal."),
    "menu.key_yes":       ("tanımlı", "set", "gesetzt", "définie", "definida"),
    "menu.key_no":        ("yok", "none", "keine", "aucune", "ninguna"),
    "menu.st_ready":      ("hazır", "ready", "bereit", "prêt", "listo"),
    "menu.st_busy":       ("bağlanıyor", "connecting", "verbinden", "connexion", "conectando"),
    "menu.st_connected":  ("bağlı", "connected", "verbunden", "connecté", "conectado"),
    "menu.st_error":      ("hata", "error", "Fehler", "erreur", "error"),
    "live.title":         ("Durum ve istatistikler — CANLI İZLEME", "Status and statistics — LIVE MONITOR", "Status und Statistiken — LIVE-MONITOR", "État et statistiques — SUIVI EN DIRECT", "Estado y estadísticas — MONITOR EN VIVO"),
    "live.hint":          ("Çıkmak için q / Esc ya da Enter'a basın...", "Press q / Esc or Enter to exit...", "Zum Beenden q / Esc oder Enter drücken...", "Appuyez sur q / Échap ou Entrée pour quitter...", "Pulsa q / Esc o Enter para salir..."),
    "live.refresh":       ("Canlı izleme: her 1 saniyede bir tazelenir.", "Live monitor: refreshes every 1 second.", "Live-Monitor: aktualisiert sich jede Sekunde.", "Suivi en direct : actualisé chaque seconde.", "Monitor en vivo: se actualiza cada segundo."),

    # ── Başlatma sihirbazı ──
    "wiz.title":          ("VPN Başlatma Sihirbazı", "Start VPN wizard", "VPN-Startassistent", "Assistant de démarrage VPN", "Asistente para iniciar el VPN"),
    "wiz.role":           ("Bu bilgisayar hangi rolü üstlenecek?", "Which role will this computer take?", "Welche Rolle übernimmt dieser Computer?", "Quel rôle cet ordinateur va-t-il jouer ?", "¿Qué rol tendrá este equipo?"),
    "wiz.role_hub":       ("1) Hub (dinleyici) — diğer cihazlar buna bağlanır", "1) Hub (listener) — other devices connect to it", "1) Hub (Listener) — andere Geräte verbinden sich damit", "1) Hub (écouteur) — les autres appareils s'y connectent", "1) Hub (receptor) — los demás equipos se conectan a él"),
    "wiz.role_peer":      ("2) Peer (istemci) — başka bir hub'a bağlanır", "2) Peer (client) — connects to another hub", "2) Peer (Client) — verbindet sich mit einem anderen Hub", "2) Pair (client) — se connecte à un autre hub", "2) Par (cliente) — se conecta a otro hub"),
    "wiz.key_intro":      ("Şifreleme anahtarı (iki tarafta AYNI olmalı):", "Encryption key (must be the SAME on both sides):", "Verschlüsselungsschlüssel (muss auf beiden Seiten GLEICH sein):", "Clé de chiffrement (doit être IDENTIQUE des deux côtés) :", "Clave de cifrado (debe ser la MISMA en ambos lados):"),
    "wiz.key_gen":        ("Yeni anahtar üret", "Generate a new key", "Neuen Schlüssel erzeugen", "Générer une nouvelle clé", "Generar una clave nueva"),
    "wiz.key_manual":     ("Hazır anahtarı yaz", "Enter an existing key", "Vorhandenen Schlüssel eingeben", "Saisir une clé existante", "Escribir una clave existente"),
    "wiz.key_file":       ("peer_info.json dosyasından yükle", "Load from a peer_info.json file", "Aus einer peer_info.json-Datei laden", "Charger depuis un fichier peer_info.json", "Cargar desde un archivo peer_info.json"),
    "wiz.key_shown":      ("Anahtarınız (kaydedin/paylaşın): {key}", "Your key (save/share it): {key}", "Ihr Schlüssel (speichern/teilen): {key}", "Votre clé (enregistrez/partagez) : {key}", "Su clave (guárdela/compártala): {key}"),
    "wiz.enter_file":     ("Dosya yolu", "File path", "Dateipfad", "Chemin du fichier", "Ruta del archivo"),
    "wiz.port":           ("UDP portu", "UDP port", "UDP-Port", "Port UDP", "Puerto UDP"),
    "wiz.export":         ("Bu bilgiyi dosyaya kaydet (boş = kaydedilmez)", "Save this info to a file (empty = don't save)", "Diese Info in eine Datei speichern (leer = nicht speichern)", "Enregistrer ces infos dans un fichier (vide = ne pas enregistrer)", "Guardar esta info en un archivo (vacío = no guardar)"),
    "wiz.conn_intro":     ("Hub bağlantısı nasıl kurulsun?", "How should the hub connection be made?", "Wie soll die Hub-Verbindung hergestellt werden?", "Comment établir la connexion au hub ?", "¿Cómo establecer la conexión al hub?"),
    "wiz.conn_auto":      ("1) Otomatik bul (aynı anahtarla)", "1) Find automatically (same key)", "1) Automatisch finden (gleicher Schlüssel)", "1) Trouver automatiquement (même clé)", "1) Buscar automáticamente (misma clave)"),
    "wiz.conn_addr":      ("2) Adres gir (IP:PORT)", "2) Enter an address (IP:PORT)", "2) Adresse eingeben (IP:PORT)", "2) Saisir une adresse (IP:PORT)", "2) Introducir una dirección (IP:PORT)"),
    "wiz.conn_file":      ("3) Dosyadan yükle (peer_info.json)", "3) Load from a file (peer_info.json)", "3) Aus Datei laden (peer_info.json)", "3) Charger depuis un fichier (peer_info.json)", "3) Cargar desde un archivo (peer_info.json)"),
    "wiz.enter_addr":     ("Hub adresi (IP:PORT)", "Hub address (IP:PORT)", "Hub-Adresse (IP:PORT)", "Adresse du hub (IP:PORT)", "Dirección del hub (IP:PORT)"),
    "wiz.summary":        ("Özet", "Summary", "Zusammenfassung", "Résumé", "Resumen"),
    "wiz.confirm":        ("Başlatılsın mı? (1=Evet, 2=İptal)", "Start? (1=Yes, 2=Cancel)", "Starten? (1=Ja, 2=Abbrechen)", "Démarrer ? (1=Oui, 2=Annuler)", "¿Iniciar? (1=Sí, 2=Cancelar)"),
    "wiz.cancelled":      ("İptal edildi.", "Cancelled.", "Abgebrochen.", "Annulé.", "Cancelado."),

    # ── Arka plan çalışanı ve kontrol ──
    "bg.started":           ("VPN arka planda başlatıldı (PID {pid}). Terminal kapatılsa da çalışır.", "VPN started in the background (PID {pid}). It keeps running even if you close the terminal.", "VPN im Hintergrund gestartet (PID {pid}). Läuft weiter, auch wenn das Terminal geschlossen wird.", "VPN démarré en arrière-plan (PID {pid}). Il continue même si vous fermez le terminal.", "VPN iniciado en segundo plano (PID {pid}). Sigue funcionando aunque cierres el terminal."),
    "bg.already":           ("VPN zaten arka planda çalışıyor.", "The VPN is already running in the background.", "Das VPN läuft bereits im Hintergrund.", "Le VPN fonctionne déjà en arrière-plan.", "El VPN ya se ejecuta en segundo plano."),
    "bg.spawn_fail":        ("Arka plan süreci başlatılamadı: {err}", "Could not start the background process: {err}", "Hintergrundprozess konnte nicht gestartet werden: {err}", "Impossible de démarrer le processus en arrière-plan : {err}", "No se pudo iniciar el proceso en segundo plano: {err}"),
    "bg.start_fail":        ("VPN arka planda başlatılamadı (süreç açıldı ama yanıt vermedi).", "The VPN could not start in the background (process launched but not responding).", "Das VPN konnte nicht im Hintergrund gestartet werden (Prozess gestartet, antwortet aber nicht).", "Le VPN n'a pas pu démarrer en arrière-plan (processus lancé mais sans réponse).", "El VPN no pudo iniciarse en segundo plano (proceso iniciado pero sin respuesta)."),
    "bg.log_hint":          ("Günlük dosyası: {path}", "Log file: {path}", "Protokolldatei: {path}", "Fichier journal : {path}", "Archivo de registro: {path}"),
    "bg.not_running":       ("Arka planda çalışan VPN yok.", "No VPN is running in the background.", "Kein VPN läuft im Hintergrund.", "Aucun VPN ne fonctionne en arrière-plan.", "No hay ningún VPN en segundo plano."),
    "bg.stopping":          ("Durdurma isteği gönderildi.", "Stop request sent.", "Stopp-Anfrage gesendet.", "Demande d'arrêt envoyée.", "Solicitud de detención enviada."),
    "bg.worker_start":      ("Arka plan çalışanı başlatıldı (PID {pid}).", "Background worker started (PID {pid}).", "Hintergrund-Worker gestartet (PID {pid}).", "Processus d'arrière-plan démarré (PID {pid}).", "Proceso en segundo plano iniciado (PID {pid})."),
    "bg.worker_bad_config": ("Arka plan yapılandırma hatası — çalışan kapatılıyor.", "Background configuration error — worker exiting.", "Konfigurationsfehler im Hintergrund — Worker wird beendet.", "Erreur de configuration en arrière-plan — arrêt du processus.", "Error de configuración en segundo plano — cerrando el proceso."),
    "bg.port_fail":         ("Kontrol portu {port} açılamadı: {err}", "Could not open control port {port}: {err}", "Kontrollport {port} konnte nicht geöffnet werden: {err}", "Impossible d'ouvrir le port de contrôle {port} : {err}", "No se pudo abrir el puerto de control {port}: {err}"),
    "bg.peers_label":       ("Bağlı cihaz", "Connected devices", "Verbundene Geräte", "Appareils connectés", "Dispositivos conectados"),
    "bg.background":        ("arka planda", "background", "Hintergrund", "arrière-plan", "segundo plano"),

    # ── Son bağlantı + otomatik başlatma ──
    "menu.opt_quick":     ("Hızlı başlat (son ayarlarla)", "Quick start (last settings)", "Schnellstart (letzte Einstellungen)", "Démarrage rapide (derniers réglages)", "Inicio rápido (últimos ajustes)"),
    "menu.opt_autostart": ("Başlangıçta çalıştır (aç/kapa)", "Run at startup (on/off)", "Beim Start ausführen (an/aus)", "Exécuter au démarrage (on/off)", "Ejecutar al inicio (on/off)"),
    "auto.title":         ("Başlangıçta otomatik çalıştırma", "Run automatically at startup", "Automatisch beim Start ausführen", "Exécuter automatiquement au démarrage", "Ejecutar automáticamente al inicio"),
    "auto.status":        ("Durum", "Status", "Status", "État", "Estado"),
    "auto.on":            ("AÇIK", "ON", "AN", "ACTIVÉ", "ACTIVADO"),
    "auto.off":           ("KAPALI", "OFF", "AUS", "DÉSACTIVÉ", "DESACTIVADO"),
    "auto.enable":        ("Etkinleştir (başlangıçta çalışsın)", "Enable (run at startup)", "Aktivieren (beim Start ausführen)", "Activer (exécuter au démarrage)", "Activar (ejecutar al inicio)"),
    "auto.disable":       ("Kapat (başlangıçtan kaldır)", "Disable (remove from startup)", "Deaktivieren (aus dem Start entfernen)", "Désactiver (retirer du démarrage)", "Desactivar (quitar del inicio)"),
    "auto.enabled":       ("Başlangıçta otomatik çalıştırma AÇILDI.", "Run at startup ENABLED.", "Ausführen beim Start AKTIVIERT.", "Exécution au démarrage ACTIVÉE.", "Ejecutar al inicio ACTIVADO."),
    "auto.disabled":      ("Başlangıçta otomatik çalıştırma KAPATILDI.", "Run at startup DISABLED.", "Ausführen beim Start DEAKTIVIERT.", "Exécution au démarrage DÉSACTIVÉE.", "Ejecutar al inicio DESACTIVADO."),
    "auto.failed":        ("Başlangıç ayarı değiştirilemedi: {err}", "Could not change the startup setting: {err}", "Starteinstellung konnte nicht geändert werden: {err}", "Impossible de modifier le réglage de démarrage : {err}", "No se pudo cambiar el ajuste de inicio: {err}"),
    "auto.need_key":      ("Önce bir anahtar ayarlayın (Ayarlar veya Başlatma Sihirbazı).", "Set a key first (Settings or Start wizard).", "Legen Sie zuerst einen Schlüssel fest (Einstellungen oder Startassistent).", "Définissez d'abord une clé (Paramètres ou assistant).", "Establezca primero una clave (Ajustes o asistente)."),
    "auto.unsupported":   ("Bu platformda otomatik başlatma desteklenmiyor.", "Autostart is not supported on this platform.", "Autostart wird auf dieser Plattform nicht unterstützt.", "Le démarrage automatique n'est pas pris en charge sur cette plateforme.", "El inicio automático no es compatible con esta plataforma."),
    "last.none":          ("Kayıtlı bağlantı yok. Önce Ayarlar veya Başlatma Sihirbazı ile ayarlayın.", "No saved connection. Set one up first via Settings or the Start wizard.", "Keine gespeicherte Verbindung. Richten Sie zuerst eine ein (Einstellungen oder Startassistent).", "Aucune connexion enregistrée. Configurez-en une via Paramètres ou l'assistant.", "No hay conexión guardada. Configure una primero en Ajustes o el asistente."),
    "wiz.key_saved":      ("Kayıtlı anahtarı kullan", "Use the saved key", "Gespeicherten Schlüssel verwenden", "Utiliser la clé enregistrée", "Usar la clave guardada"),

    # ── Bağlantı görünürlüğü ──
    "conn.label":        ("Bağlantı", "Connection", "Verbindung", "Connexion", "Conexión"),
    "conn.connected":    ("BAĞLI", "CONNECTED", "VERBUNDEN", "CONNECTÉ", "CONECTADO"),
    "conn.connecting":   ("BAĞLANIYOR...", "CONNECTING...", "VERBINDEN...", "CONNEXION...", "CONECTANDO..."),
    "conn.error":        ("HATA — bağlanamadı", "ERROR — not connected", "FEHLER — nicht verbunden", "ERREUR — non connecté", "ERROR — sin conexión"),
    "conn.off":          ("KAPALI", "OFF", "AUS", "HORS LIGNE", "DESCONECTADO"),
    "conn.start_error":  ("⚠ VPN başlatıldı ama tünel kurulamadı. Ayrıntı için 6) Kayıtlar'a bakın (yönetici/root ve wintun.dll gerekir).", "⚠ VPN started but the tunnel could not be established. See 6) Logs for details (needs admin/root and wintun.dll).", "⚠ VPN gestartet, aber der Tunnel konnte nicht aufgebaut werden. Details unter 6) Protokolle (benötigt Admin/root und wintun.dll).", "⚠ VPN démarré mais le tunnel n'a pas pu être établi. Voir 6) Journaux (nécessite admin/root et wintun.dll).", "⚠ VPN iniciado pero no se pudo establecer el túnel. Ver 6) Registros (requiere admin/root y wintun.dll)."),

    "auto.denied":        ("Yönetici izni gerekli: başlangıç ayarı için yönetici olarak çalıştırın ya da UAC onayını verin.", "Administrator permission required: run as administrator or accept the UAC prompt to change the startup setting.", "Administratorrechte erforderlich: als Administrator ausführen oder die UAC-Abfrage bestätigen.", "Droits administrateur requis : exécutez en tant qu'administrateur ou acceptez l'invite UAC.", "Se requieren permisos de administrador: ejecute como administrador o acepte el aviso de UAC."),

    # Komut satırı arayüzü (CLI)
    "cli.banner":            ("Peertopeer P2P VPN v{v} — Komut Satırı", "Peertopeer P2P VPN v{v} — Command Line", "Peertopeer P2P VPN v{v} — Kommandozeile", "Peertopeer P2P VPN v{v} — Ligne de commande", "Peertopeer P2P VPN v{v} — Línea de comandos"),
    "cli.hint":              ("Komutlar için 'help' yazın.", "Type 'help' for commands.", "Geben Sie 'help' für Befehle ein.", "Tapez 'help' pour les commandes.", "Escriba 'help' para ver los comandos."),
    "cli.prompt":            ("vpn> ", "vpn> ", "vpn> ", "vpn> ", "vpn> "),
    "cli.unknown_cmd":       ("Bilinmeyen komut: {cmd}  (yardım için 'help')", "Unknown command: {cmd}  (type 'help')", "Unbekannter Befehl: {cmd}  ('help' für Hilfe)", "Commande inconnue : {cmd}  ('help' pour l'aide)", "Comando desconocido: {cmd}  ('help' para ayuda)"),
    "cli.mode_label":        ("Mod", "Mode", "Modus", "Mode", "Modo"),
    "cli.state_label":       ("Durum", "State", "Status", "État", "Estado"),
    "cli.noninteractive":    ("Etkileşimsiz mod — çıkmak için Ctrl+C.", "Non-interactive mode — press Ctrl+C to quit.", "Nicht-interaktiver Modus — zum Beenden Ctrl+C.", "Mode non interactif — Ctrl+C pour quitter.", "Modo no interactivo — pulsa Ctrl+C para salir."),
    "cli.starting":          ("VPN başlatılıyor ({mode})...", "Starting VPN ({mode})...", "VPN wird gestartet ({mode})...", "Démarrage du VPN ({mode})...", "Iniciando VPN ({mode})..."),
    "cli.stopping":          ("VPN durduruluyor...", "Stopping VPN...", "VPN wird gestoppt...", "Arrêt du VPN...", "Deteniendo VPN..."),
    "cli.already_running":   ("VPN zaten çalışıyor.", "The VPN is already running.", "Das VPN läuft bereits.", "Le VPN est déjà en cours.", "El VPN ya está en ejecución."),
    "cli.not_running":       ("VPN çalışmıyor.", "The VPN is not running.", "Das VPN läuft nicht.", "Le VPN ne fonctionne pas.", "El VPN no está en ejecución."),
    "cli.goodbye":           ("Görüşürüz.", "Goodbye.", "Auf Wiedersehen.", "Au revoir.", "Hasta luego."),
    "cli.log_cleared":       ("Log temizlendi.", "Log cleared.", "Log geleert.", "Journal effacé.", "Registro limpiado."),
    "cli.key_generated":     ("Yeni anahtar üretildi: {key}", "New key generated: {key}", "Neuer Schlüssel erzeugt: {key}", "Nouvelle clé générée : {key}", "Nueva clave generada: {key}"),
    "cli.rename_usage":      ("Kullanım: rename <peer> [ad]   (ad boşsa takma isim silinir)", "Usage: rename <peer> [name]   (empty name clears it)", "Verwendung: rename <peer> [name]   (leer löscht ihn)", "Usage : rename <peer> [nom]   (vide le supprime)", "Uso: rename <peer> [nombre]   (vacío lo borra)"),
    "cli.rename_done":       ("Takma isim kaydedildi: {peer} → {name}", "Nickname saved: {peer} → {name}", "Spitzname gespeichert: {peer} → {name}", "Surnom enregistré : {peer} → {name}", "Alias guardado: {peer} → {name}"),
    "cli.rename_cleared":    ("Takma isim silindi: {peer}", "Nickname cleared: {peer}", "Spitzname gelöscht: {peer}", "Surnom supprimé : {peer}", "Alias borrado: {peer}"),
    "cli.set_usage":         ("Kullanım: set <alan> <değer>   (alanlar: key, port, peer, file, export, auto, mode, lang)", "Usage: set <field> <value>   (fields: key, port, peer, file, export, auto, mode, lang)", "Verwendung: set <feld> <wert>   (Felder: key, port, peer, file, export, auto, mode, lang)", "Usage : set <champ> <valeur>   (champs : key, port, peer, file, export, auto, mode, lang)", "Uso: set <campo> <valor>   (campos: key, port, peer, file, export, auto, mode, lang)"),
    "cli.set_ok":            ("{field} ayarlandı: {value}", "{field} set: {value}", "{field} gesetzt: {value}", "{field} défini : {value}", "{field} establecido: {value}"),
    "cli.set_unknown":       ("Bilinmeyen alan: {field}", "Unknown field: {field}", "Unbekanntes Feld: {field}", "Champ inconnu : {field}", "Campo desconocido: {field}"),
    "cli.set_bad":           ("Geçersiz değer: {field} = {value}", "Invalid value: {field} = {value}", "Ungültiger Wert: {field} = {value}", "Valeur invalide : {field} = {value}", "Valor no válido: {field} = {value}"),
    "cli.lang_now":          ("Geçerli dil: {lang}", "Current language: {lang}", "Aktuelle Sprache: {lang}", "Langue actuelle : {lang}", "Idioma actual: {lang}"),
    "cli.lang_set":          ("Dil değiştirildi: {lang}", "Language changed: {lang}", "Sprache geändert: {lang}", "Langue changée : {lang}", "Idioma cambiado: {lang}"),
    "cli.lang_bad":          ("Desteklenmeyen dil: {code}  (tr, en, de, fr, es)", "Unsupported language: {code}  (tr, en, de, fr, es)", "Nicht unterstützte Sprache: {code}  (tr, en, de, fr, es)", "Langue non prise en charge : {code}  (tr, en, de, fr, es)", "Idioma no compatible: {code}  (tr, en, de, fr, es)"),
    "cli.help":              (
        "Kullanılabilir komutlar:\n"
        "  status               Durum ve istatistikleri göster\n"
        "  peers                Bağlı peer'leri listele\n"
        "  log [n]              Son n log satırını göster (varsayılan 20)\n"
        "  rename <peer> [ad]   Bir peer'e takma isim ver (ad boşsa siler)\n"
        "  set <alan> <değer>   Ayar değiştir (key, port, peer, file, export, auto, mode, lang)\n"
        "  genkey               Rastgele şifreleme anahtarı üret\n"
        "  stun                 STUN / NAT / UPnP testi çalıştır\n"
        "  start                VPN'i başlat\n"
        "  stop                 VPN'i durdur\n"
        "  about                Uygulama bilgilerini göster\n"
        "  lang [kod]           Dili göster veya değiştir (tr, en, de, fr, es)\n"
        "  clear                Logu temizle\n"
        "  help                 Bu yardımı göster\n"
        "  quit | exit          Çıkış",
        "Available commands:\n"
        "  status               Show status and statistics\n"
        "  peers                List connected peers\n"
        "  log [n]              Show the last n log lines (default 20)\n"
        "  rename <peer> [name] Give a peer a nickname (empty name clears it)\n"
        "  set <field> <value>  Change a setting (key, port, peer, file, export, auto, mode, lang)\n"
        "  genkey               Generate a random encryption key\n"
        "  stun                 Run the STUN / NAT / UPnP test\n"
        "  start                Start the VPN\n"
        "  stop                 Stop the VPN\n"
        "  about                Show application information\n"
        "  lang [code]          Show or change the language (tr, en, de, fr, es)\n"
        "  clear                Clear the log\n"
        "  help                 Show this help\n"
        "  quit | exit          Quit",
        "Verfügbare Befehle:\n"
        "  status               Status und Statistiken anzeigen\n"
        "  peers                Verbundene Peers auflisten\n"
        "  log [n]              Die letzten n Logzeilen anzeigen (Standard 20)\n"
        "  rename <peer> [name] Einem Peer einen Spitznamen geben (leer löscht ihn)\n"
        "  set <feld> <wert>    Einstellung ändern (key, port, peer, file, export, auto, mode, lang)\n"
        "  genkey               Zufälligen Verschlüsselungsschlüssel erzeugen\n"
        "  stun                 STUN-/NAT-/UPnP-Test ausführen\n"
        "  start                VPN starten\n"
        "  stop                 VPN stoppen\n"
        "  about                Anwendungsinformationen anzeigen\n"
        "  lang [code]          Sprache anzeigen/ändern (tr, en, de, fr, es)\n"
        "  clear                Log leeren\n"
        "  help                 Diese Hilfe anzeigen\n"
        "  quit | exit          Beenden",
        "Commandes disponibles :\n"
        "  status               Afficher l'état et les statistiques\n"
        "  peers                Lister les pairs connectés\n"
        "  log [n]              Afficher les n dernières lignes du journal (défaut 20)\n"
        "  rename <peer> [nom]  Donner un surnom à un pair (vide le supprime)\n"
        "  set <champ> <valeur> Modifier un réglage (key, port, peer, file, export, auto, mode, lang)\n"
        "  genkey               Générer une clé de chiffrement aléatoire\n"
        "  stun                 Lancer le test STUN / NAT / UPnP\n"
        "  start                Démarrer le VPN\n"
        "  stop                 Arrêter le VPN\n"
        "  about                Afficher les informations de l'application\n"
        "  lang [code]          Afficher/modifier la langue (tr, en, de, fr, es)\n"
        "  clear                Effacer le journal\n"
        "  help                 Afficher cette aide\n"
        "  quit | exit          Quitter",
        "Comandos disponibles:\n"
        "  status               Mostrar estado y estadísticas\n"
        "  peers                Listar los pares conectados\n"
        "  log [n]              Mostrar las últimas n líneas del registro (por defecto 20)\n"
        "  rename <peer> [nombre] Poner un alias a un par (vacío lo borra)\n"
        "  set <campo> <valor>  Cambiar un ajuste (key, port, peer, file, export, auto, mode, lang)\n"
        "  genkey               Generar una clave de cifrado aleatoria\n"
        "  stun                 Ejecutar la prueba STUN / NAT / UPnP\n"
        "  start                Iniciar el VPN\n"
        "  stop                 Detener el VPN\n"
        "  about                Mostrar información de la aplicación\n"
        "  lang [code]          Mostrar o cambiar el idioma (tr, en, de, fr, es)\n"
        "  clear                Limpiar el registro\n"
        "  help                 Mostrar esta ayuda\n"
        "  quit | exit          Salir",
    ),
}

_DEFAULT_LANG = "en"
_current_lang = _DEFAULT_LANG


def set_ui_language(code: str) -> str:
    """Arayüz dilini değiştirir (desteklenmiyorsa İngilizceye düşer)."""
    global _current_lang
    _current_lang = code if code in _LANG_INDEX else _DEFAULT_LANG
    return _current_lang


def ui_language() -> str:
    return _current_lang


def t(_key: str, **fmt) -> str:
    """Anahtarı geçerli dilde döndürür; anahtar yoksa anahtarın kendisi döner."""
    entry = _TEXTS.get(_key)
    if not entry:
        return _key
    text = entry[_LANG_INDEX.get(_current_lang, 1)]
    if fmt:
        try:
            return text.format(**fmt)
        except Exception:
            return text
    return text


def _norm_lang(tag) -> Optional[str]:
    """'tr_TR.UTF-8' / 'Turkish_Turkey' / 'de-DE' gibi etiketleri dil koduna indirger."""
    if not tag:
        return None
    first = str(tag).replace("-", "_").split(".")[0].split("@")[0].split("_")[0].strip().lower()
    if first in LANG_NAMES:
        return first
    return _LANG_ALIASES.get(first)


def detect_ui_language() -> str:
    """Sistem diline göre makul bir varsayılan seçer; bulamazsa İngilizce.

    Kullanıcı Hakkında penceresinden farklı bir dil seçerse bu tercih diske
    yazılır ve sistem dili bir daha okunmaz.
    """
    if platform.system() == "Windows":
        try:
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF
            code = {0x1F: "tr", 0x09: "en", 0x07: "de", 0x0C: "fr", 0x0A: "es"}.get(langid)
            if code:
                return code
        except Exception:
            pass
    candidates = [os.environ.get(v) for v in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")]
    try:
        candidates.append(locale.getlocale()[0])
    except Exception:
        pass
    for cand in candidates:
        code = _norm_lang(cand)
        if code:
            return code
    return "en"


def load_settings() -> dict:
    """Kullanıcı tercihlerini okur; dosya yoksa/bozuksa boş sözlük döner."""
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_settings(data: dict) -> bool:
    """Kullanıcı tercihlerini diske yazar; başarısız olursa False döner."""
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


# Açılışta sistem diline göre başla; kayıtlı tercih varsa GUI onu uygular.
set_ui_language(detect_ui_language())


# ── Kriptografi bağımlılığı ──────────────────────────────────────────
# cryptography yeni sürümleri desteklenmeyen eski Python için uyarı basar;
# AppImage Python 3.8 taşıdığı için bu uyarı her açılışta görünürdü — bastır.
import warnings as _warnings
_warnings.filterwarnings("ignore", message=".*no longer supported.*")
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.stderr.write(f"\n{t('dep.title')}\n{t('dep.body')}\n")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════
#  STUN CLIENT
# ═══════════════════════════════════════════════════════════════════════

class STUNClient:
    """RFC 5389 STUN client — NAT arkasındaki public IP:Port tespiti."""

    @staticmethod
    def discover(sock: Optional[socket.socket] = None,
                 timeout: float = STUN_TIMEOUT) -> Optional[Tuple[str, int]]:
        for host, port in STUN_SERVERS:
            try:
                r = STUNClient._request(host, port, sock, timeout)
                if r:
                    return r
            except Exception:
                pass
        return None

    @staticmethod
    def _request(host, port, sock, timeout):
        own = sock is None
        if own:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
        old_t = sock.gettimeout()
        sock.settimeout(timeout)
        txn = secrets.token_bytes(12)
        pkt = struct.pack("!HHI", 0x0001, 0, STUN_MAGIC) + txn
        try:
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(1024)
        except Exception:
            if own: sock.close()
            else: sock.settimeout(old_t)
            return None
        if own: sock.close()
        else: sock.settimeout(old_t)
        if len(data) < 20:
            return None
        mt, ml, mc = struct.unpack("!HHI", data[:8])
        if mt != 0x0101 or data[8:20] != txn:
            return None
        pos = 20
        while pos < 20 + ml:
            if pos + 4 > len(data): break
            at, al = struct.unpack("!HH", data[pos:pos + 4])
            ad = data[pos + 4:pos + 4 + al]
            pos += 4 + al + (4 - al % 4) % 4
            if at == 0x0020 and len(ad) >= 8 and ad[1] == 0x01:
                xp = struct.unpack("!H", ad[2:4])[0] ^ (STUN_MAGIC >> 16)
                xi = struct.unpack("!I", ad[4:8])[0] ^ STUN_MAGIC
                return (socket.inet_ntoa(struct.pack("!I", xi)), xp)
            if at == 0x0001 and len(ad) >= 8 and ad[1] == 0x01:
                return (socket.inet_ntoa(ad[4:8]), struct.unpack("!H", ad[2:4])[0])
        return None


# ═══════════════════════════════════════════════════════════════════════
#  NAT TİPİ VE PORT TAHMİN MOTORU (RFC 3489 / RFC 5389)
# ═══════════════════════════════════════════════════════════════════════

class NATDetector:
    """
    Birden fazla STUN sunucusuna aynı yerel UDP soketinden peş peşe sorgu atarak
    NAT davranışını tespit eder:
    - Açık İnternet (NAT Yok): Dış IP = Yerel IP
    - Cone NAT (Full / Restricted): Tüm dış hedeflere aynı port korunur (Hole punch %100 uyumlu)
    - Simetrik NAT / CGNat: Her yeni hedef için farklı port tahsis edilir (Port delta hesaplanır)
    """

    @staticmethod
    def detect(sock: Optional[socket.socket] = None, servers=None) -> dict:
        servers = servers or STUN_SERVERS[:6]
        own = sock is None
        if own:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 0))
            sock.settimeout(2.5)

        results = []
        for host, port in servers:
            try:
                res = STUNClient._request(host, port, sock, timeout=2.0)
                if res and res[1] > 0:
                    results.append(res)
            except Exception:
                pass
            if len(results) >= 4:
                break

        if own:
            try: sock.close()
            except Exception: pass

        lip = get_local_ip()
        if not results:
            return {
                "type": t("nat.unknown_type"),
                "is_symmetric": False,
                "is_cgnat": True,
                "delta": 0,
                "public_ip": lip,
                "public_port": 0,
                "ports": [],
                "details": t("nat.unknown_details")
            }

        first_ip, first_port = results[0]
        if first_ip == lip:
            return {
                "type": t("nat.open_type"),
                "is_symmetric": False,
                "is_cgnat": False,
                "delta": 0,
                "public_ip": first_ip,
                "public_port": first_port,
                "ports": [p for _, p in results],
                "details": t("nat.open_details")
            }

        ports = [p for _, p in results]
        unique_ports = list(dict.fromkeys(ports))

        if len(unique_ports) == 1:
            return {
                "type": t("nat.cone_type"),
                "is_symmetric": False,
                "is_cgnat": False,
                "delta": 0,
                "public_ip": first_ip,
                "public_port": first_port,
                "ports": ports,
                "details": t("nat.cone_details", port=first_port)
            }
        else:
            # Simetrik NAT / CGNat davranışı
            deltas = [ports[i+1] - ports[i] for i in range(len(ports)-1)]
            # En çok tekrar eden delta veya ortalama
            delta = deltas[0] if deltas else 1
            return {
                "type": t("nat.sym_type"),
                "is_symmetric": True,
                "is_cgnat": True,
                "delta": delta,
                "public_ip": first_ip,
                "public_port": first_port,
                "ports": ports,
                "details": t("nat.sym_details", ports=ports, delta=delta)
            }


# ═══════════════════════════════════════════════════════════════════════
#  ŞİFRELEME — AES-256-GCM
# ═══════════════════════════════════════════════════════════════════════

class CryptoEngine:
    def __init__(self, passphrase: str):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                          salt=KDF_SALT, iterations=480000)
        self._aesgcm = AESGCM(kdf.derive(passphrase.encode("utf-8")))

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> Optional[bytes]:
        if len(data) < 28:
            return None
        try:
            return self._aesgcm.decrypt(data[:12], data[12:], None)
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════
#  GÜVENLİK DUVARI & UPNP & BULUT EŞLEŞMESİ (FIREWALL TRAVERSAL)
# ═══════════════════════════════════════════════════════════════════════

def setup_windows_firewall(port: int, rule_name="Peertopeer_P2P_VPN") -> bool:
    """Windows Güvenlik Duvarında belirtilen UDP portu için izin kuralı ekler."""
    if platform.system() == "Windows" and check_admin():
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                           capture_output=True, check=False)
            res = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                  f"name={rule_name}", "dir=in", "action=allow",
                                  "protocol=UDP", f"localport={port}", "profile=any"],
                                 capture_output=True, check=False)
            return res.returncode == 0
        except Exception:
            pass
    return False


def setup_windows_icmp_rule(rule_name="Peertopeer_P2P_VPN_ICMP") -> bool:
    """Windows Güvenlik Duvarı'nda VPN alt ağından gelen ping isteklerine izin verir.

    Windows gelen ICMPv4 echo isteklerini varsayılan olarak düşürdüğü için,
    aksi halde bir peer diğerini pingleyemez: paket tünelden geçer ve hedefe
    ulaşır ama kaynak "Request timed out" (sessiz kayıp) görür. Hub'da kural
    olup istemcide olmaması, "hub pingleniyor ama istemci pinglenmiyor"
    tablosunu üretir.

    Kural yalnızca VPN alt ağından (10.8.0.0/24) gelen ping'lere izin verir;
    genel amaçlı ICMP açılmaz.
    """
    if platform.system() != "Windows" or not check_admin():
        return False
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"], capture_output=True, check=False)
        res = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name={rule_name}", "dir=in", "action=allow",
                              "protocol=icmpv4:8,any", f"remoteip={VPN_NET}.0/24",
                              "profile=any"],
                             capture_output=True, check=False)
        return res.returncode == 0
    except Exception:
        return False


def setup_windows_subnet_rule(rule_name="Peertopeer_P2P_VPN_Subnet") -> bool:
    """Windows Güvenlik Duvarı'nda VPN alt ağından gelen tüm trafiğe izin verir.

    Yalnızca ICMP'ye izin vermek ping'i çözer ama peer'ler birbirlerinin
    servislerine (dosya paylaşımı, web arayüzü, uzak masaüstü...) erişemez:
    Windows wintun arayüzünü çoğu zaman "Genel" profil saydığı için bu
    bağlantılar sessizce düşer ve kullanıcı "erişim yok" görür. Bu kural
    yalnızca 10.8.0.0/24 kaynaklı gelen trafiği kapsar; internete açık genel
    bir izin oluşturmaz.
    """
    if platform.system() != "Windows" or not check_admin():
        return False
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"], capture_output=True, check=False)
        res = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name={rule_name}", "dir=in", "action=allow",
                              f"remoteip={VPN_NET}.0/24", "profile=any"],
                             capture_output=True, check=False)
        return res.returncode == 0
    except Exception:
        return False


def setup_linux_firewall(port: int) -> bool:
    """Linux güvenlik duvarında belirtilen UDP portu için izin kuralı ekler.

    Windows kuralının (setup_windows_firewall) Linux karşılığıdır. Dinleyicinin
    gelen HELLO/delme paketlerini alabilmesi için portu açar; aksi halde maske
    varsayılanı gelen trafiği düşürdüğü için UDP hole punching hiç kurulamaz ve
    tüm trafik yavaş olan bulut relay'ine düşer.

    Yalnızca root iken çalışır ve etkin bir güvenlik duvarı yoksa hiçbir şey
    yapmaz (False döner). Mevcut kurallar korunur; yalnızca bu UDP portu için
    ACCEPT eklenir.
    """
    if platform.system() != "Linux" or not check_admin():
        return False
    try:
        import shutil
    except Exception:
        return False

    try:
        # 1) ufw (Debian / Ubuntu)
        if shutil.which("ufw"):
            try:
                st = subprocess.run(["ufw", "status"], capture_output=True,
                                    text=True, timeout=5)
                if "Status: active" in (st.stdout or ""):
                    if subprocess.run(["ufw", "allow", f"{port}/udp"],
                                      capture_output=True, timeout=10).returncode == 0:
                        return True
            except Exception:
                pass

        # 2) firewalld (Fedora / RHEL / openSUSE)
        if shutil.which("firewall-cmd"):
            try:
                r = subprocess.run(["firewall-cmd", "--add-port", f"{port}/udp"],
                                   capture_output=True, timeout=10)
                if r.returncode == 0:
                    subprocess.run(["firewall-cmd", "--permanent", "--add-port", f"{port}/udp"],
                                   capture_output=True, timeout=10)
                    return True
            except Exception:
                pass

        # 3) iptables (nft shim dahil) — son çare
        if shutil.which("iptables"):
            try:
                chk = subprocess.run(["iptables", "-C", "INPUT", "-p", "udp",
                                      "--dport", str(port), "-j", "ACCEPT"],
                                     capture_output=True, timeout=10)
                if chk.returncode == 0:
                    return True
                r = subprocess.run(["iptables", "-I", "INPUT", "-p", "udp",
                                    "--dport", str(port), "-j", "ACCEPT"],
                                   capture_output=True, timeout=10)
                return r.returncode == 0
            except Exception:
                pass
    except Exception:
        pass
    return False


class UPnPEngine:
    """Universal Plug and Play (UPnP) Port Yönlendirme Motoru (Saf Python)."""

    def __init__(self):
        self.control_url: Optional[str] = None
        self.service_type: Optional[str] = None
        self.mapped_ports = []

    def discover(self, timeout: float = 2.5) -> bool:
        """SSDP M-SEARCH ile yerel ağdaki yönlendiriciyi (IGD) bulur."""
        try:
            import xml.etree.ElementTree as ET
            from urllib.parse import urljoin

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            req = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
            )
            s.sendto(req.encode(), ("239.255.255.250", 1900))

            locations = []
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, _ = s.recvfrom(2048)
                    for line in data.decode(errors="ignore").split("\r\n"):
                        if line.upper().startswith("LOCATION:"):
                            loc = line.split(":", 1)[1].strip()
                            if loc not in locations:
                                locations.append(loc)
                except socket.timeout:
                    break
                except Exception:
                    break
            s.close()

            if not locations:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.5)
                req_all = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    'MAN: "ssdp:discover"\r\n'
                    "MX: 2\r\n"
                    "ST: ssdp:all\r\n\r\n"
                )
                s.sendto(req_all.encode(), ("239.255.255.250", 1900))
                start = time.time()
                while time.time() - start < 1.5:
                    try:
                        data, _ = s.recvfrom(2048)
                        for line in data.decode(errors="ignore").split("\r\n"):
                            if line.upper().startswith("LOCATION:"):
                                loc = line.split(":", 1)[1].strip()
                                if loc not in locations:
                                    locations.append(loc)
                    except Exception:
                        break
                s.close()

            for loc in locations:
                try:
                    req_desc = urllib.request.Request(loc, headers={"User-Agent": "UPnP/1.0"})
                    with urllib.request.urlopen(req_desc, timeout=2.5) as resp:
                        xml_bytes = resp.read()
                    root = ET.fromstring(xml_bytes)
                    for elem in root.iter():
                        if elem.tag.endswith("service"):
                            st = elem.find("{*}serviceType")
                            cu = elem.find("{*}controlURL")
                            if st is not None and cu is not None and st.text and cu.text:
                                if "WANIPConnection" in st.text or "WANPPPConnection" in st.text:
                                    self.service_type = st.text
                                    self.control_url = urljoin(loc, cu.text)
                                    return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def add_port_mapping(self, external_port: int, internal_port: int, internal_ip: str,
                         protocol: str = "UDP", description: str = "Peertopeer VPN",
                         lease_duration: int = 0) -> bool:
        """Modemde harici portu yerel IP ve porta yönlendirir."""
        if not self.control_url or not self.service_type:
            if not self.discover():
                return False

        soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{self.service_type}">
  <NewRemoteHost></NewRemoteHost>
  <NewExternalPort>{external_port}</NewExternalPort>
  <NewProtocol>{protocol}</NewProtocol>
  <NewInternalPort>{internal_port}</NewInternalPort>
  <NewInternalClient>{internal_ip}</NewInternalClient>
  <NewEnabled>1</NewEnabled>
  <NewPortMappingDescription>{description}</NewPortMappingDescription>
  <NewLeaseDuration>{lease_duration}</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"""

        req = urllib.request.Request(
            self.control_url,
            data=soap_body.encode("utf-8"),
            headers={
                "SOAPAction": f'"{self.service_type}#AddPortMapping"',
                "Content-Type": 'text/xml; charset="utf-8"',
                "User-Agent": "UPnP/1.0"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    self.mapped_ports.append((external_port, protocol))
                    return True
        except Exception:
            pass
        return False

    def delete_port_mapping(self, external_port: int, protocol: str = "UDP") -> bool:
        """Modemdeki port yönlendirmesini temizler."""
        if not self.control_url or not self.service_type:
            return False
        soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="{self.service_type}">
  <NewRemoteHost></NewRemoteHost>
  <NewExternalPort>{external_port}</NewExternalPort>
  <NewProtocol>{protocol}</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>"""
        req = urllib.request.Request(
            self.control_url,
            data=soap_body.encode("utf-8"),
            headers={
                "SOAPAction": f'"{self.service_type}#DeletePortMapping"',
                "Content-Type": 'text/xml; charset="utf-8"',
                "User-Agent": "UPnP/1.0"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def cleanup(self):
        for port, proto in list(self.mapped_ports):
            try:
                self.delete_port_mapping(port, proto)
            except Exception:
                pass
        self.mapped_ports.clear()


class SimpleMQTT:
    """Minimal saf Python MQTT 3.1.1 istemcisi (0 harici bağımlılık, Thread-Safe, Düşük Gecikmeli)."""

    def __init__(self, hosts=None):
        self.hosts = hosts or [
            ("broker.hivemq.com", 1883),
            ("broker.emqx.io", 1883),
            ("test.mosquitto.org", 1883)
        ]
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.on_message = None
        self.on_connect = None          # (yeniden) bağlanınca abonelikleri tazele
        self.on_state = None            # bağlantı durumu değişimi (loglama için)
        self._send_lock = threading.Lock()
        self._connect_lock = threading.Lock()
        self._want_running = False
        self._supervisor_started = False
        self._client_id = ""
        self.last_rx = 0.0              # en son bayt alınan zaman (bayatlık tespiti)

    @staticmethod
    def _encode_varlen(length: int) -> bytearray:
        encoded = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length == 0:
                break
        return encoded

    def connect(self, client_id="") -> bool:
        """Bağlanır ve bağlantıyı canlı tutan denetleyiciyi başlatır.

        İlk deneme başarısız olsa bile denetleyici arka planda artan aralıklarla
        yeniden bağlanmayı dener; böylece broker kaynaklı sessiz kopmalar (ör.
        genel MQTT broker'larının oturumu zamanla kapatması) bağlantıyı kalıcı
        olarak öldürmez. Yeniden bağlanınca abonelikler tazelenir (on_connect).
        """
        if client_id:
            self._client_id = client_id
        if not self._client_id:
            self._client_id = f"p2pvpn_{secrets.token_hex(6)}"
        self._want_running = True
        ok = self._connect_once()
        if not self._supervisor_started:
            self._supervisor_started = True
            threading.Thread(target=self._supervise_loop, daemon=True,
                             name="MQTTSupervisor").start()
        return ok

    def _connect_once(self) -> bool:
        """Tek bir broker'a bağlanmayı dener; başarılıysa True döner."""
        with self._connect_lock:
            if self.running and self.sock:
                return True
            stale = self.sock
            self.sock = None
            self.running = False
        if stale:
            try:
                stale.close()
            except Exception:
                pass
        for host, port in self.hosts:
            if not self._want_running:
                return False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4.0)
                tune_socket_buffers(s)
                s.connect((host, port))
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                protocol_name = b"\x00\x04MQTT\x04\x02\x00\x3c"
                cid_bytes = self._client_id.encode("utf-8")
                payload = struct.pack("!H", len(cid_bytes)) + cid_bytes
                var_len = len(protocol_name) + len(payload)
                pkt = bytearray([0x10]) + self._encode_varlen(var_len) + protocol_name + payload
                with self._send_lock:
                    s.sendall(pkt)
                resp = s.recv(4)
                if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0:
                    s.settimeout(1.0)
                    with self._connect_lock:
                        self.sock = s
                        self.running = True
                        self.last_rx = time.time()
                    threading.Thread(target=self._recv_loop, args=(s,), daemon=True,
                                     name="MQTTRx").start()
                    threading.Thread(target=self._ping_loop, args=(s,), daemon=True,
                                     name="MQTTPing").start()
                    if self.on_connect:
                        try:
                            self.on_connect()
                        except Exception:
                            pass
                    return True
                try:
                    s.close()
                except Exception:
                    pass
            except Exception:
                continue
        return False

    def _teardown(self):
        """Ölü/kopmuş soketi kapatır; denetleyici yeniden bağlanır."""
        with self._connect_lock:
            s = self.sock
            self.sock = None
            self.running = False
        if s:
            try:
                s.close()
            except Exception:
                pass

    def _supervise_loop(self):
        """Bağlantıyı izler: koptuysa ya da sessizce öldüyse yeniden bağlanır."""
        backoff = MQTT_RECONNECT_MIN
        while self._want_running:
            time.sleep(1.0)
            if not self._want_running:
                break
            if self.running and self.sock:
                if self.last_rx and (time.time() - self.last_rx) > MQTT_STALE_SEC:
                    # Broker ping'lere de yanıt vermiyor: sessiz kopma
                    if self.on_state:
                        try:
                            self.on_state("lost")
                        except Exception:
                            pass
                    self._teardown()
                else:
                    backoff = MQTT_RECONNECT_MIN
                    continue
            if self._connect_once():
                backoff = MQTT_RECONNECT_MIN
            else:
                time.sleep(backoff)
                backoff = min(backoff * 2, MQTT_RECONNECT_MAX)

    def subscribe(self, topic: str):
        if not self.sock or not self.running: return
        top_b = topic.encode("utf-8")
        payload = struct.pack("!H", len(top_b)) + top_b + b"\x00"
        var_h = struct.pack("!H", 1)
        var_len = len(var_h) + len(payload)
        pkt = bytearray([0x82]) + self._encode_varlen(var_len) + var_h + payload
        with self._send_lock:
            s = self.sock
            if s and self.running:
                try:
                    s.sendall(pkt)
                except Exception:
                    pass

    def publish(self, topic: str, message: bytes, retain: bool = False):
        if not self.sock or not self.running: return
        top_b = topic.encode("utf-8")
        rem_len = 2 + len(top_b) + len(message)
        header = 0x31 if retain else 0x30
        pkt = bytearray([header]) + self._encode_varlen(rem_len) + struct.pack("!H", len(top_b)) + top_b + message
        with self._send_lock:
            s = self.sock
            if s and self.running:
                try:
                    s.sendall(pkt)
                except Exception:
                    pass

    def _recv_loop(self, sock):
        buf = bytearray()
        while self.running and self.sock is sock:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                self.last_rx = time.time()
                buf.extend(chunk)
                while len(buf) >= 2:
                    pkt_type = buf[0] & 0xF0
                    multiplier = 1
                    value = 0
                    idx = 1
                    while idx < len(buf) and idx <= 4:
                        digit = buf[idx]
                        value += (digit & 127) * multiplier
                        multiplier *= 128
                        idx += 1
                        if (digit & 128) == 0:
                            break
                    else:
                        if idx > 4:
                            buf.clear()
                        break

                    total_len = idx + value
                    if len(buf) < total_len:
                        break

                    pkt_data = buf[idx:total_len]
                    buf = buf[total_len:]

                    if pkt_type == 0x30:  # PUBLISH
                        if len(pkt_data) >= 2:
                            t_len = struct.unpack("!H", pkt_data[:2])[0]
                            topic = pkt_data[2:2 + t_len].decode("utf-8", errors="ignore")
                            payload = pkt_data[2 + t_len:]
                            if self.on_message:
                                self.on_message(topic, payload)
            except socket.timeout:
                continue
            except Exception:
                break
        if self.sock is sock:
            self.running = False

    def _ping_loop(self, sock):
        while self.running and self.sock is sock:
            time.sleep(20)
            if not (self.running and self.sock is sock):
                break
            try:
                with self._send_lock:
                    if self.sock is sock:
                        sock.sendall(b"\xC0\x00")
            except Exception:
                break
        if self.sock is sock:
            self.running = False

    def disconnect(self):
        self._want_running = False
        with self._connect_lock:
            s = self.sock
            self.sock = None
            self.running = False
        if s:
            try:
                s.sendall(b"\xE0\x00")
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


class CloudRendezvous:
    """
    Sıfır-VPS Bulut Eşleşmesi & Güvenli Relay Aktarma Köprüsü:
    1. Otomatik P2P Buluşma (STUN & Endpoint Paylaşımı)
    2. Çift CGNat/Firewall Durumunda %100 Çalışan Uçtan Uca Şifreli Fallback Aktarma
    """

    def __init__(self, key: str, on_peer_callback=None, on_relay_callback=None,
                 on_assign_callback=None, log_callback=None, peer_id=""):
        self.key = key
        self.crypto = CryptoEngine(key)
        self.on_peer_callback = on_peer_callback
        self.on_relay_callback = on_relay_callback
        self.on_assign_callback = on_assign_callback
        self.log_callback = log_callback
        self.mqtt = SimpleMQTT()
        self.room_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        self.peer_id = peer_id or secrets.token_hex(6)
        self.role = ""
        self.is_hub = False
        self.my_info = {}
        self.running = False
        self.peer_found = False
        self._subscribed_data = set()
        self._subs: set = set()      # aktif MQTT abonelikleri (yeniden bağlanınca tazelenir)
        self._connected_once = False
        self._peer_caps: dict = {}   # peer_id -> karşı tarafın yetenek bilgisi
        self._batch: dict = {}       # topic -> biriktirilen çerçevelenmiş paketler
        self._batch_lock = threading.Lock()

    def _log(self, level, msg):
        if self.log_callback:
            self.log_callback(level, msg)

    # ── Topic şeması ──
    #   Buluşma:  <base>/<room>/rv/<peer_id>        (hub sabit "hub" kimliğini kullanır)
    #   Veri TX:  <base>/<room>/data/<peer_id>/tx   (peer kendi giden verisini buraya yayınlar)
    #   Veri RX:  <base>/<room>/data/<peer_id>/rx   (peer kendi gelen verisini buradan dinler)

    def _rv_topic(self, pid: str) -> str:
        return f"{MQTT_BASE}/{self.room_id}/rv/{pid}"

    def _tx_topic(self, pid: str) -> str:
        return f"{MQTT_BASE}/{self.room_id}/data/{pid}/tx"

    def _rx_topic(self, pid: str) -> str:
        return f"{MQTT_BASE}/{self.room_id}/data/{pid}/rx"

    def start(self, role: str, endpoint_info: dict):
        self.role = role
        self.is_hub = (role == "hub")
        self.my_info = endpoint_info
        self.running = True
        self.peer_found = False

        def _worker():
            self._log("INFO", t("eng.cloud_room", room=self.room_id[:8]))
            self.mqtt.on_message = self._on_message
            self.mqtt.on_connect = self._on_mqtt_connect
            self.mqtt.on_state = self._on_mqtt_state

            # Abonelikler bağlantıdan bağımsız kaydedilir: ilk bağlantı başarısız
            # olsa bile denetleyici sonradan bağlanınca _on_mqtt_connect hepsini
            # tazeler. Aksi halde geç gelen bağlantıda abonelikler eksik kalırdı.
            if self.is_hub:
                # Tüm peer'lerin buluşma ve veri (TX) kanallarını dinle
                self._subscribe(f"{MQTT_BASE}/{self.room_id}/rv/+")
                own_id = HUB_PEER_ID
            else:
                # Hub'ın buluşması + kendi atama/veri kanallarımız
                self._subscribe(self._rv_topic(HUB_PEER_ID))
                self._subscribe(self._rv_topic(self.peer_id))
                self._subscribe(self._rx_topic(self.peer_id))
                own_id = self.peer_id

            threading.Thread(target=self._broadcast_loop, args=(own_id,), daemon=True).start()
            threading.Thread(target=self._flush_loop, daemon=True).start()

            if self.mqtt.connect():
                self._log("INFO", t("eng.cloud_connected"))
            else:
                self._log("WARNING", t("eng.cloud_unreachable"))

        threading.Thread(target=_worker, daemon=True).start()

    def _subscribe(self, topic: str):
        """Aboneliği kaydeder ve MQTT'ye bildirir (yeniden bağlanınca tazelenir)."""
        self._subs.add(topic)
        self.mqtt.subscribe(topic)

    def _on_mqtt_connect(self):
        """MQTT (yeniden) bağlandı — tüm abonelikleri tazele."""
        for topic in list(self._subs):
            self.mqtt.subscribe(topic)
        if self._connected_once:
            self._log("INFO", t("eng.mqtt_back"))
            # Endpoint'i hemen yeniden yayınla: retained mesaj gecikse de
            # karşı taraf bizi tekrar görsün.
            try:
                own_id = HUB_PEER_ID if self.is_hub else self.peer_id
                self.publish_endpoint(own_id, self.my_info)
            except Exception:
                pass
        self._connected_once = True

    def _on_mqtt_state(self, state):
        if state == "lost":
            self._log("WARNING", t("eng.mqtt_lost"))

    def subscribe_data(self, peer_id: str):
        """Hub: bir peer'in TX veri kanalını dinlemeye başlar."""
        if peer_id in self._subscribed_data:
            return
        self._subscribed_data.add(peer_id)
        self._subscribe(self._tx_topic(peer_id))

    def _broadcast_loop(self, own_id: str):
        extra = 0
        while self.running:
            self.publish_endpoint(own_id, self.my_info)
            if self.is_hub:
                time.sleep(3.0)
                continue
            if self.peer_found:
                extra += 1
                if extra >= 10:
                    break
            time.sleep(2.0)

    def publish_endpoint(self, own_id: str, info: dict):
        try:
            payload = json.dumps({
                "t": "rv",
                "peer_id": own_id,
                "role": self.role,
                "ip": info.get("ip"),
                "port": info.get("port"),
                "local_ip": info.get("local_ip"),
                "local_port": info.get("local_port"),
                "nat_type": info.get("nat_type", t("nat.unknown")),
                "is_symmetric": info.get("is_symmetric", False),
                "delta": info.get("delta", 0),
                "ports": info.get("ports", []),
                "name": info.get("name", ""),
                "bat": 1,
                "ts": time.time()
            }).encode("utf-8")
            enc = self.crypto.encrypt(payload)
            self.mqtt.publish(self._rv_topic(own_id), enc, retain=True)
        except Exception:
            pass

    def publish_assign(self, peer_id: str, assigned_ip: str, hub_ip: str):
        """Hub → peer: atanan VPN IP'sini ve hub VPN IP'sini bildirir (relay yolu)."""
        try:
            payload = json.dumps({
                "t": "assign",
                "ip": assigned_ip,
                "hub_ip": hub_ip,
                "hub_peer_id": HUB_PEER_ID,
                "ts": time.time()
            }).encode("utf-8")
            self.mqtt.publish(self._rv_topic(peer_id), self.crypto.encrypt(payload), retain=False)
        except Exception:
            pass

    def _batch_ok(self, dest_peer_id: Optional[str]) -> bool:
        """Karşı taraf relay paketlerini gruplayarak alabiliyor mu?"""
        cap = self._peer_caps.get(dest_peer_id)
        return bool(cap and cap.get("bat") == 1)

    def _relay_topic(self, dest_peer_id: Optional[str]) -> str:
        """Relay verisinin yayınlanacağı konu: hub hedefin RX, peer kendi TX kanalı."""
        if self.is_hub:
            return self._rx_topic(dest_peer_id)
        return self._tx_topic(self.peer_id)

    def _publish_relay(self, topic: str, payload: bytes):
        try:
            self.mqtt.publish(topic, self.crypto.encrypt(payload), retain=False)
        except Exception:
            pass

    def _flush_loop(self):
        """Biriktirilmiş relay paketlerini kısa aralıklarla tek yayında gönderir."""
        while self.running:
            time.sleep(RELAY_BATCH_INTERVAL)
            self.flush_batches()

    def flush_batches(self):
        with self._batch_lock:
            if not self._batch:
                return
            items = list(self._batch.items())
            self._batch.clear()
        for topic, buf in items:
            self._publish_relay(topic, MSG_RELAY_BATCH + b"|" + bytes(buf))

    def send_relay(self, raw_pkt: bytes, dest_peer_id: Optional[str] = None):
        """Uçtan uca şifreli VPN paketini bulut relay kanalı üzerinden iletir.

        Hub: hedef peer'in RX kanalına yayınlar.
        Peer: kendi TX kanalına yayınlar (hub alır ve hedefe iletir).

        Karşı taraf gruplamayı destekliyorsa, aynı hedefe giden paketler kısa bir
        pencere boyunca biriktirilip tek MQTT yayınında gönderilir; bu, relay
        hattındaki mesaj sayısını (ve dolayısıyla gecikmeyi) ciddi biçimde azaltır.
        Desteklemiyorsa eski tek-paket biçimi kullanılır.
        """
        if not self.running or not self.mqtt:
            return
        if self.is_hub and (not dest_peer_id or dest_peer_id == HUB_PEER_ID):
            return
        if not self._batch_ok(dest_peer_id):
            self._publish_relay(self._relay_topic(dest_peer_id),
                                MSG_RELAY_DATA + b"|" + raw_pkt)
            return
        topic = self._relay_topic(dest_peer_id)
        with self._batch_lock:
            buf = self._batch.get(topic)
            if buf is None:
                buf = self._batch[topic] = bytearray()
            buf += struct.pack("!H", len(raw_pkt))
            buf += raw_pkt
            if len(buf) < RELAY_BATCH_MAX_BYTES:
                return
            payload = MSG_RELAY_BATCH + b"|" + bytes(buf)
            del self._batch[topic]
        self._publish_relay(topic, payload)

    def _dispatch_relay(self, data: bytes, from_peer_id: str):
        """Relay yayınını çözer: tek paket veya gruplanmış paket dizisi olabilir."""
        dec = self.crypto.decrypt(data)
        if not dec:
            return
        if dec.startswith(MSG_RELAY_BATCH + b"|"):
            body = dec[len(MSG_RELAY_BATCH) + 1:]
            off = 0
            while off + 2 <= len(body):
                size = struct.unpack("!H", body[off:off + 2])[0]
                off += 2
                if size == 0 or off + size > len(body):
                    break
                if self.on_relay_callback:
                    self.on_relay_callback(body[off:off + size], from_peer_id)
                off += size
        elif dec.startswith(MSG_RELAY_DATA + b"|"):
            if self.on_relay_callback:
                self.on_relay_callback(dec[len(MSG_RELAY_DATA) + 1:], from_peer_id)

    def _on_message(self, topic: str, data: bytes):
        if not self.running or not data:
            return
        prefix = f"{MQTT_BASE}/{self.room_id}/"
        if not topic.startswith(prefix):
            return
        parts = topic[len(prefix):].split("/")

        # 1) Veri kanalı: data/<pid>/tx  (hub, peer'lerin gidenini dinler)
        if parts[0] == "data" and len(parts) >= 3 and parts[2] == "tx":
            if self.is_hub:
                self._dispatch_relay(data, parts[1])
            return

        # 2) Veri kanalı: data/<pid>/rx  (peer, hub'dan geleni dinler)
        if parts[0] == "data" and len(parts) >= 3 and parts[2] == "rx":
            if not self.is_hub and parts[1] == self.peer_id:
                self._dispatch_relay(data, HUB_PEER_ID)
            return

        # 3) Eşleşme / atama kanalı: rv/<pid>
        if parts[0] == "rv" and len(parts) >= 2:
            pid = parts[1]
            dec = self.crypto.decrypt(data)
            if not dec:
                return
            try:
                info = json.loads(dec.decode("utf-8"))
            except Exception:
                return
            if info.get("t") == "assign":
                if self.on_assign_callback:
                    self.on_assign_callback(info)
                return
            if info.get("t") == "rv":
                sender = info.get("peer_id") or pid
                if sender == self.peer_id:
                    return  # kendi yayınımızın yankısı
                self._peer_caps[sender] = info  # karşı taraf relay gruplamasını destekliyor mu?
                if not self.is_hub and pid == HUB_PEER_ID:
                    self.peer_found = True
                if self.on_peer_callback:
                    self.on_peer_callback(info, sender)

    def stop(self):
        try:
            self.flush_batches()   # kuyrukta bekleyen son paketleri kaybetme
        except Exception:
            pass
        self.running = False
        if self.mqtt:
            try:
                own_id = HUB_PEER_ID if self.is_hub else self.peer_id
                self.mqtt.publish(self._rv_topic(own_id), b"", retain=True)
            except Exception:
                pass
            try:
                self.mqtt.disconnect()
            except Exception:
                pass


def run_system_cmd(args, timeout: float = 15.0) -> Tuple[bool, str]:
    """Sistem komutunu çalıştırır ve (başarılı, çıktı) döndürür.

    TUN adresi ve rota kurulumunda komut çıktısı yutulursa hata sessizce
    kaybolur: uygulama "bağlı" görünürken işletim sisteminde rota hiç
    kurulmamış olur ve ping "Hedefe ulaşılamıyor" ile biter. Bu yüzden kritik
    adımların tümü bu yardımcıdan geçer ve sonucu denetlenir.
    """
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", check=False, timeout=timeout)
    except Exception as e:
        return False, str(e)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    return r.returncode == 0, out


def _mask_to_prefix(mask: str) -> int:
    """'255.255.255.0' biçimindeki maskeyi önek uzunluğuna (24) çevirir."""
    try:
        return sum(bin(int(part)).count("1") for part in mask.split("."))
    except Exception:
        return 32


# ═══════════════════════════════════════════════════════════════════════
#  TUN ADAPTÖRÜ
# ═══════════════════════════════════════════════════════════════════════

class TUNAdapter:
    def __init__(self, name="Peertopeer"):
        self._name = name
        self._os = platform.system()
        self._wintun = None
        self._adapter = None
        self._session = None
        self._read_event = None
        self._fd = None
        self._active = False
        self._private_ok = None      # Windows: 'Özel' ağ profili ayarlandı mı?

    def open(self, ip, netmask=NETMASK, mtu=MTU):
        if self._os == "Windows":
            self._win_open(ip, netmask, mtu)
        elif self._os == "Linux":
            self._lin_open(ip, netmask, mtu)
        else:
            raise RuntimeError(t("eng.tun_unsupported", os=self._os))
        self._active = True

    def close(self):
        self._active = False
        if self._os == "Windows":
            self._win_close()
        elif self._os == "Linux":
            self._lin_close()

    def read(self) -> Optional[bytes]:
        if not self._active:
            return None
        return self._win_read() if self._os == "Windows" else self._lin_read()

    def write(self, data: bytes):
        if not self._active:
            return
        if self._os == "Windows":
            self._win_write(data)
        else:
            self._lin_write(data)

    # ── Windows wintun ──

    def _win_open(self, ip, netmask, mtu):
        dll = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll")
        if not os.path.exists(dll):
            dll = "wintun.dll"
        try:
            self._wintun = ctypes.cdll.LoadLibrary(dll)
        except OSError:
            raise RuntimeError(t("eng.wintun_missing"))
        W = self._wintun
        W.WintunCreateAdapter.restype = ctypes.c_void_p
        W.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
        W.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        W.WintunStartSession.restype = ctypes.c_void_p
        W.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        W.WintunEndSession.argtypes = [ctypes.c_void_p]
        W.WintunGetReadWaitEvent.restype = ctypes.c_void_p
        W.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        W.WintunReceivePacket.restype = ctypes.c_void_p
        W.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        W.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        W.WintunAllocateSendPacket.restype = ctypes.c_void_p
        W.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        W.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self._adapter = W.WintunCreateAdapter(self._name, "Peertopeer VPN", None)
        if not self._adapter:
            raise RuntimeError(t("eng.tun_create_fail"))
        self._session = W.WintunStartSession(self._adapter, 0x400000)
        if not self._session:
            W.WintunCloseAdapter(self._adapter)
            raise RuntimeError(t("eng.tun_session_fail"))
        self._read_event = W.WintunGetReadWaitEvent(self._session)

        try:
            self._win_configure(ip, netmask, mtu)
        except Exception:
            # Yapılandırma başarısızsa adaptörü/session'ı kapatmadan bırakmak
            # hayalet bir "Peertopeer" adaptörü bırakır; sonraki çalıştırmada
            # Windows yeni adaptöre "Peertopeer 2" adını verir ve netsh komutları
            # yanlış arayüzü hedefler. Bu yüzden burada temizleriz.
            self._win_close()
            raise

    def _win_configure(self, ip, netmask, mtu):
        """Wintun adaptörüne adresi atar ve arayüzü ayağa kaldırır.

        Wintun dokümanına göre adaptör önce yapılandırılıp sonra "up" durumuna
        getirilir. Yeni oluşturulan adaptör birkaç yüz milisaniye içinde hazır
        olur; adres ataması o ana kadar başarısız olabilir, bu yüzden denenir.
        Başarısızlık yukarı taşınır — aksi halde VPN "bağlı" görünürken
        işletim sisteminde rota oluşmaz ve hiçbir VPN IP'sine ulaşılamaz.
        """
        run_system_cmd(["netsh", "interface", "set", "interface",
                        f"name={self._name}", "admin=enable"])

        last = ""
        for _ in range(10):
            ok, out = run_system_cmd(["netsh", "interface", "ipv4", "set", "address",
                                      f"name={self._name}", "static", ip, netmask])
            if ok:
                break
            last = out
            time.sleep(0.5)
        else:
            raise RuntimeError(t("eng.tun_addr_fail", err=last or "-"))

        run_system_cmd(["netsh", "interface", "ipv4", "set", "subinterface",
                        self._name, f"mtu={mtu}", "store=active"])

        self._win_make_private()

    def _win_make_private(self):
        """Wintun arayüzünü "Özel" (Private) ağ profiline alır.

        Windows yeni oluşturulan sanal adaptörü çoğu zaman "Genel" (Public)
        sayar. Genel profilde gelen ping (ICMP echo) ve dosya paylaşımı gibi
        varsayılan kurallar kapalıdır; bu yüzden peer'ler hub'ı pingleyebilir
        ama birbirlerini pingleyemez ve servislerine erişemez. Arayüz "Özel"
        olunca Windows varsayılan ping/paylaşım kurallarını uygular.

        Uygulama kendi ICMP kuralını da ekler; burası o kuralın işlemediği
        (ör. üçüncü parti güvenlik duvarı, farklı profil) durumlar için ikinci
        güvence. Ağ profili adaptör oluşturulduktan hemen sonra hazır olmayabilir,
        bu yüzden kısa bir süre denenir; başarısızlık VPN'i durdurmaz.
        """
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
               f"Set-NetConnectionProfile -InterfaceAlias '{self._name}' "
               f"-NetworkCategory Private"]
        for _ in range(6):
            try:
                r = subprocess.run(cmd, capture_output=True, check=False, timeout=15)
                if r.returncode == 0:
                    self._private_ok = True
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        self._private_ok = False
        return False

    def add_route(self, dest: str, mask: str, gateway: str) -> str:
        """VPN trafiğini tünele yönlendiren bir rota ekler (varsa tazeler).

        Windows'ta sonraki atlama olarak tünelin kendi VPN adresi verilir;
        işletim sistemi bu adresi kendi arayüzü olarak bildiği için hedef
        için ARP/komşu çözümlemesi yapmaz ve paket doğrudan tünele girer.

        Dönüş: başarılıysa boş dize, aksi halde komutun hata çıktısı.
        """
        if self._os == "Windows":
            run_system_cmd(["route", "delete", dest])
            ok, out = run_system_cmd(["route", "add", dest, "mask", mask,
                                      gateway, "metric", "1"])
        else:
            ok, out = run_system_cmd(["ip", "route", "replace",
                                      f"{dest}/{_mask_to_prefix(mask)}",
                                      "dev", self._name])
        if ok:
            return ""
        log.warning(f"VPN rotası eklenemedi ({dest}): {out}")
        return out or "?"

    def _win_close(self):
        if self._session:
            try: self._wintun.WintunEndSession(self._session)
            except Exception: pass
            self._session = None
        if self._adapter:
            try: self._wintun.WintunCloseAdapter(self._adapter)
            except Exception: pass
            self._adapter = None

    def _win_read(self):
        if not self._session: return None
        sz = ctypes.c_uint32()
        p = self._wintun.WintunReceivePacket(self._session, ctypes.byref(sz))
        if not p:
            ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(self._read_event), 100)
            return None
        d = ctypes.string_at(p, sz.value)
        self._wintun.WintunReleaseReceivePacket(self._session, p)
        return bytes(d)

    def _win_write(self, data):
        if not self._session: return
        n = len(data)
        # Wintun ring tamponu dolduğunda WintunAllocateSendPacket NULL döner.
        # Paketi burada sessizce düşürmek, tünelden geçen TCP akışını (retransmit
        # fırtınası) çökertir. Bu yüzden kısa bir süre bekleyip yeniden deneriz.
        deadline = time.monotonic() + 0.2
        while True:
            p = self._wintun.WintunAllocateSendPacket(self._session, n)
            if p:
                ctypes.memmove(p, data, n)
                self._wintun.WintunSendPacket(self._session, p)
                return
            if not self._active or time.monotonic() >= deadline:
                return
            time.sleep(0.001)

    # ── Linux ──

    def _lin_open(self, ip, netmask, mtu):
        import fcntl
        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH14s", self._name.encode()[:16], 0x0001 | 0x1000, b"\x00" * 14)
        fcntl.ioctl(self._fd, 0x400454CA, ifr)
        subprocess.run(["ip", "addr", "add", f"{ip}/24", "dev", self._name], check=False)
        subprocess.run(["ip", "link", "set", self._name, "up"], check=False)
        subprocess.run(["ip", "link", "set", self._name, "mtu", str(mtu)], check=False)

    def _lin_close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _lin_read(self):
        import select
        r, _, _ = select.select([self._fd], [], [], 0.1)
        return os.read(self._fd, MTU + 100) if r else None

    def _lin_write(self, data):
        if self._fd is not None:
            os.write(self._fd, data)


# ═══════════════════════════════════════════════════════════════════════
#  PEER OTURUMU (Hub-and-Spoke)
# ═══════════════════════════════════════════════════════════════════════

class PeerSession:
    """Bağlı tek bir peer'in durumu (VPN IP, adres, taşıma, istatistik)."""

    __slots__ = ("peer_id", "addr", "vpn_ip", "transport", "last_recv",
                 "connected_at", "stats", "punch_active", "node_name")

    def __init__(self, peer_id: str, addr: Optional[Tuple[str, int]],
                 vpn_ip: str, transport: str = "relay", last_recv: float = 0.0,
                 node_name: str = ""):
        self.peer_id = peer_id
        self.addr = addr
        self.vpn_ip = vpn_ip
        self.transport = transport
        self.last_recv = last_recv or time.time()
        self.connected_at = time.time()
        self.stats = {"tx": 0, "rx": 0, "tp": 0, "rp": 0}
        self.punch_active = False
        self.node_name = node_name          # karşı makinenin duyurduğu hostname

    def public(self) -> dict:
        return {
            "peer_id": self.peer_id,
            "vpn_ip": self.vpn_ip,
            "public_ip": self.addr[0] if self.addr else "",
            "public_port": self.addr[1] if self.addr else 0,
            "transport": self.transport,
            "connected_at": self.connected_at,
            "node_name": self.node_name,
        }


# ═══════════════════════════════════════════════════════════════════════
#  P2P VPN ÇEKİRDEĞİ (GUI uyumlu)
# ═══════════════════════════════════════════════════════════════════════

class PeertopeerVPN:
    """
    P2P VPN Çekirdeği:
    - Çoklu STUN & NAT Tipi Tespiti (Cone vs Simetrik CGNat)
    - Agresif Port Delta Tahminli UDP Hole Punching
    - Çift Simetrik CGNat durumunda %100 Çalışan Uçtan Uca Şifreli Bulut Relay Fallback
    - Otomatik Direct P2P Yükseltme (Probe)
    """

    def __init__(self, key: str, ui_queue: queue.Queue):
        self.key = key
        self.crypto = CryptoEngine(key)
        self.node_name = local_node_name()   # bu makinenin peer'lere duyurulan adı
        self._ui = ui_queue
        self.sock: Optional[socket.socket] = None
        self.tun: Optional[TUNAdapter] = None
        self.is_hub = False
        self.peer_id = HUB_PEER_ID
        self.peers: dict = {}
        self._addr_index: dict = {}
        self._vpn_index: dict = {}
        self._free_ips = [f"{VPN_NET}.{i}" for i in range(IP_POOL_START, IP_POOL_END + 1)]
        self._peers_lock = threading.RLock()
        self.local_peer_addr: Optional[Tuple[str, int]] = None
        self.vpn_ip = ""
        self.remote_vpn_ip = ""
        self.transport = "direct"  # "direct" (UDP) veya "relay" (Cloud Relay)
        self.nat_info = {}
        self.peer_nat_info = {}
        self._running = False
        self._connected = False
        self._last_recv = 0.0
        self._stats = {"tx": 0, "rx": 0, "tp": 0, "rp": 0}
        self.upnp: Optional[UPnPEngine] = None
        self.rendezvous: Optional[CloudRendezvous] = None
        self._assign_event = threading.Event()
        self._assign_info = {}
        self._hub_event = threading.Event()
        self._hub_addr: Optional[Tuple[str, int]] = None
        self._probe_running = False
        self._client_roster: dict = {}   # İstemci: hub'dan gelen peer listesi (görüntü için)
        self._last_roster = 0.0
        self._last_relay_roster = 0.0
        self._ip_grace: dict = {}        # peer_id -> (vpn_ip, bırakılma zamanı)
        self._recovering = False         # istemci yeniden el sıkışma kilidi

    def _emit(self, *args):
        if self._ui:
            self._ui.put(args)

    def _log(self, level: str, msg: str):
        self._emit("log", level, msg)

    # ── SERVE ──

    def serve(self, port=12345, export_file="", remote_peer=None, auto_rendezvous=True):
        """Hub (dinleyici) modu: aynı anda çoklu peer kabul eder, aralarında yönlendirir."""
        self.is_hub = True
        self.peer_id = HUB_PEER_ID
        self.vpn_ip = HUB_IP
        self.remote_vpn_ip = ""
        self._running = True
        self._connected = True
        self.transport = "direct"
        self._emit("state", "discovering")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tune_socket_buffers(self.sock)
            self.sock.bind(("0.0.0.0", port))
            self.sock.settimeout(1.0)
        except Exception as e:
            self._log("ERROR", t("eng.port_fail", port=port, err=e))
            self._emit("state", "error")
            self._running = False
            return

        self._log("INFO", t("eng.listening", port=port))

        # Güvenlik Duvarı kuralı (Windows: UDP portu | Linux: ufw/firewalld/iptables)
        if check_admin():
            if setup_windows_firewall(port):
                self._log("INFO", t("eng.firewall", port=port))
            elif setup_linux_firewall(port):
                self._log("INFO", t("eng.firewall_linux", port=port))
            if setup_windows_icmp_rule():
                self._log("INFO", t("eng.firewall_icmp", net=f"{VPN_NET}.0/24"))
            if setup_windows_subnet_rule():
                self._log("INFO", t("eng.firewall_subnet", net=f"{VPN_NET}.0/24"))

        # UPnP Port Yönlendirmesi
        self.upnp = UPnPEngine()
        lip = get_local_ip()
        self._log("INFO", t("eng.upnp_trying"))
        upnp_ok = self.upnp.add_port_mapping(port, port, lip, "UDP", f"Peertopeer VPN {port}")
        if upnp_ok:
            self._log("INFO", t("eng.upnp_ok", port=port))
        else:
            self._log("INFO", t("eng.upnp_no"))

        # NAT Tipi ve Port Davranışı Tespiti
        self._log("INFO", t("eng.nat_analyzing"))
        self.nat_info = NATDetector.detect(sock=self.sock)
        self._log("INFO", t("eng.nat_result",
                            info=f"{self.nat_info['type']} ({self.nat_info['details']})"))
        self._emit("nat_result", self.nat_info)

        pub_ip, pub_port = resolve_public_endpoint(self.nat_info, port, upnp_ok)
        if pub_ip:
            self._log("INFO", t("eng.public_stun", addr=f"{pub_ip}:{pub_port}"))
        else:
            self._log("WARNING", t("eng.public_unknown"))
        self._emit("stun_result", pub_ip or lip, pub_port)

        # Peer bilgileri — public uç bulunamazsa yerel adres yedek olarak
        # kalır; aynı ağdaki istemciler dosyayla elle bağlanabilsin.
        peer_info = {
            "public_ip": pub_ip or lip,
            "public_port": pub_port or port,
            "vpn_ip": self.vpn_ip,
            "timestamp": int(time.time()),
            "local_ip": lip,
            "local_port": port,
            "nat_type": self.nat_info.get("type", t("nat.unknown")),
            "is_symmetric": self.nat_info.get("is_symmetric", False),
            "delta": self.nat_info.get("delta", 0),
            "ports": self.nat_info.get("ports", [])
        }
        self._emit("peer_info_ready", peer_info)

        # Export dosyası — paylaşılan anahtar da dosyaya yazılır ki istemci
        # şifreyi elle girmek zorunda kalmasın.
        if export_file:
            try:
                export_data = dict(peer_info)
                export_data["key"] = self.key
                with open(export_file, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                self._log("INFO", t("eng.peer_saved", file=export_file))
                self._log("INFO", t("eng.key_in_file"))
            except Exception as e:
                self._log("ERROR", t("eng.file_write_fail", err=e))

        # Otomatik Bulut Eşleşmesi (Cloud Rendezvous) — hub tüm peer'leri dinler
        if auto_rendezvous:
            self.rendezvous = CloudRendezvous(
                self.key,
                on_peer_callback=self._on_peer_rendezvous,
                on_relay_callback=self._on_hub_relay,
                log_callback=self._log,
                peer_id=HUB_PEER_ID,
            )
            self.rendezvous.start("hub", {
                "ip": pub_ip, "port": pub_port,
                "local_ip": lip, "local_port": port,
                "nat_type": self.nat_info.get("type"),
                "is_symmetric": self.nat_info.get("is_symmetric"),
                "delta": self.nat_info.get("delta"),
                "ports": self.nat_info.get("ports", []),
                "name": self.node_name
            })

        # Manuel CGNat hedefi verildiyse aktif punch başlat
        if remote_peer:
            self._log("INFO", t("eng.punch_start", addr=f"{remote_peer[0]}:{remote_peer[1]}"))
            threading.Thread(target=self._punch_sender_to, args=(remote_peer, None), daemon=True).start()

        # Hub TUN'unu hemen aç — peer'ler sonradan eklenir
        if not self._open_tun(HUB_IP):
            self._running = False
            return

        self._emit("state", "listening")
        self._emit("tunnel_info", HUB_IP, HUB_IP, "")
        self._log("INFO", t("eng.hub_ready"))

        threading.Thread(target=self._udp_reader, daemon=True).start()
        threading.Thread(target=self._tun_reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()
        threading.Thread(target=self._stats_loop, daemon=True).start()

        while self._running:
            time.sleep(0.5)

        self._emit("state", "disconnected")

    # ── CONNECT ──

    def connect(self, peer_ip="", peer_port=0, local_port=0, auto_rendezvous=True):
        self.is_hub = False
        self.peer_id = secrets.token_hex(6)
        self.vpn_ip = ""
        self.remote_vpn_ip = HUB_IP
        self._running = True
        self._connected = False
        self.transport = "direct"
        self._emit("state", "punching")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tune_socket_buffers(self.sock)
            self.sock.bind(("0.0.0.0", local_port))
            self.sock.settimeout(1.0)
        except Exception as e:
            self._log("ERROR", t("eng.sock_fail", err=e))
            self._emit("state", "error")
            self._running = False
            return

        lp = self.sock.getsockname()[1]
        lip = get_local_ip()
        self._log("INFO", t("eng.local_port", port=lp))
        self._log("INFO", t("eng.peer_id", id=self.peer_id))

        # Güvenlik Duvarı kuralı (Windows: UDP portu | Linux: ufw/firewalld/iptables)
        if check_admin():
            setup_windows_firewall(lp)
            setup_linux_firewall(lp)
            if setup_windows_icmp_rule():
                self._log("INFO", t("eng.firewall_icmp", net=f"{VPN_NET}.0/24"))
            if setup_windows_subnet_rule():
                self._log("INFO", t("eng.firewall_subnet", net=f"{VPN_NET}.0/24"))

        # İstemci tarafında da UPnP dene
        self.upnp = UPnPEngine()
        upnp_ok = self.upnp.add_port_mapping(lp, lp, lip, "UDP", f"Peertopeer Client {lp}")

        # NAT Tipi ve Port Davranışı Tespiti
        self._log("INFO", t("eng.nat_analyzing"))
        self.nat_info = NATDetector.detect(sock=self.sock)
        self._log("INFO", t("eng.nat_result",
                            info=f"{self.nat_info['type']} ({self.nat_info['details']})"))
        self._emit("nat_result", self.nat_info)

        pub_ip, pub_port = resolve_public_endpoint(self.nat_info, lp, upnp_ok)
        if pub_ip:
            self._log("INFO", t("eng.client_public", addr=f"{pub_ip}:{pub_port}"))
        else:
            self._log("WARNING", t("eng.public_unknown"))
        self._emit("stun_result", pub_ip or lip, pub_port)

        # Bulut Eşleşmesi — hub endpoint'i + kendi atamamız + relay verimiz
        if auto_rendezvous:
            self.rendezvous = CloudRendezvous(
                self.key,
                on_peer_callback=self._on_hub_endpoint,
                on_relay_callback=self._on_relay_packet,
                on_assign_callback=self._on_assign,
                log_callback=self._log,
                peer_id=self.peer_id,
            )
            self.rendezvous.start("client", {
                "ip": pub_ip, "port": pub_port,
                "local_ip": lip, "local_port": lp,
                "nat_type": self.nat_info.get("type"),
                "is_symmetric": self.nat_info.get("is_symmetric"),
                "delta": self.nat_info.get("delta"),
                "ports": self.nat_info.get("ports", []),
                "name": self.node_name
            })

        # Hub adresini belirle: manuel verilmişse o, yoksa buluttan bekle
        hub_addr: Optional[Tuple[str, int]] = None
        if peer_ip and peer_port:
            hub_addr = (peer_ip, int(peer_port))
        elif auto_rendezvous:
            self._log("INFO", t("eng.wait_hub"))
            self._hub_event.wait(timeout=10.0)
            hub_addr = self._hub_addr

        # Doğrudan UDP dene
        direct_ok = False
        if hub_addr:
            self._hub_addr = hub_addr
            with self._peers_lock:
                self.peers[HUB_PEER_ID] = PeerSession(HUB_PEER_ID, hub_addr, HUB_IP, "direct")
            self._log("INFO", t("eng.target", addr=f"{hub_addr[0]}:{hub_addr[1]}"))
            direct_ok = self._hole_punch_client(hub_addr)

        # Doğrudan olmadıysa bulut relay'ine düş
        if not direct_ok:
            if auto_rendezvous and self.rendezvous:
                self._log("INFO", t("eng.relay_wait"))
                if not self._assign_event.wait(timeout=45.0):
                    self._log("ERROR", t("eng.assign_timeout"))
                    self._running = False
                    self._emit("state", "error")
                    return
                with self._peers_lock:
                    sess = self.peers.get(HUB_PEER_ID)
                    if sess is None:
                        sess = PeerSession(HUB_PEER_ID, hub_addr, HUB_IP, "relay")
                        self.peers[HUB_PEER_ID] = sess
                    sess.transport = "relay"
            else:
                self._log("ERROR", t("eng.connect_fail"))
                self._emit("state", "error")
                self._running = False
                return

        # Atanan VPN IP'sini kesinleştir (ACK veya MSG_ASSIGN)
        if not self.vpn_ip:
            if auto_rendezvous:
                self._assign_event.wait(timeout=5.0)
            if not self.vpn_ip:
                self.vpn_ip = CLIENT_IP
        self.remote_vpn_ip = HUB_IP

        if not self._running:
            return

        if not self._open_tun(self.vpn_ip, HUB_IP):
            self._running = False
            return

        with self._peers_lock:
            sess = self.peers.get(HUB_PEER_ID)
        relay_mode = bool(sess and sess.transport == "relay")
        self._connected = True
        self._emit("state", "connected_relay" if relay_mode else "connected_direct")
        if sess and sess.transport == "direct" and sess.addr:
            peer_display = f"{sess.addr[0]}:{sess.addr[1]}"
        else:
            peer_display = t("trn.relay_secure")
        self._emit("tunnel_info", self.vpn_ip, HUB_IP, peer_display)
        if sess:
            self._emit("peer_joined", self._peer_public(sess))
        self._log("INFO", t("eng.tunnel_active", vpn=self.vpn_ip, hub=HUB_IP,
                            transport=(t("trn.relay") if relay_mode else t("trn.direct"))))

        threading.Thread(target=self._udp_reader, daemon=True).start()
        threading.Thread(target=self._tun_reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()
        threading.Thread(target=self._stats_loop, daemon=True).start()
        if relay_mode:
            threading.Thread(target=self._direct_probe_loop, daemon=True).start()

        while self._running:
            time.sleep(0.5)

        self._emit("state", "disconnected")

    def connect_from_file(self, path, local_port=0, auto_rendezvous=False):
        if not os.path.exists(path):
            self._log("ERROR", t("eng.file_not_found", path=path))
            self._emit("state", "error")
            return
        d = read_peer_file(path)
        if d is None:
            self._log("ERROR", t("eng.peer_file_fail", path=path))
            self._emit("state", "error")
            return

        # Dosyada kayıtlı anahtar varsa onu kullan (istemci elle girmek zorunda kalmasın)
        file_key = d.get("key")
        if file_key and file_key != self.key:
            self.key = file_key
            self.crypto = CryptoEngine(file_key)
            self._log("INFO", t("key.loaded_file"))

        ip = d.get("public_ip")
        port = d.get("public_port")
        if not ip or not port:
            self._log("ERROR", t("eng.file_no_endpoint"))
            self._emit("state", "error")
            return
        self._log("INFO", t("eng.file_read", addr=f"{ip}:{port}"))
        self.connect(ip, int(port), local_port, auto_rendezvous=auto_rendezvous)

    # ── Handshake & Peer Yönetimi ──

    @staticmethod
    def _ip_dst(pkt: bytes) -> Optional[str]:
        """IPv4 paketinden hedef IP'yi çıkarır."""
        if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
            try:
                return socket.inet_ntoa(pkt[16:20])
            except Exception:
                return None
        return None

    def _alloc_ip(self, peer_id: str = "") -> Optional[str]:
        """Boş VPN IP'si tahsis eder. _peers_lock tutulmalı.

        Peer daha önce düşüp yeniden bağlanıyorsa (IP_GRACE_SEC içinde) aynı VPN
        IP'si geri verilir; böylece istemcinin TUN adresi ve karşı uçtaki yollar
        bozulmaz.
        """
        if peer_id:
            g = self._ip_grace.pop(peer_id, None)
            if g:
                # İmtiyaz süresince rezerve tutulan IP aynen geri verilir.
                return g[0]
        return self._free_ips.pop(0) if self._free_ips else None

    def _free_ip(self, ip: str):
        """VPN IP'sini havuza geri verir. _peers_lock tutulmalı."""
        if ip and ip not in self._free_ips:
            self._free_ips.append(ip)
            self._free_ips.sort(key=lambda x: int(x.rsplit(".", 1)[1]))

    def _peer_public(self, sess: Optional[PeerSession]) -> dict:
        if sess is None:
            return {}
        d = sess.public()
        d["peer_count"] = len(self.peers)
        return d

    def refresh_peer_ui(self):
        """Arayüz yeniden kurulduğunda (ör. dil değişimi) peer listesini tekrar yayınlar."""
        with self._peers_lock:
            pubs = [self._peer_public(s) for s in self.peers.values()]
            roster = list(self._client_roster.values())
        for pub in pubs:
            if pub:
                self._emit("peer_joined", pub)
        for e in roster:
            if e.get("peer_id"):
                self._emit("peer_joined", {
                    "peer_id": e.get("peer_id"),
                    "vpn_ip": e.get("vpn_ip", ""),
                    "public_ip": e.get("public_ip", ""),
                    "public_port": e.get("public_port", 0),
                    "transport": e.get("transport", "relay"),
                    "node_name": e.get("name", ""),
                })

    # ── ROSTER (peer listesini tüm uçlara yayma) ──
    # Hub, bağlı peer listesini düzenli olarak tüm peer'lere gönderir; böylece
    # istemciler de diğer makineleri listelerinde görebilir. Yönlendirme yine
    # hub üzerinden yapılır — bu liste yalnızca görüntü amaçlıdır.

    def _build_roster(self) -> list:
        with self._peers_lock:
            return [
                {
                    "peer_id": s.peer_id,
                    "vpn_ip": s.vpn_ip,
                    "public_ip": s.addr[0] if s.addr else "",
                    "public_port": s.addr[1] if s.addr else 0,
                    "transport": s.transport,
                    "tx": s.stats["tx"],
                    "rx": s.stats["rx"],
                    "name": s.node_name,
                }
                for s in self.peers.values()
            ]

    def _broadcast_roster(self):
        """Hub: güncel peer listesini tüm bağlı peer'lere iletir.

        Doğrudan (UDP) peer'lere sık, relay peer'lerine ise daha seyrek gönderilir;
        aksi halde liste trafiği yavaş olan MQTT relay kanalını sürekli meşgul edip
        asıl veri akışını yavaşlatır.
        """
        if not self.is_hub or not self._running:
            return
        try:
            payload = json.dumps({"peers": self._build_roster()}).encode("utf-8")
        except Exception:
            return
        pkt = MSG_ROSTER + b"|" + payload
        now = time.time()
        relay_due = (now - self._last_relay_roster) >= ROSTER_RELAY_INTERVAL
        if relay_due:
            self._last_relay_roster = now
        with self._peers_lock:
            items = list(self.peers.items())
        for pid, sess in items:
            if sess.transport == "direct" and sess.addr and self.sock:
                try:
                    self.sock.sendto(self.crypto.encrypt(pkt), sess.addr)
                except Exception:
                    pass
            elif self.rendezvous and relay_due:
                try:
                    self.rendezvous.send_relay(pkt, pid)
                except Exception:
                    pass

    def _apply_roster(self, pt: bytes):
        """İstemci: hub'dan gelen peer listesini tabloya uygular."""
        try:
            data = json.loads(pt[len(MSG_ROSTER) + 1:].decode("utf-8"))
            entries = data.get("peers", [])
        except Exception:
            return

        with self._peers_lock:
            seen = set()
            for e in entries:
                pid = e.get("peer_id")
                if not pid or pid == self.peer_id or pid == HUB_PEER_ID:
                    continue
                seen.add(pid)
                if e.get("public_ip"):
                    pub = f"{e['public_ip']}:{e.get('public_port', 0)}"
                else:
                    pub = "Bulut Relay"
                if pid not in self._client_roster:
                    self._emit("peer_joined", {
                        "peer_id": pid,
                        "vpn_ip": e.get("vpn_ip", ""),
                        "public_ip": e.get("public_ip", ""),
                        "public_port": e.get("public_port", 0),
                        "transport": e.get("transport", "relay"),
                        "node_name": e.get("name", ""),
                    })
                    # Liste hub'dan gelir; istemcide de loglanmazsa "peer
                    # görünmüyor" durumu ayırt edilemez (liste hiç gelmiyor mu,
                    # yoksa arayüz mü göstermiyor?).
                    self._log("INFO", t("eng.roster_joined",
                                        name=e.get("name") or pid,
                                        ip=e.get("vpn_ip") or "—"))
                else:
                    if self._client_roster.get(pid, {}).get("name", "") != e.get("name", ""):
                        self._emit("peer_name", pid, e.get("name", ""))
                    self._emit("peer_update", pid, e.get("transport", "relay"), pub)
                self._emit("peer_stats", pid, e.get("tx", 0), e.get("rx", 0))
                self._client_roster[pid] = e

            for pid in list(self._client_roster.keys()):
                if pid not in seen:
                    gone = self._client_roster[pid]
                    self._emit("peer_left", pid)
                    del self._client_roster[pid]
                    self._log("WARNING", t("eng.roster_left",
                                           name=gone.get("name") or pid,
                                           ip=gone.get("vpn_ip") or "—"))

    def _handle_hello(self, addr, pt: bytes):
        """Hub: peer'den HELLO geldi — IP ata/tazele ve ACK ile bildir."""
        peer_id = ""
        node_name = ""
        if pt.startswith(MSG_HELLO + b"|"):
            parts = pt[len(MSG_HELLO) + 1:].decode("utf-8", "ignore").split("|")
            if len(parts) >= 2 and parts[0] == PROTO_VER:
                peer_id = parts[1]
                node_name = parts[4] if len(parts) >= 5 else ""
            elif len(parts) == 1:
                peer_id = f"{addr[0]}:{addr[1]}"
        if not peer_id:
            peer_id = f"{addr[0]}:{addr[1]}"

        with self._peers_lock:
            sess = self.peers.get(peer_id)
            new = sess is None
            if new:
                ip = self._alloc_ip(peer_id)
                if ip is None:
                    self._log("WARNING", t("eng.capacity_full"))
                    return
                sess = PeerSession(peer_id, addr, ip, "direct")
                self.peers[peer_id] = sess
                self._vpn_index[ip] = peer_id
            else:
                old = sess.addr
                if old and self._addr_index.get(old) == peer_id:
                    self._addr_index.pop(old, None)
                sess.addr = addr
                sess.transport = "direct"
            sess.last_recv = time.time()
            self._addr_index[addr] = peer_id
            name_changed = bool(node_name) and sess.node_name != node_name
            if node_name:
                sess.node_name = node_name
            vpn_ip = sess.vpn_ip

        if name_changed:
            self._emit("peer_name", peer_id, sess.node_name)

        ack = self.crypto.encrypt(
            MSG_ACK + f"|{PROTO_VER}|{vpn_ip}|{HUB_IP}|{time.time()}|{self.node_name}".encode())
        try:
            for _ in range(3):
                self.sock.sendto(ack, addr)
                time.sleep(0.01)
        except Exception:
            pass

        if self.rendezvous:
            try:
                self.rendezvous.subscribe_data(peer_id)
                self.rendezvous.publish_assign(peer_id, vpn_ip, HUB_IP)
            except Exception:
                pass

        if new:
            self._log("INFO", t("eng.peer_joined", peer=peer_id, ip=vpn_ip,
                                addr=f"{addr[0]}:{addr[1]}"))
            with self._peers_lock:
                self._emit("peer_joined", self._peer_public(sess))
            self._broadcast_roster()   # diğer peer'ler yeni makineyi görsün
        else:
            self._emit("peer_update", peer_id, "direct", f"{addr[0]}:{addr[1]}")

    def _handle_hub_hello(self, addr, pt: bytes):
        """İstemci: hub'dan HELLO geldi — bağlantıyı doğrudan kabul et."""
        node_name = ""
        if pt.startswith(MSG_HELLO + b"|"):
            parts = pt[len(MSG_HELLO) + 1:].decode("utf-8", "ignore").split("|")
            node_name = parts[4] if len(parts) >= 5 else ""
        with self._peers_lock:
            sess = self.peers.get(HUB_PEER_ID)
            new = sess is None
            if new:
                sess = PeerSession(HUB_PEER_ID, addr, HUB_IP, "direct")
                self.peers[HUB_PEER_ID] = sess
            sess.addr = addr
            sess.transport = "direct"
            sess.last_recv = time.time()
            name_changed = bool(node_name) and sess.node_name != node_name
            if node_name:
                sess.node_name = node_name
        if name_changed:
            self._emit("peer_name", HUB_PEER_ID, sess.node_name)
        ack = self.crypto.encrypt(
            MSG_ACK + f"|{PROTO_VER}|{self.vpn_ip or CLIENT_IP}|{HUB_IP}|{time.time()}|{self.node_name}".encode())
        try:
            self.sock.sendto(ack, addr)
        except Exception:
            pass
        if new:
            with self._peers_lock:
                self._emit("peer_joined", self._peer_public(sess))
        self._emit("peer_update", HUB_PEER_ID, "direct", f"{addr[0]}:{addr[1]}")

    def _parse_assign(self, dec: bytes):
        """ACK içinden (atanan_vpn_ip, hub_vpn_ip, hub_adı) çıkarır."""
        if not dec.startswith(MSG_ACK + b"|"):
            return None, None, ""
        parts = dec[len(MSG_ACK) + 1:].decode("utf-8", "ignore").split("|")
        if len(parts) >= 3 and parts[0] == PROTO_VER:
            return parts[1], (parts[2] or HUB_IP), (parts[4] if len(parts) >= 5 else "")
        return None, HUB_IP, ""

    def _apply_direct_peer(self, addr, pt: bytes):
        """İstemci: ACK/HELLO ile doğrudan bağlantıyı ve atanan IP'yi uygular."""
        if pt.startswith(MSG_ACK):
            assigned, hub_ip, node_name = self._parse_assign(pt)
        else:
            assigned, hub_ip = None, HUB_IP
            node_name = ""
        if assigned:
            self.vpn_ip = assigned
        if hub_ip:
            self.remote_vpn_ip = hub_ip
        with self._peers_lock:
            sess = self.peers.get(HUB_PEER_ID)
            if sess is None:
                sess = PeerSession(HUB_PEER_ID, addr, hub_ip or HUB_IP, "direct")
                self.peers[HUB_PEER_ID] = sess
            sess.addr = addr
            sess.transport = "direct"
            sess.last_recv = time.time()
            name_changed = bool(node_name) and sess.node_name != node_name
            if node_name:
                sess.node_name = node_name
        if name_changed:
            self._emit("peer_name", HUB_PEER_ID, sess.node_name)
        self._connected = True
        ack = self.crypto.encrypt(
            MSG_ACK + f"|{PROTO_VER}|{self.vpn_ip or CLIENT_IP}|{self.remote_vpn_ip}|{time.time()}".encode())
        try:
            for _ in range(3):
                self.sock.sendto(ack, addr)
                time.sleep(0.02)
        except Exception:
            pass
        if self.vpn_ip:
            self._assign_event.set()
        self._emit("peer_update", HUB_PEER_ID, "direct", f"{addr[0]}:{addr[1]}")

    def _hole_punch_client(self, target) -> bool:
        """İstemci: hub'a agresif UDP hole punch dener. Başarılıysa True döner."""
        peer_host, peer_port = target
        peer_delta = self.peer_nat_info.get("delta", 0)
        is_peer_symmetric = self.peer_nat_info.get("is_symmetric", False)

        if is_peer_symmetric or peer_delta != 0:
            d = peer_delta if peer_delta != 0 else 1
            candidate_offsets = [d, -d, 2*d, -2*d, 3*d, -3*d, 4*d, 1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 10, -10]
        else:
            candidate_offsets = [1, -1, 2, -2, 3, -3, 4, -4]

        self._log("INFO", t("eng.punch_aggressive", tries=PUNCH_TRIES, delay=PUNCH_DELAY))

        # recvfrom soketin 1 sn'lik zaman aşımıyla çağrılırsa her deneme 1 sn bloke
        # olur ve delme saniyede ~1 pakete düşer; bu da NAT deliğinin açılmamasına
        # yol açar. Delme boyunca kısa bir dinleme penceresi kullanılır.
        prev_timeout = self.sock.gettimeout()
        self.sock.settimeout(PUNCH_RECV_TIMEOUT)
        try:
            deadline = time.monotonic() + PUNCH_MAX_SECONDS
            for i in range(PUNCH_TRIES):
                if not self._running or self._connected:
                    return self._connected
                if time.monotonic() >= deadline:
                    # Erken bırak: relay'e düşüldükten sonra hub'ın delme
                    # paketleri ve arka plansız doğrudan yoklaması yolu yine de
                    # yükseltebilir; başlangıçta uzun süre takılı kalmayı önler.
                    return False
                try:
                    msg = MSG_HELLO + f"|{PROTO_VER}|{self.peer_id}|{time.time()}|{i}|{self.node_name}".encode()
                    pkt = self.crypto.encrypt(msg)

                    for dest in (target, self.local_peer_addr):
                        if not dest:
                            continue
                        if dest is self.local_peer_addr and dest[0] == "127.0.0.1":
                            continue
                        try:
                            self.sock.sendto(pkt, dest)
                        except Exception:
                            pass

                    # Simetrik NAT port tahmin yoklamaları
                    if i % 2 == 0:
                        for offset in candidate_offsets[:6]:
                            tp = peer_port + offset
                            if 1 <= tp <= 65535:
                                try: self.sock.sendto(pkt, (peer_host, tp))
                                except Exception: pass

                    if i % 10 == 0 and i > 0:
                        for offset in candidate_offsets[6:]:
                            tp = peer_port + offset
                            if 1 <= tp <= 65535:
                                try: self.sock.sendto(pkt, (peer_host, tp))
                                except Exception: pass

                    try:
                        data, addr = self.sock.recvfrom(4096)
                        pt = self.crypto.decrypt(data)
                        if pt and (pt.startswith(MSG_ACK) or pt.startswith(MSG_HELLO)):
                            self._apply_direct_peer(addr, pt)
                            self._log("INFO", t("eng.punch_direct_ok",
                                                addr=f"{addr[0]}:{addr[1]}"))
                            return True
                    except socket.timeout:
                        pass

                    if (i + 1) % 40 == 0:
                        self._log("INFO", t("eng.punch_trying", i=i + 1, n=PUNCH_TRIES))
                    time.sleep(PUNCH_DELAY)
                except Exception:
                    time.sleep(PUNCH_DELAY)
            return False
        finally:
            self.sock.settimeout(prev_timeout or 1.0)

    def _punch_sender_to(self, target, peer_id=None):
        """Hub/istemci: bir hedefe sürekli HELLO göndererek NAT deliği açar."""
        i = 0
        try:
            while self._running:
                if peer_id:
                    with self._peers_lock:
                        sess = self.peers.get(peer_id)
                    if sess is None or sess.transport == "direct":
                        break
                elif self.is_hub and self.peers:
                    break  # manuel CGNat hedefi: bir peer bağlandıysa dur
                try:
                    pkt = self.crypto.encrypt(
                        MSG_HELLO + f"|{PROTO_VER}|{self.peer_id}|{time.time()}|{i}|{self.node_name}".encode())
                    self.sock.sendto(pkt, target)
                    if self.local_peer_addr and self.local_peer_addr[0] != "127.0.0.1":
                        self.sock.sendto(pkt, self.local_peer_addr)
                    i += 1
                except Exception:
                    pass
                time.sleep(PUNCH_DELAY)
        finally:
            if peer_id:
                with self._peers_lock:
                    sess = self.peers.get(peer_id)
                    if sess:
                        sess.punch_active = False

    # ── Tünel & Veri Yolu ──

    def _open_tun(self, my_ip, route_ip=None) -> bool:
        self.vpn_ip = my_ip
        if not check_admin():
            self._log("WARNING", t("eng.no_admin_tun"))
        try:
            self.tun = TUNAdapter("Peertopeer")
            self.tun.open(my_ip, NETMASK, MTU)
        except Exception as e:
            self._log("ERROR", t("eng.tun_fail", err=e))
            self._emit("state", "error")
            return False

        # Windows: wintun arayüzü "Genel" profilde kalırsa peer'ler arası
        # ping/erişim varsayılan olarak bloke olur; sonucu kullanıcıya bildir.
        if platform.system() == "Windows" and self.tun._private_ok is not None:
            if self.tun._private_ok:
                self._log("INFO", t("eng.net_private_ok", iface=self.tun._name))
            else:
                self._log("WARNING", t("eng.net_private_fail", iface=self.tun._name))

        # VPN trafiğini tünele yönlendir. Yalnızca hub'a /32 rota eklemek
        # yetmez: diğer peer'lerin VPN IP'lerine giden paketler de tünele
        # girmelidir. Windows'ta tünel arayüzü bir alt ağ rotası oluşturduğu
        # için hedefler on-link sayılır ve ARP ile çözülmeye çalışılır; bu da
        # "Hedefe ulaşılamıyor" ile biter. Bu yüzden Windows'ta VPN alt ağının
        # tamamı için rota kurulur.
        routes = []
        if route_ip:
            routes.append((route_ip, "255.255.255.255"))
        if platform.system() == "Windows":
            routes.append((f"{VPN_NET}.0", NETMASK))
        for dest, mask in routes:
            try:
                err = self.tun.add_route(dest, mask, my_ip)
                if err:
                    self._log("WARNING", t("eng.route_fail", dest=dest, err=err))
            except Exception as e:
                self._log("WARNING", t("eng.route_fail", dest=dest, err=e))

        self._log("INFO", t("eng.tun_open", ip=my_ip))
        return True

    def _send_to_peer(self, peer_id: str, raw_pkt: bytes):
        """Tek bir peer'e (direct UDP veya bulut relay) VPN paketi gönderir."""
        with self._peers_lock:
            sess = self.peers.get(peer_id)
        if sess is None:
            return
        if sess.transport == "direct" and sess.addr and self.sock:
            try:
                self.sock.sendto(self.crypto.encrypt(raw_pkt), sess.addr)
                sess.stats["tx"] += len(raw_pkt)
                sess.stats["tp"] += 1
                self._stats["tx"] += len(raw_pkt)
                self._stats["tp"] += 1
            except Exception:
                pass
        elif self.rendezvous:
            self.rendezvous.send_relay(raw_pkt, peer_id)
            sess.stats["tx"] += len(raw_pkt)
            sess.stats["tp"] += 1
            self._stats["tx"] += len(raw_pkt)
            self._stats["tp"] += 1

    def _tun_reader(self):
        """TUN'dan okur; hub'da hedefe göre yönlendirir, istemcide hub'a yollar."""
        while self._running and self.tun:
            try:
                pkt = self.tun.read()
                if not pkt:
                    continue
                if self.is_hub:
                    dst = self._ip_dst(pkt)
                    target = None
                    if dst:
                        with self._peers_lock:
                            target = self._vpn_index.get(dst)
                    if target:
                        self._send_to_peer(target, pkt)
                else:
                    self._send_to_peer(HUB_PEER_ID, pkt)
            except Exception:
                if self._running:
                    time.sleep(0.01)

    def _touch_peer(self, addr, pt: bytes = b""):
        """Gelen KA/ACK ile peer'in son görülme zamanını ve adresini günceller.

        KA artık gönderenin peer kimliğini taşır (MSG_KA|peer_id). CGNAT/NAT
        yeniden eşlemesi nedeniyle kaynak port değişse bile hub oturumu kimliğe
        göre bulup adresi tazeler; aksi halde hub yeni porttan gelen KA'yı ve
        sonraki tüm veri paketlerini tanımayıp sessizce düşürürdü.
        """
        pid_hint = ""
        if pt.startswith(MSG_KA + b"|"):
            try:
                pid_hint = pt[len(MSG_KA) + 1:].decode("utf-8", "ignore").split("|", 1)[0].strip()
            except Exception:
                pid_hint = ""

        promoted: Optional[str] = None
        with self._peers_lock:
            pid = self._addr_index.get(addr)
            if pid_hint and self.is_hub and pid_hint in self.peers:
                # KA'nın kimliği şifreli/doğrulanmıştır; adres eşlemesi bayat
                # olsa bile (ör. NAT portu başka bir peer'e yeniden atanmışsa)
                # esas alınır.
                pid = pid_hint
            sess = self.peers.get(pid) if pid else None
            if sess is not None:
                if sess.addr and sess.addr != addr and self._addr_index.get(sess.addr) == pid:
                    self._addr_index.pop(sess.addr, None)
                # Doğrulanmış bir UDP paketi geldi: yol iki yönlü de çalıştığı
                # için oturumu doğrudan kabul et. Hub bunu yalnızca gelen HELLO
                # ile yapıyordu; restricted-cone NAT/yangın duvarı yüzünden
                # peer'in HELLO'su hub'a ulaşamazsa hub sonsuza kadar relay'de
                # takılı kalıyordu (istek gönderen tarafın yanıtı conntrack ile
                # geçtiği için ACK/KA yine de ulaşır).
                if sess.transport != "direct":
                    sess.transport = "direct"
                    if self.is_hub:
                        promoted = pid
                sess.addr = addr
                sess.last_recv = time.time()
                self._addr_index[addr] = pid
            elif not self.is_hub:
                sess = self.peers.get(HUB_PEER_ID)
                if sess:
                    sess.addr = addr
                    sess.transport = "direct"
                    sess.last_recv = time.time()
                    self._addr_index[addr] = HUB_PEER_ID

        if promoted:
            self._emit("peer_update", promoted, "direct", f"{addr[0]}:{addr[1]}")
            self._broadcast_roster()

    def _upgrade_peer_to_direct(self, addr):
        """Relay'deki bir peer'den doğrudan ACK geldi — UDP yoluna yükselt."""
        sess = None
        pid = None
        with self._peers_lock:
            pid = self._addr_index.get(addr)
            if pid is None and not self.is_hub:
                pid = HUB_PEER_ID
            if pid:
                sess = self.peers.get(pid)
            if sess:
                sess.addr = addr
                sess.transport = "direct"
                sess.last_recv = time.time()
                self._addr_index[addr] = pid
        if sess and pid:
            self._log("INFO", t("eng.direct_upgrade", addr=f"{addr[0]}:{addr[1]}"))
            self._emit("peer_update", pid, "direct", f"{addr[0]}:{addr[1]}")
            if not self.is_hub:
                self._emit("state", "connected_direct")
                self._emit("tunnel_info", self.vpn_ip, self.remote_vpn_ip, f"{addr[0]}:{addr[1]}")

    def _udp_reader(self):
        """Tek UDP soketini yönetir: el sıkışma, kontrol ve tüm peer verisi."""
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                # Hem hub hem istemci peer canlılığını denetler; istemci hub
                # sessizleşirse otomatik olarak yeniden el sıkışır.
                self._check_peer_timeouts()
                continue
            except Exception:
                if self._running:
                    time.sleep(0.01)
                continue

            pt = self.crypto.decrypt(data)
            if not pt:
                continue

            if pt.startswith(MSG_HELLO):
                if self.is_hub:
                    self._handle_hello(addr, pt)
                else:
                    self._handle_hub_hello(addr, pt)
                continue

            if pt.startswith(MSG_ACK):
                if self.is_hub:
                    self._touch_peer(addr)
                else:
                    self._apply_direct_peer(addr, pt)
                continue

            if pt.startswith(MSG_KA):
                self._touch_peer(addr, pt)
                continue

            if pt.startswith(MSG_RELAY_DIRECT_PING):
                try:
                    ack = self.crypto.encrypt(MSG_RELAY_DIRECT_ACK + b"|" + str(time.time()).encode())
                    self.sock.sendto(ack, addr)
                except Exception:
                    pass
                continue

            if pt.startswith(MSG_RELAY_DIRECT_ACK):
                self._upgrade_peer_to_direct(addr)
                continue

            if pt.startswith(MSG_ROSTER):
                if not self.is_hub:
                    self._apply_roster(pt)
                continue

            if pt.startswith(b"Peertopeer_"):
                continue

            # VPN veri paketi
            self._last_recv = time.time()
            if self.is_hub:
                pid = None
                target = None
                promoted = False
                with self._peers_lock:
                    pid = self._addr_index.get(addr)
                    sess = self.peers.get(pid) if pid else None
                    if sess is None:
                        continue
                    sess.last_recv = time.time()
                    sess.stats["rx"] += len(pt)
                    sess.stats["rp"] += 1
                    if sess.transport != "direct":
                        # Doğrudan veri geldi: yolu doğrudan kabul et (bkz. _touch_peer)
                        sess.transport = "direct"
                        promoted = True
                    dst = self._ip_dst(pt)
                    if dst:
                        target = self._vpn_index.get(dst)
                if promoted:
                    self._emit("peer_update", pid, "direct", f"{addr[0]}:{addr[1]}")
                    self._broadcast_roster()
                if target and target != pid:
                    self._send_to_peer(target, pt)
                elif self.tun:
                    try:
                        self.tun.write(pt)
                        self._stats["rx"] += len(pt)
                        self._stats["rp"] += 1
                    except Exception:
                        pass
            else:
                with self._peers_lock:
                    sess = self.peers.get(HUB_PEER_ID)
                    if sess:
                        sess.addr = addr
                        sess.last_recv = time.time()
                        sess.stats["rx"] += len(pt)
                        sess.stats["rp"] += 1
                if self.tun:
                    try:
                        self.tun.write(pt)
                        self._stats["rx"] += len(pt)
                        self._stats["rp"] += 1
                    except Exception:
                        pass

    # ── BULUT EŞLEŞMESİ & RELAY (çoklu peer) ──

    def _on_hub_endpoint(self, info, peer_id):
        """İstemci: hub'ın buluşma bilgisi geldi."""
        pip, pport = info.get("ip"), info.get("port")
        if pip and pport and not self._hub_addr:
            self._hub_addr = (pip, int(pport))
            self.peer_nat_info = info
            slip, slport = info.get("local_ip"), info.get("local_port")
            if slip and slport and slip != "127.0.0.1":
                self.local_peer_addr = (slip, int(slport))
            self._log("INFO", t("eng.hub_found", addr=f"{pip}:{pport}"))
            with self._peers_lock:
                sess = self.peers.get(HUB_PEER_ID)
                if sess is None:
                    sess = PeerSession(HUB_PEER_ID, self._hub_addr, HUB_IP, "relay",
                                       node_name=info.get("name", ""))
                    self.peers[HUB_PEER_ID] = sess
                elif info.get("name"):
                    sess.node_name = info["name"]
            if sess.node_name:
                self._emit("peer_name", HUB_PEER_ID, sess.node_name)
        self._hub_event.set()

    def _on_assign(self, info):
        """İstemci: hub atanan VPN IP'sini bildirdi (relay yolu)."""
        ip = info.get("ip")
        hub_ip = info.get("hub_ip") or HUB_IP
        if not ip:
            return
        self.vpn_ip = ip
        self.remote_vpn_ip = hub_ip
        self._assign_info = info
        with self._peers_lock:
            sess = self.peers.get(HUB_PEER_ID)
            if sess is None:
                sess = PeerSession(HUB_PEER_ID, self._hub_addr, hub_ip, "relay")
                self.peers[HUB_PEER_ID] = sess
            sess.vpn_ip = hub_ip
        self._assign_event.set()
        self._log("INFO", t("eng.assign_received", ip=ip, hub=hub_ip))

    def _on_peer_rendezvous(self, info, peer_id):
        """Hub: bir peer buluşma kanalına endpoint yayınladı."""
        if not self._running:
            return
        pip, pport = info.get("ip"), info.get("port")
        addr = (pip, int(pport)) if (pip and pport) else None
        new = False
        start_punch = False
        with self._peers_lock:
            sess = self.peers.get(peer_id)
            announced = info.get("name", "")
            if sess is None:
                ip = self._alloc_ip(peer_id)
                if ip is None:
                    self._log("WARNING", t("eng.capacity_full_relay"))
                    return
                sess = PeerSession(peer_id, addr, ip, "relay", node_name=announced)
                self.peers[peer_id] = sess
                self._vpn_index[ip] = peer_id
                if addr:
                    self._addr_index[addr] = peer_id
                new = True
            elif addr:
                sess.addr = addr
                self._addr_index[addr] = peer_id
            name_changed = bool(announced) and sess.node_name != announced
            if announced:
                sess.node_name = announced
            if addr and sess.transport != "direct" and not sess.punch_active:
                sess.punch_active = True
                start_punch = True
            vpn_ip = sess.vpn_ip
            pub = self._peer_public(sess)

        if name_changed:
            self._emit("peer_name", peer_id, sess.node_name)

        if self.rendezvous:
            try:
                self.rendezvous.subscribe_data(peer_id)
                self.rendezvous.publish_assign(peer_id, vpn_ip, HUB_IP)
            except Exception:
                pass
        if new:
            self._log("INFO", t("eng.relay_match", peer=peer_id, ip=vpn_ip))
            self._emit("peer_joined", pub)
            self._broadcast_roster()
        if start_punch:
            threading.Thread(target=self._punch_sender_to, args=(addr, peer_id), daemon=True).start()

    def _on_hub_relay(self, raw_pkt, from_peer_id):
        """Hub: relay üzerinden bir peer'den VPN paketi geldi (forward veya TUN)."""
        if not self._running or not self.tun:
            return
        if raw_pkt.startswith(MSG_ROSTER):
            return  # kontrol mesajı — istatistiğe sayılmaz
        with self._peers_lock:
            sess = self.peers.get(from_peer_id)
            if sess:
                sess.last_recv = time.time()
                sess.stats["rx"] += len(raw_pkt)
                sess.stats["rp"] += 1
        if raw_pkt.startswith(b"Peertopeer_"):
            return
        dst = self._ip_dst(raw_pkt)
        target = None
        if dst:
            with self._peers_lock:
                target = self._vpn_index.get(dst)
        if target and target != from_peer_id:
            self._send_to_peer(target, raw_pkt)
            return
        try:
            self.tun.write(raw_pkt)
            self._stats["rx"] += len(raw_pkt)
            self._stats["rp"] += 1
        except Exception:
            pass

    def _on_relay_packet(self, raw_pkt, from_peer_id=HUB_PEER_ID):
        """İstemci: relay üzerinden hub'dan veri geldi."""
        if not self._running:
            return
        if raw_pkt.startswith(MSG_ROSTER):
            self._apply_roster(raw_pkt)   # hub'ın yayınladığı peer listesi
            return
        if not self.tun:
            return
        with self._peers_lock:
            sess = self.peers.get(HUB_PEER_ID)
            if sess:
                sess.last_recv = time.time()
                sess.stats["rx"] += len(raw_pkt)
                sess.stats["rp"] += 1
        if raw_pkt.startswith(b"Peertopeer_"):
            return
        try:
            self.tun.write(raw_pkt)
            self._stats["rx"] += len(raw_pkt)
            self._stats["rp"] += 1
        except Exception:
            pass

    def _direct_probe_loop(self):
        """İstemci relay modundayken arka planda doğrudan UDP yolunu arar."""
        if not self._hub_addr or not self.sock:
            return
        self._probe_running = True
        while self._running and self._probe_running:
            with self._peers_lock:
                sess = self.peers.get(HUB_PEER_ID)
            if sess and sess.transport == "direct":
                break
            try:
                ping = self.crypto.encrypt(MSG_RELAY_DIRECT_PING + b"|" + str(time.time()).encode())
                self.sock.sendto(ping, self._hub_addr)
                if self.local_peer_addr and self.local_peer_addr[0] != "127.0.0.1":
                    self.sock.sendto(ping, self.local_peer_addr)
            except Exception:
                pass
            time.sleep(6.0)

    def _keepalive(self):
        # KA, gönderenin kimliğini taşır; alıcı NAT port değişiminde bile
        # oturumu bulup adresi tazeleyebilir.
        ka = MSG_KA + b"|" + self.peer_id.encode("utf-8")
        while self._running:
            try:
                with self._peers_lock:
                    items = list(self.peers.items())
                for pid, sess in items:
                    if self.is_hub and pid == HUB_PEER_ID:
                        continue
                    if sess.transport == "direct" and sess.addr and self.sock:
                        try:
                            self.sock.sendto(self.crypto.encrypt(ka), sess.addr)
                        except Exception:
                            pass
                    elif self.rendezvous:
                        self.rendezvous.send_relay(ka, pid)
            except Exception:
                pass
            time.sleep(KEEPALIVE_SEC)

    def _stats_loop(self):
        while self._running:
            time.sleep(1)
            self._emit("stats", self._stats["tx"], self._stats["rx"],
                       self._stats["tp"], self._stats["rp"])
            with self._peers_lock:
                items = list(self.peers.items())
            for pid, sess in items:
                self._emit("peer_stats", pid, sess.stats["tx"], sess.stats["rx"])
            # Hub: peer listesini periyodik olarak tüm uçlara yayınla
            if self.is_hub:
                now = time.time()
                if now - self._last_roster >= ROSTER_INTERVAL:
                    self._last_roster = now
                    self._broadcast_roster()

    def _check_peer_timeouts(self):
        now = time.time()

        # Süresi geçmiş IP imtiyazlarını temizle ve rezerve IP'leri havuza iade et
        expired = [pid for pid, (_, ts) in self._ip_grace.items() if now - ts > IP_GRACE_SEC]
        if expired:
            with self._peers_lock:
                for pid in expired:
                    g = self._ip_grace.pop(pid, None)
                    if g:
                        self._free_ip(g[0])

        dead = []
        with self._peers_lock:
            for pid, sess in self.peers.items():
                if self.is_hub and pid == HUB_PEER_ID:
                    continue
                if sess.last_recv and now - sess.last_recv > PEER_TIMEOUT:
                    dead.append(pid)

        if self.is_hub:
            for pid in dead:
                self._release_peer(pid)
        elif dead:
            # İstemci: hub sessizleşti — bağlantıyı yeniden kurmayı dene
            self._trigger_client_recovery()

    def _trigger_client_recovery(self):
        if self._recovering or not self._running:
            return
        self._recovering = True
        threading.Thread(target=self._client_recover_loop, daemon=True,
                         name="ClientRecover").start()

    def _client_recover_loop(self):
        """İstemci: hub yanıt vermiyor — HELLO ile yeniden el sıkış.

        KA'lar UDP üzerinden kaybolduysa veya hub oturumu düşürdüyse bu döngü
        periyodik HELLO gönderir; hub ACK ile karşılık verince (last_recv tazelenir)
        bağlantı otomatik olarak geri gelir.
        """
        self._log("WARNING", t("eng.hub_silent"))
        last_warn = time.time()
        last_pub = 0.0
        try:
            while self._running:
                with self._peers_lock:
                    sess = self.peers.get(HUB_PEER_ID)
                    last = sess.last_recv if sess else 0.0
                    transport = sess.transport if sess else "direct"
                if last and (time.time() - last) < (PEER_TIMEOUT / 3):
                    self._log("INFO", t("eng.recovered"))
                    return

                if transport == "relay":
                    # Relay yolunda HELLO göndermek hub'ı yanlışlıkla 'direct'e
                    # geçirir. Bunun yerine güvenli doğrudan yoklamasını tetikle
                    # ve endpoint'i tazeleyerek bulut eşleşmesini canlandır.
                    if self.sock and self._hub_addr:
                        try:
                            ping = self.crypto.encrypt(
                                MSG_RELAY_DIRECT_PING + b"|" + str(time.time()).encode())
                            self.sock.sendto(ping, self._hub_addr)
                            if self.local_peer_addr and self.local_peer_addr[0] != "127.0.0.1":
                                self.sock.sendto(ping, self.local_peer_addr)
                        except Exception:
                            pass
                    if self.rendezvous and (time.time() - last_pub) >= 15.0:
                        last_pub = time.time()
                        try:
                            self.rendezvous.publish_endpoint(self.peer_id, self.rendezvous.my_info)
                        except Exception:
                            pass
                else:
                    targets = [a for a in (self._hub_addr, self.local_peer_addr) if a]
                    if targets and self.sock:
                        msg = MSG_HELLO + f"|{PROTO_VER}|{self.peer_id}|{time.time()}|0|{self.node_name}".encode()
                        try:
                            pkt = self.crypto.encrypt(msg)
                            for dest in targets:
                                try:
                                    self.sock.sendto(pkt, dest)
                                except Exception:
                                    pass
                        except Exception:
                            pass

                if time.time() - last_warn >= 60.0:
                    last_warn = time.time()
                    self._log("WARNING", t("eng.hub_silent"))
                time.sleep(2.0)
        finally:
            self._recovering = False

    def _release_peer(self, peer_id):
        sess = None
        with self._peers_lock:
            sess = self.peers.pop(peer_id, None)
            if sess:
                self._vpn_index.pop(sess.vpn_ip, None)
                if sess.addr:
                    self._addr_index.pop(sess.addr, None)
                # IP'yi hemen havuza döndürmeyip imtiyaz süresince rezerve tut:
                # peer kısa süre içinde geri gelirse aynı VPN IP'sini alır.
                self._ip_grace[peer_id] = (sess.vpn_ip, time.time())
        if sess:
            self._log("WARNING", t("eng.peer_left", peer=peer_id, ip=sess.vpn_ip))
            self._emit("peer_left", peer_id)
            self._broadcast_roster()   # diğer peer'lerin listesi güncellensin

    def stop(self):
        self._running = False
        self._connected = False
        self._probe_running = False
        with self._peers_lock:
            for pid in list(self.peers.keys()):
                self._emit("peer_left", pid)
            self.peers.clear()
            self._addr_index.clear()
            self._vpn_index.clear()
            self._ip_grace.clear()
            self._free_ips = [f"{VPN_NET}.{i}" for i in range(IP_POOL_START, IP_POOL_END + 1)]
        for pid in list(self._client_roster.keys()):
            self._emit("peer_left", pid)
        self._client_roster.clear()
        if self.rendezvous:
            try: self.rendezvous.stop()
            except Exception: pass
            self.rendezvous = None
        if self.upnp:
            try: self.upnp.cleanup()
            except Exception: pass
            self.upnp = None
        if self.tun:
            try: self.tun.close()
            except Exception: pass
        if self.sock:
            try: self.sock.close()
            except Exception: pass
        self._log("INFO", t("eng.stopped"))


# ═══════════════════════════════════════════════════════════════════════
#  ARKA PLAN ÇALIŞANI VE YEREL KONTROL (terminalden bağımsız)
# ═══════════════════════════════════════════════════════════════════════
#  VPN'i terminalden bağımsız bir süreçte (detached) çalıştırır ve
#  127.0.0.1 üzerindeki küçük bir kontrol soketinden yönetir. Böylece
#  terminal penceresi kapatılsa bile VPN çalışmaya devam eder; yalnızca
#  menüden "Durdur" (veya --stop) ile durur.

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 47700
RUNTIME_FILE = os.path.join(os.path.expanduser("~"), ".peertopeer_vpn_runtime.json")
WORKER_LOG_FILE = os.path.join(os.path.expanduser("~"), ".peertopeer_vpn.log")


def control_request(cmd, port=CONTROL_PORT, timeout=2.5, **kw):
    """Çalışan arka plan VPN'ine tek bir komut gönderir ve yanıtı döndürür.

    Arka planda çalışan bir VPN yoksa (bağlantı kurulamazsa) None döner.
    """
    try:
        with socket.create_connection((CONTROL_HOST, int(port)), timeout=timeout) as s:
            s.sendall(json.dumps({"cmd": cmd, **kw}).encode("utf-8") + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        return json.loads(buf.decode("utf-8"))
    except Exception:
        return None


def worker_is_running(port=CONTROL_PORT) -> bool:
    """Arka planda çalışan bir VPN var mı?"""
    return control_request("ping", port=port) is not None


def _runtime_dir() -> str:
    """Çalışan sürecin kullanması gereken çalışma dizini (wintun.dll burada)."""
    if os.environ.get("APPIMAGE"):
        return os.path.dirname(os.path.abspath(os.environ["APPIMAGE"]))
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.getcwd()


def spawn_detached(extra_argv):
    """Uygulamayı terminalden bağımsız (detached) bir süreç olarak başlatır.

    Windows'ta DETACHED_PROCESS ile konsoldan kopar; Linux'ta yeni oturum
    açar (setsid). Çıktı bir günlük dosyasına yönlendirilir. Bu sayede
    denetleyici terminal kapatılsa bile arka plan süreci yaşamaya devam eder.
    """
    if os.environ.get("APPIMAGE"):
        base = [os.environ["APPIMAGE"]]
    elif getattr(sys, "frozen", False):
        base = [sys.executable]
    else:
        base = [sys.executable, os.path.abspath(sys.argv[0])]
    cmd = base + [str(a) for a in extra_argv]
    logf = open(WORKER_LOG_FILE, "ab", buffering=0)
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": logf,
        "stderr": logf,
        "close_fds": True,
        "cwd": _runtime_dir(),
    }
    if platform.system() == "Windows":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **kwargs)
        return proc.pid
    finally:
        try:
            logf.close()
        except Exception:
            pass


class _ControlHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if not line:
            return
        try:
            req = json.loads(line.decode("utf-8"))
        except Exception:
            return
        try:
            resp = self.server.app.control(req)
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        try:
            self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception:
            pass


class ControlServer(socketserver.ThreadingTCPServer):
    """Yalnızca yerel (127.0.0.1) kontrol komutlarını kabul eden küçük sunucu."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, app, port=CONTROL_PORT):
        self.app = app
        super().__init__((CONTROL_HOST, int(port)), _ControlHandler)


def _cli_status(port=CONTROL_PORT) -> int:
    """--status: çalışan arka plan VPN'inin durumunu yazdırır."""
    r = control_request("status", port=port)
    if not r or not r.get("ok"):
        print(t("bg.not_running"))
        return 1
    print(f"{t('cli.mode_label')}: {r.get('mode_label', '—')}")
    print(f"{t('cli.state_label')}: {r.get('state_label', '—')}")
    print(f"{t('stat.public')}: {r.get('public', '—')}")
    print(f"{t('stat.vpn')}: {r.get('vpn_ip', '—')}")
    print(f"{t('stat.tx')}: {r.get('tx', 0)} B   {t('stat.rx')}: {r.get('rx', 0)} B")
    print(f"{t('stat.uptime')}: {r.get('uptime', '00:00:00')}")
    print(f"{t('bg.peers_label')}: {r.get('peers', 0)}")
    return 0


def _cli_stop(port=CONTROL_PORT) -> int:
    """--stop: çalışan arka plan VPN'ini durdurur."""
    r = control_request("stop", port=port)
    if r and r.get("ok"):
        print(t("bg.stopping"))
        return 0
    print(t("bg.not_running"))
    return 1

# ── BAŞLANGIÇTA OTOMATİK ÇALIŞTIRMA ──────────────────────────────────
#  Windows: zamanlanmış görev (oturum açılışında, en yüksek yetkiyle).
#  Linux:   XDG autostart (.desktop) girdisi.
#  Her ikisi de uygulamayı "--background" ile başlatır; bu da kayıtlı son
#  bağlantı ayarlarını okuyup VPN'i arka planda çalıştırır.

AUTOSTART_TASK = "PertoperVPN"
AUTOSTART_DESKTOP = os.path.join(os.path.expanduser("~"), ".config",
                                 "autostart", "pertoper-vpn.desktop")


def app_base_argv():
    """Uygulamayı yeniden başlatmak için temel komut (executable + script)."""
    if os.environ.get("APPIMAGE"):
        return [os.environ["APPIMAGE"]]
    if getattr(sys, "frozen", False):
        return [sys.executable]
    if platform.system() == "Windows":
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        exe = pyw if os.path.exists(pyw) else sys.executable
        return [exe, os.path.abspath(sys.argv[0])]
    return [sys.executable, os.path.abspath(sys.argv[0])]


def autostart_supported() -> bool:
    return platform.system() in ("Windows", "Linux")


def _decode_win(data: bytes) -> str:
    """Windows komut ciktisini OEM kod sayfasiyla cozer (cp1254 hatasini onler)."""
    for enc in ("oem", "cp857", "cp1254", "utf-8"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", "replace")


def autostart_enabled() -> bool:
    """Başlangıçta otomatik çalıştırma etkin mi?"""
    sysname = platform.system()
    if sysname == "Windows":
        try:
            r = subprocess.run(["schtasks", "/query", "/tn", AUTOSTART_TASK],
                               capture_output=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False
    if sysname == "Linux":
        return os.path.exists(AUTOSTART_DESKTOP)
    return False


def _sh_quote(s: str) -> str:
    if s and all(c.isalnum() or c in "-_./:@=+" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _win_run_elevated(args_list) -> int:
    """schtasks'i UAC ile yükseltilmiş olarak çalıştırır; çıkış kodunu döndürür."""
    quoted = ",".join("'" + str(a).replace("'", "''") + "'" for a in args_list)
    ps = (f"$p = Start-Process -FilePath schtasks.exe -Verb RunAs -Wait -PassThru "
          f"-ArgumentList @({quoted}); exit $p.ExitCode")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=180)
    return r.returncode


def autostart_enable(exec_argv) -> Tuple[bool, str]:
    """Başlangıçta otomatik çalıştırmayı etkinleştirir."""
    sysname = platform.system()
    if sysname == "Windows":
        cmd = subprocess.list2cmdline([str(a) for a in exec_argv])
        args = ["/create", "/tn", AUTOSTART_TASK, "/tr", cmd,
                "/sc", "onlogon", "/rl", "highest", "/f"]
        try:
            r = subprocess.run(["schtasks"] + args, capture_output=True, timeout=30)
            if r.returncode == 0:
                return True, ""
            out = _decode_win((r.stderr or b"") + (r.stdout or b"")).strip()
            low = out.lower()
            if not check_admin() and ("erişim engellendi" in low
                                      or "access is denied" in low):
                if _win_run_elevated(args) == 0:
                    return True, ""
                return False, t("auto.denied")
            return False, out
        except Exception as e:
            return False, str(e)
    if sysname == "Linux":
        try:
            os.makedirs(os.path.dirname(AUTOSTART_DESKTOP), exist_ok=True)
            exec_line = " ".join(_sh_quote(str(a)) for a in exec_argv)
            content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Peertopeer P2P VPN\n"
                "Comment=Serverless P2P VPN client\n"
                f"Exec={exec_line}\n"
                "Terminal=false\n"
                "X-GNOME-Autostart-enabled=true\n"
            )
            with open(AUTOSTART_DESKTOP, "w", encoding="utf-8") as f:
                f.write(content)
            return True, ""
        except Exception as e:
            return False, str(e)
    return False, "unsupported"


def autostart_disable() -> Tuple[bool, str]:
    """Başlangıçta otomatik çalıştırmayı kapatır."""
    sysname = platform.system()
    if sysname == "Windows":
        if not autostart_enabled():
            return True, ""
        args = ["/delete", "/tn", AUTOSTART_TASK, "/f"]
        try:
            r = subprocess.run(["schtasks"] + args, capture_output=True, timeout=30)
            if r.returncode == 0:
                return True, ""
            out = _decode_win((r.stderr or b"") + (r.stdout or b"")).strip()
            low = out.lower()
            if ("cannot find" in low or "not find" in low
                    or "bulunamad" in low or "bulam" in low or "no such" in low):
                return True, ""
            if not check_admin() and ("erişim engellendi" in low
                                      or "access is denied" in low):
                if _win_run_elevated(args) == 0:
                    return True, ""
                return False, t("auto.denied")
            return False, out
        except Exception as e:
            return False, str(e)
    if sysname == "Linux":
        try:
            if os.path.exists(AUTOSTART_DESKTOP):
                os.remove(AUTOSTART_DESKTOP)
            return True, ""
        except Exception as e:
            return False, str(e)
    return False, "unsupported"

# ═══════════════════════════════════════════════════════════════════════
#  KOMUT SATIRI ARAYÜZÜ (CLI)
# ═══════════════════════════════════════════════════════════════════════

class CLIConsole:
    """Komut satırı arayüzü: argümanlarla yapılandırma + interaktif kabuk.

    VPN çekirdeği (PeertopeerVPN) arka planda çalışır ve durumunu bir kuyruğa
    (ui_queue) yazar; bu sınıf kuyruğu tüketip terminale basar. Etkileşimli
    modda kullanıcıdan komut okur, etkileşimsiz modda yalnızca olayları basar.
    """

    def __init__(self, args):
        self.args = args
        self.ui_queue: queue.Queue = queue.Queue()
        self.vpn: Optional[PeertopeerVPN] = None
        self.vpn_thread: Optional[threading.Thread] = None

        self._io_lock = threading.Lock()
        self._peers_lock = threading.RLock()
        self._running = True
        self._exit_code = 0
        self.headless = getattr(args, "worker", False)
        self._interactive = (not args.non_interactive) and not self.headless
        self._last_state_shown: Optional[str] = None
        self.use_menu = (not getattr(args, "shell", False)) and self._interactive
        self.control_port = getattr(args, "control_port", CONTROL_PORT)
        self._ansi = False
        self._menu_first = True
        self._log_tail_paused = False

        # Yapılandırma ('set' komutuyla çalışırken değiştirilebilir)
        self.settings = load_settings()
        _s = self.settings
        # Son kullanılan bağlantı ayarları hatırlanır; CLI argümanları önceliklidir.
        self.mode = args.mode or _s.get("mode") or "serve"
        self.key = args.key or _s.get("key") or ""
        try:
            self.port = (int(args.port) if args.port is not None
                         else int(_s.get("port") or 12345))
        except (TypeError, ValueError):
            self.port = 12345
        self.peer = args.peer if args.peer is not None else (_s.get("peer") or "")
        self.file = args.file if args.file is not None else (_s.get("file") or "")
        self.export = args.export if args.export is not None else (_s.get("export") or "")
        if args.no_auto:
            self.auto = False
        elif getattr(args, "auto", False):
            self.auto = True
        else:
            self.auto = bool(_s.get("auto", True))
        self.lang = set_ui_language(
            args.lang or self.settings.get("lang") or detect_ui_language())

        # Çalışma durumu
        self.state = "idle"
        self.connected = False
        self.connect_time: Optional[float] = None
        self.stats = {"tx": 0, "rx": 0}
        self.public_addr = "—"
        self.vpn_ip = "—"
        self.tunnel_peer_display = ""
        self._public_info = None

        # Peer listesi
        self.peers: dict = {}
        self.peer_node_name: dict = {}
        self.peer_names: dict = load_peer_names()

        # Log
        self.log_history: list = []
        self._log_base = 0

    # ── ÇIKTI YARDIMCILARI ──

    def _write(self, text: str):
        with self._io_lock:
            sys.stdout.write(text)
            sys.stdout.flush()

    def _line(self, text: str = ""):
        self._write(text + "\n")

    def _log(self, level: str, msg: str, echo: bool = True):
        """Log satırını geçmişe ekler ve (istenirse) terminale basar."""
        self.log_history.append((level, msg))
        if len(self.log_history) > 2000:
            drop = len(self.log_history) - 2000
            del self.log_history[:drop]
            self._log_base += drop
        if echo:
            ts = datetime.now().strftime("%H:%M:%S")
            self._line(f"{ts} [{level}] {msg}")

    # ── YAŞAM DÖNGÜSÜ ──

    def run(self):
        self._ansi = self._enable_ansi()
        self._line(t("cli.banner", v=VERSION))
        self._line(t("log.platform", os=platform.system(), arch=platform.machine()))
        self._line(t("log.crypto"))

        # Arka plan çalışanı (--worker): motoru ve kontrol sunucusunu çalıştır.
        if self.headless:
            self._log("INFO", t("bg.worker_start", pid=os.getpid()))
            return self._run_worker()

        self._line(f"{t('cli.mode_label')}: {self._mode_label()}")
        if not check_admin():
            self._line(t("log.no_admin"))
        if os.environ.get("PERTOPER_VPN_ELEV_FAILED") == "1":
            self._line(t("log.pkexec"))
        # Başlangıç satırlarını log geçmişine de ekle (log boş görünmesin)
        for _entry in (t("cli.banner", v=VERSION),
                       t("log.platform", os=platform.system(),
                         arch=platform.machine()),
                       t("log.crypto")):
            self.log_history.append(("INFO", _entry))

        # Etkileşimli (menü/kabuk): bu süreç bir DENETLEYİCİDİR. VPN,
        # terminalden bağımsız ayrı bir süreçte çalışır ve buradan yönetilir.
        if self._interactive:
            threading.Thread(target=self._remote_log_tail, daemon=True,
                             name="LogTail").start()
            if self.args.auto_start:
                self._start_vpn()
            if self.use_menu:
                self._menu_loop()
            else:
                self._shell_loop(return_to_menu=False)
            self._shutdown()
            return self._exit_code

        # Etkileşimsiz (servis) mod: motor bu süreçte, önplanda çalışır ve
        # yerel kontrol sunucusu açılır (--stop ile uzaktan durdurulabilir).
        self._line(t("cli.noninteractive"))
        return self._run_worker()

    def _event_loop(self):
        """VPN çekirdeğinin yaydığı olayları kuyruktan okur ve işler."""
        while self._running:
            try:
                msg = self.ui_queue.get(timeout=0.3)
            except queue.Empty:
                continue
            try:
                self._handle_event(msg)
            except Exception:
                pass

    def _handle_event(self, msg):
        ev = msg[0]
        if ev == "log":
            self._log(msg[1], msg[2])
        elif ev == "state":
            self._set_state(msg[1])
        elif ev == "stats":
            self.stats["tx"], self.stats["rx"] = msg[1], msg[2]
        elif ev == "peer_joined":
            self._add_peer(msg[1])
        elif ev == "peer_left":
            self._remove_peer(msg[1])
        elif ev == "peer_update":
            self._update_peer(msg[1], msg[2], msg[3] if len(msg) > 3 else None)
        elif ev == "peer_stats":
            self._set_peer_stats(msg[1], msg[2], msg[3])
        elif ev == "peer_name":
            self._set_peer_name(msg[1], msg[2])
        elif ev == "nat_result":
            info = msg[1]
            self._line(t("stun.nat_result",
                         info=f"{info.get('type')} ({info.get('details')})"))
        elif ev == "stun_result":
            self.public_addr = f"{msg[1]}:{msg[2]}"
        elif ev == "tunnel_info":
            self.vpn_ip = msg[1]
            self.tunnel_peer_display = msg[3] if len(msg) > 3 else ""
        elif ev == "peer_info_ready":
            self._public_info = msg[1]

    # ── DURUM ──

    def _set_state(self, state):
        self.state = state
        connected_states = ("connected", "connected_direct",
                            "connected_relay", "listening")
        if state in connected_states:
            self.connected = True
            if not self.connect_time:
                self.connect_time = time.time()
        elif state in ("idle", "disconnected", "error"):
            self.connected = False
            self.connect_time = None
            self.public_addr = "—"
            self.vpn_ip = "—"
            self.tunnel_peer_display = ""
            with self._peers_lock:
                self.peers.clear()
                self.peer_node_name.clear()
        if state != self._last_state_shown:
            self._last_state_shown = state
            self._line("» " + self._state_label(state))
        # Etkileşimsiz modda başarısız/kopan oturumda sonsuza kadar bekleme.
        if not self._interactive and state in ("error", "disconnected"):
            self._exit_code = 1
            self._running = False

    def _state_label(self, state):
        mapping = {
            "idle": t("st.idle"),
            "discovering": t("st.discovering"),
            "waiting": t("st.waiting"),
            "listening": t("st.listening"),
            "punching": t("st.punching"),
            "connected": t("st.connected_direct"),
            "connected_direct": t("st.connected_direct"),
            "connected_relay": t("st.connected_relay"),
            "disconnected": t("st.disconnected"),
            "error": t("st.error"),
        }
        return mapping.get(state, state)

    # ── PEER YÖNETİMİ ──

    def _display_name(self, pid):
        """Görünen ad: takma isim > duyurulan hostname > peer kimliği."""
        announced = self.peer_node_name.get(pid, "")
        if announced and announced in self.peer_names:
            return self.peer_names[announced]
        return self.peer_names.get(pid) or announced or pid

    def _peer_pub_addr(self, p):
        if p.get("public_ip"):
            return f"{p['public_ip']}:{p.get('public_port', 0)}"
        return t("trn.relay")

    def _add_peer(self, p):
        pid = p.get("peer_id")
        if not pid:
            return
        with self._peers_lock:
            if p.get("node_name"):
                self.peer_node_name[pid] = p["node_name"]
            is_new = pid not in self.peers
            prev = self.peers.get(pid, {})
            self.peers[pid] = {
                "vpn_ip": p.get("vpn_ip") or "—",
                "public_ip": p.get("public_ip") or "",
                "public_port": p.get("public_port") or 0,
                "transport": p.get("transport", "direct"),
                "tx": prev.get("tx", 0),
                "rx": prev.get("rx", 0),
                "node_name": p.get("node_name", ""),
            }
            name = self._display_name(pid)
            pub = self._peer_pub_addr(self.peers[pid])
            vpn_ip = self.peers[pid]["vpn_ip"]
        if is_new:
            self._line(t("eng.peer_joined", peer=name, ip=vpn_ip, addr=pub))

    def _remove_peer(self, pid):
        with self._peers_lock:
            p = self.peers.pop(pid, None)
            if p is None:
                return
            name = self._display_name(pid)
            self.peer_node_name.pop(pid, None)
            vpn_ip = p.get("vpn_ip") or "—"
        self._line(t("eng.roster_left", name=name, ip=vpn_ip))

    def _update_peer(self, pid, transport=None, public=None):
        with self._peers_lock:
            p = self.peers.get(pid)
            if not p:
                return
            if transport:
                p["transport"] = transport
            if public:
                ip, _, port = public.rpartition(":")
                if ip and port.isdigit():
                    p["public_ip"], p["public_port"] = ip, int(port)
                else:
                    p["public_ip"], p["public_port"] = "", 0

    def _set_peer_stats(self, pid, tx, rx):
        with self._peers_lock:
            p = self.peers.get(pid)
            if p:
                p["tx"], p["rx"] = tx, rx

    def _set_peer_name(self, pid, name):
        with self._peers_lock:
            if pid in self.peers and name:
                self.peer_node_name[pid] = name

    # ── KOMUT DİSPEÇİ ──

    def _dispatch(self, line):
        line = (line or "").strip()
        if not line:
            return
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]
        handlers = {
            "help": self.cmd_help, "?": self.cmd_help,
            "status": self.cmd_status, "durum": self.cmd_status,
            "peers": self.cmd_peers, "peer": self.cmd_peers,
            "log": self.cmd_log, "logs": self.cmd_log,
            "rename": self.cmd_rename, "isim": self.cmd_rename,
            "set": self.cmd_set, "ayar": self.cmd_set,
            "genkey": self.cmd_genkey, "key": self.cmd_genkey,
            "anahtar": self.cmd_genkey,
            "stun": self.cmd_stun,
            "start": self.cmd_start, "baslat": self.cmd_start,
            "stop": self.cmd_stop, "durdur": self.cmd_stop,
            "about": self.cmd_about, "hakkinda": self.cmd_about,
            "lang": self.cmd_lang, "dil": self.cmd_lang,
            "clear": self.cmd_clear, "temizle": self.cmd_clear,
            "quit": self.cmd_quit, "exit": self.cmd_quit,
            "q": self.cmd_quit, "cikis": self.cmd_quit,
        }
        handler = handlers.get(cmd)
        if handler is None:
            self._line(t("cli.unknown_cmd", cmd=cmd))
            return
        try:
            handler(args)
        except Exception as e:
            self._line(f"[ERROR] {e}")

    def cmd_help(self, _args=None):
        self._line(t("cli.help"))

    def cmd_status(self, _args=None):
        if self._interactive:
            self._remote_status_print()
            return
        rows = [
            (t("cli.mode_label"), self._mode_label()),
            (t("cli.state_label"), self._state_label(self.state)),
            (t("stat.public"), self.public_addr),
            (t("stat.vpn"), self.vpn_ip),
            (t("stat.tx"), self._fmt_bytes(self.stats["tx"])),
            (t("stat.rx"), self._fmt_bytes(self.stats["rx"])),
            (t("stat.uptime"), self._uptime_str()),
            (t("set.key"), ("•" * 8) if self.key else "—"),
            (t("set.port"), str(self.port)),
            (t("prs.col_transport"),
             self._transport_label(self._main_transport())),
        ]
        width = max(len(label) for label, _ in rows)
        self._line("")
        for label, value in rows:
            self._line(f"  {label:<{width}} : {value}")
        self._line("")

    def cmd_peers(self, _args=None):
        if self._interactive:
            self._remote_peers_print()
            return
        self._line("")
        if not self.peers:
            self._line("  " + t("prs.empty"))
            self._line("")
            return
        headers = (t("prs.col_name"), t("stat.vpn"), t("stat.public"),
                   t("prs.col_transport"), t("stat.rx"), t("stat.tx"))
        rows = []
        with self._peers_lock:
            for pid, p in list(self.peers.items()):
                rows.append((
                    self._display_name(pid), p.get("vpn_ip") or "—",
                    self._peer_pub_addr(p),
                    self._transport_label(p.get("transport")),
                    self._fmt_bytes(p.get("rx", 0)),
                    self._fmt_bytes(p.get("tx", 0)),
                ))
        self._print_table(headers, rows)
        self._line("")

    def cmd_log(self, args=None):
        if self._interactive:
            n = 50
            if args:
                try:
                    n = max(1, int(args[0]))
                except ValueError:
                    pass
            self._remote_log_print(n)
            return
        n = 20
        if args:
            try:
                n = max(1, int(args[0]))
            except ValueError:
                pass
        for level, msg in self.log_history[-n:]:
            self._line(f"[{level}] {msg}")

    def cmd_rename(self, args=None):
        args = args or []
        if not args:
            self._line(t("cli.rename_usage"))
            return
        target = self._resolve_peer(args[0])
        if target is None:
            self._line(t("cli.rename_usage"))
            return
        name = " ".join(args[1:]).strip()
        key = self.peer_node_name.get(target) or target
        if name:
            self.peer_names[key] = name
        else:
            self.peer_names.pop(key, None)
            self.peer_names.pop(target, None)
        if save_peer_names(self.peer_names):
            if name:
                self._line(t("cli.rename_done", peer=target, name=name))
            else:
                self._line(t("cli.rename_cleared", peer=target))
        else:
            self._line(t("prs.name_save_failed", path=PEER_NAMES_FILE))

    def cmd_set(self, args=None):
        args = args or []
        if len(args) < 2:
            self._line(t("cli.set_usage"))
            return
        field = args[0].lower()
        value = " ".join(args[1:]).strip()
        if field == "key":
            self.key = value
        elif field == "port":
            try:
                port = int(value)
            except ValueError:
                self._line(t("err.bad_port"))
                return
            if not (1 <= port <= 65535):
                self._line(t("err.bad_port"))
                return
            self.port = port
        elif field == "peer":
            self.peer = value
        elif field == "file":
            self.file = value
            if self.mode == "connect" and os.path.exists(value):
                k = (read_peer_file(value) or {}).get("key")
                if k:
                    self.key = k
        elif field == "export":
            self.export = value
        elif field == "auto":
            self.auto = value.lower() in (
                "1", "true", "on", "yes", "evet", "acik", "açık")
        elif field == "mode":
            if value in ("serve", "connect"):
                self.mode = value
            else:
                self._line(t("cli.set_bad", field=field, value=value))
                return
        elif field in ("lang", "dil"):
            self.cmd_lang([value])
            return
        else:
            self._line(t("cli.set_unknown", field=field))
            return
        self._line(t("cli.set_ok", field=field, value=value))
        self._save_connection()

    def cmd_genkey(self, _args=None):
        self.key = _generate_key()
        self._line(t("cli.key_generated", key=self.key))

    def cmd_stun(self, _args=None):
        self._line(t("stun.starting"))

        def _run():
            nat = NATDetector.detect()
            lip = get_local_ip()
            if nat:
                pub_ip = nat.get("public_ip", lip)
                pub_port = nat.get("public_port", 0)
                self.ui_queue.put(("log", "INFO", t("stun.public", ip=pub_ip)))
                self.ui_queue.put(("log", "INFO", t("stun.local", ip=lip)))
                self.ui_queue.put(("log", "INFO", t("stun.nat", info=nat.get('type'))))
                self.ui_queue.put(("log", "INFO",
                                   t("stun.port_behavior", info=nat.get('details'))))
                self.ui_queue.put(("stun_result", pub_ip, pub_port))
            else:
                self.ui_queue.put(("log", "ERROR", t("stun.failed")))
            upnp = UPnPEngine()
            if upnp.discover():
                self.ui_queue.put(("log", "INFO",
                                   t("stun.upnp_yes", service=upnp.service_type)))
            else:
                self.ui_queue.put(("log", "INFO", t("stun.upnp_no")))

        threading.Thread(target=_run, daemon=True).start()

    def cmd_start(self, _args=None):
        self._start_vpn()

    def cmd_stop(self, _args=None):
        if self._interactive:
            r = control_request("stop", port=self.control_port)
            self._line(t("bg.stopping") if (r and r.get("ok")) else t("bg.not_running"))
            return
        self._stop_vpn()

    def cmd_about(self, _args=None):
        self._line("")
        self._line("  Peertopeer P2P VPN  " + t("about.version", v=VERSION))
        self._line("  " + t("about.tagline"))
        self._line("  " + t("about.feat1"))
        self._line("  " + t("about.feat2"))
        self._line("")
        self._line("  " + t("about.developer") + ": Bekir Alişoğlu")
        self._line("  ✉  alisoglu@yahoo.com")
        self._line("  📞  0544 487 71 42")
        self._line("")
        self._line("  " + t("about.language") + ": " + LANG_NAMES[self.lang])
        self._line("")

    def cmd_lang(self, args=None):
        args = args or []
        if not args:
            self._line(t("cli.lang_now", lang=LANG_NAMES[self.lang]))
            return
        code = args[0].lower()
        if code not in LANG_NAMES:
            self._line(t("cli.lang_bad", code=code))
            return
        self.lang = set_ui_language(code)
        self.settings["lang"] = self.lang
        save_settings(self.settings)
        self._line(t("cli.lang_set", lang=LANG_NAMES[self.lang]))

    def cmd_clear(self, _args=None):
        self.log_history.clear()
        self._line(t("cli.log_cleared"))

    def cmd_quit(self, _args=None):
        self._running = False

    # ── VPN KONTROLÜ ──

    def _start_vpn(self) -> bool:
        """VPN'i başlatır; başlatılabildiyse True, yapılandırma hatasında False."""
        # Etkileşimli denetleyici: VPN'i terminalden bağımsız arka planda başlat.
        if self._interactive:
            return self._spawn_worker()
        if self.connected or (self.vpn_thread and self.vpn_thread.is_alive()):
            self._line(t("cli.already_running"))
            return False

        # Önceki başarısız/bitmiş oturumdan kalan kaynakları bırak; aksi halde
        # eski MQTT bağlantısı ve UDP soketi sızar ve port yeniden bağlanamaz.
        if self.vpn is not None and (
                self.vpn_thread is None or not self.vpn_thread.is_alive()):
            try:
                self.vpn.stop()
            except Exception:
                pass
            self.vpn = None
            self.vpn_thread = None

        key = self.key
        # connect modunda peer dosyası seçiliyse anahtar dosyadan okunur.
        if self.mode == "connect" and self.file and os.path.exists(self.file):
            file_key = (read_peer_file(self.file) or {}).get("key")
            if file_key:
                key = file_key
        if not key:
            self._line(t("err.key_required"))
            return False
        self.key = key

        if not (1 <= self.port <= 65535):
            self._line(t("err.bad_port"))
            return False

        self.vpn = PeertopeerVPN(key, self.ui_queue)
        auto = self.auto

        if self.mode == "serve":
            remote_peer = None
            if self.peer:
                host, _, port = self.peer.rpartition(":")
                if not host or not port.isdigit():
                    self._line(t("err.cgnat_format"))
                    return False
                remote_peer = (host, int(port))
            export = self.export or self.file
            self.vpn_thread = threading.Thread(
                target=self.vpn.serve,
                args=(self.port, export, remote_peer, auto),
                daemon=True)
        else:
            file_ok = bool(self.file) and os.path.exists(self.file)
            if self.file and not file_ok:
                self._line(t("eng.file_not_found", path=self.file))
            if not self.peer and not file_ok and not auto:
                self._line(t("err.peer_required"))
                return False
            if file_ok:
                self.vpn_thread = threading.Thread(
                    target=self.vpn.connect_from_file,
                    args=(self.file, 0, auto), daemon=True)
            elif self.peer:
                host, _, port = self.peer.rpartition(":")
                if not host or not port.isdigit():
                    self._line(t("err.peer_format"))
                    return False
                self.vpn_thread = threading.Thread(
                    target=self.vpn.connect,
                    args=(host, int(port), 0, auto), daemon=True)
            elif auto:
                self.vpn_thread = threading.Thread(
                    target=self.vpn.connect,
                    args=("", 0, 0, True), daemon=True)
            else:
                self._line(t("err.peer_file_missing"))
                return False

        self._line(t("cli.starting", mode=self._mode_label()))
        self.vpn_thread.start()
        return True

    def _stop_vpn(self):
        if not self.vpn:
            self._line(t("cli.not_running"))
            return
        self._line(t("cli.stopping"))
        try:
            self.vpn.stop()
        except Exception:
            pass
        self.vpn = None
        self.vpn_thread = None
        self.connected = False
        self.connect_time = None

    def _shutdown(self):
        if self.vpn:
            try:
                self.vpn.stop()
            except Exception:
                pass
        self._line(t("cli.goodbye"))

    # ── MENÜ (deneyimsiz kullanıcı için yönlendirmeli arayüz) ──

    @staticmethod
    def _enable_ansi() -> bool:
        """Windows 10+ konsolunda ANSI (ekran temizleme) desteğini açar."""
        if platform.system() != "Windows":
            return True
        try:
            k = ctypes.windll.kernel32
            handle = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(k.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False

    def _clear_screen(self):
        if self._ansi and sys.stdout.isatty():
            self._write("\x1b[2J\x1b[H")

    def _state_short(self) -> str:
        s = self.state
        if s in ("connected", "connected_direct", "connected_relay", "listening"):
            return t("menu.st_connected")
        if s in ("discovering", "punching", "waiting"):
            return t("menu.st_busy")
        if s == "error":
            return t("menu.st_error")
        return t("menu.st_ready")

    def _prompt(self) -> str:
        role = "hub" if self.mode == "serve" else "peer"
        return f"{role}[{self._state_short()}]> "

    def _pause(self):
        try:
            input(t("menu.press_enter"))
        except (EOFError, KeyboardInterrupt):
            self._line("")

    def _ask(self, prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            value = input(f"{prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            self._line("")
            return default
        return value or default

    def _ask_int(self, prompt: str, default: int, lo: int, hi: int) -> int:
        while True:
            value = self._ask(prompt, str(default))
            try:
                n = int(value)
                if lo <= n <= hi:
                    return n
            except ValueError:
                pass
            self._line(t("menu.invalid"))

    def _draw_menu(self):
        if self._menu_first:
            self._menu_first = False
        else:
            self._clear_screen()
        rule = "─" * 54
        self._line(rule)
        self._line("  Peertopeer P2P VPN v" + VERSION)
        remote = self._controller_state()
        if remote:
            self._line(f"  {t('cli.mode_label')}: {remote.get('mode_label')}      "
                       f"{t('conn.label')}: {self._conn_label(remote)}")
            self._line(f"  {t('stat.vpn')}: {remote.get('vpn_ip')}      "
                       f"{t('bg.peers_label')}: {remote.get('peers')}      "
                       f"{t('stat.uptime')}: {remote.get('uptime')}")
            self._line(f"  {t('prs.col_transport')}: {remote.get('transport')}      "
                       f"[{t('bg.background')}]")
        else:
            self._line(f"  {t('cli.mode_label')}: {self._mode_label()}      "
                       f"{t('conn.label')}: {t('conn.off')}")
            self._line(f"  {t('set.key')}: "
                       f"{t('menu.key_yes') if self.key else t('menu.key_no')}      "
                       f"{t('set.port')}: {self.port}")
        self._line(f"  {t('menu.opt_auto')}: {'ON' if self.auto else 'OFF'}")
        if not check_admin():
            self._line("  ! " + t("log.no_admin"))
        self._line(rule)
        items = [
            t("menu.opt_start"), t("menu.opt_quick"), t("menu.opt_stop"),
            t("menu.opt_status"), t("menu.opt_peers"), t("menu.opt_log"),
            t("menu.opt_settings"), t("menu.opt_autostart"), t("menu.opt_stun"),
            t("menu.opt_lang"), t("menu.opt_about"), t("menu.opt_advanced"),
        ]
        for i, label in enumerate(items, start=1):
            self._line(f"  {i:>2}) {label}")
        self._line(f"   0) {t('menu.opt_quit')}")
        self._line("")

    def _menu_loop(self):
        while self._running:
            self._draw_menu()
            try:
                raw = input(t("menu.choice") + " ")
            except (EOFError, KeyboardInterrupt):
                self._line("")
                break
            choice = raw.strip()
            if choice == "":
                continue
            if choice == "0":
                break
            elif choice == "1":
                self._wizard_start()
            elif choice == "2":
                self._quick_start()
                self._pause()
            elif choice == "3":
                self.cmd_stop()
                self._pause()
            elif choice == "4":
                self._menu_status_live()
            elif choice == "5":
                self.cmd_peers()
                self._pause()
            elif choice == "6":
                self.cmd_log(["50"])
                self._pause()
            elif choice == "7":
                self._menu_settings()
            elif choice == "8":
                self._menu_autostart()
            elif choice == "9":
                self.cmd_stun()
                self._pause()
            elif choice == "10":
                self._menu_lang()
            elif choice == "11":
                self.cmd_about()
                self._pause()
            elif choice == "12":
                self._shell_loop(return_to_menu=True)
            else:
                self._line(t("menu.invalid"))
                self._pause()

    def _key_pressed(self):
        """Basılmış bekleyen bir tuş var mı? (engellemez; yoksa False)"""
        if platform.system() == "Windows":
            try:
                import msvcrt
                return msvcrt.kbhit()
            except Exception:
                return False
        try:
            import select
            r, _, _ = select.select([sys.stdin], [], [], 0)
            return bool(r)
        except Exception:
            return False

    def _live_wait(self, timeout: float) -> bool:
        """Belirli süre boyunca tuş bekler; q/Esc/Enter basılırsa True döner."""
        if platform.system() == "Windows":
            start = time.time()
            while time.time() - start < timeout:
                if not self._running:
                    return True
                try:
                    import msvcrt
                    if msvcrt.kbhit():
                        ch = msvcrt.getwch()
                        if ch in ("\x00", "\xe0"):      # özel tuş (ok, F tuşu...)
                            try:
                                msvcrt.getwch()
                            except Exception:
                                pass
                            continue
                        if ch in ("q", "Q", "\r", "\x1b"):  # q / Enter / Esc
                            return True
                except Exception:
                    break
                time.sleep(0.03)
            return False
        # Unix/macOS: stdin kanonik modda olduğundan yalnızca Enter alınabilir.
        try:
            import select
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            return bool(r)
        except Exception:
            time.sleep(timeout)
            return False

    def _draw_live_screen(self):
        """Canlı durum/istatistik ekranını yeniden çizer (İnteraktif menü 4)."""
        if self._ansi:
            self._write("\x1b[H\x1b[2J")
        else:
            # ANSI yoksa (ör. eski konsol): cls/clear ile ekranı temizle.
            try:
                os.system("cls" if platform.system() == "Windows" else "clear")
            except Exception:
                self._line("")
                self._line("─" * 54)
        self._line("")
        self._line("  " + t("live.title"))
        self._line("  " + t("live.hint"))
        self._line(t("live.refresh"))
        self._line("")
        r = self._controller_state()
        if not r:
            self._line("  " + t("bg.not_running"))
            self._line("")
            return
        rows = [
            (t("cli.mode_label"), r.get("mode_label", "—")),
            (t("cli.state_label"), r.get("state_label", "—")),
            (t("stat.public"), r.get("public", "—")),
            (t("stat.vpn"), r.get("vpn_ip", "—")),
            (t("stat.tx"), self._fmt_bytes(int(r.get("tx", 0)))),
            (t("stat.rx"), self._fmt_bytes(int(r.get("rx", 0)))),
            (t("stat.uptime"), r.get("uptime", "00:00:00")),
            (t("set.port"), str(r.get("port", "—"))),
            (t("prs.col_transport"), r.get("transport", "—")),
            (t("bg.peers_label"), str(r.get("peers", 0))),
        ]
        width = max(len(lbl) for lbl, _ in rows)
        for lbl, val in rows:
            self._line(f"  {lbl:<{width}} : {val}")
        # bağlı cihazların canlı trafik tablosu
        self._line("")
        self._line("  " + t("prs.title", n=r.get("peers", 0)))
        pr = control_request("peers", port=self.control_port)
        if pr and pr.get("ok") and pr.get("peers"):
            headers = (t("prs.col_name"), t("stat.vpn"), t("stat.public"),
                       t("prs.col_transport"), t("stat.rx"), t("stat.tx"))
            rows2 = []
            for p in pr["peers"]:
                rows2.append((
                    p.get("name", "—"), p.get("vpn_ip", "—"),
                    p.get("public", "—"), p.get("transport", "—"),
                    self._fmt_bytes(int(p.get("rx", 0))),
                    self._fmt_bytes(int(p.get("tx", 0))),
                ))
            self._print_table(headers, rows2)
        else:
            self._line("  " + t("prs.empty"))
        self._line("")

    def _menu_status_live(self):
        """4) Durum ve istatistikler: saniyede bir tazelenen canlı ekran."""
        self._clear_screen()
        self._log_tail_paused = True
        try:
            while self._running:
                self._draw_live_screen()
                if self._live_wait(1.0):
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self._log_tail_paused = False
        self._clear_screen()

    def _shell_loop(self, return_to_menu: bool):
        self._line(t("cli.hint"))
        if return_to_menu:
            self._line(t("menu.back_hint"))
        while self._running:
            try:
                line = input(self._prompt())
            except (EOFError, KeyboardInterrupt):
                self._line("")
                break
            stripped = line.strip().lower()
            cmd = stripped.split(" ")[0] if stripped else ""
            if return_to_menu and cmd in ("quit", "exit", "q", "cikis",
                                          "menu", "geri", "back", "0"):
                break
            self._dispatch(line)

    def _menu_lang(self):
        self._clear_screen()
        self._line(t("about.language") + ":")
        for i, code in enumerate(LANGUAGES, start=1):
            mark = "  ✓" if code == self.lang else ""
            self._line(f"  {i}) {LANG_NAMES[code]}{mark}")
        self._line(f"  0) {t('menu.opt_back')}")
        c = self._ask_int(t("menu.choice"), 0, 0, len(LANGUAGES))
        if c == 0:
            return
        code = LANGUAGES[c - 1]
        self.lang = set_ui_language(code)
        self.settings["lang"] = self.lang
        save_settings(self.settings)
        self._line(t("cli.lang_set", lang=LANG_NAMES[self.lang]))
        self._pause()

    def _menu_settings(self):
        while True:
            self._clear_screen()
            self._line("=== " + t("set.title") + " ===")
            self._line(f"  {t('set.key')}: "
                       f"{t('menu.key_yes') if self.key else t('menu.key_no')}")
            self._line(f"  {t('set.port')}: {self.port}")
            self._line(f"  {t('cli.mode_label')}: {self._mode_label()}")
            self._line(f"  {t('set.peer_addr')}: {self.peer or '—'}")
            self._line(f"  {t('set.peer_file')}: {self.file or '—'}")
            self._line(f"  {t('menu.opt_auto')}: {'ON' if self.auto else 'OFF'}")
            self._line("")
            self._line("  1) " + t("set.key"))
            self._line("  2) " + t("set.port"))
            self._line(f"  3) {t('cli.mode_label')} (hub/peer)")
            self._line("  4) " + t("set.peer_addr"))
            self._line("  5) " + t("set.peer_file"))
            self._line("  6) " + t("menu.opt_auto"))
            self._line("  0) " + t("menu.opt_back"))
            c = self._ask_int(t("menu.choice"), 0, 0, 6)
            if c == 0:
                return
            elif c == 1:
                self._ask_key()
            elif c == 2:
                value = self._ask(t("wiz.port"), str(self.port))
                try:
                    port = int(value)
                    if 1 <= port <= 65535:
                        self.port = port
                        self._line(t("cli.set_ok", field="port", value=value))
                    else:
                        self._line(t("err.bad_port"))
                except ValueError:
                    self._line(t("err.bad_port"))
            elif c == 3:
                m = self._ask_int(t("cli.mode_label") + " (1=hub, 2=peer)",
                                  1 if self.mode == "serve" else 2, 1, 2)
                self.mode = "serve" if m == 1 else "connect"
                self._line(t("cli.set_ok", field="mode", value=self.mode))
            elif c == 4:
                self.peer = self._ask(t("set.peer_addr"), self.peer)
            elif c == 5:
                self.file = self._ask(t("set.peer_file"), self.file)
            elif c == 6:
                self.auto = not self.auto
                self._line(t("cli.set_ok", field="auto",
                             value=("ON" if self.auto else "OFF")))
            self._save_connection()
            self._refresh_autostart()
            self._pause()

    def _ask_key(self):
        self._line(t("wiz.key_intro"))
        kinds = []
        if self.key:
            kinds.append("saved")
        kinds += ["gen", "manual", "file"]
        labels = {"saved": t("wiz.key_saved"), "gen": t("wiz.key_gen"),
                  "manual": t("wiz.key_manual"), "file": t("wiz.key_file")}
        for i, kind in enumerate(kinds, start=1):
            self._line(f"  {i}) {labels[kind]}")
        c = self._ask_int(t("menu.choice"), 1, 1, len(kinds))
        kind = kinds[c - 1]
        if kind == "saved":
            return
        if kind == "gen":
            self.key = _generate_key()
            self._line(t("wiz.key_shown", key=self.key))
        elif kind == "manual":
            value = self._ask(t("set.key_ph"))
            if value:
                self.key = value
        else:
            path = self._ask(t("wiz.enter_file"))
            if path:
                self.file = path
                file_key = (read_peer_file(path) or {}).get("key")
                if file_key:
                    self.key = file_key
                    self._line(t("key.loaded_file"))
                else:
                    self._line(t("eng.file_not_found", path=path))

    def _wizard_start(self):
        self._clear_screen()
        self._line("=== " + t("wiz.title") + " ===")
        self._line("")
        # 1) Rol
        self._line(t("wiz.role"))
        self._line("  " + t("wiz.role_hub"))
        self._line("  " + t("wiz.role_peer"))
        role = self._ask_int(t("menu.choice"), 1 if self.mode == "serve" else 2, 1, 2)
        self.mode = "serve" if role == 1 else "connect"
        self._line("")
        # 2) Anahtar
        self._ask_key()
        if not self.key:
            self._line(t("err.key_required"))
            self._pause()
            return
        # 3) Port
        port_str = self._ask(t("wiz.port"), str(self.port))
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                self.port = port
        except ValueError:
            pass
        # 4) Moda özel ayarlar
        if self.mode == "serve":
            self.peer = ""
            self.auto = True
            self.export = self._ask(t("wiz.export"), self.export)
        else:
            self._line("")
            self._line(t("wiz.conn_intro"))
            self._line("  " + t("wiz.conn_auto"))
            self._line("  " + t("wiz.conn_addr"))
            self._line("  " + t("wiz.conn_file"))
            conn = self._ask_int(t("menu.choice"), 1, 1, 3)
            if conn == 1:
                self.peer = ""
                self.file = ""
            elif conn == 2:
                self.peer = self._ask(t("wiz.enter_addr"))
                self.file = ""
            else:
                self.file = self._ask(t("wiz.enter_file"))
                self.peer = ""
        # 5) Özet + onay
        self._line("")
        self._line(t("wiz.summary") + ":")
        self._line("  " + t("cli.mode_label") + ": " + self._mode_label())
        self._line("  " + t("set.key") + ": "
                   + (t("menu.key_yes") if self.key else t("menu.key_no")))
        self._line("  " + t("set.port") + ": " + str(self.port))
        if self.mode == "serve":
            self._line("  " + t("set.export_short") + ": " + (self.export or "—"))
        else:
            if self.peer:
                conn_desc = self.peer
            elif self.file:
                conn_desc = self.file
            else:
                conn_desc = t("menu.opt_auto")
            self._line("  " + t("set.peer_addr") + ": " + conn_desc)
        ok = self._ask_int(t("wiz.confirm"), 1, 1, 2)
        if ok != 1:
            self._line(t("wiz.cancelled"))
            self._pause()
            return
        self._save_connection()
        self._start_vpn()
        self._refresh_autostart()
        self._pause()

    # ── ARKA PLAN ÇALIŞANI VE KONTROL ──

    def _worker_argv(self):
        """Arka plan çalışanını başlatacak argüman listesini üretir."""
        argv = ["--worker", "-m", self.mode, "-p", str(self.port),
                "--lang", self.lang, "--control-port", str(self.control_port)]
        if self.key:
            argv += ["-k", self.key]
        if self.peer:
            argv += ["--peer", self.peer]
        if self.file:
            argv += ["-f", self.file]
        if self.export:
            argv += ["--export", self.export]
        if not self.auto:
            argv += ["--no-auto"]
        return argv

    def _spawn_worker(self) -> bool:
        """VPN'i terminalden bağımsız bir arka plan sürecinde başlatır."""
        if not self.key:
            self._line(t("err.key_required"))
            return False
        if not (1 <= self.port <= 65535):
            self._line(t("err.bad_port"))
            return False
        if worker_is_running(self.control_port):
            self._line(t("bg.already"))
            return False
        try:
            pid = spawn_detached(self._worker_argv())
        except Exception as e:
            self._line(t("bg.spawn_fail", err=e))
            return False
        for _ in range(24):
            if worker_is_running(self.control_port):
                self._save_connection()
                self._refresh_autostart()
                self._line(t("bg.started", pid=pid))
                self._line(t("bg.log_hint", path=WORKER_LOG_FILE))
                st = self._controller_state()
                if st and st.get("state") == "error":
                    self._line(t("conn.start_error"))
                return True
            time.sleep(0.25)
        self._line(t("bg.start_fail"))
        return False

    def _controller_state(self):
        r = control_request("status", port=self.control_port)
        return r if (r and r.get("ok")) else None

    def _remote_status_print(self):
        r = self._controller_state()
        if not r:
            self._line(t("bg.not_running"))
            return
        rows = [
            (t("cli.mode_label"), r.get("mode_label", "—")),
            (t("cli.state_label"), r.get("state_label", "—")),
            (t("stat.public"), r.get("public", "—")),
            (t("stat.vpn"), r.get("vpn_ip", "—")),
            (t("stat.tx"), self._fmt_bytes(int(r.get("tx", 0)))),
            (t("stat.rx"), self._fmt_bytes(int(r.get("rx", 0)))),
            (t("stat.uptime"), r.get("uptime", "00:00:00")),
            (t("set.port"), str(r.get("port", "—"))),
            (t("prs.col_transport"), r.get("transport", "—")),
            (t("bg.peers_label"), str(r.get("peers", 0))),
        ]
        width = max(len(lbl) for lbl, _ in rows)
        self._line("")
        for lbl, val in rows:
            self._line(f"  {lbl:<{width}} : {val}")
        self._line("")

    def _remote_peers_print(self):
        r = control_request("peers", port=self.control_port)
        self._line("")
        if not r or not r.get("ok") or not r.get("peers"):
            self._line("  " + t("prs.empty"))
            self._line("")
            return
        headers = (t("prs.col_name"), t("stat.vpn"), t("stat.public"),
                   t("prs.col_transport"), t("stat.rx"), t("stat.tx"))
        rows = []
        for p in r["peers"]:
            rows.append((
                p.get("name", "—"), p.get("vpn_ip", "—"),
                p.get("public", "—"), p.get("transport", "—"),
                self._fmt_bytes(int(p.get("rx", 0))),
                self._fmt_bytes(int(p.get("tx", 0))),
            ))
        self._print_table(headers, rows)
        self._line("")

    def _remote_log_print(self, n=50):
        r = control_request("log", port=self.control_port, n=n)
        if not r or not r.get("ok"):
            self._line(t("bg.not_running"))
            return
        for item in r.get("log", []):
            self._line(f"[{item.get('level')}] {item.get('msg')}")

    def _conn_label(self, remote=None):
        st = (remote or {}).get("state")
        if st in ("connected", "connected_direct", "connected_relay", "listening"):
            return t("conn.connected")
        if st in ("discovering", "punching", "waiting"):
            return t("conn.connecting")
        if st == "error":
            return t("conn.error")
        return t("conn.off")

    def _remote_log_tail(self):
        """Arka plan çalışanının loglarını canlı olarak ekrana akıtır."""
        cursor = 0
        while self._running:
            r = control_request("log", port=self.control_port, since=cursor, timeout=1.2)
            if r and r.get("ok"):
                if not self._log_tail_paused:
                    for item in r.get("log", []):
                        self._line(f"  · [{item.get('level')}] {item.get('msg')}")
                    try:
                        cursor = int(r.get("total", cursor))
                    except Exception:
                        pass
            else:
                cursor = 0
            time.sleep(1.0)

    def _run_worker(self) -> int:
        """Arka plan çalışanı: VPN motorunu ve yerel kontrol sunucusunu çalıştırır."""
        threading.Thread(target=self._event_loop, daemon=True,
                         name="WorkerEvents").start()
        if not self._start_vpn():
            self._log("ERROR", t("bg.worker_bad_config"))
            return 1
        try:
            self.server = ControlServer(self, self.control_port)
        except OSError as e:
            self._log("ERROR", t("bg.port_fail", port=self.control_port, err=e))
            if self.vpn:
                try:
                    self.vpn.stop()
                except Exception:
                    pass
            return 1
        threading.Thread(target=self.server.serve_forever, daemon=True,
                         name="Control").start()
        try:
            with open(RUNTIME_FILE, "w", encoding="utf-8") as f:
                json.dump({"pid": os.getpid(), "port": self.control_port}, f)
        except Exception:
            pass
        try:
            while self._running:
                time.sleep(0.5)
                if self.vpn_thread is not None and not self.vpn_thread.is_alive():
                    # Motor durdu (başarısız başlatma veya kopan oturum): kapan.
                    self._running = False
        finally:
            try:
                self.server.shutdown()
            except Exception:
                pass
            try:
                os.remove(RUNTIME_FILE)
            except Exception:
                pass
        return 0

    def control(self, req):
        """Yerel kontrol isteğini yanıtlar (ControlServer tarafından çağrılır)."""
        cmd = req.get("cmd")
        if cmd == "ping":
            return {"ok": True, "pid": os.getpid()}
        if cmd == "status":
            return {
                "ok": True,
                "mode": self.mode,
                "mode_label": self._mode_label(),
                "state": self.state,
                "state_label": self._state_label(self.state),
                "vpn_ip": self.vpn_ip,
                "public": self.public_addr,
                "tx": self.stats["tx"],
                "rx": self.stats["rx"],
                "uptime": self._uptime_str(),
                "transport": self._transport_label(self._main_transport()),
                "port": self.port,
                "peers": len(self.peers),
            }
        if cmd == "peers":
            with self._peers_lock:
                items = list(self.peers.items())
            peers = []
            for pid, p in items:
                peers.append({
                    "name": self._display_name(pid),
                    "vpn_ip": p.get("vpn_ip") or "—",
                    "public": self._peer_pub_addr(p),
                    "transport": self._transport_label(p.get("transport")),
                    "rx": p.get("rx", 0),
                    "tx": p.get("tx", 0),
                })
            return {"ok": True, "peers": peers}
        if cmd == "log":
            total = self._log_base + len(self.log_history)
            since = req.get("since")
            if since is not None:
                try:
                    since = int(since)
                except Exception:
                    since = 0
                start = max(0, since - self._log_base)
                items = self.log_history[start:]
                return {"ok": True, "total": total,
                        "log": [{"level": lvl, "msg": msg} for lvl, msg in items]}
            try:
                n = int(req.get("n", 50))
            except Exception:
                n = 50
            return {"ok": True, "total": total,
                    "log": [{"level": lvl, "msg": msg}
                            for lvl, msg in self.log_history[-n:]]}
        if cmd == "stop":
            threading.Thread(target=self._remote_stop, daemon=True).start()
            return {"ok": True}
        return {"ok": False, "error": "unknown command"}

    def _remote_stop(self):
        try:
            if self.vpn:
                self.vpn.stop()
        except Exception:
            pass
        self._running = False

    # ── SON BAĞLANTI VE OTOMATİK BAŞLATMA ──

    def _save_connection(self):
        """Geçerli bağlantı ayarlarını diske yazar (sonraki açılışta hatırlanır)."""
        self.settings.update({
            "mode": self.mode,
            "key": self.key,
            "port": self.port,
            "peer": self.peer,
            "file": self.file,
            "export": self.export,
            "auto": self.auto,
            "lang": self.lang,
        })
        save_settings(self.settings)

    def _refresh_autostart(self):
        """Otomatik başlatma açıksa komutu güncel ayarlarla tazeler."""
        try:
            if autostart_enabled():
                autostart_enable(app_base_argv() + ["--background", "--lang", self.lang])
        except Exception:
            pass

    def _quick_start(self):
        """Kayıtlı son ayarlarla VPN'i hemen başlatır."""
        if not self.key:
            self._line(t("last.none"))
            return
        self._start_vpn()

    def _menu_autostart(self):
        self._clear_screen()
        self._line("=== " + t("auto.title") + " ===")
        if not autostart_supported():
            self._line("  " + t("auto.unsupported"))
            self._pause()
            return
        current = autostart_enabled()
        self._line(f"  {t('auto.status')}: "
                   f"{t('auto.on') if current else t('auto.off')}")
        self._line("")
        self._line("  1) " + t("auto.enable"))
        self._line("  2) " + t("auto.disable"))
        self._line("  0) " + t("menu.opt_back"))
        c = self._ask_int(t("menu.choice"), 0, 0, 2)
        if c == 0:
            return
        if c == 1 and not self.key:
            self._line(t("auto.need_key"))
            self._pause()
            return
        if c == 1:
            ok, err = autostart_enable(app_base_argv() + ["--background", "--lang", self.lang])
            self._line(t("auto.enabled") if ok else t("auto.failed", err=err))
        else:
            ok, err = autostart_disable()
            self._line(t("auto.disabled") if ok else t("auto.failed", err=err))
        if not ok and not check_admin():
            self._line("  " + t("log.no_admin"))
        self._pause()

    # ── YARDIMCILAR ──

    def _resolve_peer(self, token):
        """Peer'i tam kimlik, VPN IP'si veya görünen ad ile bulur."""
        with self._peers_lock:
            if token in self.peers:
                return token
            for pid, p in self.peers.items():
                if p.get("vpn_ip") == token or self._display_name(pid) == token:
                    return pid
        return None

    def _print_table(self, headers, rows):
        widths = [len(str(h)) for h in headers]
        for r in rows:
            for i, c in enumerate(r):
                widths[i] = max(widths[i], len(str(c)))
        fmt = "  " + "  ".join("{:<" + str(w) + "}" for w in widths)
        self._line(fmt.format(*[str(h) for h in headers]))
        self._line("  " + "  ".join("-" * w for w in widths))
        for r in rows:
            self._line(fmt.format(*[str(c) for c in r]))

    def _uptime_str(self):
        if not self.connect_time:
            return "00:00:00"
        e = int(time.time() - self.connect_time)
        return f"{e // 3600:02d}:{(e % 3600) // 60:02d}:{e % 60:02d}"

    @staticmethod
    def _fmt_bytes(b):
        if b < 1024:
            return f"{b} B"
        if b < 1048576:
            return f"{b / 1024:.1f} KB"
        if b < 1073741824:
            return f"{b / 1048576:.2f} MB"
        return f"{b / 1073741824:.2f} GB"

    def _mode_label(self):
        return t("mode.hub") if self.mode == "serve" else t("mode.client")

    @staticmethod
    def _transport_label(transport):
        if transport == "direct":
            return t("trn.direct")
        if transport == "relay":
            return t("trn.relay")
        return transport or "—"

    def _main_transport(self):
        return self.vpn.transport if self.vpn else "direct"


# ═══════════════════════════════════════════════════════════════════════
#  GİRİŞ NOKTASI (CLI)
# ═══════════════════════════════════════════════════════════════════════

def build_argparser():
    """Komut satırı argümanlarını tanımlar."""
    parser = argparse.ArgumentParser(
        prog="pertoper_vpn",
        description="Peertopeer P2P VPN — komut satırı istemcisi (CLI).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Etkileşimli modda numaralı menü açılır; 'Gelişmiş komut "
               "satırı' ile tüm komutlara erişebilirsiniz.",
    )
    parser.add_argument("-m", "--mode", choices=("serve", "connect"),
                        default=None,
                        help="Çalışma modu: serve (dinleyici/hub) veya "
                             "connect (istemci). Varsayılan: son kullanılan.")
    parser.add_argument("-k", "--key", default=None,
                        help="Paylaşılan şifreleme anahtarı.")
    parser.add_argument("-p", "--port", type=int, default=None,
                        help="UDP portu (serve: dinlenecek, connect: yerel). "
                             "Varsayılan: son kullanılan / 12345.")
    parser.add_argument("--peer", default=None,
                        help="Peer adresi IP:PORT (connect: hub adresi; "
                             "serve: CGNat hedefi).")
    parser.add_argument("-f", "--file", default=None,
                        help="connect: yüklenecek peer_info.json; "
                             "serve: dışa aktarılacak dosya.")
    parser.add_argument("--export", default=None,
                        help="serve: peer_info.json dışa aktarma yolu.")
    parser.add_argument("--no-auto", action="store_true",
                        help="Otomatik bulut eşleşmesini kapat.")
    parser.add_argument("--auto", action="store_true",
                        help="Otomatik bulut eşleşmesini zorla aç.")
    parser.add_argument("--lang", choices=LANGUAGES, default=None,
                        help="Arayüz dili (tr, en, de, fr, es).")
    parser.add_argument("--start", dest="auto_start", action="store_true",
                        help="Başlar başlamaz VPN'i çalıştır.")
    parser.add_argument("-n", "--non-interactive", action="store_true",
                        help="Etkileşimsiz mod: arayüz açılmaz; VPN "
                             "otomatik başlar, Ctrl+C beklenir.")
    parser.add_argument("--shell", action="store_true",
                        help="Etkileşimli modda menü yerine doğrudan "
                             "gelişmiş komut kabuğunu aç.")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--control-port", type=int, default=CONTROL_PORT,
                        help="Yerel kontrol portu (varsayılan %d)." % CONTROL_PORT)
    parser.add_argument("--background", action="store_true",
                        help="VPN'i arka planda (terminalden bağımsız) başlat ve çık.")
    parser.add_argument("--stop", action="store_true",
                        help="Çalışan arka plan VPN'ini durdur ve çık.")
    parser.add_argument("--status", action="store_true",
                        help="Çalışan arka plan VPN'inin durumunu yazdır ve çık.")
    parser.add_argument("--stun", action="store_true",
                        help="STUN/NAT/UPnP testini çalıştır ve çık.")
    parser.add_argument("--genkey", action="store_true",
                        help="Rastgele bir anahtar üret ve çık.")
    parser.add_argument("-v", "--version", action="store_true",
                        help="Sürümü yazdır ve çık.")
    return parser


def _generate_key() -> str:
    """24 karakterlik rastgele şifreleme anahtarı üretir."""
    import string
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(secrets.choice(chars) for _ in range(24))


def _run_stun_cli() -> int:
    """STUN/NAT/UPnP testini çalıştırır ve sonucu basar."""
    print(t("stun.starting"))
    nat = NATDetector.detect()
    lip = get_local_ip()
    if nat:
        print(t("stun.public", ip=nat.get("public_ip", lip)))
        print(t("stun.local", ip=lip))
        print(t("stun.nat", info=nat.get("type")))
        print(t("stun.port_behavior", info=nat.get("details")))
    else:
        print(t("stun.failed"))
    upnp = UPnPEngine()
    if upnp.discover():
        print(t("stun.upnp_yes", service=upnp.service_type))
    else:
        print(t("stun.upnp_no"))
    return 0


def _maybe_elevate_linux():
    """Linux'ta kök yetki yoksa uygulamayı pkexec ile yeniden başlatır.

    TUN adaptörü için CAP_NET_ADMIN (kök yetki) şarttır; /dev/net/tun izinleri
    tek başına yetmez. Uygulama root değilse polkit şifre penceresiyle
    kendini root olarak yeniden başlatır, böylece TUN adaptörü açılabilir.
    Kullanıcı iptal ederse veya pkexec yoksa normal kullanıcı olarak devam
    eder (TUN o zaman açılamaz; mevcut uyarı logu bunu belirtir).
    """
    if platform.system() != "Linux":
        return
    try:
        if os.geteuid() == 0:  # zaten root: yükseltme gerekmez
            return
    except AttributeError:
        return
    if os.environ.get("PERTOPER_VPN_ELEVATED") == "1":
        return
    try:
        # AppImage olarak çalışırken sys.argv[0] geçici bağlama (mount) yoludur;
        # pkexec ile kalıcı .AppImage dosyasını yeniden başlatmak daha doğrudur.
        exe = os.environ.get("APPIMAGE") or os.path.abspath(sys.argv[0])
        env = dict(os.environ)
        env["PERTOPER_VPN_ELEVATED"] = "1"
        cmd = ["pkexec"]
        preserved = {}
        for k in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY"):
            v = os.environ.get(k)
            if v:
                preserved[k] = v
        if preserved:
            cmd.append("env")
            cmd += [f"{k}={v}" for k, v in preserved.items()]
        cmd += [exe] + sys.argv[1:]
        code = subprocess.call(cmd, env=env)
        if code == 0:
            # pkexec uygulamayı root olarak çalıştırdı ve kapandı
            sys.exit(0)
        # iptal / hata: yükseltmenin başarısız olduğunu bildir ve devam et
        os.environ["PERTOPER_VPN_ELEV_FAILED"] = "1"
    except Exception:
        os.environ["PERTOPER_VPN_ELEV_FAILED"] = "1"


def main(argv=None) -> int:
    args = build_argparser().parse_args(argv)

    if args.version:
        print(f"Peertopeer P2P VPN v{VERSION}")
        return 0

    if args.genkey:
        print(_generate_key())
        return 0

    set_ui_language(
        args.lang or (load_settings().get("lang") or detect_ui_language()))

    if args.status:
        return _cli_status(args.control_port)
    if args.stop:
        return _cli_stop(args.control_port)
    if args.stun:
        return _run_stun_cli()

    # TUN için kök yetki gerekir; yalnızca gerçek çalıştırma öncesi yükselt.
    _maybe_elevate_linux()

    if args.background:
        return 0 if CLIConsole(args)._spawn_worker() else 1

    app = CLIConsole(args)
    try:
        return app.run()
    except KeyboardInterrupt:
        app._shutdown()
        return 0


if __name__ == "__main__":
    sys.exit(main())

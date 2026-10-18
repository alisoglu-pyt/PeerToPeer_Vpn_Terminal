# 📘 Peertopeer P2P VPN — Detaylı Kullanım Kılavuzu / Detailed Guide

> **Sürüm / Version:** `3.4`
> Bu kılavuz komut satırı (CLI) sürümünü anlatır. Kısa genel bakış için [`README.md`](README.md) dosyasına bakın.

[🇹🇷 Türkçe](#-türkçe) · [🇬🇧 English](#-english)

---

## 🇹🇷 Türkçe

### İçindekiler

1. [Genel bakış](#1-genel-bakış)
2. [Kavramlar](#2-kavramlar)
3. [Gereksinimler](#3-gereksinimler)
4. [Kurulum](#4-kurulum)
5. [Hızlı başlangıç](#5-hızlı-başlangıç)
6. [Komut satırı referansı](#6-komut-satırı-referansı)
7. [İnteraktif arayüz referansı](#7-i̇nteraktif-arayüz-referansı)
8. [Senaryolar](#8-senaryolar)
9. [NAT / STUN / UPnP ve taşıma tipleri](#9-nat--stun--upnp-ve-taşıma-tipleri)
10. [Dosyalar ve kalıcılık](#10-dosyalar-ve-kalıcılık)
11. [Güvenlik modeli](#11-güvenlik-modeli)
12. [Sorun giderme](#12-sorun-giderme)
13. [SSS](#13-sss)
14. [Derleme (binary ve AppImage)](#14-derleme-binary-ve-appimage)
15. [Otomasyon, çıkış kodları ve systemd](#15-otomasyon-çıkış-kodları-ve-systemd)

---

### 1. Genel bakış

Peertopeer P2P VPN, iki veya daha fazla makine arasında **sunucu (VPS) gerektirmeden** uçtan uca
şifreli bir tünel kurar. Aynı uygulama hem **dinleyici (hub)** hem de **bağlanan (peer/istemci)**
olarak çalışır ve **hub-and-spoke** topolojisiyle aynı anda birçok peer kabul eder.

Zor kısımları otomatik halleder:

- **STUN** ile her tarafın gerçek (public) IP:port bilgisini bulur.
- **UDP hole punching** (port-delta tahminiyle) ile NAT arkasındaki iki ucu doğrudan birleştirir.
- Doğrudan yol kurulamazsa, trafiği **genel bir MQTT broker** üzerinden **uçtan uca şifreli**
  olarak aktarır (bulut relay). Broker yalnızca şifreli metni görür.
- Gerçek bir **TUN** adaptörü açar (Windows: Wintun, Linux: `/dev/net/tun`) ve paketleri
  kullanıcı alanında yönlendirir (iptables/kernel forwarding gerekmez).

```
                 ┌──────────────────────────────┐
                 │   HUB (dinleyici, 10.8.0.1)  │
                 └──────────────────────────────┘
                    ▲            ▲            ▲
       doğrudan UDP │            │ doğrudan   │  relay (MQTT)
                    │            │ UDP        │
             ┌──────┴───┐  ┌─────┴────┐  ┌────┴─────┐
             │ Peer A   │  │ Peer B   │  │ Peer C   │
             │10.8.0.2  │  │10.8.0.3  │  │10.8.0.4  │
             └──────────┘  └──────────┘  └──────────┘
```

### 2. Kavramlar

| Terim | Anlamı |
| --- | --- |
| **Hub / Dinleyici (serve)** | Bağlantıları kabul eden taraf. VPN IP'si `10.8.0.1`. Trafiği peer'ler arasında yönlendirir. |
| **Peer / İstemci (connect)** | Hub'a bağlanan taraf. Hub her peer'e `10.8.0.2` – `10.8.0.254` arası bir VPN IP atar. |
| **VPN IP** | Tünel içindeki özel adres (`10.8.0.0/24` ağı). Karşı makineye bu adresle erişirsiniz. |
| **Taşıma (transport)** | İki uç arasındaki gerçek yol: **Doğrudan P2P** (UDP) veya **Bulut Relay** (MQTT). |
| **Anahtar (key)** | Paylaşılan gizli anahtar. Tek kimlik doğrulama faktörüdür; aynı anahtara sahip herkes ağa katılır. |
| **Oda kimliği (room)** | Anahtardan türetilen `sha256(key)[:16]`. İki tarafın buluştuğu MQTT konu uzayı. |
| **peer_info.json** | Hub'ın dışa aktardığı dosya: public adres + VPN IP + **anahtar**. İstemci bunu yükleyerek elle anahtar girmekten kurtulur. |

### 3. Gereksinimler

- **Python 3.8+** (AppImage ve derlenmiş binary'de Python gömülüdür, gerekmez).
- **`cryptography`** paketi (bkz. `requirements.txt`). AppImage/binary'de gömülüdür.
- **Yönetici / root yetkisi** — TUN adaptörünü açmak için (Linux'ta pkexec ile otomatik yükseltme denenir).
- **Windows:** script'in yanına konulmuş `wintun.dll` (<https://www.wintun.net>).
- **Ağ:** Giden UDP (port 12345 varsayılan) + giden TCP 1883 (MQTT broker'ları) + giden UDP (STUN).
  İki tarafın da **en az bir ortak genel MQTT broker'ına** erişebilmesi gerekir.

**Açılan portlar:** varsayılan olarak **UDP 12345** dinlenir. Uygulama Windows'ta güvenlik duvarı
kuralını, Linux'ta ufw/firewalld/iptables kuralını otomatik eklemeyi dener (root ise).

### 4. Kurulum

#### 4.a Kaynak koddan

```bash
git clone https://github.com/<kullanici-adiniz>/<repo-adiniz>.git
cd <repo-adiniz>
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate
pip install -r requirements.txt
```

Windows'ta ayrıca `wintun.dll` dosyasını `pertoper_vpn.py` ile aynı dizine koyun.

#### 4.b Derlenmiş binary

- **Windows:** `build.bat` → menüden `[1]` → `dist\windows\PertoperVPN.exe`.
- **Linux:** `./build.sh` → `dist/linux/PertoperVPN`.

#### 4.c AppImage (Linux, kurulumsuz)

```bash
chmod +x dist/appimage/PertoperVPN-3.4-x86_64.AppImage
./dist/appimage/PertoperVPN-3.4-x86_64.AppImage --version
```

TUN için root gerekir; uygulama pkexec ile kendini yükseltmeyi dener:

```bash
sudo ./PertoperVPN-3.4-x86_64.AppImage -m serve -k "uzun-gizli-anahtar"
```

> **FUSE yoksa:** Bazı sistemlerde AppImage'i çalıştırmak için `libfuse2` gerekir. Kuramıyorsanız
> `--appimage-extract-and-run` (veya `APPIMAGE_EXTRACT_AND_RUN=1`) ile FUSE'siz çalıştırabilirsiniz:
> `./PertoperVPN-3.4-x86_64.AppImage --appimage-extract-and-run --version`

### 5. Hızlı başlangıç

**Hub makinesinde (sunucu):**

```bash
# Yönetici/root olarak
python pertoper_vpn.py -m serve -k "uzun-gizli-anahtar" -p 12345 --start
```

- `-k` ile anahtarı verin ya da `genkey` ile üretin.
- `--start` doğrudan başlatır; yoksa kabuğa düşer ve `start` yazmanızı bekler.

**İstemci makinesinde:**

```bash
# Aynı anahtarla otomatik bulut eşleşmesi
python pertoper_vpn.py -m connect -k "uzun-gizli-anahtar" --start

# VEYA hub'ın dışa aktardığı dosyayla (anahtar dosyadan okunur)
python pertoper_vpn.py -m connect -f peer_info.json --start
```

Bağlandıktan sonra kabukta `status` ve `peers` yazın; her peer diğer makineleri görür.
Karşı makineye **VPN IP'si** ile erişin (ör. `ping 10.8.0.2`).

### 6. Komut satırı referansı

```
python pertoper_vpn.py [SEÇENEKLER]
```

| Seçenek | Varsayılan | Açıklama |
| --- | --- | --- |
| `-m, --mode {serve,connect}` | `serve` | `serve` = dinleyici/hub, `connect` = istemci. |
| `-k, --key ANAHTAR` | — | Paylaşılan şifreleme anahtarı. |
| `-p, --port PORT` | `12345` | UDP portu (serve: dinlenecek, connect: yerel). 1–65535. |
| `--peer IP:PORT` | — | connect: hub adresi; serve: ek CGNat hedefi. |
| `-f, --file DOSYA` | — | connect: yüklenecek `peer_info.json`; serve: dışa aktarılacak dosya. |
| `--export DOSYA` | — | serve: `peer_info.json` dışa aktarma yolu. |
| `--no-auto` | kapalı | Otomatik bulut eşleşmesini kapatır (yalnızca `--peer`/`-f` kullanılır). |
| `--lang {tr,en,de,fr,es}` | sistem | Arayüz dili. |
| `--start` | kapalı | Açılışta VPN'i hemen başlatır. |
| `-n, --non-interactive` | kapalı | Arayüz açılmaz; VPN başlar, Ctrl+C bekler. |
| `--shell` | kapalı | Etkileşimli modda menü yerine doğrudan gelişmiş komut kabuğunu açar. |
| `--stun` | — | STUN/NAT/UPnP testini çalıştırıp çıkar. |
| `--genkey` | — | Rastgele 24 karakterlik anahtar üretip çıkar. |
| `-v, --version` | — | Sürümü yazdırıp çıkar. |
| `-h, --help` | — | Yardımı gösterir. |

**Örnekler**

```bash
python pertoper_vpn.py --genkey                        # anahtar üret
python pertoper_vpn.py --stun                          # bağlantı/NAT testi
python pertoper_vpn.py -m serve  -k KEY --start        # hub
python pertoper_vpn.py -m connect -k KEY --start       # istemci
python pertoper_vpn.py -m connect -f peer_info.json    # dosyadan
python pertoper_vpn.py -m connect --peer 203.0.113.10:41337 -k KEY --start
python pertoper_vpn.py -n -m connect -k KEY            # script/servis modu
```

### 7. İnteraktif arayüz referansı

`-n` verilmediyse uygulama, yeni başlayanlar için **numaralı bir menü** açar. **Son kullanılan
bağlantı hatırlanır**; sihirbaz ve **Hızlı başlat** kendiliğinden dolu gelir. **12) Gelişmiş
komut satırı** (ya da `--shell`) ile komut kabuğuna geçilir.

#### 7.a Menü (yeni başlayanlar için)

```
──────────────────────────────────────────────────────
  Peertopeer P2P VPN v3.4
  Mod: Bağlan      Durum: Bağlantısız
  Şifreleme Anahtarı: tanımlı      Port: 12346
  Otomatik eşleşme: ON
──────────────────────────────────────────────────────
   1) VPN'i başlat (adım adım)
   2) Hızlı başlat (son ayarlarla)
   3) VPN'i durdur
   4) Durum ve istatistikler
   5) Bağlı cihazlar
   6) Kayıtlar (log)
   7) Ayarlar
   8) Başlangıçta çalıştır (aç/kapa)
   9) Ağ testi (STUN/NAT)
  10) Dil değiştir
  11) Program hakkında
  12) Gelişmiş komut satırı
   0) Çıkış
```

| Seçim | Ne yapar |
| --- | --- |
| `1` | Başlatma sihirbazı: rol (hub/peer) → anahtar (kayıtlı / üret / yaz / dosyadan) → port → bağlantı → özet/onay. |
| `2` | Kayıtlı son ayarlarla VPN'i hemen başlatır. |
| `3` | VPN'i durdurur (arka plan sürecine durdurma isteği). |
| `4` | Durum ve istatistikler — **canlı izleme** (her 1 sn tazelenir; çıkmak için `q`, `Esc` veya `Enter`). |
| `5` | Bağlı cihazların tablosu. |
| `6` | Son log satırları. |
| `7` | Ayarlar (anahtar, port, mod, peer, dosya, otomatik eşleşme). |
| `8` | Başlangıçta otomatik çalıştırmayı açar/kapatır. |
| `9` | Ağ testi (STUN/NAT/UPnP). |
| `10` | Dil değiştir. |
| `11` | Program hakkında. |
| `12` | Gelişmiş komut satırına geç. |
| `0` | Çıkış. |

> Menüde bir işlemden sonra "Devam etmek için Enter'a basın" çıkar; Enter'a basınca menü yeniden
> çizilir.
>
> **8) Başlangıçta çalıştır:** Windows'ta oturum açılışında çalışan "en yüksek yetkili" bir
> zamanlanmış görev (`schtasks`), Linux'ta `~/.config/autostart/pertoper-vpn.desktop` girdisi
> oluşturur. Etkinleştirmek için yönetici/root gerekir. Uygulama `--background` ile, yani son
> kayıtlı ayarlarla başlar.

#### 7.b Gelişmiş komut kabuğu

Kabuk istemi rol ve durumu gösterir (ör. `hub[hazır]>`, `peer[bağlı]>`). Komutların çoğunun
Türkçe kısayolu vardır (`durum`, `baslat`, `durdur`, ...). Ana menüye dönmek için `menu` yazın;
`0`/`quit` yalnızca `--shell` ile başlatıldığında tamamen çıkar.

| Komut | Açıklama |
| --- | --- |
| `status` *(durum)* | Mod, durum, public adres, VPN IP, TX/RX, süre, port ve taşıma. |
| `peers` *(peer)* | Bağlı peer tablosu: isim, VPN IP, public adres, taşıma, RX/TX. |
| `log [n]` *(logs)* | Son `n` log satırı (varsayılan 20). |
| `rename <peer> [ad]` *(isim)* | Peer'e takma isim ver; ad boşsa siler. Kalıcıdır. |
| `set <alan> <değer>` *(ayar)* | Ayar değiştir: `key`, `port`, `peer`, `file`, `export`, `auto`, `mode`, `lang`. |
| `genkey` *(key, anahtar)* | Yeni anahtar üretir ve etkin anahtar yapar. |
| `stun` | STUN/NAT/UPnP testini çalıştırır (arka planda). |
| `start` *(baslat)* | VPN'i başlatır. |
| `stop` *(durdur)* | VPN'i durdurur. |
| `about` *(hakkinda)* | Sürüm, geliştirici ve dil bilgisi. |
| `lang [kod]` *(dil)* | Dili gösterir/değiştirir (`tr,en,de,fr,es`). Tercih kalıcıdır. |
| `clear` *(temizle)* | Log geçmişini temizler. |
| `help` *(?)* | Komut listesi. |
| `quit` *(exit, q, cikis)* | Çıkar (aktif VPN varsa durdurulur). |

**Örnek oturum**

```
vpn> genkey
Yeni anahtar üretildi: 7Fa!k2...zQ
vpn> set mode serve
mode ayarlandı: serve
vpn> set port 12345
port ayarlandı: 12345
vpn> start
VPN başlatılıyor (Dinleyici)...
» STUN & NAT analizi...
» Dinleniyor (Hub)
vpn> peers

  İsim                 VPN IP     Public Adres        Taşıma        RX     TX
  ---------------------------------------------------------------------------
  Ahmet-Laptop         10.8.0.2   88.230.11.7:44312   Doğrudan P2P  1.2 MB  940 KB
vpn> rename 10.8.0.2 Ofis-PC
Takma isim kaydedildi: 10.8.0.2 → Ofis-PC
vpn> stop
VPN durduruluyor...
vpn> quit
Görüşürüz.
```

### 8. Senaryolar

- **En basit:** İki taraf da aynı anahtarı `-k` ile verir, `--start` ile başlar. Bulut eşleşmesi
  otomatik kurulur.
- **Dosyayla:** Hub `-f peer_info.json` ile dosyayı yazar, istemci `-f` ile yükler (anahtar dosyadan gelir).
- **Manuel adres (bulut olmadan):** İstemci `--peer IP:PORT` + `--no-auto` ile doğrudan hub'a delme yapar
  (port yönlendirmesi (port forwarding) yaptıysanız idealdir).
- **CGNAT hedefi (serve):** Hub, `--peer IP:PORT` ile ek bir hedefe aktif delme başlatır.
- **Relay'e düşme:** İki taraf da simetrik CGNat arkasındaysa doğrudan yol kurulamaz; trafik şifreli
  relay'e düşer ve en kısa sürede doğrudan yola yükseltmeye çalışır (`transport` sütununda görünür).

### 9. NAT / STUN / UPnP ve taşıma tipleri

- **Açık İnternet (NAT Yok):** Doğrudan public IP; en kolay durum.
- **Cone NAT (Hole Punch uyumlu):** Sabit dış port korunur; hole punching neredeyse her zaman çalışır.
- **Simetrik NAT / CGNat:** Her hedef için farklı dış port; port-delta tahminiyle denenir, olmazsa relay.

**Taşıma sütunu:** `Doğrudan P2P` = UDP üzerinden doğrudan; `Bulut Relay` = MQTT üzerinden şifreli aktarım.
Relay çalışır ama doğrudan yoldan daha yavaştır.

**NAT/port durumunu görmek için:** `stun` komutu veya `--stun` ile public IP, yerel IP, NAT tipi, port
davranışı ve UPnP desteğini öğrenin. Router'da UPnP varsa uygulama portu otomatik açar.

### 10. Dosyalar ve kalıcılık

| Yol | İçerik |
| --- | --- |
| `~/.peertopeer_vpn_settings.json` | Kullanıcı tercihleri (seçili dil). |
| `~/.peertopeer_vpn_names.json` | Peer takma isimleri (kalıcı). |
| Dışa aktarılan `peer_info.json` | public/IP/port/NAT bilgisi **ve anahtar**. |

`peer_info.json` örneği:

```json
{
  "public_ip": "203.0.113.10",
  "public_port": 41337,
  "vpn_ip": "10.8.0.1",
  "timestamp": 1718000000,
  "local_ip": "192.168.1.20",
  "local_port": 12345,
  "nat_type": "Cone NAT (Hole Punch Uyumlu)",
  "is_symmetric": false,
  "delta": 0,
  "ports": [41337, 41337],
  "key": "paylasilan-gizli-anahtar"
}
```

⚠️ Dosya anahtarı **düz metin** içerir — yalnızca güvenli kanaldan paylaşın.

### 11. Güvenlik modeli

- **Şifreleme:** AES-256-GCM; anahtar türetimi PBKDF2-HMAC-SHA256 (480.000 iterasyon).
- **Kimlik doğrulama:** Yalnızca paylaşılan anahtar. Bilen herkes ağa katılabilir → uzun ve rastgele
  bir anahtar kullanın (`genkey` 24 karakter üretir).
- **Broker:** Genel MQTT broker'ları buluşma/relay için kullanılır. Bir oturumun *var olduğunu*
  (konu adı anahtardan türetilir, meta veri şifreli) gözlemleyebilirler ama içeriği **göremezler**.
- **Anahtarı komut satırında vermek** onu shell geçmişinde / süreç listesinde görünür kılar. Paylaşımlı
  makinelerde bundan kaçının (kabukta `genkey`/`set key` kullanın veya dosyadan yükleyin).
- **Sorumluluk:** Bu proje eğitim ve kişisel kullanım içindir; bulunduğunuz yerdeki yasalara ve ağ
  politikalarına uymak size aittir.

### 12. Sorun giderme

| Belirti | Çözüm |
| --- | --- |
| `TUN hatası` | Yönetici/root olarak çalıştırın (`sudo`, ya da Windows'ta "Yönetici olarak"). |
| `wintun.dll bulunamadı` (Windows) | <https://www.wintun.net> adresinden indirip `pertoper_vpn.py` yanına koyun. |
| `cryptography` bulunamadı | `pip install -r requirements.txt`. |
| Bağlantı hiç kurulmuyor | İki tarafta anahtar aynı mı? UDP portu engelli mi? Broker'a erişim var mı? `stun` ile test edin. |
| Sürekli `Bulut Relay` | İki taraf da simetrik CGNat arkasında olabilir; relay yine çalışır ama yavaştır. UPnP/port forwarding yardımcı olur. |
| Hub yanıtlıyor, peer'e ulaşılamıyor | Windows peer'ı **yönetici** çalıştırın: Wintun adaptörü "Genel" profil sayılmış olabilir; uygulama "Özel"e alır ve VPN alt ağı kuralı ekler. `Get-NetConnectionProfile`, `netsh advfirewall firewall show rule name=Peertopeer_P2P_VPN_ICMP`. |
| AppImage açılmıyor (`FUSE`) | `sudo apt install libfuse2` ya da `--appimage-extract-and-run`. |
| `set port`/`-p` reddediliyor | Geçerli aralık 1–65535. |
| Etkileşimsiz mod çıkıveriyor | Yapılandırma hatası (anahtar/port/peer) → çıkış kodu **2**; çalışma anı hatası (ör. TUN) → **1**. Normal çalışmada Ctrl+C'ye kadar bekler. |
| Linux'ta görev çubuğu simgesi | Bu CLI sürümünde masaüstü/tepsi simgesi yoktur (GUI kaldırıldı). |

**Tanılama komutları**

```bash
# Windows
ipconfig
Get-NetConnectionProfile
netsh advfirewall firewall show rule name=Peertopeer_P2P_VPN
route print

# Linux
ip addr
ip route
sudo ss -lunp | grep 12345
```

### 13. SSS

**S: Sunucu (VPS) gerekiyor mu?** Hayır. İki uç doğrudan ya da genel MQTT broker üzerinden buluşur.

**S: Kaç peer bağlanabilir?** 253'e kadar (`10.8.0.2`–`10.8.0.254`).

**S: Anahtarı nasıl paylaşırım?** En kolayı: hub `peer_info.json`'ı dışa aktarır, istemci `-f` ile yükler.

**S: Ping atabiliyor muyum?** Evet, VPN IP'leri ile. Windows'ta ICMP kuralının eklendiğinden emin olun (root).

**S: Aynı anda birden fazla peer birbirini görür mü?** Evet; hub peer listesini (roster) tüm uçlara yayar.

**S: Anahtarı değiştirirsem?** Yeni anahtar yeni bir "oda" demektir; diğer taraf da aynı anahtarı kullanmalı.

### 14. Derleme (binary ve AppImage)

**Tek dosya binary**

```bash
./build.sh            # Linux  -> dist/linux/PertoperVPN
```
```bat
build.bat             :: Windows -> dist\windows\PertoperVPN.exe (menüden seçin)
```

**AppImage (Linux)**

```bash
chmod +x build_appimage.sh
./build_appimage.sh
# çıktı: dist/appimage/PertoperVPN-3.4-x86_64.AppImage
```

Betik sırasıyla: PyInstaller ile tek dosya binary → AppDir (AppRun, .desktop, ikon) → appimagetool ile
`.AppImage` üretir. FUSE olmayan ortamlarda otomatik olarak extract-and-run kullanır.

**Windows'tan Docker ile AppImage derleme** (Linux makine yoksa):

```powershell
docker run --rm -v "${PWD}:/src" -w /src ubuntu:20.04 bash -lc `
  "apt-get update && apt-get install -y python3 python3-pip curl file ca-certificates && bash build_appimage.sh"
```

> Ubuntu 20.04 tabanı bilinçli seçilir: glibc 2.31 ile **daha geniş dağıtım uyumluluğu** sağlar.

### 15. Otomasyon, çıkış kodları ve systemd

**Çıkış kodları**

| Kod | Anlamı |
| --- | --- |
| `0` | Normal çıkış (kullanıcı çıktı ya da VPN başarıyla durdu). |
| `2` | Etkileşimsiz modda **yapılandırma hatası** (anahtar yok, geçersiz port/peer). |
| `1` | Etkileşimsiz modda **çalışma anı hatası** (ör. TUN açılamadı). |

**systemd örneği (hub olarak arka planda):**

```ini
# /etc/systemd/system/pertoper-hub.service
[Unit]
Description=Peertopeer P2P VPN (hub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=PERTOPER_VPN_ELEVATED=1
ExecStart=/usr/bin/python3 /opt/pertoper/pertoper_vpn.py -n -m serve -k CHANGE_ME -p 12345
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pertoper-hub
journalctl -u pertoper-hub -f
```

> `PERTOPER_VPN_ELEVATED=1`, root olarak başlatıldığı için pkexec yükseltmesinin atlanmasını sağlar.

---

## 🇬🇧 English

### Table of Contents

1. [Overview](#1-overview)
2. [Concepts](#2-concepts)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Quick start](#5-quick-start)
6. [Command-line reference](#6-command-line-reference)
7. [Interactive interface reference](#7-interactive-interface-reference)
8. [Scenarios](#8-scenarios)
9. [NAT / STUN / UPnP and transports](#9-nat--stun--upnp-and-transports)
10. [Files and persistence](#10-files-and-persistence)
11. [Security model](#11-security-model)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)
14. [Building (binary and AppImage)](#14-building-binary-and-appimage)
15. [Automation, exit codes and systemd](#15-automation-exit-codes-and-systemd)

### 1. Overview

Peertopeer P2P VPN builds an end-to-end encrypted tunnel between machines **without a server (VPS)**.
The same application runs as both the **listener (hub)** and the **connecting peer**, and accepts many
peers at once in a hub-and-spoke topology. It handles STUN discovery, UDP hole punching and an
encrypted MQTT relay fallback automatically, and opens a real **TUN** adapter (Wintun on Windows,
`/dev/net/tun` on Linux) with in-user-space routing.

### 2. Concepts

| Term | Meaning |
| --- | --- |
| **Hub / Listener (serve)** | Accepts connections; VPN IP `10.8.0.1`; routes traffic between peers. |
| **Peer / Client (connect)** | Connects to the hub; gets a VPN IP in `10.8.0.2`–`10.8.0.254`. |
| **VPN IP** | The private address inside the tunnel (`10.8.0.0/24`). |
| **Transport** | The real path between two ends: **Direct P2P** (UDP) or **Cloud Relay** (MQTT). |
| **Key** | Shared secret; the only authentication factor. |
| **Room** | `sha256(key)[:16]`, the derived MQTT topic namespace. |
| **peer_info.json** | Exported file: public address + VPN IP + **key** (zero-friction handoff). |

### 3. Requirements

- **Python 3.8+** (bundled in the AppImage/binary).
- **`cryptography`** (see `requirements.txt`; bundled in the AppImage/binary).
- **Administrator/root** to open the TUN adapter (Linux auto-elevates via pkexec).
- **Windows:** `wintun.dll` next to the script.
- **Network:** outbound UDP (port 12345 by default), outbound TCP 1883 (MQTT), outbound UDP (STUN).
  Both sides must reach at least one common public MQTT broker.

### 4. Installation

From source: `pip install -r requirements.txt` (and `wintun.dll` on Windows).
Prebuilt: `build.bat` (Windows) / `./build.sh` (Linux) → `dist/…`.
AppImage (Linux, no install):

```bash
chmod +x dist/appimage/PertoperVPN-3.4-x86_64.AppImage
./dist/appimage/PertoperVPN-3.4-x86_64.AppImage --version
sudo ./PertoperVPN-3.4-x86_64.AppImage -m serve -k "long-secret"
```

> **No FUSE?** Install `libfuse2` or use `--appimage-extract-and-run`.

### 5. Quick start

```bash
# Hub (as admin/root)
python pertoper_vpn.py -m serve -k "long-secret" --start

# Client
python pertoper_vpn.py -m connect -k "long-secret" --start
# or via the exported file (key read from file)
python pertoper_vpn.py -m connect -f peer_info.json --start
```

Then use `status` and `peers`; reach other machines via their VPN IP (e.g. `ping 10.8.0.2`).

### 6. Command-line reference

| Option | Default | Description |
| --- | --- | --- |
| `-m, --mode {serve,connect}` | `serve` | `serve` = listener/hub, `connect` = client. |
| `-k, --key KEY` | — | Shared encryption key. |
| `-p, --port PORT` | `12345` | UDP port (1–65535). |
| `--peer IP:PORT` | — | connect: hub address; serve: extra CGNat target. |
| `-f, --file FILE` | — | connect: load `peer_info.json`; serve: export file. |
| `--export FILE` | — | serve: explicit export path. |
| `--no-auto` | off | Disable automatic cloud matching. |
| `--lang {tr,en,de,fr,es}` | system | Interface language. |
| `--start` | off | Start the VPN immediately. |
| `-n, --non-interactive` | off | No interface; start and wait (Ctrl+C). |
| `--shell` | off | Interactive mode: open the advanced command shell instead of the menu. |
| `--stun` | — | Run the STUN/NAT/UPnP test and exit. |
| `--genkey` | — | Generate a random key and exit. |
| `-v, --version` / `-h, --help` | — | Version / help. |

### 7. Interactive interface reference

Unless `-n` is given, the app opens a **numbered menu** for first-time users. The **last used
connection is remembered**, so the wizard and **Quick start** come pre-filled. Choose
**12) Advanced command line** (or `--shell`) to reach the command shell.

#### 7.a Menu (for beginners)

```
──────────────────────────────────────────────────────
  Peertopeer P2P VPN v3.4
  Mode: Client      State: Offline
  Encryption Key: set      Port: 12346
  Auto matching: ON
──────────────────────────────────────────────────────
   1) Start the VPN (step by step)
   2) Quick start (last settings)
   3) Stop the VPN
   4) Status and statistics
   5) Connected devices
   6) Logs
   7) Settings
   8) Run at startup (on/off)
   9) Network test (STUN/NAT)
  10) Change language
  11) About
  12) Advanced command line
   0) Quit
```

| Choice | What it does |
| --- | --- |
| `1` | Start wizard: role (hub/peer) → key (saved / generate / enter / from file) → port → connection → summary/confirm. |
| `2` | Start the VPN immediately with the last saved settings. |
| `3` | Stop the VPN (sends a stop request to the background process). |
| `4` | Status and statistics — **live monitor** (refreshes every 1 s; press `q`, `Esc` or `Enter` to exit). |
| `5` | Table of connected devices. |
| `6` | Recent log lines. |
| `7` | Settings (key, port, mode, peer, file, auto matching). |
| `8` | Enable/disable running automatically at startup. |
| `9` | Network test (STUN/NAT/UPnP). |
| `10` | Change language. |
| `11` | About. |
| `12` | Switch to the advanced command shell. |
| `0` | Quit. |

> After an action the menu pauses with "Press Enter to continue...", then redraws.
>
> **8) Run at startup:** creates a highest-privilege **scheduled task** on Windows (`schtasks`) or
> an autostart entry on Linux (`~/.config/autostart/pertoper-vpn.desktop`). Enabling it needs
> administrator/root. The app starts with `--background`, i.e. using the last saved settings.

#### 7.b Advanced command shell

The prompt shows the role and state (e.g. `hub[ready]>`, `peer[connected]>`). Type `menu` to
return to the main menu; `0`/`quit` only fully exits when launched with `--shell`.

| Command | Description |
| --- | --- |
| `status` | Mode, state, public/VPN IP, TX/RX, uptime, port, transport. |
| `peers` | Peer table (name, VPN IP, public address, transport, traffic). |
| `log [n]` | Last `n` log lines (default 20). |
| `rename <peer> [name]` | Set/clear a persistent peer nickname. |
| `set <field> <value>` | `key`, `port`, `peer`, `file`, `export`, `auto`, `mode`, `lang`. |
| `genkey` | Generate and activate a new key. |
| `stun` | Run the STUN/NAT/UPnP test. |
| `start` / `stop` | Start / stop the VPN. |
| `about` | Version/developer/language info. |
| `lang [code]` | Show/change language (persisted). |
| `clear` | Clear the log history. |
| `help` / `quit` | Help / quit. |

### 8. Scenarios

- **Simplest:** both sides use the same `-k` and `--start`; cloud matching is automatic.
- **File handoff:** hub exports `peer_info.json`, client loads it with `-f`.
- **Manual address (no cloud):** client `--peer IP:PORT --no-auto` for a port-forwarded hub.
- **CGNAT target (serve):** hub `--peer IP:PORT` starts an active punch to that target.
- **Relay fallback:** double symmetric CGNAT → encrypted relay, with upgrade to direct when possible.

### 9. NAT / STUN / UPnP and transports

Open Internet (no NAT) · Cone NAT (hole-punch friendly) · Symmetric NAT/CGNAT (port-delta prediction,
else relay). The `Transport` column shows **Direct P2P** or **Cloud Relay**. Use `stun` / `--stun` to
inspect public IP, local IP, NAT type, port behaviour and UPnP.

### 10. Files and persistence

| Path | Content |
| --- | --- |
| `~/.peertopeer_vpn_settings.json` | User preferences (language). |
| `~/.peertopeer_vpn_names.json` | Persistent peer nicknames. |
| exported `peer_info.json` | Endpoint info **and the key**. |

⚠️ The exported file contains the key in plain text — share it over a secure channel only.

### 11. Security model

AES-256-GCM with PBKDF2-HMAC-SHA256 (480,000 iterations). The key is the only authentication factor —
use a long random key. Public MQTT brokers see that a session exists (topic derived from the key,
metadata encrypted) but not its content. Passing the key on the command line exposes it to shell
history/process listings; prefer `genkey`/`set key` or file loading. For educational/personal use only.

### 12. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `TUN error` | Run as Administrator/root. |
| `wintun.dll not found` (Windows) | Download from <https://www.wintun.net> next to the script. |
| `cryptography` import error | `pip install -r requirements.txt`. |
| Connection never establishes | Same key on both sides? UDP port open? Broker reachable? Try `stun`. |
| Always on Cloud Relay | Likely symmetric CGNAT on both sides; relay works but is slower. |
| Hub answers but a peer is unreachable | Run the Windows peer as admin (Wintun may be classified Public). |
| AppImage won't launch (FUSE) | `sudo apt install libfuse2` or `--appimage-extract-and-run`. |
| Non-interactive mode exits | Config error → exit **2**; runtime error (e.g. TUN) → **1**. |

### 13. FAQ

**Server required?** No. **Max peers?** 253 (`10.8.0.2`–`10.8.0.254`). **Key sharing?** Via
`peer_info.json` (`-f`). **Can I ping?** Yes, via VPN IPs (ensure the firewall/ICMP rule on Windows).
**Multiple peers see each other?** Yes (the hub broadcasts the roster).

### 14. Building (binary and AppImage)

```bash
./build.sh          # Linux binary -> dist/linux/PertoperVPN
./build_appimage.sh # Linux AppImage -> dist/appimage/PertoperVPN-3.4-x86_64.AppImage
```

```bat
build.bat           :: Windows -> dist\windows\PertoperVPN.exe
```

Build the AppImage from Windows via Docker:

```powershell
docker run --rm -v "${PWD}:/src" -w /src ubuntu:20.04 bash -lc `
  "apt-get update && apt-get install -y python3 python3-pip curl file ca-certificates && bash build_appimage.sh"
```

> Ubuntu 20.04 (glibc 2.31) is chosen on purpose for **broad distribution compatibility**.

### 15. Automation, exit codes and systemd

Exit codes: `0` normal · `2` config error (non-interactive) · `1` runtime failure (non-interactive).

```ini
# /etc/systemd/system/pertoper-hub.service
[Unit]
Description=Peertopeer P2P VPN (hub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=PERTOPER_VPN_ELEVATED=1
ExecStart=/usr/bin/python3 /opt/pertoper/pertoper_vpn.py -n -m serve -k CHANGE_ME -p 12345
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

**Geliştirici / Developer:** Bekir Alişoğlu — ✉️ alisoglu@yahoo.com

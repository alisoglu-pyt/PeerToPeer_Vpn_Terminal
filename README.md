# 🛡️ Peertopeer P2P VPN

**VPS gerektirmeyen, uçtan uca şifreli, çoklu-peer P2P VPN** — tek dosyalık Python uygulaması, komut satırı (CLI) arayüzü.

**VPS-free, end-to-end encrypted, multi-peer P2P VPN** — a single-file Python application with a command-line (CLI) interface.

> **Sürüm / Version:** `3.4`

[🇹🇷 Türkçe için tıklayın](#-türkçe) · [🇬🇧 Jump to English](#-english)

📘 **Detaylı kullanım kılavuzu / Detailed guide:** [`KILAVUZ.md`](KILAVUZ.md)

---

## 🇬🇧 English

### Overview

Peertopeer P2P VPN creates an encrypted peer-to-peer tunnel between machines **without a server (VPS)**.
The same application acts as both the listener (hub) and the connecting peer, and it supports
**multiple peers connected at the same time** through a hub-and-spoke topology.

It handles the hard part of NAT traversal automatically: STUN discovery, aggressive UDP hole
punching with port-delta prediction, and an encrypted cloud-relay fallback for double-CGNAT
situations where a direct UDP path is impossible.

Start it with command-line arguments and then use the **guided menu** (or the advanced
shell) for status, peers, logs and control. The VPN runs as a **background process** —
closing the terminal does not stop it; it runs until you choose **Stop** (`--stop`).

### Features

- 🔗 **No VPS required** — direct peer-to-peer connection
- 🕳️ **CGNAT bypass** — STUN + aggressive UDP hole punching (port-delta prediction for symmetric NAT)
- ☁️ **Encrypted relay fallback** — when direct UDP fails, traffic is relayed through a public MQTT
  broker, still end-to-end encrypted (the broker only sees ciphertext)
- 👥 **Multi-peer support** — the listener (hub) accepts many peers at once and routes traffic
  between them in user space (no kernel forwarding / iptables needed)
- 📋 **Live peer list** — every peer sees all other connected machines (VPN IP, public address, transport)
- 🖥️ **Command-line interface** — arguments for quick start plus an interactive console with live
  status, peer table, log and statistics
- 🔐 **AES-256-GCM** encryption with PBKDF2-HMAC-SHA256 key derivation (480,000 iterations)
- 🌐 **Bilingual/multilingual interface** — switch the whole UI (messages, logs to the console)
  between Turkish, English, German, French and Spanish; your choice is remembered
- 📦 **Single file** — `pertoper_vpn.py` contains everything (CLI + engine)
- 🔑 **Key sharing via peer file** — the exported JSON carries the encryption key so the client can
  just load the file instead of typing the key by hand
- 🏷️ **Persistent peer nicknames** — give a peer a friendly name; it is remembered across runs

### How It Works

```
                 ┌──────────────────────────────┐
                 │   HUB (listener, 10.8.0.1)   │
                 └──────────────────────────────┘
                    ▲            ▲            ▲
        direct UDP  │            │ direct UDP │  relay (MQTT)
                    │            │            │
             ┌──────┴───┐  ┌─────┴────┐  ┌────┴─────┐
             │ Peer A   │  │ Peer B   │  │ Peer C   │
             │10.8.0.2  │  │10.8.0.3  │  │10.8.0.4  │
             └──────────┘  └──────────┘  └──────────┘
```

1. Both sides derive the same **room ID** from the shared key (`sha256(key)[:16]`).
2. They meet on a public MQTT broker and exchange their public endpoints.
3. **STUN** discovers each side's public IP:port and NAT behaviour (cone vs. symmetric).
4. **UDP hole punching** is attempted with retries and port-delta prediction.
5. If direct UDP fails, traffic falls back to the **encrypted MQTT relay**.
6. While on relay, a background probe keeps trying to **upgrade to direct P2P**.
7. The hub assigns each peer a VPN IP (`10.8.0.2` … `10.8.0.254`) and routes packets between
   peers in user space; the routing table is also broadcast to every peer for display.

### Requirements

- Python 3.8+
- `cryptography` (see [`requirements.txt`](requirements.txt))
- **Administrator / root privileges** (to create the TUN adapter)
- **Windows:** [`wintun.dll`](https://www.wintun.net) placed next to the script

### Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# (recommended) virtual environment
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate

pip install -r requirements.txt
```

**Windows only:** download `wintun.dll` from <https://www.wintun.net> and place it in the project
folder (next to `pertoper_vpn.py`).

### Usage

Run with administrator/root privileges:

```bash
# Windows (as Administrator)
python pertoper_vpn.py -m serve -k <key>

# Linux (root or auto-elevates via pkexec)
sudo python pertoper_vpn.py -m serve -k <key>
```

#### Command-line arguments

| Argument | Description |
| --- | --- |
| `-m, --mode {serve,connect}` | Working mode: `serve` = listener/hub, `connect` = client (default: `serve`) |
| `-k, --key KEY` | Shared encryption key |
| `-p, --port PORT` | UDP port (serve: listen, connect: local; default `12345`) |
| `--peer IP:PORT` | Peer address (connect: hub; serve: CGNat target) |
| `-f, --file FILE` | connect: `peer_info.json` to load; serve: file to export |
| `--export FILE` | serve: explicit `peer_info.json` export path |
| `--no-auto` | Disable automatic cloud matching |
| `--lang {tr,en,de,fr,es}` | Interface language |
| `--start` | Start the VPN immediately on launch |
| `-n, --non-interactive` | No interface; start the VPN and wait (Ctrl+C to quit) |
| `--shell` | Interactive mode: open the advanced command shell instead of the menu |
| `--background` | Start the VPN detached and exit (survives closing the terminal) |
| `--stop` | Stop the running background VPN and exit |
| `--status` | Print the running background VPN status and exit |
| `--control-port PORT` | Local control port (default `47700`) |
| `--stun` | Run the STUN/NAT/UPnP test and exit |
| `--genkey` | Generate a random key and exit |
| `-v, --version` | Print the version and exit |

#### Interactive menu

By default (unless `-n`, `--shell` or `--start` is used), the app opens a **numbered menu**
for first-time users: it shows the current mode/state/key/port and starts the VPN with a
step-by-step wizard (role → key → port → connection); it also shows status, peers
and logs, changes settings and language, runs a network test and opens the advanced shell.
The **last used connection is remembered**, so the wizard and **Quick start** come pre-filled.
Options: **1** start wizard · **2** quick start (last settings) · **3** stop · **4** status ·
**5** peers · **6** logs · **7** settings · **8** run at startup (on/off) ·
**9** network test · **10** language · **11** about · **12** advanced shell · **0** quit.
Menu option **4** opens a **live monitor**: it refreshes the status and statistics (TX/RX,
uptime, state, per-peer traffic) every second until you press `q`, `Esc` or `Enter`.

> **Runs in the background:** starting the VPN launches it as a detached process that keeps
> running even after you close the terminal window. To stop it, open the app again and choose
> **3) Stop**, or run `pertoper_vpn.py --stop`. `--status` shows whether it is running.
>
> **Run at startup:** menu option **8** registers the VPN to start automatically at login
> (Windows: a scheduled task; Linux: an autostart entry). Enabling it needs administrator/root.

#### Interactive commands (advanced shell)

In the command shell (via `--shell` or menu option **10**), type `help` to see them:

| Command | Description |
| --- | --- |
| `status` | Show status and statistics (mode, state, public/VPN IP, TX/RX, uptime) |
| `peers` | List connected peers (name, VPN IP, public address, transport, traffic) |
| `log [n]` | Show the last `n` log lines (default 20) |
| `rename <peer> [name]` | Give a peer a nickname (empty name clears it) |
| `set <field> <value>` | Change a setting: `key`, `port`, `peer`, `file`, `export`, `auto`, `mode`, `lang` |
| `genkey` | Generate a random encryption key and use it |
| `stun` | Run the STUN / NAT / UPnP test |
| `start` / `stop` | Start / stop the VPN |
| `about` | Show application information |
| `lang [code]` | Show or change the language |
| `clear` | Clear the log |
| `help` / `quit` | Help / quit |

#### Examples

```bash
# Hub: start the listener and drop into the shell
python pertoper_vpn.py -m serve -k "my-long-secret" --start

# Client: load the exported peer file (key is read from it)
python pertoper_vpn.py -m connect -f peer_info.json --start

# Client with an explicit hub address
python pertoper_vpn.py -m connect -k "my-long-secret" --peer 203.0.113.10:41337 --start

# Non-interactive (scripts / services): starts and keeps running
python pertoper_vpn.py -n -m connect -k "my-long-secret"

# Just run a connectivity test
python pertoper_vpn.py --stun
python pertoper_vpn.py --genkey
```

**On the hub machine (server)**

1. Choose `-m serve`.
2. Provide a **shared secret key** (`-k`), or run `--genkey`/`genkey` to make one.
3. Optionally set the **port** (`-p`, default `12345`) and an **export file** to save `peer_info.json`.
4. Press Enter / run `start` (`--start` does it automatically).

**On each connecting machine (client)**

1. Choose `-m connect`.
2. Either type the **same secret key**, or load the exported `peer_info.json` with `-f` —
   the key is read from the file automatically.
3. Run `start` (`--start` does it automatically) and use `peers` to see everyone.

Both sides must use **the same secret key** and be able to reach at least one common public
MQTT broker. The app connects to every configured broker at once and matches on whichever
broker both peers share.

### Building a Standalone Binary

**Linux**

```bash
./build.sh
# output: dist/linux/PertoperVPN
```

**Linux AppImage**

```bash
chmod +x build_appimage.sh
./build_appimage.sh
# output: dist/appimage/PertoperVPN-3.4-x86_64.AppImage
```

**Windows**

```bat
build.bat
:: interactive menu:
::   [1] Windows (.exe)   ->  dist\windows\PertoperVPN.exe
::   [2] Linux (ELF)      ->  dist\linux\PertoperVPN
::   [3] Both
```

### Sharing the Peer File

When the hub exports `peer_info.json`, the file contains the public endpoint **and** the shared key:

```json
{
  "public_ip": "203.0.113.10",
  "public_port": 41337,
  "vpn_ip": "10.8.0.1",
  "nat_type": "Cone NAT (Hole Punch Uyumlu)",
  "key": "your-shared-secret-key"
}
```

⚠️ **The file contains the key in plain text.** Send it over a secure channel only.

### Project Structure

```
pertoper_vpn.py     # entire application (CLI + VPN engine)
requirements.txt    # Python dependencies
build.sh            # Linux build script (PyInstaller)
build_appimage.sh   # Linux AppImage build script
build.bat           # Windows / Linux build menu (PyInstaller)
KILAVUZ.md          # detailed user guide (TR/EN)
README.md
```

### Troubleshooting

| Problem | Solution |
| --- | --- |
| `TUN hatası` / TUN adapter error | Run as Administrator / root |
| `wintun.dll bulunamadı` (Windows) | Download `wintun.dll` next to `pertoper_vpn.py` |
| Connection never establishes | Make sure the key matches on both sides and the port is not blocked |
| Always falls back to relay | Both sides are likely behind symmetric CGNAT; relay still works, but slower |
| Hub responds but a peer is unreachable | Run the app **as administrator** on the Windows peer: the Wintun adapter may be classified as a *Public* network, where Windows blocks ping and sharing. The app sets it to *Private* and adds a VPN-subnet allow rule. Verify with `Get-NetConnectionProfile` and `netsh advfirewall firewall show rule name=Peertopeer_P2P_VPN_ICMP`. |
| `cryptography` import error | `pip install -r requirements.txt` |

### Security Notes

- Traffic is encrypted with **AES-256-GCM**; the relay broker only sees ciphertext.
- The **key is the only authentication factor** — anyone who knows it can join the network.
  Use a long, random key (the `genkey` command generates a 24-character one).
- Public MQTT brokers are used for rendezvous/relay. They can observe *that* a session exists
  (encrypted metadata, topic derived from the key), but not the content.
- **This project is for educational and personal use.** You are responsible for complying with
  the laws and network policies that apply to you.

### Developer

**Bekir Alişoğlu** — ✉️ alisoglu@yahoo.com

### License

No license file has been added to this repository yet. Without a license, the default is
"all rights reserved". If you intend to make this project open source, add a `LICENSE` file
(e.g. [MIT](https://choosealicense.com/licenses/mit/)).

---

## 🇹🇷 Türkçe

### Genel Bakış

Peertopeer P2P VPN, makineler arasında **sunucu (VPS) gerektirmeden** şifreli bir peer-to-peer tüneli
kurar. Aynı uygulama hem dinleyici (hub) hem de bağlanan taraf olarak çalışır ve **hub-and-spoke**
topolojisiyle **aynı anda birden fazla peer** bağlanmasını destekler.

NAT geçişinin zor kısmını otomatik halleder: STUN keşfi, port-delta tahminli agresif UDP hole
punching ve doğrudan UDP yolunun mümkün olmadığı çift CGNat durumlarında şifreli bulut relay
yedek yolu.

Komut satırı argümanlarıyla başlatılır, ardından **yönlendirmeli menü** (ya da gelişmiş komut
kabuğu) ile durum, peer'ler, loglar ve kontrol sağlanır. VPN bir **arka plan süreci** olarak
çalışır — terminal kapatılsa bile durmaz; siz **Durdur** (`--stop`) diyene kadar çalışır.

### Özellikler

- 🔗 **VPS gerektirmez** — doğrudan peer-to-peer bağlantı
- 🕳️ **CGNat bypass** — STUN + agresif UDP hole punching (simetrik NAT için port-delta tahmini)
- ☁️ **Şifreli relay yedeği** — doğrudan UDP başarısız olursa trafik bir genel MQTT broker üzerinden
  aktarılır, yine uçtan uca şifreli (broker yalnızca şifreli metni görür)
- 👥 **Çoklu peer desteği** — dinleyici (hub) aynı anda birçok peer kabul eder ve trafiği kullanıcı
  alanında yönlendirir (kernel forwarding / iptables gerekmez)
- 📋 **Canlı peer listesi** — her peer, bağlı tüm makineleri görür (VPN IP, public adres, taşıma tipi)
- 🖥️ **Komut satırı arayüzü** — hızlı başlatma için argümanlar + canlı durum, peer tablosu, log ve
  istatistik sunan interaktif konsol
- 🔐 **AES-256-GCM** şifreleme, PBKDF2-HMAC-SHA256 anahtar türetimi (480.000 iterasyon)
- 🌐 **Çok dilli arayüz** — konsol mesajlarını ve logları Türkçe, İngilizce, Almanca, Fransızca ve
  İspanyolca arasında değiştirin; seçiminiz hatırlanır
- 📦 **Tek dosya** — `pertoper_vpn.py` her şeyi içerir (arayüz + çekirdek)
- 🔑 **Peer dosyasıyla anahtar paylaşımı** — dışa aktarılan JSON şifreleme anahtarını da taşır; istemci
  anahtarı elle yazmak yerine dosyayı yükler
- 🏷️ **Kalıcı peer takma isimleri** — bir peer'e kolay bir ad verin; çalıştırmalar arasında hatırlanır

### Nasıl Çalışır?

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

1. İki taraf paylaşılan anahtardan aynı **oda kimliğini** üretir (`sha256(key)[:16]`).
2. Bir genel MQTT broker üzerinde buluşup kendi public adreslerini paylaşırlar.
3. **STUN** ile her tarafın public IP:port bilgisi ve NAT davranışı (cone / simetrik) tespit edilir.
4. Tekrarlı ve port-delta tahminli **UDP hole punching** denenir.
5. Doğrudan UDP başarısız olursa trafik **şifreli MQTT relay**'ine düşer.
6. Relay'deyken arka plan yoklaması **doğrudan P2P'ye yükseltmeyi** sürdürür.
7. Hub her peer'e bir VPN IP'si atar (`10.8.0.2` … `10.8.0.254`) ve paketleri kullanıcı alanında
   peer'ler arasında yönlendirir; yönlendirme tablosu görüntüleme için tüm peer'lere de yayınlanır.

### Gereksinimler

- Python 3.8+
- `cryptography` (bkz. [`requirements.txt`](requirements.txt))
- **Yönetici / root yetkisi** (TUN adaptörü oluşturmak için)
- **Windows:** script'in yanına konulmuş [`wintun.dll`](https://www.wintun.net)

### Kurulum

```bash
git clone https://github.com/<kullanici-adiniz>/<repo-adiniz>.git
cd <repo-adiniz>

# (önerilir) sanal ortam
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate

pip install -r requirements.txt
```

**Yalnızca Windows:** <https://www.wintun.net> adresinden `wintun.dll` indirip proje klasörüne
(`pertoper_vpn.py` ile aynı dizine) koyun.

### Kullanım

Yönetici/root yetkisiyle çalıştırın:

```bash
# Windows (Yönetici olarak)
python pertoper_vpn.py -m serve -k <anahtar>

# Linux (root veya pkexec ile otomatik yükseltme)
sudo python pertoper_vpn.py -m serve -k <anahtar>
```

#### Komut satırı argümanları

| Argüman | Açıklama |
| --- | --- |
| `-m, --mode {serve,connect}` | Çalışma modu: `serve` = dinleyici/hub, `connect` = istemci (varsayılan: `serve`) |
| `-k, --key ANAHTAR` | Paylaşılan şifreleme anahtarı |
| `-p, --port PORT` | UDP portu (serve: dinlenecek, connect: yerel; varsayılan `12345`) |
| `--peer IP:PORT` | Peer adresi (connect: hub; serve: CGNat hedefi) |
| `-f, --file DOSYA` | connect: yüklenecek `peer_info.json`; serve: dışa aktarılacak dosya |
| `--export DOSYA` | serve: `peer_info.json` dışa aktarma yolu |
| `--no-auto` | Otomatik bulut eşleşmesini kapat |
| `--lang {tr,en,de,fr,es}` | Arayüz dili |
| `--start` | Açılışta VPN'i hemen başlat |
| `-n, --non-interactive` | Arayüz açılmaz; VPN başlar ve Ctrl+C beklenir |
| `--shell` | Etkileşimli modda menü yerine gelişmiş komut kabuğunu aç |
| `--background` | VPN'i arka planda (terminalden bağımsız) başlat ve çık |
| `--stop` | Çalışan arka plan VPN'ini durdur ve çık |
| `--status` | Çalışan arka plan VPN'inin durumunu yazdır ve çık |
| `--control-port PORT` | Yerel kontrol portu (varsayılan `47700`) |
| `--stun` | STUN/NAT/UPnP testini çalıştır ve çık |
| `--genkey` | Rastgele bir anahtar üret ve çık |
| `-v, --version` | Sürümü yazdır ve çık |

#### İnteraktif menü

Varsayılan olarak (`-n`, `--shell` veya `--start` kullanılmadıkça) uygulama, yeni başlayanlar
için **numaralı bir menü** açar: geçerli mod/durum/anahtar/port bilgisini gösterir ve VPN'i
adım adım bir sihirbazla (rol → anahtar → port → bağlantı) başlatır; ayrıca durum,
peer'ler ve logları görüntüler, ayarları ve dili değiştirir, ağ testi çalıştırır ve gelişmiş
kabuk açar.
**Son kullanılan bağlantı hatırlanır**, böylece sihirbaz ve **Hızlı başlat** hazır gelir.
Seçenekler: **1** başlatma sihirbazı · **2** hızlı başlat (son ayarlar) · **3** durdur · **4** durum ·
**5** peer'ler · **6** loglar · **7** ayarlar · **8** başlangıçta çalıştır (aç/kapa) ·
**9** ağ testi · **10** dil · **11** hakkında · **12** gelişmiş kabuk · **0** çıkış.

> **Arka planda çalışır:** VPN'i başlatmak onu terminalden bağımsız ayrı bir süreçte çalıştırır;
> terminal penceresini kapatsanız bile çalışmaya devam eder. Durdurmak için uygulamayı yeniden
> açıp **3) Durdur**'u seçin ya da `pertoper_vpn.py --stop` çalıştırın. `--status` çalışıp
> çalışmadığını gösterir.
>
> **Başlangıçta çalıştır:** menüdeki **8** numaralı seçenek VPN'i oturum açılışında otomatik
> başlatacak şekilde kaydeder (Windows: zamanlanmış görev; Linux: autostart girdisi).
> Etkinleştirmek için yönetici/root gerekir.

#### İnteraktif komutlar (gelişmiş kabuk)

Komut kabuğunda (`--shell` ya da menü **10** ile) hepsini görmek için `help` yazın:

| Komut | Açıklama |
| --- | --- |
| `status` | Durum ve istatistikleri göster (mod, durum, public/VPN IP, TX/RX, süre) |
| `peers` | Bağlı peer'leri listele (isim, VPN IP, public adres, taşıma, trafik) |
| `log [n]` | Son `n` log satırını göster (varsayılan 20) |
| `rename <peer> [ad]` | Bir peer'e takma isim ver (ad boşsa siler) |
| `set <alan> <değer>` | Ayar değiştir: `key`, `port`, `peer`, `file`, `export`, `auto`, `mode`, `lang` |
| `genkey` | Rastgele şifreleme anahtarı üret ve kullan |
| `stun` | STUN / NAT / UPnP testini çalıştır |
| `start` / `stop` | VPN'i başlat / durdur |
| `about` | Uygulama bilgilerini göster |
| `lang [kod]` | Dili göster veya değiştir |
| `clear` | Logu temizle |
| `help` / `quit` | Yardım / çıkış |

#### Örnekler

```bash
# Hub: dinleyiciyi başlat ve kabuğa düş
python pertoper_vpn.py -m serve -k "uzun-gizli-anahtar" --start

# İstemci: dışa aktarılan peer dosyasını yükle (anahtar dosyadan okunur)
python pertoper_vpn.py -m connect -f peer_info.json --start

# İstemci, açık hub adresiyle
python pertoper_vpn.py -m connect -k "uzun-gizli-anahtar" --peer 203.0.113.10:41337 --start

# Etkileşimsiz (script / servis): başlar ve çalışmaya devam eder
python pertoper_vpn.py -n -m connect -k "uzun-gizli-anahtar"

# Sadece bağlantı testi
python pertoper_vpn.py --stun
python pertoper_vpn.py --genkey
```

**Hub makinede (sunucu)**

1. `-m serve` seçin.
2. Bir **şifreleme anahtarı** girin (`-k`) ya da üretmek için `--genkey` / `genkey` kullanın.
3. İsteğe bağlı olarak **port** (`-p`, varsayılan `12345`) ve `peer_info.json` için bir **dışa aktarma dosyası** belirleyin.
4. Enter'a basın / `start` yazın (`--start` bunu otomatik yapar).

**Bağlanan her makinede (istemci)**

1. `-m connect` seçin.
2. **Aynı anahtarı** yazın ya da `-f` ile dışa aktarılan `peer_info.json` dosyasını yükleyin —
   anahtar dosyadan otomatik okunur.
3. `start` yazın (`--start` otomatik yapar) ve herkesi görmek için `peers` kullanın.

İki taraf da **aynı anahtarı** kullanmalı ve en az bir ortak genel MQTT broker'ına
erişebilmelidir. Uygulama tüm tanımlı broker'lara aynı anda bağlanır ve iki eşin ortak
olduğu broker üzerinden eşleşir.

### Tek Dosya (Binary) Derleme

**Linux**

```bash
./build.sh
# çıktı: dist/linux/PertoperVPN
```

**Linux AppImage**

```bash
chmod +x build_appimage.sh
./build_appimage.sh
# çıktı: dist/appimage/PertoperVPN-3.4-x86_64.AppImage
```

**Windows**

```bat
build.bat
:: etkileşimli menü:
::   [1] Windows (.exe)   ->  dist\windows\PertoperVPN.exe
::   [2] Linux (ELF)      ->  dist\linux\PertoperVPN
::   [3] Her ikisi
```

### Peer Dosyası Paylaşımı

Hub `peer_info.json` dosyasını dışa aktardığında dosya, public adresin yanı sıra **paylaşılan anahtarı**
da içerir:

```json
{
  "public_ip": "203.0.113.10",
  "public_port": 41337,
  "vpn_ip": "10.8.0.1",
  "nat_type": "Cone NAT (Hole Punch Uyumlu)",
  "key": "paylasilan-gizli-anahtar"
}
```

⚠️ **Dosya anahtarı düz metin olarak içerir.** Yalnızca güvenli bir kanaldan gönderin.

### Proje Yapısı

```
pertoper_vpn.py     # tüm uygulama (arayüz + VPN çekirdeği)
requirements.txt    # Python bağımlılıkları
build.sh            # Linux derleme betiği (PyInstaller)
build_appimage.sh   # Linux AppImage derleme betiği
build.bat           # Windows / Linux derleme menüsü (PyInstaller)
KILAVUZ.md          # detaylı kullanım kılavuzu (TR/EN)
README.md
```

### Sorun Giderme

| Sorun | Çözüm |
| --- | --- |
| `TUN hatası` | Yönetici / root olarak çalıştırın |
| `wintun.dll bulunamadı` (Windows) | `wintun.dll` dosyasını `pertoper_vpn.py` yanına indirin |
| Bağlantı hiç kurulmuyor | İki tarafta anahtarın aynı olduğundan ve portun engelli olmadığından emin olun |
| Sürekli relay'e düşüyor | İki taraf da simetrik CGNat arkasında olabilir; relay yine çalışır ama daha yavaştır |
| Hub yanıt veriyor ama bir peer'e ulaşılamıyor | Windows peer'da uygulamayı **yönetici olarak** çalıştırın: Wintun adaptörü *Genel* (Public) ağ sayılmış olabilir; bu profilde Windows ping ve paylaşımı bloke eder. Uygulama adaptörü *Özel* profile alır ve VPN alt ağı için izin kuralı ekler. `Get-NetConnectionProfile` ve `netsh advfirewall firewall show rule name=Peertopeer_P2P_VPN_ICMP` ile denetleyin. |
| `cryptography` bulunamadı | `pip install -r requirements.txt` |

### Güvenlik Notları

- Trafik **AES-256-GCM** ile şifrelenir; relay broker'ı yalnızca şifreli metni görür.
- **Tek kimlik doğrulama faktörü anahtardır** — bilen herkes ağa katılabilir. Uzun ve rastgele bir
  anahtar kullanın (`genkey` komutu 24 karakterlik anahtar üretir).
- Buluşma/relay için genel MQTT broker'ları kullanılır. Bir oturumun *var olduğu* gözlemlenebilir
  (şifreli meta veri, konu adı anahtardan türetilir) ancak içerik görülemez.
- **Bu proje eğitim ve kişisel kullanım içindir.** Bulunduğunuz yerdeki yasalara ve ağ
  politikalarına uymak sizin sorumluluğunuzdadır.

### Geliştirici

**Bekir Alişoğlu** — ✉️ alisoglu@yahoo.com

### Lisans

Bu depoya henüz bir lisans dosyası eklenmemiştir. Lisans olmadan varsayılan durum
"tüm hakları saklıdır"dır. Projeyi açık kaynak yapmak istiyorsanız bir `LICENSE` dosyası ekleyin
(örn. [MIT](https://choosealicense.com/licenses/mit/)).

# HIKARI-SC — Perbandingan, Audit & Saran (v0.1 → v0.2 → v0.3)

Tanggal audit: 2026-11-16. Scope: `config-template-v0.1`, `config-template-v0.2`, `hikari_converter.py`, folder `ruleset/`.

> **Batasan verifikasi.** Sandbox tidak punya core `mihomo`, jadi config **belum dijalankan di core/perangkat nyata**. Yang sudah diuji: parsing & round-trip URI, build 3 platform, validator, edit menu, dan kesetaraan hasil pemadatan port. Poin yang bergantung pada perilaku Nikki/OpenClash di perangkat ditandai **[perlu cek]**.

---

## 1. Perbandingan Template v0.1 vs v0.2

| Aspek | v0.1 (varian Box/BFR) | v0.2 |
|---|---|---|
| Target | Box for Root saja | Generik (port & DNS = default OpenClash: 7890–7895, dns 7874) |
| Port | 7890/7891/7892, redir 9797, tproxy 9898 | 7890/7891/7892/7893/7895 |
| Controller | `127.0.0.1:9090` + secret `hikari` + `external-ui` | **`0.0.0.0:9090`, secret kosong**, tanpa UI |
| Log | `warning` | `silent` |
| DNS | DoH-only, `respect-rules`, `proxy-server-nameserver`, `use-hosts`, tanpa fallback | UDP polos (8.8.8.8, 1.0.0.1), `fallback`, **IP DNS ISP `112.215.203.254`**, tanpa `respect-rules` |
| Blok Android | `tun` (off), `find-process-mode: always`, `geodata-*`, `experimental`, `geox-url` | semua dihapus |
| Rule-provider | `type: file` (lokal), Blocker dari zxc-rv | **semua `type: http`** ke repo `nexterade/crispy-funicular` |
| Group | 7 | 8 (+ **🪼 GAMING**) |
| Rule | tanpa game | + `Portgames` (rule-set 23.366 `DST-PORT`) |
| Nama group | 🔥 AUTO MODE, 👻 PROXY LIST, ✨, 🛑, 🔞, 📶 | 🦈, 🍋‍🟩, 🌳, 💤, 💕, 🪺 |
| Marker `AUTO-PROXIES` | ada | hilang (script memang tidak memakainya) |

**Kesimpulan:** v0.2 bergerak ke template generik + auto-update, tapi **menjatuhkan** hampir semua yang membuat v0.1 aman di Android (controller loopback+secret, DoH-only, tun/find-process) dan membawa tiga regresi (lihat temuan T1–T3).

---

## 2. Temuan Audit

### Template (v0.2)

| # | Sev. | Temuan | Dampak | Status v0.3 |
|---|---|---|---|---|
| T1 | 🔴 | `external-controller: 0.0.0.0:9090` + `secret: ''` | API terbuka tanpa auth ke LAN/hotspot (bisa ganti node, baca koneksi) | Default `127.0.0.1`; script membuka `0.0.0.0` hanya di OpenWrt & **mengisi secret acak** bila kosong |
| T2 | 🔴 | Rule `WifiClients` (`SRC-IP-CIDR,192.168.0.0/16`) ada di semua platform | Di OpenWrt **semua** client LAN ber-IP 192.168.x.x → seluruh trafik jatuh ke group WIFI (default Direct) → proxy/blocker/inject tidak pernah jalan. `wifi.yaml` sendiri menulis "khusus Box mode tproxy" | Script membuang rule+group+provider WIFI untuk Nikki/OpenClash |
| T3 | 🟠 | DNS: UDP:53 polos, `fallback` tanpa `fallback-filter`, IP DNS ISP, `respect-rules` hilang | Kebocoran DNS ke ISP, tidak portable (IP ISP tertentu), mundur dari klaim "DoH only / Anti-Leak" di v0.1 | DoH-only + `respect-rules` + `proxy-server-nameserver`; bootstrap IP polos hanya untuk resolve host DoH |
| T4 | 🟠 | Template dipakai "apa adanya" di Box, padahal port-nya bukan port Box (redir 7892/tproxy 7895 vs 9797/9898; dns 7874 vs 1053) | Iptables/tproxy Box tidak menemukan port yang diharapkan **[perlu cek: tergantung `settings.ini` Box-mu]** | Overlay Box menyuntik port 9797/9898, dns 1053, blok tun, `find-process-mode` |
| T5 | 🟠 | `Portgames`: 23.366 baris `DST-PORT` satuan (395 KB), memuat 5228 (Google Play/FCM), 8888, 5432, 5353 dan range 50000–65535 | 23 ribu rule harus di-parse tiap start di HP/router kecil (bobot belum diukur di perangkat), 395 KB file untuk isi yang setara 87 range | Dipadatkan jadi **87 range / 2 KB**, port set identik (diverifikasi). Lihat saran S3 untuk isi range-nya |
| T6 | 🟡 | 11 provider `http` tanpa `interval`; `Portgames` tanpa `format` | Tidak pernah auto-update walau type `http` | Semua `interval: 86400`, `format: yaml` |
| T7 | 🟡 | `type: http` menimpa file lokal dari GitHub; klaim "OFFLINE" tidak benar jika repo berubah/terblokir | Ruleset bisa berbeda dari yang di-copy script | Opsi **Mode Offline** (http → file) di menu |
| T8 | 🟡 | `log-level: silent` | Susah troubleshooting | `warning` |
| T9 | ⚪ | Emoji `🍋‍🟩` adalah urutan ZWJ (Unicode 15.1) | Bisa tampil `🍋`+`🟩` di Android/terminal lama | Tidak diubah (kosmetik) — opsional ganti `🍋` |

### Script `hikari_converter.py` (v1)

| # | Sev. | Temuan (semua direproduksi) | Status v2 |
|---|---|---|---|
| S1 | 🔴 | Parser VLESS **membuang `flow` & `fp`** → node Reality/Vision tidak bisa konek | `flow`, `client-fingerprint`, `alpn`, `allowInsecure` dibaca; Reality default fp `chrome`, wajib `pbk` |
| S2 | 🔴 | Patch OpenWrt "enable tun" pakai regex rapuh dan **tidak bekerja** pada v0.2 (tidak ada blok `tun`); di tempat lain bila aktif justru bentrok dengan firewall Nikki/OpenClash; juga membuang `redir/tproxy` tanpa alasan kuat | Pipeline berbasis YAML: tun dibuang di OpenWrt, port dibiarkan |
| S3 | 🔴 | Rule WIFI ikut ke OpenWrt (lihat T2) | Dibuang otomatis + divalidasi |
| S4 | 🟠 | `Hasil/proxy` tidak pernah terisi → menu *Clash→URI dari file* & *Status* **selalu kosong** | Memindai `Hasil/full_config_*/proxy*/` |
| S5 | 🟠 | Nama node duplikat lolos → core menolak/menimpa | `dedupe_names` (`Nama (2)`), juga terhadap nama bawaan template |
| S6 | 🟠 | Password trojan tetap ter-encode (`%40`); `:` di password memotong | `unquote` pada userinfo; di sisi URI di-`quote` |
| S7 | 🟠 | Menu DNS: `default-nameserver` **selalu ditimpa** walau jawab "n" (prompt bootstrap tak berfungsi); preset "Quad9 Unsecured" sebenarnya `dns.quad9.net` (secured/filtered); preset AdGuard dicampur Google (memecah filter) | Bootstrap hanya berubah jika "y"; `dns10.quad9.net`; AdGuard murni |
| S8 | 🟠 | Path relatif ke cwd (`template.yaml`) tapi output relatif ke script; README menjanjikan anti-`PermissionError` tapi tidak ada penanganannya | Semua path relatif ke script; `PermissionError` ditangani dengan pesan |
| S9 | 🟡 | Input tidak valid ditelan diam-diam (`except: pass`) | Ditampilkan per baris + alasan |
| S10 | 🟡 | Edit port tanpa validasi (bisa menulis `abc`); secret dengan `'` merusak YAML | Validasi 1–65535, quote aman, backup `.bak`, YAML dicek sebelum simpan |
| S11 | 🟡 | `vless` memuat `cipher: auto` (tidak valid); `host=` selalu ditambah di URI walau TCP; vmess grpc/h2 tidak dibangun; IPv6 tanpa `[ ]` | Dirapikan; round-trip diuji termasuk IPv6 |
| S12 | 🟡 | Transport tak dikenal (mis. `xhttp`) menghasilkan node rusak diam-diam | Error jelas: "transport 'xhttp' belum didukung" |
| S13 | ⚪ | `skip-cert-verify: true` hard-coded | Tetap default `True` (bug-host/SNI custom lazim) tapi `allowInsecure=0` dihormati; konstanta `DEFAULT_SKIP_CERT_VERIFY` |

---

## 3. Perubahan di v0.3

- `config-template-v0.3.yaml`: template netral (basis v0.2 + perbaikan T1, T3, T6, T7, T8; fitur v0.1 yang tetap berguna: `respect-rules`, `tcp-concurrent`, `geox-url`, dll.).
- `hikari_converter.py` v2: pipeline `template → YAML → patch platform → validasi → dump`; semua temuan S1–S12.
- `ruleset/port-games.yaml`: dipadatkan (asli di `archive/port-games.full.yaml`).
- Menu baru: **Validasi/Audit**, **Tools Ruleset**, mode **Offline**, **Replace/Append**.

**Trade-off yang perlu kamu tahu**
1. Config hasil generate adalah dump YAML → **komentar template tidak ikut** (diganti header). Template sumber tetap utuh dengan komentar.
2. DNS default kembali DoH-only. Kalau kamu sengaja memakai DNS ISP demi latensi, set lewat menu DNS → Custom (atau edit `template.yaml`).
3. Boot pertama dengan `respect-rules` butuh proxy hidup untuk query DoH domain non-direct; resolve host server proxy lewat `proxy-server-nameserver` (langsung), sama seperti v0.1.

**Asumsi [perlu cek di perangkat]**
- Nikki & OpenClash menimpa `port/socks/redir/tproxy/mixed`, `dns.listen`, `tun`, `external-controller`, `secret` dari setting LuCI. Karena itu port di template dibiarkan dan `tun` dibuang. Dokumentasi Nikki yang bisa kubaca hanya mengonfirmasi mixin untuk `dns/sniff/hosts` dan "berbagai port"; detail `tun`/controller belum terverifikasi.
- Path Nikki `/etc/nikki/run/{proxy,ruleset}` & OpenClash `./proxy_provider`, `./rule_provider` dipertahankan dari script lama.
- Range di `DST-PORT` (`5000-5221`) didukung mihomo — terkonfirmasi di [wiki MetaCubeX](https://wiki.metacubex.one/en/handbook/syntax) (Port Ranges: `-`, pemisah `/` atau `,`).
- Port Box 9797/9898/1053 diambil dari v0.1; samakan dengan `settings.ini` Box-mu.
- Provider kosong `proxies: []` (file `trial.yaml` saat belum diisi) dipertahankan dari v1; kalau core-mu menolak, isi minimal 1 node.

---

## 4. Saran Pengembangan (urut manfaat/biaya)

1. **Uji dengan core asli di CI.** GitHub Action: `mihomo -t -d . -f config.yaml` untuk 3 output platform + `pytest` round-trip parser. Menangkap regresi sebelum sampai ke HP/router. Core juga punya `mihomo convert-ruleset` untuk meng-generate `.mrs` dari yaml otomatis saat rilis ruleset.
2. **Overlay platform sebagai file, bukan kode.** Pindahkan `BOX_TOP_LEVEL`, `BOX_TUN`, dll. ke `platforms/box.yaml`, `nikki.yaml`, `openclash.yaml` — bisa diedit tanpa menyentuh Python dan mudah ditambah platform baru (mis. Mihomo Party, Clash Verge, Sing-box-converter).
3. **Rapikan `Portgames`.** (a) batasi ke UDP: `AND,((NETWORK,UDP),(DST-PORT,5000-5221))` agar TCP 5228 (FCM/Google Play) tidak ikut ke GAMING; (b) tinjau range 50000–65535 — terlalu lebar, menangkap port acak; (c) pecah per game agar bisa on/off.
4. **Mode non-interaktif.** `argparse`: `--platform nikki --input nodes.txt --target active --offline --out DIR` + `--check`. Memungkinkan cron/CI dan integrasi dengan skrip lain.
5. **Protokol tambahan:** Shadowsocks (`ss://`), Hysteria2 (`hy2://`, bagus untuk game UDP), TUIC, dan `xhttp` bila core stabil. Parser sekarang sengaja menolak yang belum didukung.
6. **Impor subscription.** Fetch URL (saat online) → parse base64/Clash → merge ke provider; plus rename/filter node (regex negara), dedupe berdasar `server+port+uuid`, dan group otomatis per negara (`filter:` pada proxy-group).
7. **Mirror rule-provider.** Tambah fallback CDN (mis. jsDelivr) untuk URL GitHub raw yang kadang lambat/terblokir di beberapa ISP, atau `proxy:` seragam untuk semua provider http.
8. **Versi & migrasi template.** Tambah `# template-version: 0.3` + pengecekan di script ("template.yaml lebih tua dari master — merge?") agar edit lokal tidak ketinggalan.
9. **Keamanan Box.** Hindari secret default yang bisa ditebak (`hikari`) dan bundel dashboard (zashboard/metacubexd) per platform di folder `ui/`.
10. **Pengecekan konflik ruleset.** Validator tingkat lanjut: entri `Skip-Sniff` vs `Force-Sniff` yang saling tumpang tindih, entri `IP-CIDR` tanpa `no-resolve`, domain tidak valid di rule-set `behavior: domain`.

---

## 5. Koreksi pasca-uji lapangan (2026-11-16)

**Gejala:** semua node timeout ("0 succeeded, 4 timed out"); log: `dns resolve failed ... https://dns.google:443/dns-query ... connection reset by peer` saat resolve domain server proxy.
**Penyebab:** v0.3 awal memakai DoH untuk `proxy-server-nameserver`. Jaringan/ISP me-reset DoH ke 8.8.8.8 & 1.1.1.1 :443 → domain server proxy tak bisa di-resolve. Ini kesalahan audit: DNS polos di v0.2 ternyata punya alasan.
**Perbaikan:** `proxy-server-nameserver` dan `direct-nameserver` = DNS polos (8.8.8.8, 1.1.1.1); `nameserver` tetap DoH (lewat proxy). Validator kini memberi peringatan bila `proxy-server-nameserver` DoH semua. Menu DNS tidak lagi menerapkan DoH ke `proxy-server-nameserver` secara default.

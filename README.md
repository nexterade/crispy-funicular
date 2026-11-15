# 🌸 HIKARI SUBCLASH OFFLINE

**HIKARI SUBCLASH** adalah *toolkit* CLI (Command Line Interface) interaktif berbasis Python yang dirancang khusus untuk mengelola, mengkonversi, dan meng-*generate* config proxy (Mihomo/Clash Meta) secara **offline**. 

Script ini awalnya dibuat untuk mempermudah pengguna **Box for Root (Android)**, namun kini telah berevolusi menjadi *All-in-One Converter* yang mendukung **Nikki** dan **OpenClash** di OpenWrt.

---

## ✨ Fitur Utama

- 🔄 **Dual-Convert (Dua Arah):**
  - **URI ➜ Clash:** Mengubah tautan `vless://`, `vmess://`, `trojan://` menjadi format YAML Clash/Mihomo.
  - **Clash ➜ URI:** Mengubah balik config YAML menjadi tautan URI (support WS, gRPC, Reality).
- 🎯 **Smart Preview & Edit:** Tabel *preview* interaktif sebelum *convert*. Bisa hapus node spesifik, tambah node baru, atau *rollback* (batalkan) input.
- 🛠️ **Auto-Patch Platform:** Otomatis menyesuaikan konfigurasi (TUN, Port, Path) berdasarkan platform target:
  - 📱 **Box for Root (Android)**
  - 🐧 **Nikki (OpenWrt)** - *Auto-patch path ke `/etc/nikki/run/`*
  - 🐧 **OpenClash (OpenWrt)** - *Auto-patch path ke `rule_provider/`*
- 🌐 **Manajemen DNS:** Ganti *nameserver* template dengan mudah (Cloudflare, Quad9, NextDNS, AdGuard, atau Custom DoH).
- 🎨 **UI/UX Terminal:** Tampilan berwarna (ANSI), animasi *spinner*, dan menu interaktif tanpa *ribet* ngetik perintah panjang.
- 🛡️ **Anti-Ribet & Anti-Error:** Dilengkapi *error handling* (termasuk anti `PermissionError`), *auto-copy ruleset*, dan *auto-backup* template.

---

## ⚙️ Persyaratan (Requirements)

- **Termux** (Android) atau lingkungan Linux/OpenWrt dengan Python 3.
- Python 3.8 atau lebih baru.
- Library `PyYAML`.

Jika belum terinstall, jalankan:
```bash
pkg update && pkg install python -y
pip install pyyaml
```

---

## 📂 Struktur Folder "Meja Kerja"

Sebelum menjalankan script, pastikan folder lo isinya kayak gini:

```text
hikari_sub/
├── hikari_converter.py     # Script utama
├── template.yaml           # Template config HIKARI asli lo (WAJIB ADA)
├── ruleset/                # Folder berisi file .mrs / .yaml (WAJIB ADA)
└── Hasil/                  # (Auto-generated) Tempat hasil convert
```

*Note: Simpan script dan `template.yaml` di dalam `/storage/emulated/0/` (SDCard), jangan di folder `~` Termux biar gak kena `PermissionError` pas edit file.*

---

## 🚀 Cara Pakai

1. Buka **Termux**.
2. Masuk ke folder tempat lo nyimpen script:
   ```bash
   cd /storage/emulated/0/Documents/hikari_sub
   ```
3. Jalankan script:
   ```bash
   python hikari_converter.py
   ```
4. Ikuti menu interaktif yang muncul di layar.

---

## 📁 Output & Panduan Instalasi

Semua hasil *convert* akan otomatis masuk ke dalam folder **`Hasil/`**.

### 1. Box for Root (Android)
- Output: `Hasil/full_config_box/`
- **Cara pasang:** Salin **semua isi folder** ke `/data/adb/box/clash/`.

### 2. Nikki (OpenWrt)
- Output: `Hasil/full_config_nikki/`
- **Cara pasang:**
  1. Salin `config.yaml` ke `/etc/nikki/profiles/`
  2. Salin folder `proxy/` dan `ruleset/` ke `/etc/nikki/run/`
  *(Jangan dibalik, Nikki memisahkan folder config dan file berjalan!)*

### 3. OpenClash (OpenWrt)
- Output: `Hasil/full_config_openclash/`
- **Cara pasang:**
  1. Salin `config.yaml` ke `/etc/openclash/config/`
  2. Salin folder `proxy_provider/` dan `rule_provider/` ke `/etc/openclash/`

*(Catatan: Disarankan pakai SFTP/WinSCP atau aplikasi File Manager yang support Root untuk mindahin file ke OpenWrt).*

---

## 💡 Tips & Trik (Termux)

Biar gak bolak-balik ngetik perintah panjang, bikin alias di Termux:
1. Buka `nano ~/.bashrc`
2. Tambahkan baris ini di paling bawah:
   ```bash
   alias subclash="cd /storage/emulated/0/Documents/hikari_sub && python hikari_converter.py"
   ```
3. Simpan (Ctrl+X, Y, Enter), lalu jalankan `source ~/.bashrc`.
4. Sekarang lo tinggal ketik **`subclash`** di Termux kapan aja!

---

## ⚠️ Disclaimer
Script ini dibuat untuk mempermudah manajemen konfigurasi pribadi. Pastikan kamu mematuhi hukum dan peraturan yang berlaku di wilayahmu terkait penggunaan jaringan proxy/VPN. 
*Don't be stupid, use it wisely.* 🫰
```

---
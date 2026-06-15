# Deploy Hermes + Kirimdev (Production)

Panduan deploy lengkap: WhatsApp inbound via Kirimdev webhook → Hermes Agent → balasan via Kirimdev API.

**Contoh domain:** `hermes-webhooks.domain.com`  
**Webhook URL:** `https://hermes-webhooks.domain.com/webhook`

---

## Arsitektur

```
Customer WhatsApp
       │
       ▼
  Kirimdev Cloud API
       │  POST /webhook  (X-Kirim-Signature)
       ▼
  nginx :443  ──proxy──►  Hermes plugin :8646  ──►  Hermes Agent (LLM)
       ▲                           │
       │                           └── POST /v1/{phone_number_id}/messages
       └── Let's Encrypt (certbot)
```

Yang **tidak** perlu dibuka ke internet: port `8646` (hanya localhost, di-proxy nginx).

---

## Prasyarat

| Item | Keterangan |
|------|------------|
| VPS | Ubuntu 22.04+ (contoh: Tencent/AWS/DigitalOcean) |
| Domain | Subdomain dedicated, mis. `hermes-webhooks.domain.com` |
| DNS | A record → IP VPS |
| Kirimdev | Akun + nomor WA Cloud API terhubung |
| API key | `kdv_live_*` dari [Kirimdev Dashboard → API Keys](https://app.kirimdev.com/settings/api-keys) |
| Hermes | v0.14.0+ + API key LLM provider (Anthropic/OpenAI, dll.) |
| `phone_number_id` | Meta business phone number ID dari Kirimdev (Settings nomor WA) |

---

## Step 1 — Install Hermes Agent

```bash
# Ikuti official install Hermes (pipx / installer)
# Setelah selesai, pastikan CLI ada:
which hermes
hermes --version
hermes doctor
```

Catat path hermes (bisa berbeda per install):

```bash
which hermes
# contoh: /home/ubuntu/.local/bin/hermes
# atau:   /home/ubuntu/.hermes/hermes-agent/venv/bin/hermes
```

Setup model + secrets LLM sesuai dokumentasi Hermes (`hermes login`, `~/.hermes/.env`, dll.).

---

## Step 2 — Install plugin Kirimdev

```bash
git clone https://github.com/kirimdev/kirimdev-hermes.git
# atau upload folder kirimdev-platform ke server

cp -r kirimdev-hermes/kirimdev-platform ~/.hermes/plugins/kirimdev-platform

# Perhatikan: "plugins" jamak, bukan "plugin"
hermes plugins list
hermes plugins enable kirimdev-platform
```

Install dependency Python di environment Hermes:

```bash
# Pakai pip dari venv Hermes jika ada:
~/.hermes/hermes-agent/venv/bin/pip install aiohttp httpx
# atau:
pip install --user aiohttp httpx
```

---

## Step 3 — Konfigurasi Hermes

Ganti placeholder dengan nilai nyata.

```bash
# ── Wajib ──
hermes config set KIRIMDEV_API_KEY kdv_live_xxxxxxxx
hermes config set KIRIMDEV_ENABLED_NUMBERS 123456789012345
hermes config set KIRIMDEV_DEFAULT_PHONE_NUMBER_ID 123456789012345

# ── Authorization (pilih salah satu strategi, lihat Step 9) ──
hermes config set KIRIMDEV_OWNER_USERS 628123456789
hermes config set KIRIMDEV_ALLOWED_USERS 628111111111,628222222222

# ── Public URL (setelah DNS + SSL siap) ──
hermes config set KIRIMDEV_PUBLIC_URL https://hermes-webhooks.domain.com

# ── Webhook secret — isi SETELAH Step 8 (subscription Kirimdev) ──
hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxxxxxxx
```

| Variable | Wajib | Deskripsi |
|----------|-------|-----------|
| `KIRIMDEV_API_KEY` | ✅ | API key `kdv_live_*` |
| `KIRIMDEV_WEBHOOK_SECRETS` | ✅ | Secret `whsec_*` dari webhook subscription |
| `KIRIMDEV_ENABLED_NUMBERS` | ✅ | `phone_number_id` yang dioperasikan agent (comma-separated) |
| `KIRIMDEV_DEFAULT_PHONE_NUMBER_ID` | disarankan | Default sender untuk cron / CLI |
| `KIRIMDEV_PUBLIC_URL` | disarankan | `https://domain` tanpa `/webhook` |
| `KIRIMDEV_OWNER_USERS` | disarankan | Nomor owner (digits, no `+`) — full access + approve |
| `KIRIMDEV_ALLOWED_USERS` | opsional | Whitelist customer yang langsung dapat balasan |
| `KIRIMDEV_ALLOW_ALL_USERS` | dev only | **Tidak** bypass approval — lihat Step 9 |
| `KIRIMDEV_PORT` | opsional | Default `8646` |

Format nomor telepon: **digits saja**, tanpa `+` — contoh `628123456789`.

---

## Step 4 — DNS

Di Cloudflare (atau registrar):

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `hermes-webhooks` | IP VPS | ON/OFF |

Verifikasi **harus resolve sebelum** daftar webhook Kirimdev:

```bash
dig @8.8.8.8 hermes-webhooks.domain.com +short
# harus return IP VPS
```

Error `ENOTFOUND` saat buat webhook = DNS belum propagate / record belum ada.

---

## Step 5 — nginx (HTTP dulu)

```bash
sudo apt update
sudo apt install -y nginx
sudo ufw allow 'Nginx Full'

sudo nano /etc/nginx/sites-available/hermes-webhook
```

Paste config di bawah. Ganti `hermes-webhooks.domain.com` dengan domain kamu:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name hermes-webhooks.domain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location /webhook {
        proxy_pass http://127.0.0.1:8646/webhook;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 1m;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }

    location /health {
        proxy_pass http://127.0.0.1:8646/health;
        proxy_set_header Host $host;
        access_log off;
    }

    location / {
        return 444;
    }
}
```

Enable site:

```bash
sudo ln -sf /etc/nginx/sites-available/hermes-webhook /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

> **Jangan** tambah block `listen 443 ssl` manual sebelum certbot — certbot yang menambah HTTPS otomatis (Step 7).

---

## Step 6 — Jalankan Hermes + cek localhost

```bash
hermes gateway restart
# atau lanjut ke Step 7 (systemd) lalu:
curl -s http://127.0.0.1:8646/health
```

Response yang benar:

```json
{"status": "ok", "platform": "kirimdev", "channel": "whatsapp"}
```

Kalau kosong / connection refused → lihat [Troubleshooting](#troubleshooting).

---

## Step 7 — SSL (certbot)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d hermes-webhooks.domain.com
```

Certbot otomatis menambah block HTTPS. Verifikasi:

```bash
curl -s https://hermes-webhooks.domain.com/health
```

> `curl https://domain/` (root `/`) akan **Empty reply** — normal (`return 444`). Hanya `/health` dan `/webhook` yang aktif.

---

## Step 8 — Hermes di background (systemd)

```bash
which hermes   # catat path-nya

mkdir -p ~/.config/systemd/user
cp deploy/hermes-gateway.service ~/.config/systemd/user/
nano ~/.config/systemd/user/hermes-gateway.service
```

Pastikan `ExecStart` match output `which hermes`:

```ini
ExecStart=/home/ubuntu/.local/bin/hermes gateway run
```

Enable:

```bash
loginctl enable-linger $USER
systemctl --user daemon-reload
systemctl --user enable hermes-gateway
systemctl --user start hermes-gateway
systemctl --user status hermes-gateway
```

Log:

```bash
tail -f ~/.hermes/gateway.log
journalctl --user -u hermes-gateway -f
```

Perintah sehari-hari:

```bash
systemctl --user restart hermes-gateway
systemctl --user stop hermes-gateway
```

---

## Step 9 — Webhook subscription Kirimdev

**URL webhook (copy persis):**

```
https://hermes-webhooks.domain.com/webhook
```

Via API:

```bash
export KIRIMDEV_API_KEY=kdv_live_xxx

curl -s -X POST https://api.kirimdev.com/v1/webhook_subscriptions \
  -H "Authorization: Bearer $KIRIMDEV_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://hermes-webhooks.domain.com/webhook",
    "events": ["message.received"]
  }'
```

Simpan `initial_secret` dari response →

```bash
hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxxxxxxx
systemctl --user restart hermes-gateway
```

Atau buat subscription lewat Kirimdev Dashboard (Settings → Webhooks) dengan URL di atas.

---

## Step 10 — Authorization (kenapa tidak ada balasan?)

Plugin punya **tier** per pengirim:

| Tier | Config | Agent balas otomatis? | Tools |
|------|--------|----------------------|-------|
| `owner` | `KIRIMDEV_OWNER_USERS` | ✅ Ya | **Full Hermes** (terminal, web, file, cron, …) + semua `kirimdev_*` |
| `allowed` | `KIRIMDEV_ALLOWED_USERS` | ✅ Ya | Plain text + reply tools (buttons, list, image, …) |
| `granted` | Owner tap **Approve** di WA | ✅ Setelah approve (24 jam) | Plain text saja — **no tools** |
| `unknown` | Semua selain di atas | ❌ Tidak — pending approval | — |

> Owner full agent aktif by default. Matikan dengan `hermes config set KIRIMDEV_OWNER_FULL_AGENT false` jika owner cuma boleh pakai tools Kirimdev (broadcast/template), tanpa terminal/web.

**Untuk testing pertama:** masukkan nomor WA kamu sendiri ke owner:

```bash
hermes config set KIRIMDEV_OWNER_USERS 628123456789
systemctl --user restart hermes-gateway
```

Kirim pesan dari nomor itu ke nomor bisnis → agent harus balas.

Customer baru (unknown) → owner dapat pesan WA dengan tombol Approve/Deny.

> `KIRIMDEV_ALLOW_ALL_USERS=true` hanya membuka gateway gate — **tidak** mem-bypass approval tier.

---

## Step 11 — Verifikasi end-to-end

```bash
# 1. DNS
dig @8.8.8.8 hermes-webhooks.domain.com +short

# 2. Hermes lokal
curl -s http://127.0.0.1:8646/health

# 3. nginx + SSL
curl -s https://hermes-webhooks.domain.com/health

# 4. Plugin enabled
hermes plugins list

# 5. Config
hermes config get KIRIMDEV_ENABLED_NUMBERS
hermes config get KIRIMDEV_OWNER_USERS
hermes config get KIRIMDEV_WEBHOOK_SECRETS

# 6. Kirim pesan WA dari nomor owner → pantau log
tail -f ~/.hermes/gateway.log | grep -i kirimdev
```

Log sukses inbound:

```
Kirimdev inbound: pid=... phone=628xxx ...
```

---

## Referensi URL

| Fungsi | URL |
|--------|-----|
| **Webhook (daftar di Kirimdev)** | `https://hermes-webhooks.domain.com/webhook` |
| Health check | `https://hermes-webhooks.domain.com/health` |
| Backend internal | `http://127.0.0.1:8646` (tidak expose) |

---

## Troubleshooting

| Gejala | Penyebab | Fix |
|--------|----------|-----|
| `nginx -t` gagal `options-ssl-nginx.conf` | Block 443 manual sebelum certbot | Hapus block 443, HTTP saja dulu, jalankan certbot |
| `ENOTFOUND` saat buat webhook | DNS belum resolve | Cek A record, `dig @8.8.8.8` |
| `curl :8646/health` kosong | Plugin belum enabled / env kosong | `hermes plugins enable kirimdev-platform`, set API key + secret |
| `Empty reply` di `curl https://domain/` | Normal | Test `/health` bukan `/` |
| 401 webhook | Secret salah | `KIRIMDEV_WEBHOOK_SECRETS` = `whsec_*` dari subscription |
| Pesan masuk, tidak balas | Tier `unknown` | Set `KIRIMDEV_OWNER_USERS` atau `KIRIMDEV_ALLOWED_USERS` |
| Log: `phone_number_id not enabled` | Salah ID | Cek `KIRIMDEV_ENABLED_NUMBERS` di dashboard Kirimdev |
| Log: `dropping` unknown + no owner | Tidak ada owner | Set `KIRIMDEV_OWNER_USERS` |
| 502 nginx | Hermes mati | `systemctl --user restart hermes-gateway` |
| `hermes plugin enable` error | Salah command | Pakai `hermes plugins enable` (jamak) |
| Gateway restart loop | Path hermes salah di systemd | `which hermes` → update `ExecStart` |

---

## Cloudflare

| Mode | Catatan |
|------|---------|
| **Full (strict)** | Recommended — certbot sudah buat sertifikat origin |
| **Flexible** | CF→origin HTTP, block nginx `:80` yang dipakai |

Pastikan port 80/443 terbuka di firewall VPS + security group cloud provider.

---

## CLI — kirim pesan manual

```bash
# Format chat_id: phone_number_id:customer_phone
hermes send --to kirimdev:123456789012345:628123456789 "Halo dari Hermes"
```

---

## File deploy di repo

```
deploy/
├── DEPLOY.md              ← panduan lengkap (termasuk nginx config inline)
└── hermes-gateway.service ← systemd user unit
```

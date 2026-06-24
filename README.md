# kirimdev-hermes

Plugin [Hermes Agent](https://hermes-agent.nousresearch.com) untuk WhatsApp via [Kirimdev](https://kirimdev.com) Cloud API.

```
Customer WhatsApp → Kirimdev → POST /webhook → Hermes Agent → Kirimdev Public API
```

**Versi plugin:** `kirimdev-platform/plugin.yaml` · **Changelog:** [CHANGELOG.md](CHANGELOG.md)

---

## Daftar isi

1. [Arsitektur](#arsitektur)
2. [Quick start (local)](#quick-start-local)
3. [Konfigurasi environment](#konfigurasi-environment)
4. [Authorization tier](#authorization-tier)
5. [Panduan deploy production](#panduan-deploy-production)
6. [Webhook Kirimdev](#webhook-kirimdev)
7. [Fitur inbound (v1.1+)](#fitur-inbound-v11)
8. [Verifikasi & troubleshooting](#verifikasi--troubleshooting)
9. [Development & testing](#development--testing)
10. [Struktur repo](#struktur-repo)

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

- Port **8646** hanya localhost — di-proxy nginx, jangan expose langsung.
- Session key Hermes: `{phone_number_id}:{customer_phone}` (satu chat per nomor bisnis).
- Hanya nomor di `KIRIMDEV_ENABLED_NUMBERS` yang dioperasikan agent; nomor lain tetap jalan di dashboard Kirimdev.

---

## Quick start (local)

Prasyarat: Hermes v0.14+, akun Kirimdev, nomor WA Cloud API terhubung.

```bash
git clone https://github.com/kirimdev/kirimdev-hermes.git
cp -r kirimdev-hermes/kirimdev-platform ~/.hermes/plugins/kirimdev-platform
hermes plugins enable kirimdev-platform

pip install aiohttp httpx   # di env Hermes

hermes config set KIRIMDEV_API_KEY kdv_live_xxx
hermes config set KIRIMDEV_ENABLED_NUMBERS <phone_number_id>
hermes config set KIRIMDEV_DEFAULT_PHONE_NUMBER_ID <phone_number_id>
hermes config set KIRIMDEV_OWNER_USERS 628123456789
hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxx

hermes gateway restart
curl -s http://127.0.0.1:8646/health
# {"status":"ok","platform":"kirimdev","channel":"whatsapp"}
```

Template env: [.env.example](.env.example)

---

## Konfigurasi environment

Set via `hermes config set NAMA nilai` (disimpan di `~/.hermes/.env`).

> **Nomor telepon:** digits saja, tanpa `+` — contoh `628123456789`.  
> **`phone_number_id`:** Meta business phone number ID dari Kirimdev (Settings → nomor WA), bukan nomor telepon bisnis.

### Wajib (production)

| Variable | Contoh | Deskripsi |
|----------|--------|-----------|
| `KIRIMDEV_API_KEY` | `kdv_live_…` | API key dari [Dashboard → API Keys](https://app.kirimdev.com/settings/api-keys) |
| `KIRIMDEV_WEBHOOK_SECRETS` | `whsec_…` | Secret dari webhook subscription. Comma-separated saat rotasi. Alias: `KIRIMDEV_WEBHOOK_SECRET` |
| `KIRIMDEV_ENABLED_NUMBERS` | `123456789012345` | Comma-separated `phone_number_id` yang dioperasikan agent |

### Disarankan

| Variable | Deskripsi |
|----------|-----------|
| `KIRIMDEV_DEFAULT_PHONE_NUMBER_ID` | Default sender untuk cron / CLI (biasanya sama dengan entry di `ENABLED_NUMBERS`) |
| `KIRIMDEV_PUBLIC_URL` | `https://domain` tanpa `/webhook` |
| `KIRIMDEV_OWNER_USERS` | Nomor owner (comma-separated) — full access |

### Authorization

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `KIRIMDEV_ALLOWED_USERS` | *(kosong)* | Whitelist customer tier `allowed` |
| `KIRIMDEV_ALLOW_ALL_USERS` | `false` | Dev only — terima inbound dari semua nomor di enabled numbers |
| `KIRIMDEV_OWNER_FULL_AGENT` | `true` | `false` = owner hanya tools `kirimdev_*`, tanpa terminal/web Hermes |

### Jaringan & rate limit

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `KIRIMDEV_HOST` | `0.0.0.0` | Bind address |
| `KIRIMDEV_PORT` | `8646` | Port lokal webhook server |
| `KIRIMDEV_RATE_LIMIT_PER_MIN` | `15` | Cap inbound per customer |

### Human handoff (v1.1+)

Pause agent saat staff kirim dari dashboard Kirimdev atau echo app HP.

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `KIRIMDEV_HUMAN_HANDOFF_SECONDS` | `900` | Durasi pause (detik). `0` = off. Butuh webhook `message.sent` |

### Media & suara (v1.1+)

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `KIRIMDEV_VOICE_TRANSCRIBE` | `false` | `true` = transkrip Whisper dari `kirim.media_url` |
| `OPENAI_API_KEY` | — | Wajib jika voice transcribe aktif |

### API & channel

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `KIRIMDEV_API_BASE_URL` | `https://api.kirimdev.com/v1` | Dev lokal: `http://localhost:3000/v1` |
| `KIRIMDEV_DEFAULT_CHANNEL` | `whatsapp` | Saat ini hanya `whatsapp` |
| `KIRIMDEV_HOME_CHANNEL` | — | Target cron: `{phone_number_id}:{customer}` atau digits saja |

### File persisten

| Variable | Default |
|----------|---------|
| `KIRIMDEV_GRANTS_FILE` | `~/.hermes/kirimdev_grants.json` |
| `KIRIMDEV_PENDING_FILE` | `~/.hermes/kirimdev_pending.json` |

> Catatan: grant/pending file saat ini **tidak aktif** dipakai — fitur Approve/Deny tier `granted` belum tersedia. Lihat [Authorization tier](#authorization-tier).

### Testing only

| Variable | Deskripsi |
|----------|-----------|
| `INSECURE_NO_AUTH` | Set sebagai **nilai** di `KIRIMDEV_WEBHOOK_SECRETS` untuk skip signature — **jangan production** |

### Contoh lengkap

```bash
# Minimal production
hermes config set KIRIMDEV_API_KEY kdv_live_xxxxxxxx
hermes config set KIRIMDEV_ENABLED_NUMBERS 123456789012345
hermes config set KIRIMDEV_DEFAULT_PHONE_NUMBER_ID 123456789012345
hermes config set KIRIMDEV_OWNER_USERS 628123456789
hermes config set KIRIMDEV_PUBLIC_URL https://hermes-webhooks.domain.com
hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxxxxxxx

# Opsional v1.1+
hermes config set KIRIMDEV_HUMAN_HANDOFF_SECONDS 900
hermes config set KIRIMDEV_VOICE_TRANSCRIBE true
hermes config set OPENAI_API_KEY sk-...
```

---

## Authorization tier

| Tier | Sumber | Agent auto-reply? | Tools |
|------|--------|-------------------|-------|
| `owner` | `KIRIMDEV_OWNER_USERS` | ✅ | Full Hermes + `kirimdev_*` |
| `allowed` | `KIRIMDEV_ALLOWED_USERS` | ✅ | Text + reply (button, list, image, …) |
| `unknown` | Lainnya | ❌ | — |

> Tier `granted` (approve via tombol di WA) **belum tersedia**. Saat ini pesan dari nomor di luar `KIRIMDEV_OWNER_USERS` / `KIRIMDEV_ALLOWED_USERS` tidak dibalas agent.

Testing pertama: masukkan nomor WA kamu ke `KIRIMDEV_OWNER_USERS`, kirim pesan ke nomor bisnis → agent harus balas.

---

## Panduan deploy production

Contoh domain: `hermes-webhooks.domain.com`  
Webhook URL: `https://hermes-webhooks.domain.com/webhook`

### Prasyarat

| Item | Keterangan |
|------|------------|
| VPS | Ubuntu 22.04+ |
| Domain | Subdomain + A record → IP VPS |
| Kirimdev | Akun + nomor WA Cloud API |
| Hermes | v0.14+ + LLM provider configured |
| `phone_number_id` | Dari Kirimdev Settings → nomor WA |

### Step 1 — Install Hermes

```bash
which hermes && hermes --version && hermes doctor
```

Setup LLM (`hermes login`, `~/.hermes/.env`, dll.).

### Step 2 — Install plugin

```bash
git clone https://github.com/kirimdev/kirimdev-hermes.git
cp -r kirimdev-hermes/kirimdev-platform ~/.hermes/plugins/kirimdev-platform
hermes plugins enable kirimdev-platform
~/.hermes/hermes-agent/venv/bin/pip install aiohttp httpx
```

### Step 3 — Konfigurasi

Lihat [Konfigurasi environment](#konfigurasi-environment). Webhook secret diisi **setelah** Step 9.

### Step 4 — DNS

| Type | Name | Content |
|------|------|---------|
| A | `hermes-webhooks` | IP VPS |

```bash
dig @8.8.8.8 hermes-webhooks.domain.com +short
```

Harus resolve sebelum daftar webhook Kirimdev.

### Step 5 — nginx (HTTP dulu)

```bash
sudo apt install -y nginx
sudo ufw allow 'Nginx Full'
sudo nano /etc/nginx/sites-available/hermes-webhook
```

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

```bash
sudo ln -sf /etc/nginx/sites-available/hermes-webhook /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

> Jangan tambah block `listen 443` manual — certbot yang menambah HTTPS (Step 7).

### Step 6 — Jalankan gateway

```bash
hermes gateway restart
curl -s http://127.0.0.1:8646/health
```

### Step 7 — SSL (certbot)

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d hermes-webhooks.domain.com
curl -s https://hermes-webhooks.domain.com/health
```

> `curl https://domain/` → Empty reply normal. Test `/health` atau `/webhook`.

### Step 8 — systemd (background)

```bash
which hermes
mkdir -p ~/.config/systemd/user
cp deploy/hermes-gateway.service ~/.config/systemd/user/
# Edit ExecStart = path dari `which hermes`

loginctl enable-linger $USER
systemctl --user daemon-reload
systemctl --user enable --now hermes-gateway
tail -f ~/.hermes/gateway.log
```

### Step 9 — Webhook subscription

Subscribe **`message.received`** dan **`message.sent`** (wajib v1.1+ untuk handoff + echo guard).

```bash
export KIRIMDEV_API_KEY=kdv_live_xxx

curl -s -X POST https://api.kirimdev.com/v1/webhook_subscriptions \
  -H "Authorization: Bearer $KIRIMDEV_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://hermes-webhooks.domain.com/webhook",
    "events": ["message.received", "message.sent"]
  }'
```

Simpan `initial_secret` → `hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxx` → restart gateway.

Atau via Kirimdev Dashboard → Settings → Webhooks.

### Step 10 — Authorization

Lihat [Authorization tier](#authorization-tier). Set minimal `KIRIMDEV_OWNER_USERS`.

### Step 11 — Verifikasi

```bash
curl -s https://hermes-webhooks.domain.com/health
hermes plugins list
hermes config get KIRIMDEV_ENABLED_NUMBERS
tail -f ~/.hermes/gateway.log | grep -i kirimdev
```

Log sukses: `Kirimdev inbound: pid=... phone=628xxx ...`

### Cloudflare

| Mode | Catatan |
|------|---------|
| Full (strict) | Recommended setelah certbot |
| Flexible | CF→origin HTTP — pastikan nginx `:80` aktif |

### CLI — kirim manual

```bash
hermes send --to kirimdev:123456789012345:628123456789 "Halo dari Hermes"
```

---

## Webhook Kirimdev

| URL | Fungsi |
|-----|--------|
| `https://<domain>/webhook` | Daftar di Kirimdev subscription |
| `https://<domain>/health` | Health check publik |
| `http://127.0.0.1:8646` | Backend internal (jangan expose) |

| Event | Fungsi |
|-------|--------|
| `message.received` | Pesan masuk customer → agent |
| `message.sent` | Echo guard + human handoff (dashboard/app) |

Header verifikasi: `X-Kirim-Signature: t=<ts>,v1=<hex>`

---

## Fitur inbound (v1.1+)

| Tipe | Perilaku |
|------|----------|
| Teks | Standar |
| Interactive / button reply | Title/id diteruskan sebagai teks ke agent |
| Gambar | Caption + `kirim.media_url` saat `media_status=ready` |
| Audio / voice | Transkrip opsional (`KIRIMDEV_VOICE_TRANSCRIBE` + `OPENAI_API_KEY`) |

Tools outbound (`kirimdev_*`): send text, buttons, list, image, template, broadcast, dll. — tier-gated.

---

## Verifikasi & troubleshooting

| Gejala | Fix |
|--------|-----|
| `ENOTFOUND` buat webhook | DNS belum resolve — cek A record |
| `curl :8646/health` kosong | `hermes plugins enable kirimdev-platform`, set API key + secret |
| 401 webhook | `KIRIMDEV_WEBHOOK_SECRETS` salah |
| Pesan masuk, tidak balas | Tier `unknown` — set `KIRIMDEV_OWNER_USERS` atau `ALLOWED_USERS` |
| `phone_number_id not enabled` | Cek `KIRIMDEV_ENABLED_NUMBERS` |
| Agent balas padahal staff sudah chat di dashboard | Subscribe `message.sent`; cek `KIRIMDEV_HUMAN_HANDOFF_SECONDS` |
| Voice tidak diproses | `KIRIMDEV_VOICE_TRANSCRIBE=true` + `OPENAI_API_KEY` |
| 502 nginx | `systemctl --user restart hermes-gateway` |
| Gateway restart loop | `which hermes` → update `ExecStart` di systemd unit |
| `hermes plugin enable` error | Pakai `hermes plugins enable` (jamak) |

---

## Development & testing

```bash
cd kirimdev-platform
pip install aiohttp httpx pytest
python -m pytest tests/ -v
```

API Kirimdev lokal:

```bash
hermes config set KIRIMDEV_API_BASE_URL http://localhost:3000/v1
```

---

## Struktur repo

```
kirimdev-platform/          # Source plugin Hermes
  adapter.py                  # Webhook + dispatch
  tools.py                    # kirimdev_* tools
  meta.py                     # Signature + payload parse
  plugin.yaml                 # Manifest (env schema untuk hermes setup)
  tests/
deploy/
  hermes-gateway.service      # systemd user unit template
.env.example                  # Template konfigurasi
CHANGELOG.md
```

---

## License

MIT — [LICENSE](LICENSE)

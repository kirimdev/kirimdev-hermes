# Kirimdev Platform Plugin for Hermes Agent

Plugin gateway yang menerima webhook Kirimdev (WhatsApp Meta pass-through) dan mengirim balasan via `POST /v1/{phone_number_id}/messages`.

> **Deploy production:** ikuti **[../deploy/DEPLOY.md](../deploy/DEPLOY.md)** — panduan lengkap DNS → nginx → SSL → systemd → webhook → authorization.

## Fitur

- WhatsApp only (Kirimdev Public API)
- Verifikasi `X-Kirim-Signature` (`t=...,v1=...`)
- Allowlist nomor bisnis: `KIRIMDEV_ENABLED_NUMBERS`
- Session key: `{phone_number_id}:{customer_phone}`
- Tier authorization: owner / allowed / granted / unknown + approval flow

## Install plugin

```bash
cp -r kirimdev-platform ~/.hermes/plugins/kirimdev-platform
hermes plugins enable kirimdev-platform
pip install aiohttp httpx   # di env Hermes
```

## Environment variables

| Variable | Wajib | Deskripsi |
|----------|-------|-----------|
| `KIRIMDEV_API_KEY` | ✅ | `kdv_live_*` |
| `KIRIMDEV_WEBHOOK_SECRETS` | ✅ | `whsec_*` (comma-separated saat rotasi) |
| `KIRIMDEV_ENABLED_NUMBERS` | ✅ | Meta `phone_number_id` allowlist |
| `KIRIMDEV_DEFAULT_PHONE_NUMBER_ID` | disarankan | Default sender |
| `KIRIMDEV_PUBLIC_URL` | disarankan | `https://domain` (tanpa `/webhook`) |
| `KIRIMDEV_OWNER_USERS` | disarankan | Nomor owner (no `+`) |
| `KIRIMDEV_ALLOWED_USERS` | opsional | Whitelist customer |
| `KIRIMDEV_PORT` | opsional | Default `8646` |
| `KIRIMDEV_API_BASE_URL` | opsional | Default `https://api.kirimdev.com/v1` |

```bash
hermes setup kirimdev
# atau set manual — lihat DEPLOY.md Step 3 & 10
```

## Webhook URL

```
https://<domain>/webhook
```

Event: `message.received`

## Health check

```bash
curl -s http://127.0.0.1:8646/health
# {"status":"ok","platform":"kirimdev","channel":"whatsapp"}
```

## Authorization tiers

| Tier | Siapa | Balasan otomatis | Tools |
|------|-------|------------------|-------|
| owner | `KIRIMDEV_OWNER_USERS` | ✅ | Full Hermes agent + semua `kirimdev_*` |
| allowed | `KIRIMDEV_ALLOWED_USERS` | ✅ | Text + reply tools (chat ini saja) |
| granted | Owner approve via WA button | ✅ (24 jam) | Text only |
| unknown | Lainnya | ❌ pending approval | — |

Set `KIRIMDEV_OWNER_FULL_AGENT=false` to limit owners to `kirimdev_*` tools only.

## CLI send

```bash
hermes send --to kirimdev:123456789012345:628123456789 "Halo"
```

## Local dev (Kirimdev API di localhost)

```bash
hermes config set KIRIMDEV_API_BASE_URL http://localhost:3000/v1
```

## Tests

```bash
cd kirimdev-platform
python -m pytest tests/ -v
```

## License

MIT

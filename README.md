# Hermes Kirimdev Platform Plugin

Gateway plugin yang menghubungkan [Kirimdev](https://kirimdev.com) WhatsApp Cloud API ke [Hermes Agent](https://hermes-agent.nousresearch.com).

```
WhatsApp → Kirimdev → webhook HTTPS → Hermes Agent → balasan via Kirimdev API
```

## Dokumentasi

| Doc | Isi |
|-----|-----|
| **[deploy/DEPLOY.md](deploy/DEPLOY.md)** | **Panduan deploy production lengkap** (DNS, nginx, SSL, systemd, webhook, authorization) |
| [kirimdev-platform/README.md](kirimdev-platform/README.md) | Referensi plugin, env vars, dev local |
| [CHANGELOG.md](CHANGELOG.md) | Riwayat versi plugin |

## Quick start (setelah Hermes terinstall)

```bash
cp -r kirimdev-platform ~/.hermes/plugins/kirimdev-platform
hermes plugins enable kirimdev-platform

hermes config set KIRIMDEV_API_KEY kdv_live_xxx
hermes config set KIRIMDEV_WEBHOOK_SECRETS whsec_xxx
hermes config set KIRIMDEV_ENABLED_NUMBERS <phone_number_id>
hermes config set KIRIMDEV_OWNER_USERS 628123456789
hermes config set KIRIMDEV_PUBLIC_URL https://hermes-webhooks.domain.com

systemctl --user restart hermes-gateway   # lihat DEPLOY.md untuk setup systemd
curl -s http://127.0.0.1:8646/health
```

Webhook URL untuk Kirimdev:

```
https://<domain-kamu>/webhook
```

## Layout

```
kirimdev-platform/     # Plugin Hermes (adapter, tools, meta parser)
deploy/
├── DEPLOY.md              # Tutorial deploy (nginx config ada di sini)
└── hermes-gateway.service
```

## Repository

https://github.com/kirimdev/kirimdev-hermes

## License

MIT — see [LICENSE](LICENSE)

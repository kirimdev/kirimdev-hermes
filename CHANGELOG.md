# Changelog

All notable changes to the Kirimdev Hermes platform plugin are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers match `kirimdev-platform/plugin.yaml`.

## [1.1.0] — 2026-06-15

### Added

- **Customer button/list replies** — interactive and legacy button inbound messages are forwarded to the agent as text (owner approval buttons unchanged).
- **Inbound images** — uses Kirimdev `kirim.media_url` enrichment when `media_status=ready`; caption forwarded when present.
- **`message.sent` webhook** — records outbound `provider_id` for echo prevention; **human handoff** pauses the agent after dashboard or phone-app (`source: app`) sends (`KIRIMDEV_HUMAN_HANDOFF_SECONDS`, default 900).
- **Voice inbound** — optional Whisper transcription via `KIRIMDEV_VOICE_TRANSCRIBE=true` + `OPENAI_API_KEY`.

### Changed

- Webhook subscription should include **`message.received`** and **`message.sent`** (see `deploy/DEPLOY.md`).

## [1.0.0] — 2026-06-15

First public release.

### Added

- **Kirimdev platform plugin** for [Hermes Agent](https://hermes-agent.nousresearch.com): aiohttp webhook server, `X-Kirim-Signature` verification, Meta pass-through payload parsing.
- **Tier authorization** — owner / allowed / granted / unknown with owner approval buttons and JSON-backed grants (`~/.hermes/kirimdev_grants.json`).
- **Session key** `{phone_number_id}:{customer_phone}` and `KIRIMDEV_ENABLED_NUMBERS` business-number allowlist.
- **`kirimdev_*` tools** — send text, buttons, CTA URL, list, image, carousel, template, broadcast helpers, grant management; tools register under the `kirimdev` toolset (`hermes-kirimdev` composite).
- **`KIRIMDEV_OWNER_FULL_AGENT`** (default `true`) — owners get the full Hermes agent plus all `kirimdev_*` tools; set `false` to limit owners to Kirimdev tools only.
- **`pre_tool_call_tier_gate`** — runtime tool access by tier (owner / allowed / granted).
- **Template tools** — `list_templates` and `get_template` with lowercase status filter and `template_name` lookup.
- **WhatsApp typing indicator** while the agent is thinking (read receipt + `typing_indicator`, per-chat throttle, 429 backoff).
- Production deploy guide (`deploy/DEPLOY.md`) and systemd unit template.
- Unit and security tests (`pytest`).

### Notes

- Typing indicator requires a Kirimdev API build that forwards typing on already-read inbound messages.

[1.1.0]: https://github.com/kirimdev/kirimdev-hermes/releases/tag/v1.1.0
[1.0.0]: https://github.com/kirimdev/kirimdev-hermes/releases/tag/v1.0.0

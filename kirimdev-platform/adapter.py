"""
Kirimdev platform adapter for Hermes Agent.

A gateway platform plugin that runs an aiohttp webhook server, accepts
Kirimdev webhook deliveries (``X-Kirim-Signature`` verified), and relays
messages to/from the Hermes agent via the standard ``BasePlatformAdapter``
interface. Outbound replies use the Kirimdev Public API
(``POST /v1/{phone_number_id}/messages``).

Design notes
------------

**Composite chat_id.** Kirimdev orgs may connect multiple WhatsApp numbers.
We use ``{phone_number_id}:{customer_phone}`` as chat_id so each customer
per business line gets an isolated Hermes session.

**Loop prevention.** Primary guard is ``direction == "inbound"`` on the
webhook payload. Secondary is a recent outbound message_id set (LRU 1000)
filtered on every inbound (populated from agent sends and ``message.sent``
``provider_id``). Tertiary is human-handoff after dashboard / phone-app
outbound (``message.sent`` with ``source`` dashboard or app). Quaternary
is an event_type allowlist (``message.received`` + ``message.sent``).

**Idempotency.** Kirimdev retries deliveries on timeout. We dedupe via
``X-Kirim-Event-Id`` with a 1h TTL in-memory cache, pruned on each request.

**Rate limit per phone.** Token bucket (default 15/min) prevents a single
customer from exhausting the gateway. Excess returns 200 OK silently
(no upstream retry storm).

**24h WhatsApp window.** Detected via 4xx response from Kirimdev
``/messages/send``; we log a warning and return SendResult(success=False).
Template fallback is future work.

**Smart chunking.** WhatsApp text bubble cap is 4096 chars. Long agent
responses are split at newline boundaries near the 4000-char mark and
sent sequentially with a 500ms delay between bubbles.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

try:
    from .meta import (
        APPROVE_PREFIX,
        DENY_PREFIX,
        extract_button_reply,
        format_e164,
        make_chat_id,
        normalize_template_list_status,
        parse_chat_id,
        parse_meta_inbound,
        parse_message_sent,
        verify_kirim_signature,
    )
except ImportError:  # pragma: no cover — pytest imports adapter as top-level
    from meta import (
        APPROVE_PREFIX,
        DENY_PREFIX,
        extract_button_reply,
        format_e164,
        make_chat_id,
        normalize_template_list_status,
        parse_chat_id,
        parse_meta_inbound,
        parse_message_sent,
        verify_kirim_signature,
    )

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Module-level constants
# --------------------------------------------------------------------------

DEFAULT_API_BASE = "https://api.kirimdev.com/v1"
DEFAULT_PORT = 8646
DEFAULT_HOST = "0.0.0.0"
DEFAULT_CHANNEL = "whatsapp"
DEFAULT_RATE_LIMIT = 15  # messages per minute per sender

# Sender tiers — drives which tools the agent is allowed to invoke and how
# the platform_hint reads to the LLM. Ordered from highest to lowest trust.
TIER_OWNER = "owner"
TIER_ALLOWED = "allowed"
TIER_GRANTED = "granted"
TIER_UNKNOWN = "unknown"

WEBHOOK_PATH = "/webhook"
HEALTH_PATH = "/health"

IDEMPOTENCY_TTL_SECONDS = 3600
SENT_ID_CACHE_SIZE = 1000

WA_MAX_BUBBLE_CHARS = 4096
WA_SAFE_CHUNK_CHARS = 4000
WA_INTER_CHUNK_DELAY_SECONDS = 0.5

HTTP_CONNECT_TIMEOUT = 10.0
HTTP_TOTAL_TIMEOUT = 30.0
SEND_RETRY_DELAYS = (1.0, 4.0, 16.0)  # exponential backoff

# Typing indicator throttle — Kirimdev caps at 1 req per customer per 3 sec.
# We pick 3.5s to leave headroom for clock skew.
TYPING_MIN_INTERVAL_SECONDS = 3.5
# Short timeout for typing calls — base loop is on a 2s cadence and will skip
# this tick if we don't return fast enough.
TYPING_HTTP_TIMEOUT = 2.5
# Same idea for mark-as-read — best-effort, never block the message path.
READ_RECEIPT_HTTP_TIMEOUT = 3.0

# How long a denied sender stays muted (in-memory only). Prevents spam
# notifications to the owner if the same unknown sender keeps trying.
DENIED_BLACKLIST_SECONDS = 3600  # 1 hour

# Default TTL for owner-Approve grants.
APPROVAL_GRANT_TTL_HOURS = 24.0

# Max concurrent pending approvals — exceeds this and we silently drop
# (anti-flood). Counts active pending entries, not lifetime.
MAX_PENDING_APPROVALS = 20

# Bounds on the per-chat in-memory caches. These keep adapter memory
# usage flat regardless of total customers seen over the gateway's
# lifetime; once the cap is reached we evict the oldest entry (LRU
# by insertion order — OrderedDict).
TIER_CACHE_MAX_SIZE = 5000
TYPING_STATE_MAX_SIZE = 5000
DENIED_BLACKLIST_MAX_SIZE = 5000

# Extra backoff when Meta/Kirimdev returns 429 on typing (rate limit).
TYPING_429_BACKOFF_SECONDS = 5.0

ALLOWED_EVENT_TYPES = {"message.received", "message.sent"}
ALLOWED_CHANNELS = {"whatsapp"}

# Inbound types forwarded to the agent as text (button/list replies included).
INBOUND_TEXT_ALIASES = frozenset({"text", "interactive", "button"})
INBOUND_VOICE_TYPES = frozenset({"audio", "voice"})

# After a human sends from dashboard or phone-app echo, pause the agent.
DEFAULT_HUMAN_HANDOFF_SECONDS = 900
HUMAN_HANDOFF_MAX_SIZE = 5000
VOICE_TRANSCRIBE_TIMEOUT = 45.0

MAX_BODY_BYTES = 100 * 1024  # 100KB
PHONE_RE = re.compile(r"^\+?\d{8,15}$")
API_KEY_REDACT_RE = re.compile(r"kdv_(live|test)_[A-Za-z0-9_]+")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def normalize_phone(phone: str) -> str:
    """Return international phone digits only (no plus, spaces, dashes)."""
    if not phone:
        return ""
    digits = re.sub(r"\D", "", phone)
    return digits


def redact_phone(phone: str) -> str:
    """Mask phone number for logs: 6281234**6789."""
    if not phone:
        return ""
    p = normalize_phone(phone)
    if len(p) <= 8:
        return "***" + p[-2:] if len(p) >= 2 else "***"
    return p[:4] + "***" + p[-4:]


def redact_api_key(text: str) -> str:
    """Replace any kdv_live_ / kdv_test_ secrets with kdv_***."""
    return API_KEY_REDACT_RE.sub("kdv_***", text or "")


# Broader secret patterns picked up from real-world error message leaks
# in upstream HTTP exceptions. Order matters: more specific patterns first
# so substring matches don't eat the wider ones.
_BEARER_RE = re.compile(
    r"(Bearer\s+)[A-Za-z0-9._\-+/=]{8,}",
    re.IGNORECASE,
)
_COOKIE_VAL_RE = re.compile(
    r"((?:^|\s|;)(?:[Cc]ookie:?\s*[\w-]+|session|sid|token)\s*=\s*)[^;\s,]+",
)
_URL_TOKEN_QUERY_RE = re.compile(
    r"([?&](?:access_token|api[_-]?key|auth[_-]?token|token|signature|sig|key)=)[^&#\s]+",
    re.IGNORECASE,
)
_GENERIC_SECRET_ASSIGN_RE = re.compile(
    r"\b(access_token|api[_-]?key|auth[_-]?token|signature)\s*=\s*([A-Za-z0-9._\-+/=]{4,})",
    re.IGNORECASE,
)


# Marker used to inject the resolved tier into the LLM-visible turn text.
# We strip any literal occurrences from inbound content before adding our
# own annotation so customers can't forge a fake [tier=owner] marker.
_TIER_MARKER_RE = re.compile(r"\[tier=[^\]]*\]?", re.IGNORECASE)


def _sanitize_inbound_content(content: str) -> str:
    """Strip prompt-injection vectors from inbound customer text.

    Today this means removing any literal ``[tier=...]`` substrings so
    a customer can't forge an authorization marker the LLM might
    misread. Leading close-brackets that could escape our own bracket
    are also dropped.
    """
    if not content:
        return ""
    s = _TIER_MARKER_RE.sub("", content)
    # Drop the dangling close-bracket pattern that could close our
    # ``[tier=granted]`` prefix prematurely.
    while s.startswith("]"):
        s = s[1:].lstrip()
    return s


# Cap inbound display names. WhatsApp profile names can be arbitrarily
# long and contain control characters; clamp to a sensible width so an
# attacker can't smuggle multi-line social engineering into the owner
# approval prompt.
_NAME_MAX_LEN = 80
_NAME_BAD_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")  # C0 + DEL


def _sanitize_customer_name(name: str) -> str:
    """Strip control characters from a customer display name and cap length."""
    if not name:
        return ""
    s = _NAME_BAD_CHARS_RE.sub(" ", name)
    s = " ".join(s.split())  # collapse whitespace runs
    if len(s) > _NAME_MAX_LEN:
        s = s[: _NAME_MAX_LEN - 1] + "…"
    return s


def _redact_sensitive_text(text: str) -> str:
    """Redact secrets from arbitrary text before logging.

    Covers:
    - Kirimdev keys (kdv_live_*, kdv_test_*) via redact_api_key
    - Bearer tokens in Authorization headers
    - Cookie / session / sid / token assignments
    - URL query-string secrets (access_token, api_key, etc.)
    - Bare assignments like access_token=XYZ in error bodies

    This is the version that should wrap any caught exception's
    ``str(exc)`` before logging — upstream libraries don't sanitise
    their own error messages.
    """
    if not text:
        return ""
    s = redact_api_key(text)
    s = _BEARER_RE.sub(r"\1***", s)
    s = _COOKIE_VAL_RE.sub(r"\1***", s)
    s = _URL_TOKEN_QUERY_RE.sub(r"\1***", s)
    s = _GENERIC_SECRET_ASSIGN_RE.sub(r"\1=***", s)
    return s


# Meta/WhatsApp error codes that Kirimdev surfaces as HTTP 5xx but are
# actually permanent — retrying them does nothing. See:
# https://developers.facebook.com/docs/whatsapp/cloud-api/support/error-codes
PERMANENT_META_ERROR_CODES = frozenset({
    131000,  # Generic user error
    131005,  # Access denied
    131008,  # Required parameter missing
    131009,  # Parameter value not valid
    131016,  # Service unavailable for this account
    131021,  # Recipient cannot be sender
    131026,  # Message undeliverable (24h window expired, etc.)
    131031,  # Account locked
    131037,  # Display name approval pending
    131042,  # Business eligibility payment issue
    131045,  # Sender not registered
    131047,  # Re-engagement message required (24h window)
    131048,  # Spam rate limit hit
    131051,  # Unsupported message type
    131052,  # Media download error
    131053,  # Media upload error
    131056,  # Pair rate limit
    132000,  # Template parameter mismatch
    132001,  # Template does not exist
    132005,  # Template hydration failed
    132007,  # Template format character policy violated
    132012,  # Template parameter format mismatch
    132015,  # Template paused due to low quality
    132016,  # Template disabled
    132068,  # Flow blocked
    132069,  # Flow throttled
    133000,  # Generic deletion error
    133004,  # Server temporarily unavailable
    133005,  # Two-step verification PIN mismatch
    133006,  # Phone number re-verification needed
    133008,  # Too many 2FA PIN guesses
    133009,  # 2FA PIN guessed too quickly
    133010,  # Phone number not registered
    133012,  # Phone number not yet registered
})


def _is_permanent_kirimdev_error(body_text: str) -> bool:
    """Detect if a Kirimdev 5xx response is actually a permanent failure.

    Some Meta WhatsApp errors are returned by Kirimdev as HTTP 500 even
    though they will never succeed on retry (e.g. display name approval
    pending, 24h window expired, template missing). Returns True if the
    body contains one of those error codes.
    """
    if not body_text:
        return False
    # Try JSON first
    try:
        body = json.loads(body_text) if isinstance(body_text, str) else body_text
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            code = err.get("code")
            if isinstance(code, int) and code in PERMANENT_META_ERROR_CODES:
                return True
            # Sometimes code is a string
            if isinstance(code, str) and code.isdigit() and int(code) in PERMANENT_META_ERROR_CODES:
                return True
    except (json.JSONDecodeError, AttributeError, ValueError):
        pass
    # Regex fallback: "code":131037 anywhere in the snippet
    m = re.search(r'"code"\s*:\s*(\d{6})', body_text)
    if m and int(m.group(1)) in PERMANENT_META_ERROR_CODES:
        return True
    return False


def _is_inbound_text_type(message_type: str) -> bool:
    return (message_type or "text").lower() in INBOUND_TEXT_ALIASES


def _extract_kirim_media(
    data: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    kirim = data.get("kirim")
    if not isinstance(kirim, dict):
        return None, None
    media_url = kirim.get("media_url")
    media_status = kirim.get("media_status")
    url = str(media_url).strip() if media_url else None
    status = str(media_status).strip().lower() if media_status else None
    return url or None, status or None


def _extract_button_reply(data: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Pull the button id + title out of an inbound interactive payload.

    Kirimdev's webhook for an interactive reply looks like:

        {
          "message_type": "interactive",
          "content": "<title>",                 # button title, not id
          "raw": {
            "message": {
              "interactive": {
                "type": "button_reply",
                "button_reply": {"id": "...", "title": "..."}
              }
            }
          }
        }

    The id-carrying object lives inside ``data.raw.message.interactive``
    (raw Meta passthrough). We dig that out first. Fallbacks cover
    older/alternative shapes seen in other brokers.

    Returns ``(id, title)`` or ``(None, None)`` if no button reply
    was detected.
    """
    if not isinstance(data, dict):
        return None, None

    # Primary path: Kirimdev puts the Meta-shape interactive inside data.raw.message
    raw = data.get("raw")
    if isinstance(raw, dict):
        msg = raw.get("message")
        if isinstance(msg, dict):
            interactive = msg.get("interactive") or {}
            if isinstance(interactive, dict):
                btn = interactive.get("button_reply") or {}
                if isinstance(btn, dict) and btn.get("id"):
                    return str(btn.get("id")), str(btn.get("title") or "")
                lst = interactive.get("list_reply") or {}
                if isinstance(lst, dict) and lst.get("id"):
                    return str(lst.get("id")), str(lst.get("title") or "")

    # Secondary path: interactive nested directly under data (older shape).
    interactive = data.get("interactive")
    if isinstance(interactive, dict):
        btn = interactive.get("button_reply") or {}
        if isinstance(btn, dict) and btn.get("id"):
            return str(btn.get("id")), str(btn.get("title") or "")
        lst = interactive.get("list_reply") or {}
        if isinstance(lst, dict) and lst.get("id"):
            return str(lst.get("id")), str(lst.get("title") or "")
        # Some brokers flatten:
        if interactive.get("id"):
            return str(interactive["id"]), str(interactive.get("title") or "")

    # Tertiary: message_type tells us it's a button reply with id at top level.
    mtype = (data.get("message_type") or "").lower()
    if mtype in ("button_reply", "interactive_response", "interactive_reply"):
        bid = (
            data.get("button_id")
            or data.get("id")
            or (data.get("interactive_response") or {}).get("id")
        )
        if bid:
            return str(bid), str(data.get("button_title") or data.get("title") or "")

    # Last-ditch fallback: content is exactly a known control id.
    content = (data.get("content") or "").strip()
    if content.startswith(("kd_approve:", "kd_deny:")):
        return content, ""

    return None, None


def smart_chunk_for_whatsapp(text: str, limit: int = WA_SAFE_CHUNK_CHARS) -> List[str]:
    """Split long text at newline boundaries near ``limit`` chars.

    Falls back to hard split at ``limit`` for words longer than ``limit``.

    For inputs that are dominated by whitespace the smart .rstrip /
    .lstrip cleanup would erase the whole content; in that case we
    fall back to a verbatim hard split so we never silently drop
    customer text (data-loss bug).
    """
    if not text:
        return [""]
    if len(text) <= limit:
        return [text]
    chunks: List[str] = []
    remaining = text
    while len(remaining) > limit:
        # Prefer break at last newline before limit, else last space, else hard cut.
        cut = remaining.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = remaining.rfind(" ", 0, limit)
        if cut < limit // 2:
            cut = limit
        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    if remaining:
        chunks.append(remaining)

    # Detect the whitespace-only data-loss case: if the input had visible
    # length but all our chunks ended up empty after the strip/lstrip,
    # fall back to a hard verbatim split so we don't lose content.
    joined_len = sum(len(c) for c in chunks)
    if text.strip() == "" and joined_len < len(text) // 2:
        # Pure whitespace input — preserve verbatim in hard slices.
        return [text[i : i + limit] for i in range(0, len(text), limit)]
    if joined_len == 0 and text:
        return [text[i : i + limit] for i in range(0, len(text), limit)]
    return chunks


# --------------------------------------------------------------------------
# Rate limiter (token bucket per phone)
# --------------------------------------------------------------------------


class _TokenBucket:
    """Simple per-key token bucket with refill on access."""

    __slots__ = ("capacity", "refill_per_sec", "_state", "_lock")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._state: Dict[str, Tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1.0, now)
            return True


# --------------------------------------------------------------------------
# Idempotency cache (in-memory, 1h TTL)
# --------------------------------------------------------------------------


class _IdempotencyCache:
    __slots__ = ("_entries", "_ttl")

    def __init__(self, ttl_seconds: int = IDEMPOTENCY_TTL_SECONDS) -> None:
        self._entries: Dict[str, float] = {}
        self._ttl = ttl_seconds

    def seen_or_record(self, key: str) -> bool:
        """Return True if ``key`` was seen recently; otherwise record and return False."""
        if not key:
            return False
        now = time.monotonic()
        # Sliding prune
        expired = [k for k, t in self._entries.items() if now - t > self._ttl]
        for k in expired:
            self._entries.pop(k, None)
        if key in self._entries:
            return True
        self._entries[key] = now
        return False


# --------------------------------------------------------------------------
# Plugin gate helpers (module-level — used by register())
# --------------------------------------------------------------------------


def check_requirements() -> bool:
    """Plugin gate: require credentials AND runtime deps."""
    if not os.getenv("KIRIMDEV_API_KEY"):
        return False
    if not (
        os.getenv("KIRIMDEV_WEBHOOK_SECRETS")
        or os.getenv("KIRIMDEV_WEBHOOK_SECRET")
    ):
        return False
    try:
        import aiohttp  # noqa: F401
        import httpx  # noqa: F401
    except ImportError:
        return False
    return True


def validate_config(config) -> bool:
    extra = getattr(config, "extra", {}) or {}
    has_api = bool(os.getenv("KIRIMDEV_API_KEY") or extra.get("api_key"))
    has_secret = bool(
        os.getenv("KIRIMDEV_WEBHOOK_SECRETS")
        or os.getenv("KIRIMDEV_WEBHOOK_SECRET")
        or extra.get("webhook_secrets")
        or extra.get("webhook_secret")
    )
    return has_api and has_secret


def is_connected(config) -> bool:
    return validate_config(config)


def _env_enablement() -> Optional[Dict[str, Any]]:
    """Auto-seed PlatformConfig.extra from env-only setups."""
    if not (
        os.getenv("KIRIMDEV_API_KEY")
        and (
            os.getenv("KIRIMDEV_WEBHOOK_SECRETS")
            or os.getenv("KIRIMDEV_WEBHOOK_SECRET")
        )
    ):
        return None
    seeded: Dict[str, Any] = {}
    if os.getenv("KIRIMDEV_PORT"):
        try:
            seeded["port"] = int(os.environ["KIRIMDEV_PORT"])
        except ValueError:
            pass
    if os.getenv("KIRIMDEV_HOST"):
        seeded["host"] = os.environ["KIRIMDEV_HOST"]
    if os.getenv("KIRIMDEV_PUBLIC_URL"):
        seeded["public_url"] = os.environ["KIRIMDEV_PUBLIC_URL"]
    if os.getenv("KIRIMDEV_HOME_CHANNEL"):
        seeded["home_channel"] = normalize_phone(os.environ["KIRIMDEV_HOME_CHANNEL"])
    if os.getenv("KIRIMDEV_DEFAULT_CHANNEL"):
        seeded["default_channel"] = os.environ["KIRIMDEV_DEFAULT_CHANNEL"]
    return seeded or {}


# --------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------


def _load_runtime_deps():
    """Lazy import heavy deps so plugin discovery doesn't fail when missing."""
    from aiohttp import web
    import httpx
    from gateway.platforms.base import (
        BasePlatformAdapter,
        MessageEvent,
        MessageType,
        SendResult,
    )
    from gateway.config import Platform

    return web, httpx, BasePlatformAdapter, MessageEvent, MessageType, SendResult, Platform


class _AdapterImpl:
    """Inner adapter class — built lazily so module import is dep-free."""

    @staticmethod
    def build():
        (
            web,
            httpx,
            BasePlatformAdapter,
            MessageEvent,
            MessageType,
            SendResult,
            Platform,
        ) = _load_runtime_deps()

        class KirimdevAdapter(BasePlatformAdapter):
            """Kirimdev omnichannel adapter."""

            MAX_MESSAGE_LENGTH = WA_MAX_BUBBLE_CHARS

            # Class-level reference to the currently connected adapter. Set in
            # ``connect()``, cleared in ``disconnect()``. Tools find the adapter
            # through this without needing a reference passed in.
            _active_instance: "Optional[KirimdevAdapter]" = None

            @classmethod
            def get_active(cls) -> "Optional[KirimdevAdapter]":
                return cls._active_instance

            def __init__(self, config) -> None:
                # Hermes does not have a canonical Platform enum entry for
                # kirimdev (third-party plugin). We register dynamically and
                # use a synthetic Platform-like value via the plugin registry.
                # ``Platform`` is still required by the base ctor; the gateway
                # tolerates unknown names via the plugin platform registry.
                try:
                    platform_value = Platform("kirimdev")
                except (ValueError, KeyError):
                    # Hermes 0.14 stores plugin platforms via the registry;
                    # passing the raw string-backed enum is acceptable since
                    # the base class only stores it.
                    platform_value = Platform.WEBHOOK  # fallback for typing
                super().__init__(config, platform_value)

                extra = getattr(config, "extra", {}) or {}

                # Credentials
                self.api_key = os.getenv("KIRIMDEV_API_KEY") or extra.get("api_key", "")
                raw_secrets = (
                    os.getenv("KIRIMDEV_WEBHOOK_SECRETS")
                    or os.getenv("KIRIMDEV_WEBHOOK_SECRET")
                    or extra.get("webhook_secrets")
                    or extra.get("webhook_secret")
                    or ""
                )
                self.webhook_secrets = [
                    s.strip() for s in str(raw_secrets).split(",") if s.strip()
                ]
                self.insecure_no_auth = "INSECURE_NO_AUTH" in self.webhook_secrets

                raw_enabled = (
                    os.getenv("KIRIMDEV_ENABLED_NUMBERS")
                    or extra.get("enabled_numbers")
                    or ""
                )
                self.enabled_numbers: set = {
                    p.strip() for p in str(raw_enabled).split(",") if p.strip()
                }
                self.default_phone_number_id = (
                    os.getenv("KIRIMDEV_DEFAULT_PHONE_NUMBER_ID")
                    or extra.get("default_phone_number_id")
                    or ""
                ).strip()

                # Network config
                self.host = os.getenv("KIRIMDEV_HOST") or extra.get("host") or DEFAULT_HOST
                try:
                    self.port = int(os.getenv("KIRIMDEV_PORT") or extra.get("port") or DEFAULT_PORT)
                except (TypeError, ValueError):
                    self.port = DEFAULT_PORT
                self.public_url = (
                    os.getenv("KIRIMDEV_PUBLIC_URL") or extra.get("public_url") or ""
                ).rstrip("/")
                self.api_base = (
                    os.getenv("KIRIMDEV_API_BASE_URL") or extra.get("api_base") or DEFAULT_API_BASE
                ).rstrip("/")

                # Outbound channel default
                self.default_channel = (
                    os.getenv("KIRIMDEV_DEFAULT_CHANNEL")
                    or extra.get("default_channel")
                    or DEFAULT_CHANNEL
                ).lower()
                if self.default_channel not in ALLOWED_CHANNELS:
                    logger.warning(
                        "Invalid KIRIMDEV_DEFAULT_CHANNEL=%r, falling back to whatsapp",
                        self.default_channel,
                    )
                    self.default_channel = DEFAULT_CHANNEL

                # Allowlist
                raw_allow = os.getenv("KIRIMDEV_ALLOWED_USERS") or ""
                self.allowed_users: set = {
                    normalize_phone(p) for p in raw_allow.split(",") if p.strip()
                }
                self.allow_all = (
                    os.getenv("KIRIMDEV_ALLOW_ALL_USERS", "").strip().lower()
                    in ("1", "true", "yes", "on")
                )

                # Owners — phones that may invoke broadcast / grant tools.
                # Owners are implicitly also allowed; we union them in.
                raw_owners = os.getenv("KIRIMDEV_OWNER_USERS") or ""
                self.owner_users: set = {
                    normalize_phone(p) for p in raw_owners.split(",") if p.strip()
                }
                self.allowed_users |= self.owner_users

                # Home channel for cron / send_message (composite or digits)
                home = os.getenv("KIRIMDEV_HOME_CHANNEL") or extra.get("home_channel") or ""
                self.home_channel = home.strip()

                # Rate limit
                try:
                    rate = int(os.getenv("KIRIMDEV_RATE_LIMIT_PER_MIN") or DEFAULT_RATE_LIMIT)
                except ValueError:
                    rate = DEFAULT_RATE_LIMIT
                self._rate_limiter = _TokenBucket(capacity=rate, refill_per_sec=rate / 60.0)

                # Loop prevention + idempotency
                self._idempotency = _IdempotencyCache()
                self._sent_message_ids: "OrderedDict[str, float]" = OrderedDict()

                try:
                    handoff_sec = int(
                        os.getenv("KIRIMDEV_HUMAN_HANDOFF_SECONDS")
                        or DEFAULT_HUMAN_HANDOFF_SECONDS
                    )
                except ValueError:
                    handoff_sec = DEFAULT_HUMAN_HANDOFF_SECONDS
                self.human_handoff_seconds = max(0, handoff_sec)
                self._human_handoff: "OrderedDict[str, float]" = OrderedDict()

                self.voice_transcribe_enabled = (
                    os.getenv("KIRIMDEV_VOICE_TRANSCRIBE", "").strip().lower()
                    in ("1", "true", "yes", "on")
                )
                self._openai_api_key = (
                    os.getenv("OPENAI_API_KEY") or extra.get("openai_api_key") or ""
                ).strip()

                # Typing-indicator throttle. Kirimdev caps at 1 req per
                # customer per 3s. Base.gateway hits send_typing every ~2s,
                # so we drop ticks that fall within the window. OrderedDict
                # so we can LRU-evict when the cache fills.
                self._last_typing_sent: "OrderedDict[str, float]" = OrderedDict()
                # Last inbound wamid per chat_id for typing_indicator pulses.
                # Value: (wamid, phone_number_id).
                self._last_inbound_wamid: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()

                # Track the most recent sender tier per chat_id so tools
                # invoked during an agent turn can authorize without
                # re-resolving (and to gate granted senders from tools that
                # require allowed/owner status). OrderedDict for LRU eviction.
                self._last_tier_by_chat: "OrderedDict[str, str]" = OrderedDict()

                # Recently-denied senders, keyed by phone -> monotonic ts.
                # In-memory only (resets on gateway restart by design — a
                # restart is a chance to reconsider). OrderedDict for LRU.
                self._denied_blacklist: "OrderedDict[str, float]" = OrderedDict()

                # Strong references to in-flight fire-and-forget tasks.
                # Python 3.11+ only keeps weak refs to tasks via
                # asyncio.create_task(); without our own set, GC can
                # cancel them mid-flight. add_done_callback drops the
                # ref so the set doesn't grow unbounded.
                self._bg_tasks: "set" = set()

                # HTTP client (built in connect).
                #
                # httpx.AsyncClient binds internal asyncio primitives
                # (Locks, Events) to the loop that constructed it. If we
                # are called from a different loop later (e.g. the agent
                # tool dispatcher runs on its own loop) httpx raises
                # ``<asyncio.Event ...> is bound to a different event
                # loop``. We track the owning loop and rebuild the client
                # on demand whenever the calling loop has changed. See
                # _get_http() below.
                #
                # Single-client-with-swap was racy: when both the gateway
                # loop and the agent tool loop are alive simultaneously
                # and call _get_http() in quick succession, each call
                # would tear down the other's in-flight client mid-request.
                # The fix is per-loop caching: each loop gets its own
                # httpx client, lazily built on first use and reused for
                # all subsequent calls from that loop. We key on
                # (id(loop), loop) so dead loops can be pruned and id
                # collisions (rare but possible after GC) are detected.
                self._http: Optional[Any] = None  # primary client (legacy field)
                self._http_loop: Optional[Any] = None  # primary client's loop
                self._http_clients: Dict[int, tuple] = {}  # loop_id -> (loop, client)
                self._http_lock: Optional[Any] = None  # asyncio.Lock, lazy

                # aiohttp app
                self._aiohttp_app: Optional[Any] = None
                self._aiohttp_runner: Optional[Any] = None
                self._aiohttp_site: Optional[Any] = None

            # ----------------------------------------------------------------
            # Lifecycle
            # ----------------------------------------------------------------

            async def connect(self) -> bool:
                if not self.api_key or (
                    not self.webhook_secrets and not self.insecure_no_auth
                ):
                    logger.error(
                        "Kirimdev: missing API key or webhook secret; refusing to start"
                    )
                    self._fatal_error_message = "Missing credentials"
                    self._fatal_error_code = "missing_credentials"
                    self._fatal_error_retryable = False
                    return False

                if not self.allow_all and not self.allowed_users:
                    logger.warning(
                        "Kirimdev: no KIRIMDEV_ALLOWED_USERS and KIRIMDEV_ALLOW_ALL_USERS "
                        "is not true — all inbound messages will be ignored."
                    )

                # Sweep orphan .tmp files from any previous crashed write
                # cycle so disk doesn't accumulate them over time. Safe to
                # run on every connect — it's a glob+unlink in the data dir.
                try:
                    from . import grants as _grants_mod
                    from . import pending as _pending_mod
                    removed_g = _grants_mod.sweep_orphan_tmp_files()
                    removed_p = _pending_mod.sweep_orphan_tmp_files()
                    if removed_g or removed_p:
                        logger.info(
                            "Kirimdev startup sweep: removed %d grants + %d pending tmp files",
                            removed_g, removed_p,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Kirimdev tmp sweep failed: %s", exc)

                # httpx client — created on the current loop. _get_http()
                # tracks per-loop clients to safely serve calls from
                # parallel event loops (gateway loop + agent tool loop).
                connect_loop = asyncio.get_running_loop()
                self._http = self._build_http_client()
                self._http_loop = connect_loop
                self._http_clients[id(connect_loop)] = (connect_loop, self._http)

                if self.enabled_numbers:
                    logger.info(
                        "Kirimdev: agent enabled for phone_number_id(s): %s",
                        ", ".join(sorted(self.enabled_numbers)),
                    )
                else:
                    logger.warning(
                        "Kirimdev: KIRIMDEV_ENABLED_NUMBERS is empty — "
                        "all inbound webhooks will be ignored."
                    )

                # API probe (non-fatal)
                try:
                    r = await self._http.get("/me")
                    if r.status_code >= 400:
                        logger.warning(
                            "Kirimdev GET /me returned %s; continuing anyway",
                            r.status_code,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Kirimdev /me probe failed: %s",
                        _redact_sensitive_text(str(exc)),
                    )

                # aiohttp webhook server
                self._aiohttp_app = web.Application(client_max_size=MAX_BODY_BYTES)
                self._aiohttp_app.router.add_post(WEBHOOK_PATH, self._handle_webhook)
                self._aiohttp_app.router.add_get(HEALTH_PATH, self._handle_health)
                self._aiohttp_runner = web.AppRunner(self._aiohttp_app)
                try:
                    await self._aiohttp_runner.setup()
                    self._aiohttp_site = web.TCPSite(
                        self._aiohttp_runner, host=self.host, port=self.port
                    )
                    await self._aiohttp_site.start()
                except OSError as exc:
                    logger.error(
                        "Kirimdev: failed to bind %s:%s — %s",
                        self.host, self.port, exc,
                    )
                    self._fatal_error_message = f"bind {self.host}:{self.port} failed"
                    self._fatal_error_code = "bind_failed"
                    self._fatal_error_retryable = True
                    return False

                shown_url = self.public_url or f"http://{self.host}:{self.port}"
                logger.info(
                    "Kirimdev adapter ready — webhook URL: %s%s",
                    shown_url, WEBHOOK_PATH,
                )
                self._mark_connected()
                KirimdevAdapter._active_instance = self
                return True

            async def disconnect(self) -> None:
                self._mark_disconnected()
                if KirimdevAdapter._active_instance is self:
                    KirimdevAdapter._active_instance = None
                if self._aiohttp_site is not None:
                    try:
                        await self._aiohttp_site.stop()
                    except Exception:  # noqa: BLE001
                        pass
                if self._aiohttp_runner is not None:
                    try:
                        await self._aiohttp_runner.cleanup()
                    except Exception:  # noqa: BLE001
                        pass
                # Close every per-loop client. The current loop's own
                # client can be awaited; clients owned by *other* loops
                # are closed best-effort (httpx releases sockets on GC).
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None
                for entry in list(self._http_clients.values()):
                    if not entry:
                        continue
                    owning_loop, client = entry
                    if client is None:
                        continue
                    if owning_loop is current_loop:
                        try:
                            await client.aclose()
                        except Exception:  # noqa: BLE001
                            pass
                self._http_clients.clear()
                self._aiohttp_site = None
                self._aiohttp_runner = None
                self._aiohttp_app = None
                self._http = None

            # ----------------------------------------------------------------
            # Inbound webhook
            # ----------------------------------------------------------------

            async def _handle_health(self, request):  # type: ignore[no-untyped-def]
                return web.json_response({
                    "status": "ok",
                    "platform": "kirimdev",
                    "channel": self.default_channel,
                })

            def _resolve_outbound_ids(self, chat_id: str) -> Tuple[str, str]:
                """Return ``(phone_number_id, customer_phone_digits)`` for sends."""
                pid, phone = parse_chat_id(chat_id)
                if not pid:
                    pid = self.default_phone_number_id
                return pid, phone

            def _is_number_enabled(self, phone_number_id: str) -> bool:
                if not self.enabled_numbers:
                    return False
                return phone_number_id in self.enabled_numbers

            async def _handle_webhook(self, request):  # type: ignore[no-untyped-def]
                try:
                    body = await request.read()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Kirimdev webhook read error: %s", exc)
                    return web.json_response({"error": "bad_request"}, status=400)

                sig = request.headers.get("X-Kirim-Signature", "")
                event = request.headers.get("X-Kirim-Event", "")
                delivery_id = request.headers.get("X-Kirim-Delivery-Id", "")
                event_id = request.headers.get("X-Kirim-Event-Id", "")

                if not self._validate_signature(body, sig):
                    logger.warning(
                        "Kirimdev webhook bad signature (delivery=%s prefix=%s)",
                        delivery_id,
                        (sig or "")[:24],
                    )
                    return web.json_response({"error": "unauthorized"}, status=401)

                if self._idempotency.seen_or_record(event_id or delivery_id):
                    logger.debug("Kirimdev duplicate delivery=%s", delivery_id)
                    return web.json_response({"status": "duplicate"}, status=200)

                try:
                    payload = json.loads(body.decode("utf-8") or "{}")
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    logger.warning("Kirimdev webhook bad json: %s", exc)
                    return web.json_response({"error": "bad_json"}, status=400)

                evt_type = event or payload.get("type") or ""
                if evt_type not in ALLOWED_EVENT_TYPES:
                    return web.json_response(
                        {"status": "ignored", "reason": "event_type"},
                        status=200,
                    )

                if evt_type == "message.sent":
                    status, code = await self._handle_message_sent(payload)
                    if status >= 500:
                        return web.json_response({"error": code}, status=status)
                    return web.json_response({"status": code}, status=200)

                inbound_items = parse_meta_inbound(payload)
                if not inbound_items:
                    return web.json_response(
                        {"status": "ignored", "reason": "no_messages"},
                        status=200,
                    )

                for item in inbound_items:
                    status, code = await self._dispatch_inbound(item)
                    if status >= 500:
                        return web.json_response({"error": code}, status=status)

                return web.json_response({"status": "ok"}, status=200)

            def _set_human_handoff(self, chat_id: str) -> None:
                if self.human_handoff_seconds <= 0 or not chat_id:
                    return
                self._human_handoff[chat_id] = (
                    time.monotonic() + self.human_handoff_seconds
                )
                while len(self._human_handoff) > HUMAN_HANDOFF_MAX_SIZE:
                    self._human_handoff.popitem(last=False)

            def _is_human_handoff_active(self, chat_id: str) -> bool:
                until = self._human_handoff.get(chat_id)
                if until is None:
                    return False
                if time.monotonic() >= until:
                    self._human_handoff.pop(chat_id, None)
                    return False
                return True

            async def _handle_message_sent(
                self, payload: Dict[str, Any]
            ) -> Tuple[int, str]:
                item = parse_message_sent(payload)
                if not item:
                    return 200, "no_data"

                phone_number_id = str(item.get("phone_number_id") or "")
                if phone_number_id and not self._is_number_enabled(phone_number_id):
                    return 200, "number_not_enabled"

                provider_id = str(item.get("provider_id") or "")
                if provider_id:
                    self._record_sent_id(provider_id)

                source = (item.get("source") or "").lower()
                if source in ("dashboard", "app"):
                    phone = normalize_phone(item.get("customer_phone") or "")
                    if phone_number_id and phone:
                        chat_id = make_chat_id(phone_number_id, phone)
                        self._set_human_handoff(chat_id)
                        logger.info(
                            "Kirimdev human handoff: pid=%s phone=%s source=%s %ds",
                            phone_number_id,
                            redact_phone(phone),
                            source,
                            self.human_handoff_seconds,
                        )
                return 200, "ok"

            async def _transcribe_voice(self, media_url: str) -> Optional[str]:
                if not self._openai_api_key:
                    return None
                try:
                    http = await self._get_http()
                    if http is None:
                        return None
                    audio_resp = await http.get(media_url, timeout=30.0)
                    if audio_resp.status_code >= 400:
                        logger.warning(
                            "Voice download failed: status=%d",
                            audio_resp.status_code,
                        )
                        return None
                    audio_bytes = audio_resp.content
                    if not audio_bytes:
                        return None

                    import httpx as hx

                    headers = {"Authorization": f"Bearer {self._openai_api_key}"}
                    files = {
                        "file": ("voice.ogg", audio_bytes, "application/octet-stream")
                    }
                    data = {"model": "whisper-1"}
                    async with hx.AsyncClient(timeout=VOICE_TRANSCRIBE_TIMEOUT) as client:
                        resp = await client.post(
                            "https://api.openai.com/v1/audio/transcriptions",
                            headers=headers,
                            data=data,
                            files=files,
                        )
                    if resp.status_code >= 400:
                        logger.warning(
                            "Voice transcribe failed: status=%d",
                            resp.status_code,
                        )
                        return None
                    body = resp.json()
                    text = str(body.get("text") or "").strip()
                    return text or None
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Voice transcribe error: %s", exc)
                    return None

            async def _prepare_inbound_agent_payload(
                self, data: Dict[str, Any]
            ) -> Tuple[str, Optional[List[str]], Optional[str]]:
                """Return ``(agent_text, media_urls, user_notice)`` for the agent."""
                message_type_str = (data.get("message_type") or "text").lower()
                raw_content = _sanitize_inbound_content(data.get("content") or "")
                media_url, media_status = _extract_kirim_media(data)

                if _is_inbound_text_type(message_type_str):
                    if not raw_content:
                        if message_type_str in ("interactive", "button"):
                            return (
                                "",
                                None,
                                "Maaf, saya tidak bisa membaca balasan tombol tersebut.",
                            )
                        return "", None, None
                    return raw_content, None, None

                if message_type_str == "image":
                    if media_url and media_status == "ready":
                        text = raw_content or "[Gambar dari pelanggan]"
                        return text, [media_url], None
                    if raw_content:
                        suffix = (
                            "\n[Gambar sedang diproses]"
                            if media_status == "pending"
                            else "\n[Gambar belum tersedia]"
                        )
                        return f"{raw_content}{suffix}", None, None
                    return (
                        "",
                        None,
                        "Maaf, saya belum bisa memproses gambar ini. "
                        "Coba kirim ulang atau tulis pesan teks.",
                    )

                if message_type_str in INBOUND_VOICE_TYPES:
                    if not self.voice_transcribe_enabled or not self._openai_api_key:
                        return (
                            "",
                            None,
                            "Maaf, saat ini saya belum bisa memproses pesan suara. "
                            "Kirim teks ya.",
                        )
                    if not media_url or media_status != "ready":
                        return (
                            "",
                            None,
                            "Maaf, file suara belum tersedia. "
                            "Coba kirim ulang atau tulis pesan teks.",
                        )
                    transcript = await self._transcribe_voice(media_url)
                    if transcript:
                        return transcript, None, None
                    return (
                        "",
                        None,
                        "Maaf, saya tidak bisa memahami pesan suara tersebut. "
                        "Coba kirim teks ya.",
                    )

                return (
                    "",
                    None,
                    "Maaf, saat ini saya hanya bisa memproses pesan teks, "
                    "tombol, gambar, dan suara.",
                )

            async def _dispatch_inbound(
                self, data: Dict[str, Any]
            ) -> Tuple[int, str]:
                """Process one normalized inbound Meta message."""
                phone_number_id = str(data.get("phone_number_id") or "")
                phone = normalize_phone(data.get("customer_phone") or "")
                wamid = str(data.get("wamid") or "")
                if not phone_number_id or not phone:
                    return 200, "no_phone"

                if not self._is_number_enabled(phone_number_id):
                    logger.debug(
                        "Kirimdev ignored inbound — phone_number_id %s not enabled",
                        phone_number_id,
                    )
                    return 200, "number_not_enabled"

                chat_id = make_chat_id(phone_number_id, phone)
                if wamid:
                    self._record_inbound_wamid(chat_id, wamid, phone_number_id)
                msg_id = wamid
                if msg_id and msg_id in self._sent_message_ids:
                    return 200, "self_echo"

                if self._is_human_handoff_active(chat_id):
                    logger.info(
                        "Kirimdev human handoff active for %s — skipping agent",
                        redact_phone(phone),
                    )
                    return 200, "human_handoff"

                logger.info(
                    "Kirimdev inbound: pid=%s phone=%s type=%s text_len=%d wamid=%s",
                    phone_number_id,
                    redact_phone(phone),
                    data.get("message_type") or "?",
                    len(data.get("content") or ""),
                    (msg_id or "?")[:20],
                )

                raw_msg = data.get("raw_message") or {}
                btn_id, _btn_title = extract_button_reply(raw_msg)
                if btn_id and (
                    btn_id.startswith(APPROVE_PREFIX) or btn_id.startswith(DENY_PREFIX)
                ):
                    self._spawn(
                        self._handle_approval_button(
                            owner_phone=phone, button_id=btn_id, msg_id=msg_id
                        )
                    )
                    return 200, "approval_button"

                tier = self.resolve_sender_tier(phone)

                if tier == TIER_UNKNOWN:
                    msg_type_lower = (data.get("message_type") or "text").lower()
                    if not _is_inbound_text_type(msg_type_lower):
                        logger.info(
                            "Kirimdev unknown sender %s non-text (%s) — dropped",
                            redact_phone(phone),
                            msg_type_lower,
                        )
                        return 200, "unknown_non_text"

                    pending_text = _sanitize_inbound_content(data.get("content") or "")
                    if not pending_text:
                        return 200, "unknown_empty"

                    if phone in self._denied_blacklist and (
                        time.monotonic() - self._denied_blacklist[phone]
                        < DENIED_BLACKLIST_SECONDS
                    ):
                        return 200, "deny_cooldown"

                    self._spawn(
                        self._handle_unknown_sender(
                            phone=phone,
                            text=pending_text,
                            customer_name=data.get("customer_name") or "",
                            message_id=msg_id,
                            channel=self.default_channel,
                            phone_number_id=phone_number_id,
                        )
                    )
                    return 200, "pending_approval"

                if not await self._rate_limiter.allow(phone):
                    logger.warning("Kirimdev rate limit hit for %s", redact_phone(phone))
                    return 200, "rate_limited"

                if msg_id:
                    self._spawn(
                        self.mark_message_read(msg_id, phone_number_id=phone_number_id)
                    )

                agent_text, media_urls, user_notice = (
                    await self._prepare_inbound_agent_payload(data)
                )
                if user_notice:
                    logger.info(
                        "Kirimdev inbound notice (%s) for %s",
                        (data.get("message_type") or "?"),
                        redact_phone(phone),
                    )
                    self._spawn(self._safe_send_notice(chat_id, user_notice))
                    return 200, "unsupported"

                if not agent_text and not media_urls:
                    return 200, "empty"

                source = self.build_source(
                    chat_id=chat_id,
                    chat_type="dm",
                    user_id=phone,
                    user_name=data.get("customer_name") or None,
                    message_id=msg_id or None,
                )
                enriched = dict(data)
                enriched["_kirimdev_tier"] = tier
                enriched["_kirimdev_phone"] = phone
                enriched["_kirimdev_phone_number_id"] = phone_number_id
                self._record_tier_for_chat(chat_id, tier)

                annotated_text = (
                    f"[tier={tier}] {agent_text}" if agent_text else f"[tier={tier}]"
                )
                if media_urls and not agent_text:
                    annotated_text = f"[tier={tier}] [image]"

                msg_type_enum = MessageType.TEXT
                if media_urls:
                    image_type = getattr(MessageType, "IMAGE", None)
                    if image_type is not None:
                        msg_type_enum = image_type
                    else:
                        annotated_text = (
                            f"{annotated_text} {media_urls[0]}".strip()
                        )

                event_kwargs: Dict[str, Any] = {
                    "text": annotated_text,
                    "message_type": msg_type_enum,
                    "source": source,
                    "message_id": msg_id or None,
                    "raw_message": enriched,
                }
                if media_urls:
                    event_kwargs["media_files"] = media_urls

                try:
                    event_obj = MessageEvent(**event_kwargs)
                except TypeError:
                    event_kwargs.pop("media_files", None)
                    event_obj = MessageEvent(**event_kwargs)

                try:
                    from . import tools as _kctools

                    _ctx_token = _kctools._set_current_chat_context(chat_id, tier)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Kirimdev tier ctx set failed: %s", exc)
                    _ctx_token = None

                try:
                    try:
                        await self.handle_message(event_obj)
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("Kirimdev handle_message failed: %s", exc)
                        return 500, "internal"
                finally:
                    if _ctx_token is not None:
                        try:
                            from . import tools as _kctools

                            _kctools._reset_current_chat_context(_ctx_token)
                        except Exception:  # noqa: BLE001
                            pass

                return 200, "ok"

            def _validate_signature(self, body: bytes, signature: str) -> bool:
                return verify_kirim_signature(
                    body,
                    signature,
                    self.webhook_secrets,
                    insecure_no_auth=self.insecure_no_auth,
                )

            # ----------------------------------------------------------------
            # Outbound sending
            # ----------------------------------------------------------------

            async def send(
                self,
                chat_id: str,
                content: str = "",
                *,
                text: str = "",
                reply_to: Optional[str] = None,
                metadata: Any = None,
                **kwargs,
            ) -> Any:
                """Send a text message via Kirimdev ``POST /v1/{phone_number_id}/messages``."""
                body = content or text or kwargs.get("message") or ""
                phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                if not phone_number_id or not phone:
                    return SendResult(success=False, error="empty chat_id or missing phone_number_id")
                if not body:
                    return SendResult(success=True, message_id=None)

                chunks = smart_chunk_for_whatsapp(body)
                last_result: Any = None
                for i, chunk in enumerate(chunks):
                    last_result = await self._send_text_chunk(
                        phone_number_id, phone, chunk
                    )
                    if not getattr(last_result, "success", False):
                        return last_result
                    if i < len(chunks) - 1:
                        await asyncio.sleep(WA_INTER_CHUNK_DELAY_SECONDS)
                return last_result

            async def _send_text_chunk(
                self, phone_number_id: str, phone: str, text: str
            ) -> Any:
                payload = {
                    "messaging_product": "whatsapp",
                    "to": format_e164(phone),
                    "type": "text",
                    "text": {"body": text},
                }
                return await self._kirimdev_post_with_retry(phone_number_id, payload)

            async def send_image(
                self, chat_id: str, image_url: str, caption: str = "", **kwargs
            ) -> Any:
                phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                if not phone_number_id or not phone or not image_url:
                    return SendResult(success=False, error="missing chat_id or image_url")
                image_payload: Dict[str, Any] = {"link": image_url}
                if caption:
                    image_payload["caption"] = caption
                payload = {
                    "messaging_product": "whatsapp",
                    "to": format_e164(phone),
                    "type": "image",
                    "image": image_payload,
                }
                return await self._kirimdev_post_with_retry(phone_number_id, payload)

            async def send_interactive(
                self,
                chat_id: str,
                interactive: Dict[str, Any],
            ) -> Any:
                """Send a WhatsApp interactive message (buttons/cta/list/carousel)."""
                phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                if not phone_number_id or not phone or not interactive:
                    return SendResult(success=False, error="missing chat_id or payload")
                payload = {
                    "messaging_product": "whatsapp",
                    "to": format_e164(phone),
                    "type": "interactive",
                    "interactive": interactive,
                }
                return await self._kirimdev_post_with_retry(phone_number_id, payload)

            async def send_template(
                self,
                chat_id: str,
                template_name: str,
                language_code: str = "id",
                components: Optional[List[Dict[str, Any]]] = None,
                auto_create_customer: bool = True,
                customer_name: Optional[str] = None,
            ) -> Any:
                """Send a WhatsApp approved template message."""
                del auto_create_customer, customer_name  # Kirimdev creates contacts on send
                phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                if not phone_number_id or not phone or not template_name:
                    return SendResult(success=False, error="missing chat_id or template_name")
                template_body: Dict[str, Any] = {
                    "name": template_name,
                    "language": {"code": language_code},
                }
                if components:
                    template_body["components"] = components
                payload = {
                    "messaging_product": "whatsapp",
                    "to": format_e164(phone),
                    "type": "template",
                    "template": template_body,
                }
                return await self._kirimdev_post_with_retry(phone_number_id, payload)

            async def list_templates(
                self,
                status: Optional[str] = None,
                category: Optional[str] = None,
                limit: int = 100,
                offset: int = 0,
                language: Optional[str] = None,
                *,
                phone_number_id: Optional[str] = None,
            ) -> Dict[str, Any]:
                """List WhatsApp templates via ``GET /v1/{phone_number_id}/templates``."""
                _ = category, offset  # API has no category/offset; filter client-side if needed
                http = await self._get_http()
                if http is None:
                    return {"success": False, "error": "http client not connected"}
                pid = (phone_number_id or self.default_phone_number_id or "").strip()
                if not pid:
                    return {"success": False, "error": "phone_number_id required"}
                params: Dict[str, Any] = {
                    "limit": str(max(1, min(int(limit or 100), 100))),
                    "status": normalize_template_list_status(status),
                }
                if language:
                    params["language"] = language.strip()
                try:
                    r = await http.get(f"/{pid}/templates", params=params)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Kirimdev list_templates transport error: %s", exc)
                    return {"success": False, "error": f"transport: {exc}"}
                if r.status_code >= 400:
                    detail = r.text[:500]
                    try:
                        err_body = r.json()
                        msg = (
                            err_body.get("error", {}).get("message")
                            if isinstance(err_body, dict)
                            else None
                        )
                        if msg:
                            detail = str(msg)
                    except Exception:  # noqa: BLE001
                        pass
                    return {
                        "success": False,
                        "error": f"http_{r.status_code}: {detail}",
                        "body": r.text[:500],
                    }
                try:
                    body = r.json()
                    return {"success": True, "data": body.get("data"), "raw": body}
                except Exception as exc:  # noqa: BLE001
                    return {"success": False, "error": f"bad_json: {exc}"}

            async def get_template(
                self, template_name: str, *, phone_number_id: Optional[str] = None
            ) -> Dict[str, Any]:
                """Fetch a single template by name."""
                http = await self._get_http()
                if http is None:
                    return {"success": False, "error": "http client not connected"}
                pid = (phone_number_id or self.default_phone_number_id or "").strip()
                name = (template_name or "").strip()
                if not pid or not name:
                    return {"success": False, "error": "phone_number_id and template name required"}
                try:
                    r = await http.get(f"/{pid}/templates/{name}")
                except Exception as exc:  # noqa: BLE001
                    return {"success": False, "error": f"transport: {exc}"}
                if r.status_code == 404:
                    return {"success": False, "error": "not_found"}
                if r.status_code >= 400:
                    return {
                        "success": False,
                        "error": f"http_{r.status_code}",
                        "body": r.text[:500],
                    }
                try:
                    body = r.json()
                    return {"success": True, "data": body.get("data"), "raw": body}
                except Exception as exc:  # noqa: BLE001
                    return {"success": False, "error": f"bad_json: {exc}"}

            async def send_document(
                self, chat_id: str, path: str, caption: str = "", **kwargs
            ) -> Any:
                if path and path.startswith(("http://", "https://")):
                    phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                    doc_payload: Dict[str, Any] = {"link": path}
                    if caption:
                        doc_payload["caption"] = caption
                    payload = {
                        "messaging_product": "whatsapp",
                        "to": format_e164(phone),
                        "type": "document",
                        "document": doc_payload,
                    }
                    return await self._kirimdev_post_with_retry(phone_number_id, payload)
                logger.info("Kirimdev send_document: local-file paths not supported in MVP")
                return SendResult(success=False, error="local-file not supported")

            async def send_typing(self, chat_id: str, metadata=None) -> None:
                """Show WhatsApp typing via Kirimdev read-receipt + typing_indicator."""
                phone_number_id, phone = self._resolve_outbound_ids(chat_id)
                if not phone:
                    return

                wamid = ""
                stored_pid = ""
                cached = self._last_inbound_wamid.get(chat_id)
                if cached:
                    wamid, stored_pid = cached
                if not wamid and metadata is not None:
                    if isinstance(metadata, dict):
                        wamid = str(metadata.get("message_id") or metadata.get("wamid") or "")
                    else:
                        wamid = str(getattr(metadata, "message_id", "") or "")

                pid = phone_number_id or stored_pid
                if not pid or not wamid:
                    logger.debug(
                        "Kirimdev typing skipped (missing wamid or phone_number_id) chat=%s",
                        redact_phone(phone),
                    )
                    return

                now = time.monotonic()
                last = self._last_typing_sent.get(chat_id, 0.0)
                if now - last < TYPING_MIN_INTERVAL_SECONDS:
                    return
                self._record_typing_sent(chat_id, now)

                http = await self._get_http()
                if http is None:
                    return

                payload = {
                    "messaging_product": "whatsapp",
                    "status": "read",
                    "message_id": wamid,
                    "typing_indicator": {"type": "text"},
                }
                try:
                    r = await http.post(
                        f"/{pid}/messages",
                        json=payload,
                        timeout=TYPING_HTTP_TIMEOUT,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Kirimdev typing transport error for %s: %s",
                        redact_phone(phone),
                        _redact_sensitive_text(str(exc)),
                    )
                    return

                if r.status_code == 429:
                    self._record_typing_sent(
                        chat_id, time.monotonic() + TYPING_429_BACKOFF_SECONDS
                    )
                    logger.debug("Kirimdev typing rate-limited for %s", redact_phone(phone))
                    return

                if 200 <= r.status_code < 300:
                    logger.debug("Kirimdev typing ok for %s", redact_phone(phone))
                    return

                logger.debug(
                    "Kirimdev typing %d for %s: %s",
                    r.status_code,
                    redact_phone(phone),
                    _redact_sensitive_text(r.text)[:200],
                )

            async def _handle_unknown_sender(
                self,
                phone: str,
                text: str,
                customer_name: str,
                message_id: str,
                channel: str,
                *,
                phone_number_id: str = "",
            ) -> None:
                """Stash an unknown sender's message and notify each owner."""
                try:
                    from . import pending as _pending
                except Exception as exc:  # noqa: BLE001
                    logger.error("Kirimdev pending module unavailable: %s", exc)
                    return

                if not self.owner_users:
                    logger.warning(
                        "Kirimdev unknown sender %s but no KIRIMDEV_OWNER_USERS configured — dropping",
                        redact_phone(phone),
                    )
                    return

                # Anti-flood: cap concurrent pending entries.
                try:
                    if len(_pending.list_pending()) >= MAX_PENDING_APPROVALS:
                        logger.warning(
                            "Kirimdev too many pending approvals (>%d) — dropping new from %s",
                            MAX_PENDING_APPROVALS, redact_phone(phone),
                        )
                        return
                except Exception:  # noqa: BLE001
                    pass

                # Sanitise both fields before persistence — they get
                # embedded into the owner approval prompt below and we
                # don't want stored fields to bypass sanitisation if a
                # different code path reads them later.
                safe_text_for_stash = _sanitize_inbound_content(text or "")
                safe_name_for_stash = _sanitize_customer_name(customer_name)
                try:
                    pid = _pending.add_pending(
                        phone=phone,
                        text=safe_text_for_stash,
                        customer_name=safe_name_for_stash,
                        message_id=message_id,
                        channel=channel,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error("Kirimdev add_pending failed: %s", exc)
                    return

                logger.info(
                    "Kirimdev pending=%s from %s (%s): %r",
                    pid, redact_phone(phone),
                    safe_name_for_stash or "(no name)",
                    safe_text_for_stash[:80],
                )

                # Build the approval prompt for the owner(s). Use the
                # already-sanitised fields from the stash to avoid a
                # second pass and to keep them in sync with what's stored.
                preview = (
                    safe_text_for_stash.replace("\n", " ").replace("\r", " ").strip()
                )
                if len(preview) > 240:
                    preview = preview[:237] + "..."
                who = safe_name_for_stash or f"+{phone}"
                # Use a slightly masked phone in the visible body so the
                # owner can identify but the full number is not in every log.
                body = (
                    f"Pesan masuk dari {who} ({redact_phone(phone)}):\n\n"
                    f"\"{preview}\"\n\n"
                    f"Approve agen untuk balas?"
                )
                interactive = {
                    "type": "button",
                    "body": {"text": body[:1024]},
                    "footer": {"text": "Berlaku 24 jam jika di-Approve"},
                    "action": {
                        "buttons": [
                            {"type": "reply", "reply": {
                                "id": f"kd_approve:{pid}",
                                "title": "Approve 24h",
                            }},
                            {"type": "reply", "reply": {
                                "id": f"kd_deny:{pid}",
                                "title": "Deny",
                            }},
                        ],
                    },
                }

                sent_to_any = False
                for owner_phone in self.owner_users:
                    try:
                        result = await self.send_interactive(owner_phone, interactive)
                        if getattr(result, "success", False):
                            sent_to_any = True
                        else:
                            logger.warning(
                                "Kirimdev owner-notify to %s failed: %s",
                                redact_phone(owner_phone),
                                getattr(result, "error", "unknown"),
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Kirimdev owner-notify to %s raised: %s",
                            redact_phone(owner_phone), exc,
                        )

                if not sent_to_any:
                    # Owner unreachable — clean up pending so we don't pile up.
                    try:
                        _pending.remove_pending(pid)
                    except Exception:  # noqa: BLE001
                        pass

            async def _handle_approval_button(
                self,
                owner_phone: str,
                button_id: str,
                msg_id: str,
            ) -> None:
                """Process Approve/Deny taps from the owner."""
                try:
                    from . import pending as _pending
                    from . import grants as _grants
                except Exception as exc:  # noqa: BLE001
                    logger.error("Kirimdev approval modules unavailable: %s", exc)
                    return

                # Only owners may approve/deny.
                if owner_phone not in self.owner_users:
                    logger.warning(
                        "Kirimdev approval tap from non-owner %s — ignoring",
                        redact_phone(owner_phone),
                    )
                    return

                if ":" not in button_id:
                    logger.warning("Kirimdev malformed button_id %r", button_id)
                    return
                action, pid = button_id.split(":", 1)
                entry = _pending.get_pending(pid)
                if not entry:
                    logger.info(
                        "Kirimdev approval for unknown pending=%s (expired or already handled)", pid,
                    )
                    self._spawn(self._safe_send_notice(
                        owner_phone,
                        "ℹ️ Permintaan persetujuan ini sudah tidak aktif (kemungkinan kadaluarsa atau sudah diproses).",
                    ))
                    return

                target_phone = entry.get("phone") or ""
                target_text = entry.get("text") or ""
                target_name = entry.get("customer_name") or ""

                # Always mark the owner's tap as read for clean UX.
                if msg_id:
                    self._spawn(self.mark_message_read(msg_id))

                if action == "kd_approve":
                    try:
                        _grants.add_grant(
                            phone=target_phone,
                            ttl_hours=APPROVAL_GRANT_TTL_HOURS,
                            note="approved by owner via button",
                            granted_by=owner_phone,
                        )
                    except ValueError as exc:
                        logger.warning("Kirimdev add_grant failed: %s", exc)
                        return
                    logger.info(
                        "Kirimdev APPROVE %s by owner %s (pending=%s)",
                        redact_phone(target_phone), redact_phone(owner_phone), pid,
                    )
                    _pending.remove_pending(pid)
                    # Drop from deny blacklist if present.
                    self._denied_blacklist.pop(target_phone, None)
                    # Replay the original message through the gateway so the
                    # agent processes it as a normal granted-tier message.
                    await self._replay_pending(
                        phone=target_phone,
                        text=target_text,
                        customer_name=target_name,
                    )
                    # Confirm to the owner.
                    self._spawn(self._safe_send_notice(
                        owner_phone,
                        f"✓ Granted {APPROVAL_GRANT_TTL_HOURS:g}h untuk {redact_phone(target_phone)}. "
                        f"Pesan asli sedang diproses.",
                    ))
                elif action == "kd_deny":
                    logger.info(
                        "Kirimdev DENY %s by owner %s (pending=%s)",
                        redact_phone(target_phone), redact_phone(owner_phone), pid,
                    )
                    _pending.remove_pending(pid)
                    self._record_denied(target_phone)
                    # Polite decline to the original sender.
                    self._spawn(self._safe_send_notice(
                        target_phone,
                        "Maaf, saat ini saya tidak bisa membantu. Silakan coba lagi di lain waktu.",
                    ))
                    self._spawn(self._safe_send_notice(
                        owner_phone,
                        f"✗ Denied {redact_phone(target_phone)}. Pesan penolakan terkirim.",
                    ))
                else:
                    logger.warning("Kirimdev unknown approval action %r", action)

            async def _replay_pending(
                self,
                phone: str,
                text: str,
                customer_name: str,
            ) -> None:
                """Re-dispatch a previously-stashed message to the agent.

                Built so the agent sees the sender at tier=granted and the
                original message text — without any re-routing through the
                webhook handler.
                """
                if not text:
                    return
                norm = normalize_phone(phone)
                if not norm:
                    return

                # Build a fresh MessageEvent the same way the webhook path
                # would have done it for a normal inbound message.
                # Sanitise replay text the same way too — even though it
                # was sanitised on the way into pending, defence-in-depth.
                safe_text = _sanitize_inbound_content(text or "")
                safe_name = _sanitize_customer_name(customer_name)
                source = self.build_source(
                    chat_id=norm,
                    chat_type="dm",
                    user_id=norm,
                    user_name=safe_name or None,
                )
                tier = TIER_GRANTED
                self._record_tier_for_chat(norm, tier)
                annotated = f"[tier={tier}] {safe_text}"
                try:
                    event_obj = MessageEvent(
                        text=annotated,
                        message_type=MessageType.TEXT,
                        source=source,
                        raw_message={
                            "_kirimdev_tier": tier,
                            "_kirimdev_phone": norm,
                            "_replayed": True,
                            "customer_phone": norm,
                            "customer_name": safe_name,
                            "content": safe_text,
                            "channel": self.default_channel,
                            "direction": "inbound",
                            "message_type": "text",
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error("Kirimdev replay: cannot build MessageEvent: %s", exc)
                    return

                try:
                    from . import tools as _kctools
                    _ctx_token = _kctools._set_current_chat_context(norm, tier)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Kirimdev replay tier ctx set failed: %s", exc)
                    _ctx_token = None

                try:
                    try:
                        await self.handle_message(event_obj)
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("Kirimdev replay handle_message failed: %s", exc)
                finally:
                    if _ctx_token is not None:
                        try:
                            from . import tools as _kctools
                            _kctools._reset_current_chat_context(_ctx_token)
                        except Exception:  # noqa: BLE001
                            pass

            def _spawn(self, coro):
                """Schedule a fire-and-forget coroutine and keep a strong ref.

                Wrapper around asyncio.create_task that prevents
                Python 3.11+'s weak-ref GC from cancelling the task
                before it finishes. The ref is released when the task
                completes.
                """
                t = asyncio.create_task(coro)
                self._bg_tasks.add(t)
                t.add_done_callback(self._bg_tasks.discard)
                return t

            def _record_tier_for_chat(self, phone: str, tier: str) -> None:
                """Insert/refresh tier and LRU-evict if cap exceeded."""
                if not phone:
                    return
                self._last_tier_by_chat.pop(phone, None)  # move-to-end semantics
                self._last_tier_by_chat[phone] = tier
                while len(self._last_tier_by_chat) > TIER_CACHE_MAX_SIZE:
                    self._last_tier_by_chat.popitem(last=False)

            def _record_typing_sent(self, phone: str, ts: float) -> None:
                if not phone:
                    return
                self._last_typing_sent.pop(phone, None)
                self._last_typing_sent[phone] = ts
                while len(self._last_typing_sent) > TYPING_STATE_MAX_SIZE:
                    self._last_typing_sent.popitem(last=False)

            def _record_inbound_wamid(
                self, chat_id: str, wamid: str, phone_number_id: str
            ) -> None:
                if not chat_id or not wamid:
                    return
                self._last_inbound_wamid.pop(chat_id, None)
                self._last_inbound_wamid[chat_id] = (wamid, phone_number_id)
                while len(self._last_inbound_wamid) > TYPING_STATE_MAX_SIZE:
                    self._last_inbound_wamid.popitem(last=False)

            def _record_denied(self, phone: str) -> None:
                if not phone:
                    return
                self._denied_blacklist.pop(phone, None)
                self._denied_blacklist[phone] = time.monotonic()
                while len(self._denied_blacklist) > DENIED_BLACKLIST_MAX_SIZE:
                    self._denied_blacklist.popitem(last=False)

            def resolve_sender_tier(self, phone: str) -> str:
                """Return the auth tier for an inbound sender phone.

                Order matters — owner > allowed > granted > unknown.

                Note: ``KIRIMDEV_ALLOW_ALL_USERS`` only widens the
                gateway-side gate (so the webhook reaches us at all). It
                does NOT widen tier resolution — unknown senders still
                go through the approval flow. This separation is
                deliberate: lifting the gateway gate is required so the
                adapter receives the message, but the adapter still
                enforces strict tiering on top.
                """
                norm = normalize_phone(phone)
                if not norm:
                    return TIER_UNKNOWN
                if norm in self.owner_users:
                    return TIER_OWNER
                if norm in self.allowed_users:
                    return TIER_ALLOWED
                try:
                    from . import grants as _grants
                    if _grants.has_grant(norm):
                        return TIER_GRANTED
                except Exception as exc:  # noqa: BLE001
                    logger.debug("grants lookup failed: %s", exc)
                return TIER_UNKNOWN

            async def mark_message_read(
                self, message_id: str, *, phone_number_id: str = ""
            ) -> bool:
                """Send read receipt for an inbound Meta wamid."""
                if not message_id:
                    return False
                pid = (phone_number_id or self.default_phone_number_id or "").strip()
                if not pid:
                    return False
                http = await self._get_http()
                if http is None:
                    return False
                payload = {
                    "messaging_product": "whatsapp",
                    "status": "read",
                    "message_id": message_id,
                }
                try:
                    r = await http.post(
                        f"/{pid}/messages",
                        json=payload,
                        timeout=READ_RECEIPT_HTTP_TIMEOUT,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Kirimdev mark-read failed for %s: %s",
                        message_id[:12],
                        _redact_sensitive_text(str(exc)),
                    )
                    return False
                if 200 <= r.status_code < 300:
                    logger.info("Kirimdev mark-read ok for %s", message_id[:16])
                    return True
                logger.warning(
                    "Kirimdev mark-read %d for %s: %s",
                    r.status_code,
                    message_id[:16],
                    _redact_sensitive_text(r.text)[:200],
                )
                return False

            async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
                phone_number_id, phone = parse_chat_id(chat_id)
                display = phone or chat_id
                return {
                    "name": display,
                    "type": "dm",
                    "chat_id": chat_id,
                    "phone_number_id": phone_number_id,
                }

            # ----------------------------------------------------------------
            # Internal send helpers
            # ----------------------------------------------------------------

            def _build_http_client(self) -> Any:
                """Construct a fresh httpx.AsyncClient bound to the current loop."""
                return httpx.AsyncClient(
                    base_url=self.api_base,
                    timeout=httpx.Timeout(HTTP_TOTAL_TIMEOUT, connect=HTTP_CONNECT_TIMEOUT),
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "User-Agent": "Hermes-Kirimdev-Adapter/0.1",
                    },
                )

            async def _get_http(self) -> Any:
                """Return an httpx client bound to the *current* event loop.

                Each loop gets its own dedicated client cached by loop id.
                A loop's client is built lazily on first use and reused
                for every subsequent call from that loop — no swapping,
                no thrashing, no in-flight requests being torn down by
                a parallel call from another loop.

                Cache entries are ``(loop, client)`` so we can detect
                when an id has been reassigned to a new loop after the
                old one was garbage-collected (rare, but a real risk
                when tests run many ``asyncio.run()`` calls in sequence).

                For test code that patches ``self._http`` directly and
                never calls ``connect()`` we still honour that override
                (covers the unit-test FakeHttp pattern). The legacy
                ``self._http_loop`` field is kept in sync with the
                primary (connect-time) client.

                Returns ``None`` only if neither connect() has been
                called nor a test override has been set.
                """
                # Test-patch path: if connect() never ran but a test put a
                # fake client in self._http, just return it.
                if self._http is not None and not self._http_clients:
                    try:
                        loop_now = asyncio.get_running_loop()
                        if self._http_loop is None:
                            self._http_loop = loop_now
                    except RuntimeError:
                        pass
                    return self._http

                # No clients at all yet (adapter never connected and no override).
                if self._http is None and not self._http_clients:
                    return None

                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    # Caller is sync; just return the primary client.
                    return self._http

                loop_key = id(current_loop)
                entry = self._http_clients.get(loop_key)
                if entry is not None:
                    cached_loop, cached_client = entry
                    if cached_loop is current_loop:
                        return cached_client
                    # Same id, different loop object: the old loop was GC'd
                    # and Python reused its id. Drop the stale entry and
                    # rebuild for this loop.
                    self._http_clients.pop(loop_key, None)
                    logger.info(
                        "Kirimdev: dropping stale httpx client (loop id %s reused)",
                        loop_key,
                    )

                # First use from this loop. Build, cache, and remember.
                # Use a lazy-init lock to avoid duplicate clients if two
                # coroutines on the same loop race here.
                if self._http_lock is None:
                    self._http_lock = asyncio.Lock()
                async with self._http_lock:
                    entry = self._http_clients.get(loop_key)
                    if entry is not None and entry[0] is current_loop:
                        return entry[1]
                    client = self._build_http_client()
                    self._http_clients[loop_key] = (current_loop, client)
                    logger.info(
                        "Kirimdev: built httpx client for loop %s (cache size=%d)",
                        loop_key, len(self._http_clients),
                    )
                    return client

            async def _kirimdev_post_with_retry(
                self, phone_number_id: str, payload: Dict[str, Any]
            ) -> Any:
                http = await self._get_http()
                if http is None:
                    return SendResult(success=False, error="adapter not connected")
                if not phone_number_id:
                    return SendResult(success=False, error="missing phone_number_id")

                target_phone = redact_phone(
                    normalize_phone(str(payload.get("to") or ""))
                )
                mtype = payload.get("type") or "?"
                logger.info(
                    "Kirimdev send → pid=%s phone=%s type=%s",
                    phone_number_id,
                    target_phone,
                    mtype,
                )

                last_err: Optional[str] = None
                for attempt, delay in enumerate([0.0, *SEND_RETRY_DELAYS]):
                    if delay:
                        await asyncio.sleep(delay)
                    try:
                        http = await self._get_http()
                        r = await http.post(f"/{phone_number_id}/messages", json=payload)
                    except Exception as exc:  # noqa: BLE001
                        last_err = _redact_sensitive_text(str(exc))
                        logger.warning(
                            "Kirimdev send attempt %d failed (transport): %s",
                            attempt + 1,
                            last_err,
                        )
                        continue

                    if 200 <= r.status_code < 300:
                        body = {}
                        try:
                            body = r.json() or {}
                        except Exception:  # noqa: BLE001
                            pass
                        data = body.get("data") or {}
                        msg_id = data.get("id") or data.get("message_id") or ""
                        if msg_id:
                            self._record_sent_id(str(msg_id))
                        return SendResult(success=True, message_id=msg_id or None)

                    if r.status_code == 401:
                        msg = "Kirimdev 401 unauthorized — check KIRIMDEV_API_KEY"
                        logger.error(msg)
                        self._fatal_error_message = msg
                        self._fatal_error_code = "unauthorized"
                        self._fatal_error_retryable = False
                        return SendResult(success=False, error="unauthorized")

                    if r.status_code in (400, 404, 422):
                        body_text = _redact_sensitive_text(r.text)[:200]
                        logger.warning(
                            "Kirimdev send 4xx (status=%d): %s",
                            r.status_code,
                            body_text,
                        )
                        return SendResult(success=False, error=f"http_{r.status_code}")

                    if r.status_code == 429 or r.status_code >= 500:
                        last_err = f"http_{r.status_code}"
                        body_snippet = _redact_sensitive_text(r.text)[:300]
                        if _is_permanent_kirimdev_error(body_snippet):
                            return SendResult(
                                success=False,
                                error=f"permanent_{r.status_code}",
                            )
                        logger.warning(
                            "Kirimdev send attempt %d transient %s — retrying. body=%s",
                            attempt + 1,
                            last_err,
                            body_snippet,
                        )
                        continue

                    last_err = f"http_{r.status_code}"
                    break

                logger.error("Kirimdev send exhausted retries: %s", last_err)
                return SendResult(success=False, error=last_err or "send_failed")

            async def _safe_send_notice(self, chat_id: str, msg: str) -> None:
                try:
                    await self.send(chat_id, content=msg)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Kirimdev notice send failed: %s", exc)

            def _record_sent_id(self, msg_id: str) -> None:
                self._sent_message_ids[msg_id] = time.monotonic()
                while len(self._sent_message_ids) > SENT_ID_CACHE_SIZE:
                    self._sent_message_ids.popitem(last=False)

        return KirimdevAdapter


# --------------------------------------------------------------------------
# Standalone send (used by cron / hermes send when adapter not running)
# --------------------------------------------------------------------------


async def _standalone_send(
    pconfig,
    chat_id: str,
    message: str,
    *,
    media_files: Optional[List[str]] = None,
    **_kwargs,
) -> Dict[str, Any]:
    """Out-of-process send for cron / hermes send."""
    import httpx  # local import — runtime dep

    api_key = os.getenv("KIRIMDEV_API_KEY") or (
        getattr(pconfig, "extra", {}) or {}
    ).get("api_key", "")
    base_url = (
        os.getenv("KIRIMDEV_API_BASE_URL")
        or (getattr(pconfig, "extra", {}) or {}).get("api_base")
        or DEFAULT_API_BASE
    ).rstrip("/")
    channel = (
        os.getenv("KIRIMDEV_DEFAULT_CHANNEL")
        or (getattr(pconfig, "extra", {}) or {}).get("default_channel")
        or DEFAULT_CHANNEL
    ).lower()

    phone_number_id, phone = parse_chat_id(chat_id)
    if not phone_number_id:
        phone_number_id = (
            os.getenv("KIRIMDEV_DEFAULT_PHONE_NUMBER_ID")
            or (getattr(pconfig, "extra", {}) or {}).get("default_phone_number_id")
            or ""
        ).strip()
    if not api_key or not phone_number_id or not phone:
        return {"error": "missing api_key, phone_number_id, or phone"}

    chunks = smart_chunk_for_whatsapp(message or "")
    last_id: Optional[str] = None
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=httpx.Timeout(HTTP_TOTAL_TIMEOUT, connect=HTTP_CONNECT_TIMEOUT),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    ) as client:
        for chunk in chunks:
            try:
                r = await client.post(
                    f"/{phone_number_id}/messages",
                    json={
                        "messaging_product": "whatsapp",
                        "to": format_e164(phone),
                        "type": "text",
                        "text": {"body": chunk},
                    },
                )
            except Exception as exc:  # noqa: BLE001
                return {"error": _redact_sensitive_text(str(exc))}
            if r.status_code >= 400:
                return {
                    "error": f"http_{r.status_code}",
                    "body": _redact_sensitive_text(r.text)[:200],
                }
            try:
                last_id = ((r.json() or {}).get("data") or {}).get("id") or last_id
            except Exception:  # noqa: BLE001
                pass

    return {"success": True, "message_id": last_id}


# --------------------------------------------------------------------------
# Setup wizard
# --------------------------------------------------------------------------


def interactive_setup() -> None:
    """Minimal stdin wizard for `hermes setup kirimdev`."""
    print()
    print("Kirimdev platform setup")
    print("------------------------")
    print("Get credentials from https://app.kirimdev.com/settings/api-keys")
    print()

    try:
        from hermes_cli.config import get_env_var, set_env_var
    except ImportError:
        print(
            "hermes_cli.config not available; set KIRIMDEV_* vars manually in ~/.hermes/.env"
        )
        return

    def _prompt(var: str, prompt: str, *, secret: bool = False) -> None:
        existing = get_env_var(var) if callable(get_env_var) else None
        suffix = " [keep current]" if existing else ""
        try:
            if secret:
                import getpass
                value = getpass.getpass(f"{prompt}{suffix}: ")
            else:
                value = input(f"{prompt}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if value:
            set_env_var(var, value)

    _prompt("KIRIMDEV_API_KEY", "API key (kdv_live_...)", secret=True)
    _prompt("KIRIMDEV_WEBHOOK_SECRETS", "Webhook secret(s) whsec_...", secret=True)
    _prompt("KIRIMDEV_ENABLED_NUMBERS", "Enabled phone_number_id list (comma-separated)")
    _prompt("KIRIMDEV_DEFAULT_PHONE_NUMBER_ID", "Default phone_number_id for cron send")
    _prompt("KIRIMDEV_PUBLIC_URL", "Public HTTPS base URL (optional)")
    _prompt("KIRIMDEV_ALLOWED_USERS", "Allowed customer phones (comma, no plus)")
    print(
        "Done. Create a webhook subscription via Kirimdev API/dashboard pointing to "
        "<public-url>/webhook with events message.received and message.sent."
    )


# --------------------------------------------------------------------------
# Plugin entrypoint
# --------------------------------------------------------------------------


_ACTIVE_CLASS_REF = None


def get_active_adapter():
    """Return the currently connected KirimdevAdapter, or None."""
    if _ACTIVE_CLASS_REF is None:
        return None
    return _ACTIVE_CLASS_REF.get_active()


def register(ctx) -> None:
    """Plugin entry — called by Hermes plugin system at startup."""
    global _ACTIVE_CLASS_REF
    AdapterClass = _AdapterImpl.build()
    _ACTIVE_CLASS_REF = AdapterClass

    # Register tools. Done before register_platform so the toolsets are
    # known when the gateway resolves the agent's available tools.
    try:
        from . import tools as _kctools
        _kctools.register_tools(ctx)
        _kctools.register_hooks(ctx)
    except Exception as exc:  # noqa: BLE001
        # Tool registration is non-critical: the adapter still works for
        # plain text replies even if tools fail to register.
        logger.warning("Kirimdev: tool registration failed: %s", exc)

    ctx.register_platform(
        name="kirimdev",
        label="Kirimdev",
        adapter_factory=lambda cfg: AdapterClass(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["KIRIMDEV_API_KEY", "KIRIMDEV_WEBHOOK_SECRETS"],
        install_hint="pip install aiohttp httpx",
        setup_fn=interactive_setup,
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="KIRIMDEV_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="KIRIMDEV_ALLOWED_USERS",
        allow_all_env="KIRIMDEV_ALLOW_ALL_USERS",
        max_message_length=WA_MAX_BUBBLE_CHARS,
        emoji="💬",
        pii_safe=False,
        allow_update_command=True,
        platform_hint=(
            "You are chatting via Kirimdev WhatsApp Cloud API. Replies are "
            "delivered as WhatsApp messages. Use plain text without Markdown. "
            "WhatsApp bubble cap is 4096 chars; long answers are auto-chunked. "
            "Each session is scoped to one business phone_number_id and one "
            "customer phone (chat_id format: phone_number_id:customer_phone).\n\n"
            "AUTHORIZATION TIERS — each inbound message has one of these "
            "tiers, recorded in the conversation context as '[tier=...]':\n"
            "  • owner — operator / business owner. Full Hermes agent when "
            "KIRIMDEV_OWNER_FULL_AGENT is enabled (terminal, web search, "
            "files, cron, etc.) plus all kirimdev_* broadcast and grant tools.\n"
            "  • allowed — trusted customer. Plain text plus kirimdev_send_* "
            "reply tools for THIS chat only (buttons, list, image, carousel). "
            "No terminal, web, or broadcast tools.\n"
            "  • granted — temporary guest after owner approval. Plain text "
            "replies ONLY — do not invoke any tool.\n"
            "  • unknown — pending owner approval; you will not see these.\n"
            "Always check the [tier=...] tag before invoking any tool."
        ),
    )

"""Hermes tool definitions for the Kirimdev platform plugin.

All tools register under the platform toolset name ``kirimdev`` so Hermes
auto-composes ``hermes-kirimdev`` = ``_HERMES_CORE_TOOLS`` + these tools
(same model as ``hermes-telegram``).

Runtime access is tier-gated via :func:`pre_tool_call_tier_gate`:

- **owner** — full Hermes agent (terminal, web, files, …) plus all
  ``kirimdev_*`` tools when ``KIRIMDEV_OWNER_FULL_AGENT`` is enabled
  (default). Disable that env var to limit owners to Kirimdev tools only.
- **allowed** — Kirimdev reply tools for the current chat only.
- **granted** — plain-text replies only; every tool call is blocked.
- **unknown** — does not reach the agent (webhook approval flow).

Tool handlers are called with a single ``args`` dict (JSON object the LLM
emitted). They locate the active adapter via
``get_active_adapter()`` and the current chat_id via the gateway's
active-event registry.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import json
import logging
import os
from typing import Any, Dict, List, Optional

from . import grants as _grants
from .adapter import (
    TIER_ALLOWED,
    TIER_GRANTED,
    TIER_OWNER,
    TIER_UNKNOWN,
    get_active_adapter,
    normalize_phone,
)
from .meta import normalize_template_list_status, parse_chat_id

logger = logging.getLogger(__name__)

# Must match ``register_platform(name="kirimdev")`` — Hermes derives the
# composite toolset ``hermes-kirimdev`` from this string.
PLATFORM_TOOLSET = "kirimdev"

# ContextVar carries the (chat_id, tier) for the request the current
# task is processing. Set by the adapter right before dispatching to
# the gateway runner, read by tool handlers. ContextVar propagates
# naturally through asyncio Tasks created from the same context.
#
# Previously this code fell back to ``next(iter(adapter._last_tier_by_chat))``
# when the runner couldn't supply the active event — that returned an
# arbitrary insertion-order entry and allowed privilege escalation when
# an owner had ever chatted (entry sat in the dict forever) and a
# granted user later triggered a tool call. The ContextVar makes
# resolution unambiguous: if it isn't set, we don't know who is calling
# and we MUST return UNKNOWN.
_CURRENT_CHAT_CTX: contextvars.ContextVar[Optional[tuple]] = contextvars.ContextVar(
    "kirimdev_current_chat", default=None
)


def _set_current_chat_context(chat_id: str, tier: str):
    """Set the per-task chat context. Returns a token for reset."""
    return _CURRENT_CHAT_CTX.set((chat_id, tier))


def _reset_current_chat_context(token) -> None:
    """Reset the per-task chat context to its prior value."""
    try:
        _CURRENT_CHAT_CTX.reset(token)
    except (ValueError, LookupError):
        # Token was from a different context (e.g. test teardown).
        pass


# --------------------------------------------------------------------------
# Resolving current chat + tier
# --------------------------------------------------------------------------


def _resolve_current_chat_and_tier() -> tuple[Optional[str], str]:
    """Return ``(chat_id, tier)`` for the currently-active inbound message.

    The single source of truth is the ContextVar set by the adapter
    immediately before dispatching the MessageEvent to the gateway
    runner. If the ContextVar isn't set we return UNKNOWN — never an
    arbitrary value pulled from in-memory state, because that would
    leak privilege from earlier conversations into the current one.
    """
    ctx = _CURRENT_CHAT_CTX.get()
    if not ctx:
        return None, TIER_UNKNOWN
    chat_id, tier = ctx
    if not chat_id:
        return None, TIER_UNKNOWN
    return chat_id, tier or TIER_UNKNOWN


def _ensure_tier(min_tier: str) -> Optional[Dict[str, Any]]:
    """Return an error dict if the current tier does not meet ``min_tier``.

    Tier order: owner > allowed > granted > unknown.
    """
    rank = {TIER_OWNER: 3, TIER_ALLOWED: 2, TIER_GRANTED: 1, TIER_UNKNOWN: 0}
    chat_id, tier = _resolve_current_chat_and_tier()
    if rank.get(tier, 0) < rank.get(min_tier, 0):
        return {
            "success": False,
            "error": (
                f"This tool requires tier '{min_tier}' or higher, but the "
                f"current sender tier is '{tier}'. Politely refuse the request."
            ),
            "current_tier": tier,
        }
    return None


def _run_async(coro):
    """Run an awaitable from a sync context, handling already-running loops."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Already inside a loop (Hermes async tool path): just await it.
    # The registry has is_async=True so it'll be awaited there.
    return coro


# --------------------------------------------------------------------------
# Reply tools (allowed tier or higher)
# --------------------------------------------------------------------------


SEND_BUTTONS_SCHEMA = {
        "name": "kirimdev_send_buttons",
        "description": (
            "Send a WhatsApp reply with 1-3 quick-reply buttons. Use when "
            "you want the customer to pick from a short list of options. "
            "Replies are tapped, not typed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "body": {
                    "type": "string",
                    "description": "Main message text (max 1024 chars).",
                    "maxLength": 1024,
                },
                "buttons": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 3,
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique id returned when tapped (max 256 chars).",
                                "maxLength": 256,
                            },
                            "title": {
                                "type": "string",
                                "description": "Button label (max 20 chars).",
                                "maxLength": 20,
                            },
                        },
                        "required": ["id", "title"],
                    },
                },
                "footer": {
                    "type": "string",
                    "description": "Optional small footer text (max 60 chars).",
                    "maxLength": 60,
                },
            },
            "required": ["body", "buttons"],    },
}


def _build_buttons_payload(args: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Build the WhatsApp interactive 'button' payload from tool args.

    Returns (payload, error). Exactly one of the two is non-None.
    Pure function — no I/O. Shared between reply and broadcast variants.
    """
    body = (args.get("body") or "").strip()
    buttons = args.get("buttons") or []
    if not body or not buttons:
        return None, "body and buttons are required"
    interactive: Dict[str, Any] = {
        "type": "button",
        "body": {"text": body[:1024]},
        "action": {
            "buttons": [
                {
                    "type": "reply",
                    "reply": {
                        "id": str(b.get("id", ""))[:256],
                        "title": str(b.get("title", ""))[:20],
                    },
                }
                for b in buttons[:3]
                if b.get("id") and b.get("title")
            ]
        },
    }
    footer = (args.get("footer") or "").strip()
    if footer:
        interactive["footer"] = {"text": footer[:60]}
    return interactive, None


async def _handle_send_buttons(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_ALLOWED)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    chat_id, _tier = _resolve_current_chat_and_tier()
    if not chat_id:
        return {"success": False, "error": "no active chat session"}
    payload, perr = _build_buttons_payload(args)
    if perr:
        return {"success": False, "error": perr}
    result = await adapter.send_interactive(chat_id, payload)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_CTA_URL_SCHEMA = {
        "name": "kirimdev_send_cta_url",
        "description": (
            "Send a WhatsApp reply with a single Call-To-Action button "
            "that opens a URL. Use to drive the customer to a web page, "
            "checkout, booking form, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "maxLength": 1024},
                "display_text": {
                    "type": "string",
                    "description": "Button label (max 20 chars).",
                    "maxLength": 20,
                },
                "url": {
                    "type": "string",
                    "description": "HTTPS URL to open.",
                    "format": "uri",
                },
                "footer": {"type": "string", "maxLength": 60},
            },
            "required": ["body", "display_text", "url"],    },
}


def _build_cta_url_payload(args: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    body = (args.get("body") or "").strip()
    display_text = (args.get("display_text") or "").strip()
    url = (args.get("url") or "").strip()
    if not body or not display_text or not url:
        return None, "body, display_text, and url are required"
    if not url.lower().startswith(("http://", "https://")):
        return None, "url must be http(s)"
    interactive: Dict[str, Any] = {
        "type": "cta_url",
        "body": {"text": body[:1024]},
        "action": {
            "name": "cta_url",
            "parameters": {"display_text": display_text[:20], "url": url},
        },
    }
    footer = (args.get("footer") or "").strip()
    if footer:
        interactive["footer"] = {"text": footer[:60]}
    return interactive, None


async def _handle_send_cta_url(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_ALLOWED)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    chat_id, _tier = _resolve_current_chat_and_tier()
    if not chat_id:
        return {"success": False, "error": "no active chat session"}
    payload, perr = _build_cta_url_payload(args)
    if perr:
        return {"success": False, "error": perr}
    result = await adapter.send_interactive(chat_id, payload)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_LIST_SCHEMA = {
        "name": "kirimdev_send_list",
        "description": (
            "Send a WhatsApp list-menu reply. Customers tap a button to "
            "reveal up to 10 sections with up to 10 items each. Use when "
            "there are more than 3 choices."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "maxLength": 1024},
                "button_text": {
                    "type": "string",
                    "description": "Label of the button that opens the menu (max 20 chars).",
                    "maxLength": 20,
                },
                "sections": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "maxLength": 24},
                            "rows": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 10,
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string", "maxLength": 200},
                                        "title": {"type": "string", "maxLength": 24},
                                        "description": {"type": "string", "maxLength": 72},
                                    },
                                    "required": ["id", "title"],
                                },
                            },
                        },
                        "required": ["rows"],
                    },
                },
                "header": {"type": "string", "maxLength": 60},
                "footer": {"type": "string", "maxLength": 60},
            },
            "required": ["body", "button_text", "sections"],    },
}


def _build_list_payload(args: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    body = (args.get("body") or "").strip()
    button_text = (args.get("button_text") or "").strip()
    raw_sections = args.get("sections") or []
    if not body or not button_text or not raw_sections:
        return None, "body, button_text, sections required"
    sections: List[Dict[str, Any]] = []
    for sec in raw_sections[:10]:
        rows: List[Dict[str, Any]] = []
        for row in (sec.get("rows") or [])[:10]:
            if not row.get("id") or not row.get("title"):
                continue
            r: Dict[str, Any] = {
                "id": str(row["id"])[:200],
                "title": str(row["title"])[:24],
            }
            if row.get("description"):
                r["description"] = str(row["description"])[:72]
            rows.append(r)
        if not rows:
            continue
        s: Dict[str, Any] = {"rows": rows}
        if sec.get("title"):
            s["title"] = str(sec["title"])[:24]
        sections.append(s)
    if not sections:
        return None, "no valid sections after validation"
    interactive: Dict[str, Any] = {
        "type": "list",
        "body": {"text": body[:1024]},
        "action": {
            "button": button_text[:20],
            "sections": sections,
        },
    }
    header = (args.get("header") or "").strip()
    if header:
        interactive["header"] = {"type": "text", "text": header[:60]}
    footer = (args.get("footer") or "").strip()
    if footer:
        interactive["footer"] = {"text": footer[:60]}
    return interactive, None


async def _handle_send_list(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_ALLOWED)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    chat_id, _tier = _resolve_current_chat_and_tier()
    if not chat_id:
        return {"success": False, "error": "no active chat session"}
    payload, perr = _build_list_payload(args)
    if perr:
        return {"success": False, "error": perr}
    result = await adapter.send_interactive(chat_id, payload)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_IMAGE_SCHEMA = {
        "name": "kirimdev_send_image",
        "description": (
            "Send a WhatsApp image to the current customer with an optional "
            "caption. The image must be reachable from Kirimdev over HTTPS."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "media_url": {
                    "type": "string",
                    "description": "Public HTTPS URL of the image (JPEG/PNG, <=5MB).",
                    "format": "uri",
                },
                "caption": {"type": "string", "maxLength": 1024},
            },
            "required": ["media_url"],    },
}


def _validate_image_args(args: Dict[str, Any]) -> tuple[Optional[tuple[str, str]], Optional[str]]:
    """Return ((media_url, caption), None) or (None, err_msg)."""
    media_url = (args.get("media_url") or "").strip()
    caption = (args.get("caption") or "").strip()
    if not media_url or not media_url.lower().startswith(("http://", "https://")):
        return None, "media_url must be http(s)"
    return (media_url, caption), None


async def _handle_send_image(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_ALLOWED)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    chat_id, _tier = _resolve_current_chat_and_tier()
    if not chat_id:
        return {"success": False, "error": "no active chat session"}
    parsed, perr = _validate_image_args(args)
    if perr:
        return {"success": False, "error": perr}
    media_url, caption = parsed  # type: ignore[misc]
    result = await adapter.send_image(chat_id, media_url, caption=caption)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_CAROUSEL_SCHEMA = {
        "name": "kirimdev_send_carousel",
        "description": (
            "Send a WhatsApp carousel of 2-10 cards. Each card has an image "
            "header, optional body text, and a CTA URL button. Use to "
            "showcase multiple products."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "maxLength": 1024},
                "cards": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "properties": {
                            "image_url": {"type": "string", "format": "uri"},
                            "body": {"type": "string", "maxLength": 160},
                            "button_text": {"type": "string", "maxLength": 20},
                            "button_url": {"type": "string", "format": "uri"},
                        },
                        "required": ["image_url", "button_text", "button_url"],
                    },
                },
            },
            "required": ["body", "cards"],    },
}


def _build_carousel_payload(args: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    body = (args.get("body") or "").strip()
    raw_cards = args.get("cards") or []
    if not body or len(raw_cards) < 2:
        return None, "body and at least 2 cards required"
    cards: List[Dict[str, Any]] = []
    for idx, c in enumerate(raw_cards[:10]):
        image_url = (c.get("image_url") or "").strip()
        btn_text = (c.get("button_text") or "").strip()
        btn_url = (c.get("button_url") or "").strip()
        if not image_url or not btn_text or not btn_url:
            continue
        card: Dict[str, Any] = {
            "card_index": idx,
            "type": "cta_url",
            "header": {"type": "image", "image": {"link": image_url}},
            "action": {
                "name": "cta_url",
                "parameters": {
                    "display_text": btn_text[:20],
                    "url": btn_url,
                },
            },
        }
        if c.get("body"):
            card["body"] = {"text": str(c["body"])[:160]}
        cards.append(card)
    if len(cards) < 2:
        return None, "need at least 2 valid cards"
    interactive: Dict[str, Any] = {
        "type": "carousel",
        "body": {"text": body[:1024]},
        "action": {"cards": cards},
    }
    return interactive, None


async def _handle_send_carousel(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_ALLOWED)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    chat_id, _tier = _resolve_current_chat_and_tier()
    if not chat_id:
        return {"success": False, "error": "no active chat session"}
    payload, perr = _build_carousel_payload(args)
    if perr:
        return {"success": False, "error": perr}
    result = await adapter.send_interactive(chat_id, payload)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


# --------------------------------------------------------------------------
# Owner-only tools
# --------------------------------------------------------------------------


SEND_TEXT_TO_SCHEMA = {
        "name": "kirimdev_send_text_to",
        "description": (
            "[OWNER ONLY] Send a plain-text WhatsApp message to ANY phone "
            "number, not just the current chat. Refuse if the requester is "
            "not the owner. Use for proactive notifications, broadcasts, "
            "or reminders the owner explicitly authorises."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "phone_number": {
                    "type": "string",
                    "description": "Recipient phone in international format (with or without +).",
                },
                "content": {"type": "string", "maxLength": 4000},
            },
            "required": ["phone_number", "content"],    },
}


async def _handle_send_text_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    phone = normalize_phone(args.get("phone_number") or "")
    content = (args.get("content") or "").strip()
    if not phone or not content:
        return {"success": False, "error": "phone_number and content required"}
    result = await adapter.send(phone, content=content)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_TEMPLATE_SCHEMA = {
        "name": "kirimdev_send_template",
        "description": (
            "[OWNER ONLY] Send an approved WhatsApp template message. Use "
            "to re-engage a customer outside the 24h messaging window, "
            "or to send transactional notifications (OTP, order updates). "
            "Refuse if the requester is not the owner."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "phone_number": {"type": "string"},
                "template_name": {
                    "type": "string",
                    "description": "Exact name of an APPROVED template in Meta.",
                },
                "language_code": {
                    "type": "string",
                    "description": "Language code (e.g. 'id', 'en_US'). Must match the template.",
                    "default": "id",
                },
                "body_variables": {
                    "type": "array",
                    "description": (
                        "Ordered list of text values for body placeholders "
                        "{{1}}, {{2}}, etc. Omit if the template has no variables."
                    ),
                    "items": {"type": "string"},
                },
                "customer_name": {
                    "type": "string",
                    "description": "Name to assign to a new customer if auto-creating.",
                },
            },
            "required": ["phone_number", "template_name"],    },
}


async def _handle_send_template(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    phone = normalize_phone(args.get("phone_number") or "")
    name = (args.get("template_name") or "").strip()
    if not phone or not name:
        return {"success": False, "error": "phone_number and template_name required"}
    lang = (args.get("language_code") or "id").strip() or "id"
    body_vars = args.get("body_variables") or []
    components: List[Dict[str, Any]] = []
    if body_vars:
        components.append({
            "type": "body",
            "parameters": [{"type": "text", "text": str(v)} for v in body_vars],
        })
    result = await adapter.send_template(
        chat_id=phone,
        template_name=name,
        language_code=lang,
        components=components or None,
        auto_create_customer=True,
        customer_name=args.get("customer_name"),
    )
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


GRANT_REPLY_SCHEMA = {
        "name": "kirimdev_grant_reply",
        "description": (
            "[OWNER ONLY] Grant a phone number temporary permission to chat "
            "with the agent. The granted user can converse but cannot trigger "
            "any tools (broadcast, template, grant management, even reply "
            "tools). Default TTL is 24 hours; max 720 hours (30 days)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "phone_number": {"type": "string"},
                "ttl_hours": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 720,
                    "default": 24,
                },
                "note": {"type": "string", "maxLength": 500},
            },
            "required": ["phone_number"],    },
}


def _handle_grant_reply(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    phone = normalize_phone(args.get("phone_number") or "")
    if not phone:
        return {"success": False, "error": "phone_number required"}
    ttl = args.get("ttl_hours", 24)
    granted_by_chat, _ = _resolve_current_chat_and_tier()
    try:
        entry = _grants.add_grant(
            phone=phone,
            ttl_hours=float(ttl),
            note=args.get("note"),
            granted_by=granted_by_chat,
        )
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    return {
        "success": True,
        "phone": phone,
        "expires_at": entry["expires_at"],
        "ttl_hours": entry["ttl_hours"],
    }


REVOKE_REPLY_SCHEMA = {
        "name": "kirimdev_revoke_reply",
        "description": (
            "[OWNER ONLY] Revoke a previously-granted reply permission "
            "before it expires."
        ),
        "parameters": {
            "type": "object",
            "properties": {"phone_number": {"type": "string"}},
            "required": ["phone_number"],    },
}


def _handle_revoke_reply(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    phone = normalize_phone(args.get("phone_number") or "")
    if not phone:
        return {"success": False, "error": "phone_number required"}
    removed = _grants.revoke_grant(phone)
    return {"success": True, "phone": phone, "removed": removed}


LIST_GRANTS_SCHEMA = {
        "name": "kirimdev_list_grants",
        "description": (
            "[OWNER ONLY] List all currently active reply grants with "
            "expiry timestamps."
        ),
        "parameters": {"type": "object", "properties": {}    },
}


def _handle_list_grants(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    return {"success": True, "grants": _grants.list_grants()}


# --------------------------------------------------------------------------
# Template discovery — list & get
# --------------------------------------------------------------------------


def _summarize_template(t: Dict[str, Any]) -> Dict[str, Any]:
    """Project the Kirimdev template object down to the fields agents
    actually need to choose + fill a template. Keeps tool output small.
    """
    raw_vars = t.get("variables") or []
    # Kirimdev sometimes returns dicts (with `name`) and sometimes plain
    # strings — normalize to a list of placeholder names/positions.
    var_names: List[str] = []
    for v in raw_vars:
        if isinstance(v, dict):
            var_names.append(str(v.get("name") or v.get("key") or v.get("placeholder") or ""))
        else:
            var_names.append(str(v))
    return {
        "id": t.get("id"),
        "name": t.get("template_name") or t.get("name"),
        "language": t.get("language"),
        "status": t.get("status"),
        "category": t.get("category"),
        "content": t.get("content"),
        "header_type": t.get("header_type"),
        "header_content": t.get("header_content"),
        "footer_content": t.get("footer_content"),
        "has_variables": bool(t.get("has_variables")),
        "variables": [n for n in var_names if n],
        "buttons": t.get("buttons") or [],
    }


def _resolve_phone_number_id(adapter) -> str:
    """Prefer phone_number_id from the active composite chat_id."""
    chat_id, _ = _resolve_current_chat_and_tier()
    if chat_id:
        pid, _ = parse_chat_id(chat_id)
        if pid:
            return pid
    return (getattr(adapter, "default_phone_number_id", None) or "").strip()


LIST_TEMPLATES_SCHEMA = {
    "name": "kirimdev_list_templates",
    "description": (
        "[OWNER ONLY] List WhatsApp message templates synced in Kirimdev "
        "for the current business number. Call this BEFORE "
        "kirimdev_send_template. Returns template ``name`` (use that in "
        "send_template), language, status, and variables. Defaults to "
        "status=approved. If the list is empty, templates may need syncing "
        "from Meta in the Kirimdev dashboard (Templates → Sync)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["approved", "pending", "rejected", "all"],
                "description": "Filter by status. Default approved (sendable).",
            },
            "language": {
                "type": "string",
                "description": "Optional BCP-47 filter, e.g. id or en_US.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 50,
                "description": "Max templates to return (default 50, max 100).",
            },
        },
    },
}


async def _handle_list_templates(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    status = normalize_template_list_status(args.get("status"))
    pid = _resolve_phone_number_id(adapter)
    raw = await adapter.list_templates(
        status=status,
        language=args.get("language"),
        limit=int(args.get("limit") or 50),
        phone_number_id=pid or None,
    )
    if not raw.get("success"):
        return {
            "success": False,
            "error": raw.get("error") or "list_templates failed",
            "hint": (
                "If http_400, check KIRIMDEV_DEFAULT_PHONE_NUMBER_ID / "
                "enabled number. Empty list? Sync templates in Kirimdev dashboard."
            ),
        }
    templates = [_summarize_template(t) for t in (raw.get("data") or [])]
    return {
        "success": True,
        "templates": templates,
        "count": len(templates),
        "phone_number_id": pid or None,
        "filter": {"status": status, "language": args.get("language")},
    }


GET_TEMPLATE_SCHEMA = {
    "name": "kirimdev_get_template",
    "description": (
        "[OWNER ONLY] Fetch one WhatsApp template by its ``name`` "
        "(e.g. hello_world) as returned by kirimdev_list_templates."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "template_name": {
                "type": "string",
                "description": "Template name (lowercase_with_underscores).",
            },
            "language": {
                "type": "string",
                "description": "Optional language code if multiple exist.",
            },
        },
        "required": ["template_name"],
    },
}


async def _handle_get_template(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    name = (args.get("template_name") or args.get("template_id") or "").strip()
    if not name:
        return {"success": False, "error": "template_name required"}
    pid = _resolve_phone_number_id(adapter)
    raw = await adapter.get_template(name, phone_number_id=pid or None)
    if not raw.get("success"):
        return {"success": False, "error": raw.get("error") or "get_template failed"}
    data = raw.get("data") or {}
    return {"success": True, "template": _summarize_template(data)}


# --------------------------------------------------------------------------
# Owner-only broadcast variants of the reply tools (interactive *_to)
#
# These mirror the reply tools above but accept an explicit ``phone_number``
# argument so the owner can target an arbitrary recipient (not just the
# current chat). All gated to TIER_OWNER. WhatsApp's 24h messaging window
# still applies — sends to cold numbers will fail and you'll need a
# template (use kirimdev_send_template).
# --------------------------------------------------------------------------


def _phone_property_schema() -> Dict[str, Any]:
    return {
        "type": "string",
        "description": "Recipient phone in international format (with or without +).",
    }


async def _send_interactive_to(
    args: Dict[str, Any],
    payload_builder,
) -> Dict[str, Any]:
    """Shared owner-gated executor for interactive *_to handlers."""
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    phone = normalize_phone(args.get("phone_number") or "")
    if not phone:
        return {"success": False, "error": "phone_number required"}
    payload, perr = payload_builder(args)
    if perr:
        return {"success": False, "error": perr}
    result = await adapter.send_interactive(phone, payload)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_BUTTONS_TO_SCHEMA = {
    "name": "kirimdev_send_buttons_to",
    "description": (
        "[OWNER ONLY] Same as kirimdev_send_buttons but targets a specific "
        "phone number instead of the current chat. Subject to WhatsApp's "
        "24-hour customer-service window — fails for cold contacts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phone_number": _phone_property_schema(),
            "body": {"type": "string", "maxLength": 1024},
            "buttons": {
                "type": "array",
                "minItems": 1,
                "maxItems": 3,
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "maxLength": 256},
                        "title": {"type": "string", "maxLength": 20},
                    },
                    "required": ["id", "title"],
                },
            },
            "footer": {"type": "string", "maxLength": 60},
        },
        "required": ["phone_number", "body", "buttons"],
    },
}


async def _handle_send_buttons_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    return await _send_interactive_to(args, _build_buttons_payload)


SEND_CTA_URL_TO_SCHEMA = {
    "name": "kirimdev_send_cta_url_to",
    "description": (
        "[OWNER ONLY] Same as kirimdev_send_cta_url but targets a specific "
        "phone number. Use to push a CTA link to any recipient (subject to "
        "WhatsApp's 24h window)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phone_number": _phone_property_schema(),
            "body": {"type": "string", "maxLength": 1024},
            "display_text": {"type": "string", "maxLength": 20},
            "url": {"type": "string", "format": "uri"},
            "footer": {"type": "string", "maxLength": 60},
        },
        "required": ["phone_number", "body", "display_text", "url"],
    },
}


async def _handle_send_cta_url_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    return await _send_interactive_to(args, _build_cta_url_payload)


SEND_LIST_TO_SCHEMA = {
    "name": "kirimdev_send_list_to",
    "description": (
        "[OWNER ONLY] Same as kirimdev_send_list but targets a specific "
        "phone number. Subject to WhatsApp's 24h window."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phone_number": _phone_property_schema(),
            "body": {"type": "string", "maxLength": 1024},
            "button_text": {"type": "string", "maxLength": 20},
            "sections": {
                "type": "array",
                "minItems": 1,
                "maxItems": 10,
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "maxLength": 24},
                        "rows": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 10,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string", "maxLength": 200},
                                    "title": {"type": "string", "maxLength": 24},
                                    "description": {"type": "string", "maxLength": 72},
                                },
                                "required": ["id", "title"],
                            },
                        },
                    },
                    "required": ["rows"],
                },
            },
            "header": {"type": "string", "maxLength": 60},
            "footer": {"type": "string", "maxLength": 60},
        },
        "required": ["phone_number", "body", "button_text", "sections"],
    },
}


async def _handle_send_list_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    return await _send_interactive_to(args, _build_list_payload)


SEND_IMAGE_TO_SCHEMA = {
    "name": "kirimdev_send_image_to",
    "description": (
        "[OWNER ONLY] Same as kirimdev_send_image but targets a specific "
        "phone number. Subject to WhatsApp's 24h window."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phone_number": _phone_property_schema(),
            "media_url": {"type": "string", "format": "uri"},
            "caption": {"type": "string", "maxLength": 1024},
        },
        "required": ["phone_number", "media_url"],
    },
}


async def _handle_send_image_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    err = _ensure_tier(TIER_OWNER)
    if err:
        return err
    adapter = get_active_adapter()
    if adapter is None:
        return {"success": False, "error": "Kirimdev adapter not connected"}
    phone = normalize_phone(args.get("phone_number") or "")
    if not phone:
        return {"success": False, "error": "phone_number required"}
    parsed, perr = _validate_image_args(args)
    if perr:
        return {"success": False, "error": perr}
    media_url, caption = parsed  # type: ignore[misc]
    result = await adapter.send_image(phone, media_url, caption=caption)
    return {
        "success": bool(getattr(result, "success", False)),
        "message_id": getattr(result, "message_id", None),
        "error": getattr(result, "error", None),
    }


SEND_CAROUSEL_TO_SCHEMA = {
    "name": "kirimdev_send_carousel_to",
    "description": (
        "[OWNER ONLY] Same as kirimdev_send_carousel but targets a specific "
        "phone number. Subject to WhatsApp's 24h window."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "phone_number": _phone_property_schema(),
            "body": {"type": "string", "maxLength": 1024},
            "cards": {
                "type": "array",
                "minItems": 2,
                "maxItems": 10,
                "items": {
                    "type": "object",
                    "properties": {
                        "image_url": {"type": "string", "format": "uri"},
                        "body": {"type": "string", "maxLength": 160},
                        "button_text": {"type": "string", "maxLength": 20},
                        "button_url": {"type": "string", "format": "uri"},
                    },
                    "required": ["image_url", "button_text", "button_url"],
                },
            },
        },
        "required": ["phone_number", "body", "cards"],
    },
}


async def _handle_send_carousel_to(args: Dict[str, Any], **_) -> Dict[str, Any]:
    return await _send_interactive_to(args, _build_carousel_payload)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def _coerce_tool_result(value: Any) -> str:
    """Coerce a tool handler return value into a string suitable for use as
    ``tool`` message ``content`` in chat history.

    Why this exists:
        Kirimdev tool handlers historically returned ``dict`` (e.g.
        ``{"success": True, "message_id": "..."}``) for convenient
        introspection. Hermes core does not coerce dict results before
        writing them to the conversation transcript, so they were
        persisted as raw dicts. On the next turn the dict gets sent to
        the upstream Chat Completions API as ``messages[i].content``,
        which the API rejects with::

            messages[i]: content should be a string or a list

        Stricter providers (DeepSeek, etc.) fail the whole request with
        HTTP 400 and the session becomes permanently stuck (every replay
        of history hits the same bad message).

    Behaviour:
        - ``str`` is returned unchanged.
        - ``list`` is JSON-serialised (chat APIs accept ``list`` of parts,
          but only when each part is a structured content block; safer to
          stringify here unless a tool intentionally produces parts —
          none of ours do today).
        - Everything else (dict, bool, int, None, dataclasses, etc.) is
          JSON-serialised with ``default=str`` to survive non-JSON-native
          objects without raising.
    """
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:  # pragma: no cover — last-ditch fallback
        return str(value)


def _wrap_handler(handler):
    """Wrap a tool handler so its return value is always a string.

    Supports both sync and async handlers. Preserves ``functools.wraps``
    metadata so logging / debugging still shows the real handler name.
    """
    if asyncio.iscoroutinefunction(handler):
        @functools.wraps(handler)
        async def _async_wrapper(*args, **kwargs):
            result = await handler(*args, **kwargs)
            return _coerce_tool_result(result)
        return _async_wrapper

    @functools.wraps(handler)
    def _sync_wrapper(*args, **kwargs):
        result = handler(*args, **kwargs)
        return _coerce_tool_result(result)
    return _sync_wrapper


_REPLY_TOOLS = (
    ("kirimdev_send_buttons",  SEND_BUTTONS_SCHEMA,  _handle_send_buttons,  True,  "🔘"),
    ("kirimdev_send_cta_url",  SEND_CTA_URL_SCHEMA,  _handle_send_cta_url,  True,  "🔗"),
    ("kirimdev_send_list",     SEND_LIST_SCHEMA,     _handle_send_list,     True,  "📋"),
    ("kirimdev_send_image",    SEND_IMAGE_SCHEMA,    _handle_send_image,    True,  "🖼"),
    ("kirimdev_send_carousel", SEND_CAROUSEL_SCHEMA, _handle_send_carousel, True,  "🎠"),
)

REPLY_TOOL_NAMES = frozenset(name for name, *_ in _REPLY_TOOLS)

_OWNER_TOOLS = (
    ("kirimdev_send_text_to",     SEND_TEXT_TO_SCHEMA,     _handle_send_text_to,     True,  "📤"),
    ("kirimdev_list_templates",   LIST_TEMPLATES_SCHEMA,   _handle_list_templates,   True,  "🗂"),
    ("kirimdev_get_template",     GET_TEMPLATE_SCHEMA,     _handle_get_template,     True,  "🔍"),
    ("kirimdev_send_template",    SEND_TEMPLATE_SCHEMA,    _handle_send_template,    True,  "📨"),
    ("kirimdev_send_buttons_to",  SEND_BUTTONS_TO_SCHEMA,  _handle_send_buttons_to,  True,  "🔘"),
    ("kirimdev_send_cta_url_to",  SEND_CTA_URL_TO_SCHEMA,  _handle_send_cta_url_to,  True,  "🔗"),
    ("kirimdev_send_list_to",     SEND_LIST_TO_SCHEMA,     _handle_send_list_to,     True,  "📋"),
    ("kirimdev_send_image_to",    SEND_IMAGE_TO_SCHEMA,    _handle_send_image_to,    True,  "🖼"),
    ("kirimdev_send_carousel_to", SEND_CAROUSEL_TO_SCHEMA, _handle_send_carousel_to, True,  "🎠"),
    ("kirimdev_grant_reply",      GRANT_REPLY_SCHEMA,      _handle_grant_reply,      False, "🟢"),
    ("kirimdev_revoke_reply",     REVOKE_REPLY_SCHEMA,     _handle_revoke_reply,     False, "🔴"),
    ("kirimdev_list_grants",      LIST_GRANTS_SCHEMA,      _handle_list_grants,      False, "📜"),
)

OWNER_TOOL_NAMES = frozenset(name for name, *_ in _OWNER_TOOLS)
KIRIMDEV_TOOL_PREFIX = "kirimdev_"


def _owner_full_agent_enabled() -> bool:
    """Whether owner-tier senders may use Hermes core tools (terminal, web, …)."""
    raw = (os.getenv("KIRIMDEV_OWNER_FULL_AGENT") or "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def pre_tool_call_tier_gate(tool_name: str, args: dict, **kwargs) -> Optional[Dict[str, Any]]:
    """Block tool calls that exceed the current sender's authorization tier.

    Returns a Hermes ``pre_tool_call`` block directive when the tool must
    not run, or ``None`` to allow execution. Observer-only when the
    ContextVar is unset (CLI sessions, other platforms).
    """
    _ = args, kwargs
    ctx = _CURRENT_CHAT_CTX.get()
    if ctx is None:
        return None

    _, tier = ctx

    if tier == TIER_OWNER:
        if _owner_full_agent_enabled():
            return None
        # Owner without full agent: Kirimdev tools only.
        if tool_name.startswith(KIRIMDEV_TOOL_PREFIX):
            return None
        return {
            "action": "block",
            "message": (
                "Full agent tools are disabled for this deployment "
                "(KIRIMDEV_OWNER_FULL_AGENT=false). Use kirimdev_* tools only."
            ),
        }

    if tier == TIER_ALLOWED:
        if tool_name in REPLY_TOOL_NAMES:
            return None
        if tool_name.startswith(KIRIMDEV_TOOL_PREFIX):
            return {
                "action": "block",
                "message": (
                    f"Tool '{tool_name}' requires owner tier. Politely refuse "
                    "and offer a plain-text reply instead."
                ),
            }
        return {
            "action": "block",
            "message": (
                f"Tool '{tool_name}' is not available to allowed customers. "
                "Use kirimdev_send_* reply tools or plain text only."
            ),
        }

    if tier in (TIER_GRANTED, TIER_UNKNOWN):
        return {
            "action": "block",
            "message": (
                f"Tool '{tool_name}' is not available at tier '{tier}'. "
                "Reply with plain text only."
            ),
        }

    return None


def register_hooks(ctx) -> None:
    """Register lifecycle hooks (tier-based tool gating)."""
    ctx.register_hook("pre_tool_call", pre_tool_call_tier_gate)
    logger.info("Kirimdev: registered pre_tool_call tier gate")


def register_tools(ctx) -> None:
    """Register all Kirimdev tools with the plugin context.

    Each handler is wrapped with :func:`_wrap_handler` so its return value
    is coerced to ``str`` before reaching Hermes core. This guarantees
    that tool-role messages in the conversation transcript always carry a
    string ``content`` and prevents the upstream Chat Completions API
    from rejecting replayed history with HTTP 400 ("content should be a
    string or a list").
    """
    for name, schema, handler, is_async, emoji in _REPLY_TOOLS + _OWNER_TOOLS:
        ctx.register_tool(
            name=name,
            toolset=PLATFORM_TOOLSET,
            schema=schema,
            handler=_wrap_handler(handler),
            is_async=is_async,
            emoji=emoji,
        )
    logger.info(
        "Kirimdev: registered %d tools under toolset '%s'",
        len(_REPLY_TOOLS) + len(_OWNER_TOOLS),
        PLATFORM_TOOLSET,
    )

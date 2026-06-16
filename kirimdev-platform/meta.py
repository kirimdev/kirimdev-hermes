"""Kirimdev webhook + chat-id helpers (Meta pass-through payloads)."""

from __future__ import annotations

import hmac
import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple

# Approval / deny button prefixes (owner flow).
APPROVE_PREFIX = "kd_approve:"
DENY_PREFIX = "kd_deny:"

CHAT_ID_SEP = ":"


def format_e164(phone_digits: str) -> str:
    """Convert normalized digits to E.164 (+ prefix)."""
    digits = re.sub(r"\D", "", phone_digits or "")
    if not digits:
        return ""
    return f"+{digits}"


def make_chat_id(phone_number_id: str, customer_phone: str) -> str:
    """Composite session key: ``{business_phone_number_id}:{customer_digits}``."""
    pid = (phone_number_id or "").strip()
    phone = re.sub(r"\D", "", customer_phone or "")
    if not pid or not phone:
        return phone or pid
    return f"{pid}{CHAT_ID_SEP}{phone}"


def parse_chat_id(chat_id: str) -> Tuple[str, str]:
    """Return ``(phone_number_id, customer_phone_digits)``."""
    raw = (chat_id or "").strip()
    if CHAT_ID_SEP in raw:
        pid, phone = raw.split(CHAT_ID_SEP, 1)
        return pid.strip(), re.sub(r"\D", "", phone)
    return "", re.sub(r"\D", "", raw)


def verify_kirim_signature(
    raw_body: bytes,
    header_value: Optional[str],
    secrets: List[str],
    *,
    tolerance_sec: int = 300,
    insecure_no_auth: bool = False,
) -> bool:
    """Verify ``X-Kirim-Signature: t=<ts>,v1=<hex>`` per Kirimdev docs."""
    if insecure_no_auth:
        return True
    if not header_value or not secrets:
        return False
    parts = header_value.split(",")
    t_entry = next((p for p in parts if p.startswith("t=")), None)
    if not t_entry:
        return False
    try:
        t = int(t_entry[2:])
    except ValueError:
        return False
    if abs(time.time() - t) > tolerance_sec:
        return False

    try:
        supplied = [bytes.fromhex(p[3:]) for p in parts if p.startswith("v1=")]
    except ValueError:
        return False
    if not supplied:
        return False

    signed_payload = f"{t}.".encode("utf-8") + raw_body
    for secret in secrets:
        if not secret:
            continue
        expected = hmac.new(
            secret.encode("utf-8"), signed_payload, hashlib.sha256
        ).digest()
        for sig in supplied:
            if hmac.compare_digest(sig, expected):
                return True
    return False


def _message_text(msg: Dict[str, Any]) -> Tuple[str, str]:
    """Return ``(message_type, text_content)`` from a Meta message object."""
    mtype = (msg.get("type") or "text").lower()
    if mtype == "text":
        body = (msg.get("text") or {}).get("body") or ""
        return "text", str(body)
    if mtype == "interactive":
        interactive = msg.get("interactive") or {}
        itype = (interactive.get("type") or "").lower()
        if itype == "button_reply":
            br = interactive.get("button_reply") or {}
            return "interactive", str(br.get("title") or br.get("id") or "")
        if itype == "list_reply":
            lr = interactive.get("list_reply") or {}
            return "interactive", str(lr.get("title") or lr.get("id") or "")
        return "interactive", ""
    if mtype == "button":
        btn = msg.get("button") or {}
        return "button", str(btn.get("text") or btn.get("payload") or "")
    if mtype == "image":
        img = msg.get("image") or {}
        return "image", str(img.get("caption") or "")
    if mtype in ("audio", "voice"):
        return mtype, ""
    if mtype == "video":
        vid = msg.get("video") or {}
        return "video", str(vid.get("caption") or "")
    return mtype, ""


def normalize_template_list_status(raw: Optional[str]) -> str:
    """Map agent/Meta-style status labels to Kirimdev ``GET /templates`` values.

    Public API accepts: ``approved``, ``pending``, ``rejected``, ``all``
    (lowercase). Uppercase Meta labels (``APPROVED``) cause HTTP 400.
    """
    if not raw:
        return "approved"
    key = str(raw).strip()
    lower = key.lower()
    if lower in {"approved", "pending", "rejected", "all"}:
        return lower
    upper_map = {
        "APPROVED": "approved",
        "PENDING": "pending",
        "REJECTED": "rejected",
        "ALL": "all",
        "PAUSED": "pending",
        "DISABLED": "rejected",
    }
    return upper_map.get(key, "approved")


def extract_button_reply(msg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Pull button/list reply id from a Meta message object."""
    if not isinstance(msg, dict):
        return None, None
    interactive = msg.get("interactive") or {}
    if isinstance(interactive, dict):
        btn = interactive.get("button_reply") or {}
        if isinstance(btn, dict) and btn.get("id"):
            return str(btn["id"]), str(btn.get("title") or "")
        lst = interactive.get("list_reply") or {}
        if isinstance(lst, dict) and lst.get("id"):
            return str(lst["id"]), str(lst.get("title") or "")
    return None, None


def parse_meta_inbound(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize Kirimdev ``message.received`` Meta pass-through payloads.

    Each item:
      phone_number_id, customer_phone, wamid, message_type, content,
      customer_name, raw_message, kirim (optional enrichment block)
    """
    if not isinstance(body, dict):
        return []
    if body.get("object") != "whatsapp_business_account":
        return []

    kirim_block = body.get("kirim")
    kirim_ctx = kirim_block if isinstance(kirim_block, dict) else None

    out: List[Dict[str, Any]] = []
    for entry in body.get("entry") or []:
        if not isinstance(entry, dict):
            continue
        for change in entry.get("changes") or []:
            if not isinstance(change, dict):
                continue
            if change.get("field") != "messages":
                continue
            value = change.get("value") or {}
            if not isinstance(value, dict):
                continue
            metadata = value.get("metadata") or {}
            phone_number_id = str(metadata.get("phone_number_id") or "").strip()
            if not phone_number_id:
                continue

            names: Dict[str, str] = {}
            for c in value.get("contacts") or []:
                if not isinstance(c, dict):
                    continue
                wa_id = re.sub(r"\D", "", str(c.get("wa_id") or ""))
                profile = c.get("profile") or {}
                if wa_id and isinstance(profile, dict):
                    names[wa_id] = str(profile.get("name") or "")

            for msg in value.get("messages") or []:
                if not isinstance(msg, dict):
                    continue
                from_raw = msg.get("from") or ""
                customer_phone = re.sub(r"\D", "", str(from_raw))
                if not customer_phone:
                    continue
                wamid = str(msg.get("id") or "")
                mtype, content = _message_text(msg)
                out.append(
                    {
                        "phone_number_id": phone_number_id,
                        "customer_phone": customer_phone,
                        "wamid": wamid,
                        "message_type": mtype,
                        "content": content,
                        "customer_name": names.get(customer_phone, ""),
                        "raw_message": msg,
                        "kirim": kirim_ctx,
                    }
                )
    return out


def parse_message_sent(body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize Kirimdev ``message.sent`` webhook envelope."""
    if not isinstance(body, dict):
        return None
    if body.get("type") != "message.sent":
        return None
    data = body.get("data")
    if not isinstance(data, dict):
        return None
    msg = data.get("message") or {}
    meta_block = data.get("meta") or {}
    contact = data.get("contact") or {}
    if not isinstance(msg, dict):
        return None
    phone_number_id = str(
        data.get("session") or meta_block.get("phone_number_id") or ""
    ).strip()
    to_raw = msg.get("to") or contact.get("phone_number") or ""
    customer_phone = re.sub(r"\D", "", str(to_raw))
    return {
        "phone_number_id": phone_number_id,
        "customer_phone": customer_phone,
        "provider_id": str(msg.get("provider_id") or ""),
        "source": str(msg.get("source") or ""),
        "body": msg.get("body"),
        "message_type": str(msg.get("type") or ""),
    }

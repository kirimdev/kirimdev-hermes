"""Tests for kirimdev.meta helpers."""

from __future__ import annotations

import hashlib
import hmac
import sys
import time
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))

import meta  # noqa: E402


def test_make_and_parse_chat_id():
    cid = meta.make_chat_id("12345", "+628123456789")
    assert cid == "12345:628123456789"
    pid, phone = meta.parse_chat_id(cid)
    assert pid == "12345"
    assert phone == "628123456789"


def test_verify_kirim_signature_valid():
    secret = "whsec_test"
    body = b'{"object":"whatsapp_business_account"}'
    t = int(time.time())
    sig = hmac.new(
        secret.encode(),
        f"{t}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    header = f"t={t},v1={sig}"
    assert meta.verify_kirim_signature(body, header, [secret]) is True


def test_verify_kirim_signature_rejects_bad():
    body = b"{}"
    assert meta.verify_kirim_signature(body, "t=1,v1=00", ["secret"]) is False


def test_parse_meta_inbound_text():
    payload = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "metadata": {"phone_number_id": "999"},
                            "contacts": [
                                {
                                    "wa_id": "628111",
                                    "profile": {"name": "Ali"},
                                }
                            ],
                            "messages": [
                                {
                                    "from": "628111",
                                    "id": "wamid.abc",
                                    "type": "text",
                                    "text": {"body": "halo"},
                                }
                            ],
                        },
                    }
                ]
            }
        ],
    }
    items = meta.parse_meta_inbound(payload)
    assert len(items) == 1
    assert items[0]["phone_number_id"] == "999"
    assert items[0]["customer_phone"] == "628111"
    assert items[0]["content"] == "halo"
    assert items[0]["wamid"] == "wamid.abc"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, "approved"),
        ("APPROVED", "approved"),
        ("pending", "pending"),
        ("all", "all"),
        ("PAUSED", "pending"),
    ],
)
def test_normalize_template_list_status(raw, expected):
    assert meta.normalize_template_list_status(raw) == expected

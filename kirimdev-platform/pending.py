"""Persistent storage for pending approval requests.

When an unknown sender (tier=unknown) messages the agent, the adapter
stashes their message here and sends an approval prompt to the owner.
The owner's button tap (Approve / Deny) is matched against this store
by pending_id.

Storage: JSON file at ``~/.hermes/kirimdev_pending.json``. Atomic
write via tmp+rename. Stale entries (older than ``MAX_AGE_HOURS``)
are pruned on every load.

Pending IDs are prefixed ``pend_`` for human readability and use the
phone-derived hash as the discriminator so the same sender retries
collapse to the same ID (built-in dedup).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

# Reuse the cross-platform file lock implemented in grants.py so we
# have a single source of truth for the locking primitive.
try:
    from .grants import _file_lock  # type: ignore
except ImportError:
    # When loaded as a standalone module (some test setups) — fall
    # back to a no-op context manager; callers still get correctness
    # in single-process asyncio thanks to the lack of awaits inside
    # the critical section.
    import contextlib as _ctxlib

    @_ctxlib.contextmanager
    def _file_lock(_path):  # type: ignore[no-redef]
        yield


logger = logging.getLogger(__name__)

DEFAULT_PENDING_FILE = "~/.hermes/kirimdev_pending.json"
MAX_AGE_HOURS = 24  # auto-expire stale approval prompts


def _pending_path() -> Path:
    return Path(
        os.path.expanduser(
            os.getenv("KIRIMDEV_PENDING_FILE", DEFAULT_PENDING_FILE)
        )
    )


def _normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    return "".join(ch for ch in phone if ch.isdigit())


def _phone_hash(phone: str) -> str:
    """Deterministic short hash so retries from the same phone collapse to one id."""
    return hashlib.sha256(phone.encode("utf-8")).hexdigest()[:10]


def make_pending_id(phone: str) -> str:
    return f"pend_{_phone_hash(phone)}"


def _load_raw() -> Dict[str, dict]:
    path = _pending_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Kirimdev pending file unreadable: %s — starting empty", exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("Kirimdev pending file malformed — ignoring")
        return {}
    return data


_TMP_PREFIX = ".kirimdev_pending."
_TMP_SUFFIX = ".tmp"


def _save_raw(data: Dict[str, dict]) -> None:
    path = _pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=_TMP_PREFIX,
        suffix=_TMP_SUFFIX,
        delete=False,
    )
    tmp_name = tmp.name
    try:
        try:
            json.dump(data, tmp, indent=2, sort_keys=True)
            tmp.flush()
            try:
                os.fsync(tmp.fileno())
            except OSError:
                pass
        finally:
            try:
                tmp.close()
            except Exception:  # noqa: BLE001
                pass
        os.replace(tmp_name, path)
        tmp_name = None
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if tmp_name is not None and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def sweep_orphan_tmp_files() -> int:
    """Remove leftover ``.kirimdev_pending.*.tmp`` files. See
    grants.sweep_orphan_tmp_files for rationale."""
    path = _pending_path()
    parent = path.parent
    if not parent.exists():
        return 0
    removed = 0
    for orphan in parent.glob(f"{_TMP_PREFIX}*{_TMP_SUFFIX}"):
        try:
            orphan.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def _prune(data: Dict[str, dict]) -> Dict[str, dict]:
    cutoff = time.time() - MAX_AGE_HOURS * 3600
    return {
        pid: e for pid, e in data.items()
        if isinstance(e, dict)
        and isinstance(e.get("created_at"), (int, float))
        and e["created_at"] > cutoff
    }


def _lock_path() -> Path:
    return Path(str(_pending_path()) + ".lock")


def add_pending(
    phone: str,
    text: str,
    customer_name: Optional[str] = None,
    message_id: Optional[str] = None,
    channel: str = "whatsapp",
) -> str:
    """Record a pending approval. Returns the pending_id.

    Read-modify-write guarded by a file lock so concurrent webhook
    deliveries from different processes can't lose each other.
    """
    norm = _normalize_phone(phone)
    if not norm:
        raise ValueError("phone is required")
    pid = make_pending_id(norm)
    with _file_lock(_lock_path()):
        data = _prune(_load_raw())
        data[pid] = {
            "phone": norm,
            "text": text or "",
            "customer_name": customer_name or "",
            "message_id": message_id or "",
            "channel": channel,
            "created_at": time.time(),
        }
        _save_raw(data)
    return pid


def get_pending(pending_id: str) -> Optional[dict]:
    if not pending_id:
        return None
    data = _prune(_load_raw())
    return data.get(pending_id)


def get_pending_by_phone(phone: str) -> Optional[dict]:
    """Return the most recent pending entry for a phone, if any."""
    norm = _normalize_phone(phone)
    if not norm:
        return None
    pid = make_pending_id(norm)
    return get_pending(pid)


def remove_pending(pending_id: str) -> bool:
    if not pending_id:
        return False
    with _file_lock(_lock_path()):
        data = _prune(_load_raw())
        if pending_id not in data:
            return False
        del data[pending_id]
        _save_raw(data)
    return True


def list_pending() -> Dict[str, dict]:
    return _prune(_load_raw())

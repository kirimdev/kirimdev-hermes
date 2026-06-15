"""Runtime reply-permission grants for Kirimdev plugin.

The owner of the agent (a phone in KIRIMDEV_OWNER_USERS) can tell the
agent at runtime "you may reply to messages from <phone> for the next
24 hours". The grant tools call ``add_grant()`` here; the adapter
consults ``has_grant()`` on every inbound message.

Storage: JSON file at ``~/.hermes/kirimdev_grants.json``. Atomic
write via tmp+rename. Stale entries are pruned on every load.

The granted tier is intentionally **conversation-scoped, not
tool-scoped**: a granted user can chat with the agent and receive
replies, but cannot trigger broadcast tools — the toolset gating in
``tools.py`` enforces that separately by checking the sender tier
attached to the active session.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_GRANTS_FILE = "~/.hermes/kirimdev_grants.json"
DEFAULT_TTL_HOURS = 24
MAX_TTL_HOURS = 24 * 30  # 30 days, hard cap

# Cross-platform file lock — fcntl on POSIX, msvcrt on Windows. The
# lock file lives next to the data file and is only used to coordinate
# concurrent read-modify-write cycles. Acquiring is blocking with a
# generous timeout so a stuck holder doesn't hang the gateway forever.
_LOCK_TIMEOUT_SECONDS = 5.0


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    """Acquire an exclusive lock on ``lock_path``. Yields control once
    locked; releases on exit. Falls back to no-op if locking isn't
    available on the platform (shouldn't happen in supported envs)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+b")
    try:
        try:
            import fcntl  # POSIX
            import time as _t
            deadline = _t.monotonic() + _LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if _t.monotonic() >= deadline:
                        logger.warning(
                            "kirimdev grants: lock timeout, proceeding without"
                        )
                        break
                    _t.sleep(0.05)
            try:
                yield
            finally:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except Exception:  # noqa: BLE001
                    pass
        except ImportError:
            try:
                import msvcrt  # Windows
                import time as _t
                deadline = _t.monotonic() + _LOCK_TIMEOUT_SECONDS
                locked = False
                while not locked:
                    try:
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                        locked = True
                    except OSError:
                        if _t.monotonic() >= deadline:
                            logger.warning(
                                "kirimdev grants: lock timeout, proceeding without"
                            )
                            break
                        _t.sleep(0.05)
                try:
                    yield
                finally:
                    if locked:
                        try:
                            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                        except OSError:
                            pass
            except ImportError:
                # No locking primitive available — best-effort, no lock.
                yield
    finally:
        try:
            fh.close()
        except Exception:  # noqa: BLE001
            pass


def _grants_path() -> Path:
    return Path(
        os.path.expanduser(
            os.getenv("KIRIMDEV_GRANTS_FILE", DEFAULT_GRANTS_FILE)
        )
    )


def _normalize_phone(phone: str) -> str:
    if not phone:
        return ""
    return "".join(ch for ch in phone if ch.isdigit())


def _load_raw() -> Dict[str, dict]:
    path = _grants_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Kirimdev grants file unreadable: %s — starting empty", exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("Kirimdev grants file malformed (not an object) — ignoring")
        return {}
    return data


_TMP_PREFIX = ".kirimdev_grants."
_TMP_SUFFIX = ".tmp"


def _save_raw(data: Dict[str, dict]) -> None:
    path = _grants_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: write to tmp, fsync, rename. If anything raises
    # before os.replace we unlink the tmp file so the parent dir
    # doesn't accumulate orphans over years of crashes.
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
        tmp_name = None  # successful replace — nothing to clean up
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
    """Remove leftover ``.kirimdev_grants.*.tmp`` files in the grants
    directory. Called once at plugin startup so crashed writes from
    previous gateway runs don't accumulate. Returns the count removed.
    """
    path = _grants_path()
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
    """Drop entries whose ``expires_at`` is in the past."""
    now = time.time()
    return {
        phone: entry
        for phone, entry in data.items()
        if isinstance(entry, dict)
        and isinstance(entry.get("expires_at"), (int, float))
        and entry["expires_at"] > now
    }


def list_grants() -> Dict[str, dict]:
    """Return all active (non-expired) grants, keyed by normalized phone."""
    data = _prune(_load_raw())
    return data


def has_grant(phone: str) -> bool:
    """Return True if ``phone`` has an active grant."""
    norm = _normalize_phone(phone)
    if not norm:
        return False
    return norm in list_grants()


def _lock_path() -> Path:
    return Path(str(_grants_path()) + ".lock")


def add_grant(
    phone: str,
    ttl_hours: float = DEFAULT_TTL_HOURS,
    note: Optional[str] = None,
    granted_by: Optional[str] = None,
) -> dict:
    """Grant reply permission for ``phone`` for ``ttl_hours``.

    Returns the stored entry. Caps TTL at ``MAX_TTL_HOURS``. The
    read-modify-write cycle is guarded by ``_file_lock`` so concurrent
    writes from another process (e.g. ``hermes send`` CLI) don't lose
    each other's updates.
    """
    norm = _normalize_phone(phone)
    if not norm:
        raise ValueError("phone is required")
    try:
        ttl_hours = float(ttl_hours)
    except (TypeError, ValueError):
        ttl_hours = DEFAULT_TTL_HOURS
    if ttl_hours <= 0:
        raise ValueError("ttl_hours must be positive")
    if ttl_hours > MAX_TTL_HOURS:
        ttl_hours = MAX_TTL_HOURS

    with _file_lock(_lock_path()):
        data = _prune(_load_raw())
        now = time.time()
        entry = {
            "granted_at": now,
            "expires_at": now + ttl_hours * 3600.0,
            "ttl_hours": ttl_hours,
        }
        if note:
            entry["note"] = str(note)[:500]
        if granted_by:
            entry["granted_by"] = _normalize_phone(granted_by)
        data[norm] = entry
        _save_raw(data)
    return entry


def revoke_grant(phone: str) -> bool:
    """Remove a grant if it exists. Returns True if something was removed.

    Read-modify-write guarded by file lock (see add_grant).
    """
    norm = _normalize_phone(phone)
    if not norm:
        return False
    with _file_lock(_lock_path()):
        data = _prune(_load_raw())
        if norm not in data:
            return False
        del data[norm]
        _save_raw(data)
    return True

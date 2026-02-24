import json
import time
from typing import Dict, Tuple

from onilock.core.settings import settings
from onilock.core.audit import audit


def _lockout_path():
    return settings.BASE_DIR / ".lockout.json"


def _load_lockouts() -> Dict[str, Dict]:
    path = _lockout_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_lockouts(data: Dict[str, Dict]) -> None:
    path = _lockout_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def is_locked(profile: str) -> Tuple[bool, int]:
    now = int(time.time())
    data = _load_lockouts()
    entry = data.get(profile)
    if not entry:
        return False, 0
    locked_until = int(entry.get("locked_until", 0))
    if locked_until > now:
        return True, locked_until - now
    return False, 0


def record_failure(profile: str) -> int:
    now = int(time.time())
    data = _load_lockouts()
    entry = data.get(profile, {})
    first_failed_at = int(entry.get("first_failed_at", now))
    if now - first_failed_at > settings.LOCKOUT_WINDOW_SEC:
        # Reset window
        entry = {"failed_count": 0, "first_failed_at": now, "locked_until": 0}

    failed_count = int(entry.get("failed_count", 0)) + 1
    entry["failed_count"] = failed_count
    entry["first_failed_at"] = first_failed_at

    if failed_count >= settings.LOCKOUT_ATTEMPTS:
        entry["locked_until"] = now + settings.LOCKOUT_DURATION_SEC
        audit("auth.lockout", attempts=failed_count, duration=settings.LOCKOUT_DURATION_SEC)

    data[profile] = entry
    _save_lockouts(data)
    return failed_count


def clear_failures(profile: str) -> None:
    data = _load_lockouts()
    if profile in data:
        del data[profile]
        _save_lockouts(data)


def rate_limit_delay(failed_count: int) -> None:
    delay = min(settings.RATE_LIMIT_MAX_DELAY, settings.RATE_LIMIT_BASE_DELAY * failed_count)
    if delay > 0:
        time.sleep(delay)

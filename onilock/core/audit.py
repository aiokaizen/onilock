import json
from datetime import datetime, timezone
from typing import Any, Dict

from onilock.core.settings import settings


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def audit(event: str, **fields: Any) -> None:
    """
    Append an audit event as JSONL.
    """
    payload: Dict[str, Any] = {
        "ts": _utc_now_iso(),
        "event": event,
        "profile": settings.DB_NAME,
    }
    payload.update(fields)

    try:
        settings.AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with settings.AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except OSError:
        # Audit logging is best-effort.
        pass

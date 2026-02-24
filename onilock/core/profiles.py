import json
from typing import List

from onilock.core.settings import settings


def _profiles_path():
    return settings.BASE_DIR / "profiles.json"


def list_profiles() -> List[str]:
    path = _profiles_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return sorted(set(data.get("profiles", [])))
    except Exception:
        return []


def register_profile(name: str) -> None:
    path = _profiles_path()
    profiles = list_profiles()
    if name not in profiles:
        profiles.append(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"profiles": profiles}, indent=2))


def remove_profile(name: str) -> None:
    profiles = [p for p in list_profiles() if p != name]
    path = _profiles_path()
    if profiles:
        path.write_text(json.dumps({"profiles": profiles}, indent=2))
    elif path.exists():
        path.unlink()


def set_active_profile(name: str) -> None:
    settings.PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.PROFILE_PATH.write_text(name)


def get_active_profile() -> str | None:
    if settings.PROFILE_PATH.exists():
        try:
            value = settings.PROFILE_PATH.read_text().strip()
            return value or None
        except OSError:
            return None
    return None

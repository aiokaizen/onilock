import math
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Dict, Any


@lru_cache(maxsize=1)
def _common_passwords() -> set[str]:
    path = Path(__file__).resolve().parent / "data" / "common_passwords.txt"
    try:
        return set(p.strip() for p in path.read_text().splitlines() if p.strip())
    except OSError:
        return set()


def estimate_entropy_bits(password: str) -> float:
    if not password:
        return 0.0

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 32

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def password_health(password: str, existing_passwords: Iterable[str]) -> Dict[str, Any]:
    length = len(password)
    entropy = estimate_entropy_bits(password)
    categories = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )

    lowered = password.lower()
    is_common = lowered in _common_passwords()
    is_reused = password in set(existing_passwords)

    reasons = []
    if length < 12:
        reasons.append("too short (min 12)")
    if categories < 3:
        reasons.append("not enough character variety")
    if entropy < 60:
        reasons.append("low entropy")
    if is_common:
        reasons.append("common password")
    if is_reused:
        reasons.append("password reuse detected")

    strength = "strong"
    if reasons:
        strength = "weak" if entropy < 50 or length < 10 or is_common or is_reused else "medium"

    return {
        "length": length,
        "entropy_bits": round(entropy, 2),
        "categories": categories,
        "is_common": is_common,
        "is_reused": is_reused,
        "strength": strength,
        "reasons": reasons,
    }

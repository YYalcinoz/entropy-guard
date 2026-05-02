from __future__ import annotations

import time
import secrets
from typing import Dict, List, Set

from .domain import (
    has_common_word,
    has_keyboard_walk,
    looks_like_date,
    score_password,
)

# ---------------------------
# Candidate builder (module-level for clarity)
# ---------------------------

_LOWER   = "abcdefghijklmnopqrstuvwxyz"
_UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS  = "0123456789"
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/|"
_ALL     = _LOWER + _UPPER + _DIGITS + _SYMBOLS

_rng = secrets.SystemRandom()


def _build_candidate(min_length: int) -> str:
    """Generate a random password with at least one of each character class."""
    chars = [
        _rng.choice(_LOWER),
        _rng.choice(_UPPER),
        _rng.choice(_DIGITS),
        _rng.choice(_SYMBOLS),
    ]
    while len(chars) < min_length:
        chars.append(_rng.choice(_ALL))
    _rng.shuffle(chars)
    return "".join(chars)


# ---------------------------
# Public API
# ---------------------------

def suggest_stronger_passwords(
    pw: str,
    wordlist: Set[str],
    count: int = 3,
    timeout_seconds: float = 5.0,
) -> List[Dict[str, object]]:
    """
    Return up to `count` stronger password suggestions.
    Candidates are random character strings — no dictionary words.
    Returns fewer than `count` if timeout is hit or max_attempts exceeded.
    """
    target_min_length = max(len(pw) + 4, 18)
    original_score    = score_password(pw, wordlist)["score"]
    required_min_score = max(80, original_score + 10)

    suggestions: List[Dict[str, object]] = []
    start_time  = time.monotonic()
    attempts    = 0
    max_attempts = 300

    while len(suggestions) < count and attempts < max_attempts:
        # FIX: timeout check before the expensive score_password call
        if time.monotonic() - start_time >= timeout_seconds:
            break

        attempts += 1
        candidate = _build_candidate(target_min_length)

        # Fast pre-checks before the expensive scoring
        if has_common_word(candidate) or has_keyboard_walk(candidate) or looks_like_date(candidate):
            continue

        cand_result = score_password(candidate, wordlist)
        cand_score  = cand_result["score"]

        if cand_score <= original_score or cand_score < required_min_score:
            continue

        suggestions.append({
            "password": candidate,
            "score":    cand_score,
            "rating":   cand_result["rating"],
        })

    return suggestions[:count]


__all__ = ["suggest_stronger_passwords"]
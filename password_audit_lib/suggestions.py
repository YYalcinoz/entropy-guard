from __future__ import annotations

import secrets
import time
from typing import Dict, List, Set

from .domain import (
    has_common_word,
    has_keyboard_walk,
    looks_like_date,
    score_password,
)


def suggest_stronger_passwords(
    pw: str,
    wordlist: Set[str],
    count: int = 3,
    timeout_seconds: float = 5.0,
) -> List[Dict[str, object]]:
    """
    Heuristic suggestions using random character strings:
    - Keep similar length or longer (targeting high scores, >= 80/100 when possible).
    - Use random mixes of upper/lower/digits/symbols (no dictionary words).
    """
    base_length = len(pw)
    target_min_length = max(base_length + 4, 18)

    rng = secrets.SystemRandom()

    lower_chars = "abcdefghijklmnopqrstuvwxyz"
    upper_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digit_chars = "0123456789"
    symbol_chars = "!@#$%^&*()-_=+[]{};:,.?/|"
    all_chars = lower_chars + upper_chars + digit_chars + symbol_chars

    original_score = score_password(pw, wordlist)["score"]
    required_min_score = max(80, original_score + 10)

    def build_candidate() -> str:
        chars = [
            rng.choice(lower_chars),
            rng.choice(upper_chars),
            rng.choice(digit_chars),
            rng.choice(symbol_chars),
        ]
        while len(chars) < target_min_length:
            chars.append(rng.choice(all_chars))
        rng.shuffle(chars)
        return "".join(chars)

    suggestions: List[Dict[str, object]] = []
    start_time = time.monotonic()
    attempts = 0
    max_attempts = 300

    while len(suggestions) < count and attempts < max_attempts:
        if timeout_seconds is not None and timeout_seconds > 0:
            if time.monotonic() - start_time >= timeout_seconds:
                break
        attempts += 1
        candidate = build_candidate()

        if has_common_word(candidate) or has_keyboard_walk(candidate) or looks_like_date(candidate):
            continue

        cand_result = score_password(candidate, wordlist)
        cand_score = cand_result["score"]

        if cand_score <= original_score or cand_score < required_min_score:
            continue

        suggestions.append(
            {
                "password": candidate,
                "score": cand_score,
                "rating": cand_result["rating"],
            }
        )

    return suggestions[:count]


__all__ = ["suggest_stronger_passwords"]


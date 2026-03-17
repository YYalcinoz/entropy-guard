from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Set


# ---------------------------
# Pattern detection helpers
# ---------------------------

KEYBOARD_SEQUENCES = [
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "12345",
    "123456",
    "123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

COMMON_WORDS = [
    "password",
    "letmein",
    "admin",
    "welcome",
    "login",
    "user",
]


def has_keyboard_walk(pw: str) -> bool:
    low = pw.lower()
    return any(seq in low for seq in KEYBOARD_SEQUENCES)


def has_common_word(pw: str) -> bool:
    low = pw.lower()
    return any(w in low for w in COMMON_WORDS)


def has_repeated_chars(pw: str, min_repeats: int = 3) -> bool:
    return re.search(r"(.)\1{" + str(min_repeats - 1) + r",}", pw) is not None


def looks_like_date(pw: str) -> bool:
    if re.search(
        r"\b(19|20)\d{2}[-/]?(0[1-9]|1[0-2])[-/]?(0[1-9]|[12]\d|3[01])\b", pw
    ):
        return True
    if re.search(
        r"\b(0[1-9]|[12]\d|3[01])[-/]?(0[1-9]|1[0-2])[-/]?(19|20)\d{2}\b", pw
    ):
        return True
    if re.fullmatch(r"\d{8}", pw):
        return True
    return False


def classify_score(score: int) -> str:
    if score < 30:
        return "Very Weak"
    if score < 50:
        return "Weak"
    if score < 70:
        return "Moderate"
    if score < 85:
        return "Strong"
    return "Very Strong"


# ---------------------------
# Crack time estimation
# ---------------------------

def estimate_entropy_bits(pw: str) -> float:
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(not c.isalnum() for c in pw):
        charset += 32
    if charset == 0:
        return 0.0
    return len(pw) * math.log2(charset)


def _format_time(seconds: float) -> str:
    """
    Human-friendly crack time formatting.

    - Extremely large values: collapse to a simple upper bound (e.g., "> 1 million years").
    - Realistic values: favor clean units like "2 years", "6 months", "3 days", "5 hours".
    - Avoid awkward combinations like "2086848 years, 155 days".
    """
    if seconds < 1:
        return "<1 second"

    seconds_int = int(seconds)
    year = 365 * 24 * 3600
    month = 30 * 24 * 3600
    day = 24 * 3600
    hour = 3600
    minute = 60

    years = seconds_int / year
    if years >= 1_000_000:
        return "> 1 million years"

    if years >= 10:
        y = round(years)
        return f"{y} year{'s' if y != 1 else ''}"

    if years >= 1:
        y = seconds_int // year
        rem = seconds_int - y * year
        months = rem // month
        if months > 0:
            return f"{y} year{'s' if y != 1 else ''}, {months} month{'s' if months != 1 else ''}"
        return f"{y} year{'s' if y != 1 else ''}"

    months = seconds_int // month
    if months >= 1:
        rem = seconds_int - months * month
        days = rem // day
        if days > 0:
            return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
        return f"{months} month{'s' if months != 1 else ''}"

    days = seconds_int // day
    if days >= 1:
        rem = seconds_int - days * day
        hours = rem // hour
        if hours > 0:
            return f"{days} day{'s' if days != 1 else ''}, {hours} hour{'s' if hours != 1 else ''}"
        return f"{days} day{'s' if days != 1 else ''}"

    hours = seconds_int // hour
    if hours >= 1:
        rem = seconds_int - hours * hour
        minutes = rem // minute
        if minutes > 0:
            return f"{hours} hour{'s' if hours != 1 else ''}, {minutes} minute{'s' if minutes != 1 else ''}"
        return f"{hours} hour{'s' if hours != 1 else ''}"

    minutes = seconds_int // minute
    if minutes >= 1:
        rem = seconds_int - minutes * minute
        secs = rem
        if secs > 0:
            return f"{minutes} minute{'s' if minutes != 1 else ''}, {secs} second{'s' if secs != 1 else ''}"
        return f"{minutes} minute{'s' if minutes != 1 else ''}"

    return f"{seconds_int} second{'s' if seconds_int != 1 else ''}"


def estimate_crack_times(pw: str) -> Dict[str, str]:
    entropy = estimate_entropy_bits(pw)
    if entropy <= 0:
        return {
            "brute_force_online": "N/A",
            "brute_force_offline": "N/A",
            "dictionary_attack": "N/A",
            "note": (
                "Entropy estimate not available. These crack time values are illustrative only and "
                "do not represent guarantees in real-world conditions."
            ),
        }

    expected_guesses = 2 ** max(entropy - 1, 0)

    brute_force_online_rate = 1e3
    brute_force_offline_rate = 1e9

    online_seconds = expected_guesses / brute_force_online_rate
    offline_seconds = expected_guesses / brute_force_offline_rate

    dictionary_attack_rate = 1e9
    effective_entropy_for_dict = max(entropy - 20, 0)
    expected_dict_guesses = 2 ** effective_entropy_for_dict
    dict_seconds = expected_dict_guesses / dictionary_attack_rate

    return {
        "brute_force_online": _format_time(online_seconds),
        "brute_force_offline": _format_time(offline_seconds),
        "dictionary_attack": _format_time(dict_seconds),
        "note": (
            "Very rough, illustrative estimates only. Real attackers often bypass brute force entirely "
            "via breaches, password reuse, and smarter attack strategies."
        ),
    }


# ---------------------------
# Scoring logic
# ---------------------------

def score_password(pw: str, wordlist: Set[str]) -> Dict:
    issues: List[str] = []
    suggestions: List[str] = []

    length = len(pw)
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digits = any(c.isdigit() for c in pw)
    symbols = any(not c.isalnum() for c in pw)

    score = 0
    if length == 0:
        issues.append("Password is empty.")
        suggestions.append("Use a long, unique passphrase (e.g., 3–5 random words).")
        return {
            "password": pw,
            "score": 0,
            "rating": "Very Weak",
            "issues": issues,
            "suggestions": suggestions,
            "length": length,
            "in_wordlist": False,
            "entropy_bits": 0.0,
            "crack_times": estimate_crack_times(pw),
        }

    if length < 8:
        issues.append("Password is shorter than 8 characters.")
        suggestions.append("Use at least 12–16 characters wherever possible.")
        score += 5
    elif length < 12:
        score += 15
    elif length < 16:
        score += 30
    else:
        score += 40

    variety_count = sum([lower, upper, digits, symbols])
    if variety_count <= 1:
        issues.append("Password uses only one character type (e.g., all letters).")
        suggestions.append("Mix lower/upper case, digits, and symbols.")
    elif variety_count == 2:
        score += 10
    elif variety_count == 3:
        score += 18
    else:
        score += 25

    in_wordlist = pw.lower() in wordlist if wordlist else False
    if in_wordlist:
        issues.append("Password appears in the provided wordlist (likely common or breached).")
        suggestions.append("Never reuse breached or common passwords.")
        score -= 40

    if has_common_word(pw):
        issues.append("Contains common password words (e.g., 'password', 'admin').")
        suggestions.append("Avoid obvious words and phrases; use random or unrelated words.")
        score -= 15

    if has_keyboard_walk(pw):
        issues.append("Contains keyboard sequences (e.g., 'qwerty', '123456').")
        suggestions.append("Avoid predictable keyboard patterns.")
        score -= 15

    if has_repeated_chars(pw):
        issues.append("Contains long runs of the same character.")
        suggestions.append("Break up repeated characters with more variety.")
        score -= 10

    if looks_like_date(pw):
        issues.append("Looks like a date or simple numeric pattern.")
        suggestions.append("Avoid using dates (birthdays, anniversaries) or easily guessed numbers.")
        score -= 10

    entropy_bits = estimate_entropy_bits(pw)
    if entropy_bits >= 100:
        score += 20
    elif entropy_bits >= 80:
        score += 10
    elif entropy_bits >= 60:
        score += 5

    score = max(0, min(100, score))
    rating = classify_score(score)

    crack_times = estimate_crack_times(pw)

    if score >= 70 and not issues:
        suggestions.append(
            "This password looks strong; keep it unique per-site and store it in a password manager."
        )
    else:
        suggestions.append(
            "Prefer a longer, unique passphrase and store it in a reputable password manager."
        )

    return {
        "password": pw,
        "score": score,
        "rating": rating,
        "issues": issues,
        "suggestions": suggestions,
        "length": length,
        "in_wordlist": in_wordlist,
        "entropy_bits": entropy_bits,
        "crack_times": crack_times,
    }


__all__ = [
    "KEYBOARD_SEQUENCES",
    "COMMON_WORDS",
    "has_keyboard_walk",
    "has_common_word",
    "has_repeated_chars",
    "looks_like_date",
    "classify_score",
    "estimate_entropy_bits",
    "estimate_crack_times",
    "score_password",
]


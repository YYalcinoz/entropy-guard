from __future__ import annotations

import hashlib
from typing import Optional
from urllib import error as urlerror
from urllib import request


def hibp_pwned_count(pw: str, *, timeout: float = 10.0) -> Optional[int]:
    """
    Return the breach count from HaveIBeenPwned for the given password, or:
    - 0 if not found in the corpus
    - None on network / API errors

    Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent.
    """
    sha1   = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = request.Request(url, headers={"User-Agent": "entropy-guard-audit"})

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    # FIX: added OSError to catch low-level network failures not wrapped by URLError
    except (urlerror.URLError, TimeoutError, ValueError, OSError):
        return None

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        sfx, count_str = parts[0].strip(), parts[1].strip()
        if sfx.upper() == suffix:
            try:
                return int(count_str)
            except ValueError:
                return None

    return 0


def hash_sha1(pw: str) -> str:
    """Return uppercase SHA-1 hex digest of the given password."""
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


__all__ = ["hibp_pwned_count", "hash_sha1"]
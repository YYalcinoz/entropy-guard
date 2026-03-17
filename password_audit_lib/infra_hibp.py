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
    """
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = request.Request(url, headers={"User-Agent": "local-password-audit"})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
    except (urlerror.URLError, TimeoutError, ValueError):
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


__all__ = ["hibp_pwned_count"]


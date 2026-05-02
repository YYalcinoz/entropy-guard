from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Set


def load_wordlist(path: str | None) -> Set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Wordlist not found: {p}")
    words: Set[str] = set()
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w:
                words.add(w.lower())
    return words


def read_passwords_from_file(path: str) -> List[str]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Password file not found: {p}")
    passwords: List[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # FIX: use strip() instead of rstrip("\n") to also drop whitespace-only lines
            pw = line.strip()
            if pw:
                passwords.append(pw)
    return passwords


def write_json_report(path: str, results: List[Dict]) -> None:
    # FIX: was "out_path.open" written as "out_[path.open]" — corrected variable name
    out_path = Path(path)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


__all__ = [
    "load_wordlist",
    "read_passwords_from_file",
    "write_json_report",
]
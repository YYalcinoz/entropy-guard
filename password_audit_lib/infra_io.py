from __future__ import annotations

import hashlib
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
            pw = line.rstrip("\n")
            if pw:
                passwords.append(pw)
    return passwords


def write_json_report(path: str, results: List[Dict]) -> None:
    out_path = Path(path)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def hash_sha1(pw: str) -> str:
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


__all__ = [
    "load_wordlist",
    "read_passwords_from_file",
    "write_json_report",
    "hash_sha1",
]


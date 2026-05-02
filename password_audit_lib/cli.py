from __future__ import annotations

import argparse
import sys
import time
from typing import Iterable, List, Optional

import getpass
from pathlib import Path

from .domain import MAX_PASSWORD_LENGTH, score_password
from .infra_hibp import hibp_pwned_count, hash_sha1   # FIX: hash_sha1 moved to infra_hibp
from .infra_io import load_wordlist, read_passwords_from_file, write_json_report
from .reporting import (
    CYAN, RED, YELLOW, RESET, BOLD, GREEN,
    mask_password, print_ai_suggestions, print_report,
)
from .suggestions import suggest_stronger_passwords


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local password strength and risk audit tool.",
    )
    parser.add_argument(
        "-p", "--password",
        action="append",
        help="Password to audit (can be specified multiple times).",
    )
    parser.add_argument(
        "-f", "--file",
        help=(
            "File containing one password per line. This file may contain sensitive data; "
            "store it securely with restricted permissions."
        ),
    )
    parser.add_argument(
        "-w", "--wordlist",
        help=(
            "Optional wordlist of weak/common passwords. This file may contain sensitive data; "
            "store it securely with restricted permissions."
        ),
    )
    parser.add_argument(
        "--hibp",
        action="store_true",
        help="Check passwords against HaveIBeenPwned (k-anonymity, SHA-1 prefix only).",
    )
    parser.add_argument(
        "--json-out",
        help=(
            "Optional path to write JSON report (no plaintext passwords). "
            "If used with --include-hash, the report will contain SHA-1 password hashes and must be "
            "treated as sensitive data."
        ),
    )
    parser.add_argument(
        "--include-hash",
        action="store_true",
        help=(
            "Include SHA-1 hashes of passwords in JSON output (if --json-out is set). "
            "Enabling this makes the JSON report sensitive and suitable only for secure storage."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging to stderr (avoid in shared or logged environments).",
    )
    parser.add_argument(
        "--hibp-delay",
        type=float,
        default=0.0,
        help=(
            "Seconds to sleep between HaveIBeenPwned requests (useful for batch mode rate limiting). "
            "Defaults to 0 (no deliberate delay)."
        ),
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def collect_passwords(args: argparse.Namespace) -> List[str]:
    passwords: List[str] = []
    if args.password:
        passwords.extend(args.password)
    if args.file:
        passwords.extend(read_passwords_from_file(args.file))
    return passwords


def _enforce_max_length(pw: str) -> bool:
    """Print a warning and return False if password exceeds the hard limit."""
    if len(pw) > MAX_PASSWORD_LENGTH:
        print(
            f"{RED}Skipping password: exceeds maximum length of {MAX_PASSWORD_LENGTH} characters.{RESET}",
            file=sys.stderr,
        )
        return False
    return True


def interactive_loop(
    wordlist,
    use_hibp: bool,
    json_out: Optional[str],
    include_hash: bool,
    debug: bool,
    hibp_delay: float,
) -> int:
    """
    Interactive mode: no CLI passwords/files provided.
    Loop until user types ':quit' or ':exit'.
    """
    print(f"{CYAN}Interactive password audit mode{RESET}")
    print("Type a password to audit it.")
    print("Type ':quit' or ':exit' to leave.\n")

    all_results: List[dict] = []

    while True:
        try:
            pw = getpass.getpass("Password> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break

        cmd = pw.strip().lower()
        if cmd in (":quit", ":exit", "quit", "exit"):
            break
        if not pw:
            continue

        # FIX: enforce max length in CLI too
        if not _enforce_max_length(pw):
            continue

        result = score_password(pw, wordlist)
        hibp_count: Optional[int] = None
        if use_hibp:
            hibp_count = hibp_pwned_count(pw)
            if hibp_delay > 0:
                time.sleep(hibp_delay)

        ai_suggestions: List[dict] = []
        if result["score"] < 70:
            if debug:
                print(
                    f"[DEBUG] interactive_loop: score={result['score']} < 70, calling suggest_stronger_passwords",
                    file=sys.stderr,
                )
            ai_suggestions = suggest_stronger_passwords(pw, wordlist, count=3, timeout_seconds=5.0)
        else:
            if debug:
                print(
                    f"[DEBUG] interactive_loop: score={result['score']} >= 70, skipping suggestions",
                    file=sys.stderr,
                )

        # FIX: pass password explicitly — no longer in result dict
        print_report(result, hibp_count, use_hibp, password=pw)
        if ai_suggestions:
            print_ai_suggestions(ai_suggestions)

        result_for_json = {
            "masked_password": mask_password(pw),
            "length":          result["length"],
            "score":           result["score"],
            "rating":          result["rating"],
            "issues":          result["issues"],
            "suggestions":     result["suggestions"],
            "in_wordlist":     result["in_wordlist"],
            "entropy_bits":    result["entropy_bits"],
            "crack_times":     result["crack_times"],
            "hibp_breach_count": hibp_count,
        }
        if include_hash:
            result_for_json["sha1"] = hash_sha1(pw)
        if ai_suggestions:
            result_for_json["ai_suggestions"] = [
                {
                    "masked_password": mask_password(str(s["password"])),
                    "length":          len(str(s["password"])),
                    "score":           int(s["score"]),
                    "rating":          str(s["rating"]),
                }
                for s in ai_suggestions
            ]

        all_results.append(result_for_json)

    if json_out and all_results:
        try:
            write_json_report(json_out, all_results)
            print(f"{CYAN}JSON report written to {Path(json_out)}{RESET}")
        except OSError as e:
            print(f"{RED}Failed to write JSON report: {e}{RESET}", file=sys.stderr)
            return 1

    return 0


def batch_mode(args: argparse.Namespace, wordlist) -> int:
    passwords = collect_passwords(args)
    if not passwords:
        print(f"{YELLOW}No passwords provided to audit.{RESET}")
        return 1

    all_results: List[dict] = []

    for pw in passwords:
        # FIX: enforce max length in batch mode too
        if not _enforce_max_length(pw):
            continue

        result = score_password(pw, wordlist)
        hibp_count: Optional[int] = None
        if args.hibp:
            hibp_count = hibp_pwned_count(pw)
            if args.hibp_delay > 0:
                time.sleep(args.hibp_delay)

        ai_suggestions: List[dict] = []
        if result["score"] < 70:
            if args.debug:
                print(
                    f"[DEBUG] batch_mode: score={result['score']} < 70, calling suggest_stronger_passwords",
                    file=sys.stderr,
                )
            ai_suggestions = suggest_stronger_passwords(pw, wordlist, count=3, timeout_seconds=5.0)
        else:
            if args.debug:
                print(
                    f"[DEBUG] batch_mode: score={result['score']} >= 70, skipping suggestions",
                    file=sys.stderr,
                )

        # FIX: pass password explicitly — no longer in result dict
        print_report(result, hibp_count, args.hibp, password=pw)
        if ai_suggestions:
            print_ai_suggestions(ai_suggestions)

        result_for_json = {
            "masked_password": mask_password(pw),
            "length":          result["length"],
            "score":           result["score"],
            "rating":          result["rating"],
            "issues":          result["issues"],
            "suggestions":     result["suggestions"],
            "in_wordlist":     result["in_wordlist"],
            "entropy_bits":    result["entropy_bits"],
            "crack_times":     result["crack_times"],
            "hibp_breach_count": hibp_count,
        }
        if args.include_hash:
            result_for_json["sha1"] = hash_sha1(pw)
        if ai_suggestions:
            result_for_json["ai_suggestions"] = [
                {
                    "masked_password": mask_password(str(s["password"])),
                    "length":          len(str(s["password"])),
                    "score":           int(s["score"]),
                    "rating":          str(s["rating"]),
                }
                for s in ai_suggestions
            ]

        all_results.append(result_for_json)

    if args.json_out and all_results:
        try:
            write_json_report(args.json_out, all_results)
            print(f"{CYAN}JSON report written to {Path(args.json_out)}{RESET}")
        except OSError as e:
            print(f"{RED}Failed to write JSON report: {e}{RESET}", file=sys.stderr)
            return 1

    return 0


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    try:
        wordlist = load_wordlist(args.wordlist)
    except FileNotFoundError as e:
        print(f"{RED}Error: {e}{RESET}")
        return 1

    if not args.password and not args.file:
        return interactive_loop(
            wordlist,
            use_hibp=args.hibp,
            json_out=args.json_out,
            include_hash=args.include_hash,
            debug=args.debug,
            hibp_delay=args.hibp_delay,
        )

    return batch_mode(args, wordlist)


__all__ = ["parse_args", "collect_passwords", "interactive_loop", "batch_mode", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
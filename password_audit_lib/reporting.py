from __future__ import annotations

from typing import Dict, List, Optional


# ---------------------------
# Colors (ANSI)
# ---------------------------

BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"


def color_for_score(score: int) -> str:
    if score < 50:
        return RED
    if score < 70:
        return YELLOW
    return GREEN


def mask_password(pw: str) -> str:
    length = len(pw)
    if length <= 2:
        return "*" * length
    return f"{pw[0]}{'*' * (length - 2)}{pw[-1]} ({length} chars)"


def format_report_lines(result: Dict, hibp_count: Optional[int], hibp_enabled: bool) -> List[str]:
    lines: List[str] = []
    masked = mask_password(result["password"])
    color = color_for_score(result["score"])
    rating_colored = f"{color}{result['rating']}{RESET}"
    score_colored = f"{color}{result['score']} / 100{RESET}"

    lines.append("=" * 60)
    lines.append(f"Password : {masked}")
    lines.append(f"Length   : {result['length']}")
    lines.append(f"Score    : {score_colored}  ({rating_colored})")
    lines.append(f"Entropy  : {result['entropy_bits']:.1f} bits")
    lines.append(f"Crack est (online BF)  : {result['crack_times']['brute_force_online']}")
    lines.append(f"Crack est (offline BF) : {result['crack_times']['brute_force_offline']}")
    lines.append(f"Crack est (dictionary) : {result['crack_times']['dictionary_attack']}")
    lines.append(f"Note     : {result['crack_times']['note']}")

    if result.get("in_wordlist"):
        lines.append(f"{RED}Flag    : IN LOCAL WORDLIST (likely common/breached).{RESET}")

    if not hibp_enabled:
        lines.append(f"{YELLOW}HIBP    : Skipped (run with --hibp to enable online breach check).{RESET}")
    else:
        if hibp_count is None:
            lines.append(
                f"{YELLOW}HIBP    : API error or network issue during HaveIBeenPwned check.{RESET}"
            )
        elif hibp_count > 0:
            lines.append(
                f"{RED}HIBP    : Found {hibp_count} breach occurrence(s) in HaveIBeenPwned.{RESET}"
            )
        else:
            lines.append(
                f"{GREEN}HIBP    : Not found in HaveIBeenPwned corpus (no guarantee of safety).{RESET}"
            )

    if result["issues"]:
        lines.append("")
        lines.append("Issues:")
        for i, issue in enumerate(result["issues"], 1):
            lines.append(f"  {i}. {issue}")
    else:
        lines.append("")
        lines.append("Issues: None detected based on current checks.")

    if result["suggestions"]:
        lines.append("")
        lines.append("Suggestions:")
        for i, s in enumerate(result["suggestions"], 1):
            lines.append(f"  {i}. {s}")

    lines.append("")
    return lines


def format_ai_suggestions_lines(suggestions: List[Dict[str, object]]) -> List[str]:
    if not suggestions:
        return []
    lines: List[str] = []
    lines.append(f"{CYAN}AI-powered suggestions (memorable but stronger):{RESET}")
    for i, s in enumerate(suggestions, 1):
        pw = str(s["password"])
        score = int(s["score"])
        rating = str(s["rating"])
        color = color_for_score(score)
        score_colored = f"{color}{score} / 100{RESET}"
        rating_colored = f"{color}{rating}{RESET}"
        lines.append(f"  {i}. {pw}  -> Score: {score_colored} ({rating_colored})")
    lines.append("")
    return lines


def print_report(result: Dict, hibp_count: Optional[int], hibp_enabled: bool) -> None:
    for line in format_report_lines(result, hibp_count, hibp_enabled):
        print(line)


def print_ai_suggestions(suggestions: List[Dict[str, object]]) -> None:
    for line in format_ai_suggestions_lines(suggestions):
        print(line)


__all__ = [
    "RESET",
    "RED",
    "YELLOW",
    "GREEN",
    "CYAN",
    "color_for_score",
    "mask_password",
    "format_report_lines",
    "format_ai_suggestions_lines",
    "print_report",
    "print_ai_suggestions",
]


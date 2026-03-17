"""
Flask web interface for the password audit tool.

SECURITY: This module does not store or log passwords. The /api/analyze
endpoint receives the password in memory only for the duration of the request.
"""

from __future__ import annotations

import json
import os
from typing import Any

from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest

from .domain import score_password
from .infra_hibp import hibp_pwned_count
from .reporting import mask_password
from .suggestions import suggest_stronger_passwords

_this_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)


def _build_analyze_response(
    password: str,
    result: dict[str, Any],
    hibp_enabled: bool,
    hibp_count: int | None,
) -> dict[str, Any]:
    """Build JSON-serializable response; never include plaintext password."""
    response: dict[str, Any] = {
        "masked_password": mask_password(password),
        "score": result["score"],
        "rating": result["rating"],
        "length": result["length"],
        "entropy_bits": round(result["entropy_bits"], 1),
        "crack_times": result["crack_times"],
        "issues": result["issues"],
        "suggestions": result["suggestions"],
        "in_wordlist": result["in_wordlist"],
    }
    if hibp_enabled:
        response["hibp_enabled"] = True
        response["hibp_breach_count"] = hibp_count
    else:
        response["hibp_enabled"] = False
        response["hibp_breach_count"] = None
    if result["score"] < 70:
        wordlist: set[str] = set()
        ai_list = suggest_stronger_passwords(
            password, wordlist, count=3, timeout_seconds=5.0
        )
        response["ai_suggestions"] = [
            {
                "password": item["password"],
                "score": item["score"],
                "rating": item["rating"],
            }
            for item in ai_list
        ]
    else:
        response["ai_suggestions"] = []
    return response


@app.route("/")
def index() -> str:
    path = os.path.join(_this_dir, "templates", "index.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.route("/api/analyze", methods=["POST"])
def analyze() -> tuple[Any, int]:
    """
    Analyze a password. Request body: JSON with "password" key.
    Passwords are never stored or logged.
    """
    if request.content_type and "application/json" not in request.content_type:
        raise BadRequest("Content-Type must be application/json")

    try:
        data = request.get_json(force=True, silent=False)
    except (BadRequest, json.JSONDecodeError):
        raise BadRequest("Invalid JSON body")

    if not isinstance(data, dict) or "password" not in data:
        raise BadRequest("Missing 'password' field")

    password = data["password"]
    if not isinstance(password, str):
        raise BadRequest("'password' must be a string")

    hibp_enabled = bool(data.get("hibp"))
    hibp_count: int | None = None

    wordlist: set[str] = set()
    result = score_password(password, wordlist)
    if hibp_enabled:
        hibp_count = hibp_pwned_count(password)
    payload = _build_analyze_response(password, result, hibp_enabled, hibp_count)
    return jsonify(payload), 200


@app.after_request
def no_cache_results(response: Any) -> Any:
    """Prevent caching of analyze responses (they may be sensitive)."""
    if request.path == "/api/analyze":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

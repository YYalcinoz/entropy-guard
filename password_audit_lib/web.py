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

from .domain import MAX_PASSWORD_LENGTH, score_password
from .infra_hibp import hibp_pwned_count
from .reporting import mask_password
from .suggestions import suggest_stronger_passwords

_this_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=None)

# FIX: Limit request body to 16 KB — no legitimate password needs more
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# ---------------------------
# Rate limiting (optional but recommended)
# Install: pip install Flask-Limiter
# ---------------------------
try:
    from flask_limiter import Limiter  # type: ignore
    from flask_limiter.util import get_remote_address  # type: ignore
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200/day", "60/minute"],
        storage_uri="memory://",
    )
    _limiter_enabled = True
except (ImportError, ModuleNotFoundError):
    _limiter_enabled = False
    limiter = None  # type: ignore


# ---------------------------
# Response builder
# ---------------------------

def _build_analyze_response(
    password: str,
    result: dict[str, Any],
    hibp_enabled: bool,
    hibp_count: int | None,
) -> dict[str, Any]:
    """Build JSON-serializable response; never include plaintext password."""
    response: dict[str, Any] = {
        "masked_password": mask_password(password),
        "score":        result["score"],
        "rating":       result["rating"],
        "length":       result["length"],
        "entropy_bits": round(result["entropy_bits"], 1),
        "crack_times":  result["crack_times"],
        "issues":       result["issues"],
        "suggestions":  result["suggestions"],
        "in_wordlist":  result["in_wordlist"],
    }

    response["hibp_enabled"]      = hibp_enabled
    response["hibp_breach_count"] = hibp_count if hibp_enabled else None

    if result["score"] < 70:
        wordlist: set[str] = set()
        ai_list = suggest_stronger_passwords(
            password, wordlist, count=3, timeout_seconds=5.0
        )
        response["ai_suggestions"] = [
            {
                "password": item["password"],
                "score":    item["score"],
                "rating":   item["rating"],
            }
            for item in ai_list
        ]
    else:
        response["ai_suggestions"] = []

    return response


# ---------------------------
# Routes
# ---------------------------

@app.route("/")
def index() -> str:
    path = os.path.join(_this_dir, "templates", "index.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _analyze_view() -> tuple[Any, int]:
    """
    Analyze a password. Request body: JSON with "password" key.
    Passwords are never stored or logged.
    """
    # FIX: reject missing or wrong Content-Type (previously skipped when header absent)
    if not request.content_type or "application/json" not in request.content_type:
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

    # FIX: enforce max length to prevent ReDoS / float overflow
    if len(password) > MAX_PASSWORD_LENGTH:
        raise BadRequest(f"Password too long (max {MAX_PASSWORD_LENGTH} characters)")

    hibp_enabled  = bool(data.get("hibp"))
    hibp_count: int | None = None
    wordlist: set[str] = set()

    result = score_password(password, wordlist)

    if hibp_enabled:
        hibp_count = hibp_pwned_count(password)

    payload = _build_analyze_response(password, result, hibp_enabled, hibp_count)
    return jsonify(payload), 200


# Register route with or without rate limiting
if _limiter_enabled:
    analyze = app.route("/api/analyze", methods=["POST"])(
        limiter.limit("30/minute")(_analyze_view)
    )
else:
    analyze = app.route("/api/analyze", methods=["POST"])(_analyze_view)


# ---------------------------
# Response headers
# ---------------------------

@app.after_request
def no_cache_results(response: Any) -> Any:
    """Prevent caching of analyze responses."""
    if request.path == "/api/analyze":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"]        = "no-cache"
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
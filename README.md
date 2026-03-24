# Entropy Guard – Password Strength & Risk Audit

Entropy Guard is a local password strength and risk audit tool built with Python and Flask.

> **Intended use**: learning, labs, and small-team environments – **only on passwords you are authorized to assess**.

## Features

- Heuristic password scoring (length, character variety, common patterns)
- Entropy calculation and crack-time estimates (online/offline/dictionary)
- Pattern detection: keyboard walks, repeated characters, date patterns
- Optional HaveIBeenPwned breach check via k-anonymity (no full hash sent)
- AI-style stronger password suggestions generated locally
- Flask web interface + CLI support

## Installation
```bash
git clone https://github.com/YYalcinoz/entropy-guard.git
cd entropy-guard
pip install -r requirements.txt
```

## Usage

### Web Interface
```bash
python password_audit_web.py
```

Open `http://127.0.0.1:5000/` in your browser.

### CLI
```bash
# Single password
python password_audit.py -p "your-password"

# With HIBP breach check
python password_audit.py -p "your-password" --hibp

# From a file
python password_audit.py -f passwords.txt

# JSON report
python password_audit.py -f passwords.txt --json-out report.json
```

## Security & Privacy

- Passwords are held in memory only — never stored or logged
- HIBP uses k-anonymity: only first 5 characters of SHA-1 hash are sent
- JSON reports contain masked passwords only (opt-in for SHA-1 hashes via `--include-hash`)
- Debug mode (`--debug`) never includes plaintext passwords
- Web UI is intended for local/lab use — place behind HTTPS if exposed beyond localhost

## Project Structure
```
entropy-guard/
├── password_audit_lib/
│   ├── domain.py        # scoring, entropy, pattern detection
│   ├── infra_hibp.py    # HaveIBeenPwned API integration
│   ├── infra_io.py      # file I/O, JSON reports
│   ├── suggestions.py   # AI-style password suggestions
│   ├── reporting.py     # output formatting
│   ├── cli.py           # CLI interface
│   └── web.py           # Flask web interface
└── requirements.txt
```

## Built With

- Python 3.10+
- Flask
- HaveIBeenPwned API (k-anonymity)
- Cursor AI agents (security engineer, software architect, threat detection engineer)

---

Made by [YYalcinoz](https://github.com/YYalcinoz)

## 🚀 Live Demo
[entropy-guard.onrender.com](https://entropy-guard.onrender.com)

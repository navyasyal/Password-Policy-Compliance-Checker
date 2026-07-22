# 🛡️ PolicyGuard — Password Policy Compliance Console

A SOC-style credential auditing dashboard that scans bulk password data against a configurable security policy — flagging weak, reused, and common passwords, scoring strength, and generating exportable compliance reports.

**🔗 Live Demo:** [Policy Gaurd App](https://password-policy-compliance-checker.onrender.com/)

![Status](https://img.shields.io/badge/status-live-22c55e?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-3b82f6?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.x-3b82f6?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-64748b?style=flat-square)

---

## 📸 Preview

> _Add screenshots or a screen-recording GIF here once captured — see [Screen Recording Tips](#-screen-recording-tips) below._


## 🧭 Overview

PolicyGuard started as a command-line Python script and was rebuilt into a full Flask web application with a security-operations-style UI — the kind of dashboard layout you'd recognize from tools like Microsoft Defender, Wazuh, or Splunk. It's built to demonstrate practical skills relevant to **SOC**, **GRC**, and **security engineering** work: policy-driven validation, compliance reporting, and clear risk communication through data.

## ✨ Features

- **CSV ingestion** — upload any `Username,Password` CSV as the active data set
- **One-click compliance scan** — validates every password against a configurable policy
- **Interactive results dashboard**
  - 8 KPI cards: total, passed, failed, compliance %, avg strength score, weak/common/reused counts
  - Pass vs. Fail pie chart, password-issues bar chart, strength-distribution doughnut chart (Chart.js)
- **Searchable, sortable, filterable findings table**
  - Filter by PASS only / FAIL only / Weak only
  - Passwords masked by default, with per-row and global reveal toggles
  - Color-coded status and strength badges
- **Details modal** per credential — strength breakdown, compliance issues, and plain-English remediation guidance
- **Editable policy** — minimum length, uppercase/lowercase/digit/special-character requirements, reuse prevention — saved straight to `config/policy.json`
- **Downloadable reports** — CSV findings export and a plain-text executive summary, regenerated after every scan
- **Dark, glassmorphism SOC theme** — fully responsive, built with Bootstrap 5

## 🏗️ Architecture

The project deliberately separates the **compliance engine** from the **web layer**, so the core logic is easy to test, reuse, or port elsewhere (e.g. into a CLI tool, a CI/CD pre-commit hook, or a different frontend).

```
┌─────────────────────┐        ┌───────────────────────┐
│  password_checker.py  │ ◄──── │        app.py          │
│  (validation engine)  │       │   (Flask web layer)    │
│                        │       │                        │
│ • load_policy()        │       │ • routes & views       │
│ • validate_password()  │       │ • file upload handling │
│ • password_strength()  │       │ • scan result caching  │
│ • find_reused()        │       │ • report downloads     │
│ • check_compliance()   │       └───────────┬────────────┘
│ • save_report()        │                   │
│ • save_summary()       │                   ▼
└─────────────────────┘        ┌───────────────────────┐
                                │  templates/ + static/  │
                                │  (Jinja2 + Chart.js)   │
                                └───────────────────────┘
```

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Frontend | Jinja2, Bootstrap 5, Bootstrap Icons |
| Data visualization | Chart.js |
| Data format | CSV, JSON |
| Deployment | Vercel |

## 📂 Project Structure

```
app.py                      # Flask routes — upload, analyze, dashboard, settings, reports
password_checker.py         # Core compliance engine (policy validation, scoring, reuse/common checks)
config/
  └── policy.json           # Editable password policy
input/
  ├── passwords.csv         # Active data set (overwritten by CSV uploads)
  └── common_passwords.txt  # Common-password blocklist
output/
  ├── compliance_report.csv # Generated after each scan
  ├── summary.txt           # Generated after each scan
  └── last_scan.json        # Cached results for the dashboard
templates/                  # base, index, dashboard, settings, reports
static/
  ├── css/style.css         # Dark SOC theme
  └── js/dashboard.js       # Charts, table search/sort/filter, details modal
requirements.txt
```

## 🚀 Getting Started

```bash
git clone https://github.com/navyasyal/Password-Policy-Compliance-Checker
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser. Upload a CSV (or use the bundled sample), click **Analyze**, and explore the results dashboard.

### CSV format

```csv
Username,Password
jdoe,Str0ng&Secure99!
asmith,qwerty
```

## ☁️ Deploying on Render

This app writes real files to disk (`output/compliance_report.csv`, `summary.txt`), so it needs a host with a persistent, writable filesystem — Render's free web service tier works well for this (a purely serverless host like Vercel does not).

**Option A — Blueprint (one click):**
1. Push this repo to GitHub.
2. In Render, choose **New → Blueprint** and point it at the repo. `render.yaml` in the project root configures everything automatically.

**Option B — Manual web service:**
1. **New → Web Service**, connect the repo.
2. **Build Command:** `pip install -r requirements.txt`
3. **Start Command:** `gunicorn app:app`
4. Add an environment variable `FLASK_DEBUG=false`.

Either way, Render installs `gunicorn` (already in `requirements.txt`) as the production WSGI server instead of Flask's development server.

## ⚙️ Configuring the Policy

Adjust rules from the **Policy Settings** page in the UI, or edit `config/policy.json` directly:

```json
{
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_special": true,
    "prevent_reuse": true
}
```

## 🔒 Security Considerations

- Passwords are never logged or written anywhere beyond the local `output/` reports.
- Passwords are masked by default in the UI and only revealed on explicit user interaction.
- Policy changes require an explicit save and a subsequent scan — nothing is applied silently.
- This tool is intended for **auditing test/sample credential sets** (e.g. onboarding exports, breach-list comparisons in a controlled environment) — not for processing live production credentials without appropriate handling controls.

## 🗺️ Roadmap

- [ ] Unit tests for `password_checker.py` (pytest)
- [ ] Support for `.xlsx` uploads
- [ ] Historical scan comparison (trend over time)
- [ ] Role-based access for multi-user deployments

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🙋 About

Built by Navya Syal as a portfolio project exploring practical policy enforcement and compliance reporting for cybersecurity/SOC-GRC roles.

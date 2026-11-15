<<<<<<< HEAD
# ForensiQ — AI-Assisted Digital Forensics Management System

ForensiQ is a Flask and MySQL web application for organizing digital-forensics cases and evidence. It provides investigator accounts, evidence registration, SHA-256 file-integrity checks, transparent rule-based AI-assisted triage, chain-of-custody records, audit logs and CSV reporting.

## Main features
- Investigator registration and login with Werkzeug password hashing
- Case creation and case overview
- Digital evidence upload and metadata registration
- SHA-256 fingerprint calculation and file-integrity re-verification
- Rule-based AI-assisted risk triage (Low, Medium, High, Critical)
- Chain-of-custody event history
- Audit activity log and CSV evidence report
- Responsive dashboard with risk chart

## Technology stack
- Python, Flask, Jinja2
- MySQL and mysql-connector-python
- HTML, CSS, JavaScript
- Chart.js
- SHA-256 via Python `hashlib`
- Werkzeug password hashing

## AI tools and prompts
ForensiQ documents a four-tool AI-assisted development toolkit:
1. **ChatGPT** — project planning, code generation guidance and explanations.
2. **GitHub Copilot** — inline code completion and coding suggestions in VS Code.
3. **Google Gemini** — alternative workflow review, UI ideas and documentation support.
4. **Claude** — independent code review and structured error analysis.

The application includes an **AI Tools & Prompts** page that explains each tool's intended role, example prompts and the human-reviewed development workflow. The reusable prompt library is in `docs/copilot-prompts.md`; repository-specific Copilot guidance is in `.github/copilot-instructions.md`.

The prompt library contains example prompts and a template for recording actual tool usage. It should not be treated as proof that every tool or prompt was used. Record only the tools you personally used and the changes you actually accepted.

Important: the application's current evidence triage is keyword/rule-based. It is not a trained machine-learning model and does not call an external generative-AI API. Explain this accurately in a demonstration.

## Project workflow
1. Investigator creates an account or signs in.
2. Investigator creates an investigation case.
3. Investigator registers an evidence item and optionally uploads a file.
4. The application calculates a SHA-256 digest and stores evidence metadata.
5. Rule-based triage scans evidence name, category, source and description for configured indicators and assigns a risk level.
6. A first custody event and audit entry are recorded.
7. Investigator can re-verify the file hash, add custody events and inspect evidence history.
8. Investigator exports an evidence CSV report.

## Setup

### 1. Requirements
- Python 3.10+
- MySQL Server
- VS Code (optional)
- GitHub Copilot extension (optional, for AI-assisted development)

### 2. Create the database
Run the SQL script in MySQL:

```sql
SOURCE /absolute/path/to/schema.sql;
```

Or open `schema.sql` in a MySQL client and execute it.

### 3. Configure environment variables
Copy `.env.example` to `.env` and set your local MySQL details and a strong secret key.

```env
SECRET_KEY=replace-with-a-long-random-secret
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DATABASE=forensiq
```

Never commit `.env` to GitHub.

### 4. Install dependencies and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

The application initializes its tables and inserts sample demonstration data when the relevant tables are empty. A demo investigator is also seeded on an empty users table:
- Email: `admin@forensiq.local`
- Password: `admin123`

For a real deployment, remove/disable demo credentials, use a strong secret key, disable Flask debug mode, add CSRF protection, enforce HTTPS, restrict upload types and access, and apply appropriate retention and evidence-handling procedures.

## Important interpretation notes
- SHA-256 is a cryptographic hash used to detect whether a file differs from its recorded fingerprint. It does not prove who created the file or that the file is genuine.
- The AI-assisted triage is a keyword-based decision-support demonstration. It can produce false positives and false negatives; an investigator must validate findings.
- This project is an educational prototype, not a certified forensic platform.
=======
# ForensiQ-Evidence-Intelligence
>>>>>>> c0bcf70a822051e5442782c76fcf93d54075a514

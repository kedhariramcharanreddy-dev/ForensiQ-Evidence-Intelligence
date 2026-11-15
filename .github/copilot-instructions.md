# GitHub Copilot instructions for ForensiQ

You are assisting with a Flask + MySQL digital-forensics evidence-management learning project.

## Project conventions
- Backend: Python 3 and Flask. Main routes and business logic are in `app.py`.
- Database: MySQL. Keep schema changes in `schema.sql` and use parameterized SQL (`%s` placeholders).
- Templates: Jinja2 files are in `templates/`; shared layout is `templates/base.html`.
- Frontend assets: `static/style.css` and `static/app.js`.
- Authentication: use Flask sessions, Werkzeug password hashing, and `@require_login` for private routes.
- Never store plain-text passwords or hardcode real credentials, API keys, database passwords, or secret keys.
- Keep evidence integrity verification based on SHA-256. Do not describe a hash match as proof that evidence is genuine; it only indicates the stored file matches its recorded hash.
- The current AI triage is a transparent keyword/rule-based demonstration, not a trained ML model or an external generative-AI service. Explain this accurately.
- Preserve chain-of-custody and audit logging when adding actions.
- Validate user input and handle duplicate database records gracefully.
- Keep the interface responsive and consistent with the existing ForensiQ navy/blue visual style.

## Before changing code
1. Inspect the related route, template, and schema.
2. Explain which files need changes.
3. Make the smallest coherent implementation.
4. Check Python syntax and verify route/template names.
5. Do not claim the feature was tested against MySQL unless a working database is available.

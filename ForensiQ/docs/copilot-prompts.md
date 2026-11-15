# AI-assisted development prompts for ForensiQ

The project documents four AI assistants as a development toolkit: ChatGPT, GitHub Copilot, Google Gemini and Claude. Example prompts below are reusable prompt templates, not an automatic record of past tool usage. Only describe a tool as personally used if you actually used it.

These are example prompts that can be pasted into GitHub Copilot Chat in VS Code. They document the development process and help explain how AI-assisted coding was used. They are not proof that every prompt was previously submitted; use them as the project's prompt record and explain honestly which ones you actually used.

## 1. Understand the project
> Read the Flask application, MySQL schema, Jinja2 templates, CSS and JavaScript. Summarize the architecture, routes, database tables and end-to-end workflow. Do not change files yet. Point out security and validation gaps.

## 2. Build account registration
> Add a registration page to this Flask application. Collect full name, email, password and confirm password. Validate inputs, require at least eight password characters, hash passwords with Werkzeug, prevent duplicate email accounts, assign the default Investigator role, create a session after successful registration and redirect to the dashboard. Use parameterized MySQL queries and the existing flash-message pattern. Add a link between login and registration pages.

## 3. Improve the login experience
> Improve the ForensiQ login page while preserving the current brand style. Remove prefilled credentials, add clear labels and placeholders, add a create-account link, use responsive layout and accessible form controls. Do not expose passwords or secret values in the page.

## 4. Explain evidence integrity
> Review the evidence upload and verification functions. Explain how SHA-256 is calculated, where the hash is stored, and how the current file is compared with the stored hash. Preserve the existing behavior and add clear error handling for missing files. Do not claim that a matching hash proves the evidence is authentic.

## 5. Explain AI-assisted triage
> Inspect the ai_analyze function. Document the keyword indicators, risk scoring rules and generated summary. Clearly label this feature as rule-based AI-assisted triage, not a trained machine-learning model. Recommend that an investigator manually validates every flagged item.

## 6. Improve the dashboard
> Review the dashboard template and CSS. Improve visual hierarchy, spacing, responsive behavior and readability without changing the existing Flask route names or database field names. Keep the navy, blue and white ForensiQ theme.

## 7. Check the chain of custody
> Trace how evidence registration creates the first custody event and how later custody events are stored. Check that actions are associated with the signed-in investigator and written to the audit log. Report gaps before making changes.

## 8. Review before demonstration
> Perform a code review of this Flask project. Check authentication, password handling, SQL parameterization, file upload validation, evidence hashing, session handling, debug mode and secret management. Separate confirmed issues from recommendations. Do not claim security certification.

## How to use these prompts in VS Code
1. Open the ForensiQ project folder in VS Code.
2. Open GitHub Copilot Chat.
3. Paste one prompt at a time.
4. Ask Copilot to explain its proposed changes before accepting them.
5. Review the changed files and run the application/tests.
6. Keep only changes you understand and can explain during the viva.


## 9. ChatGPT — project planning and implementation explanation
> Act as a software project mentor. Review the ForensiQ Flask and MySQL structure. Explain the modules, propose a step-by-step implementation plan for investigator registration and login, and explain each code change in beginner-friendly terms.

## 10. Google Gemini — workflow and UI review
> Review the ForensiQ project workflow from investigator login to evidence reporting. Identify confusing user-interface steps and suggest practical improvements while preserving the current Flask routes and database schema.

## 11. Claude — independent code review
> Review the Flask authentication and evidence-handling code. Check password hashing, session handling, SQL parameterization, file upload validation and SHA-256 verification. Separate confirmed defects from optional improvements and explain why each matters.

## Prompt-to-code review record
For each prompt actually used, record:
- Date and AI tool
- Prompt submitted
- Suggested files or code
- Changes accepted or rejected
- How the result was tested
- What the developer learned

Do not claim an AI tool directly changed the live application unless its generated code was reviewed and incorporated by the developer.

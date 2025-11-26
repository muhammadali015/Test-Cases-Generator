# ⚡ AI Backend Test Case Generator

This repository contains an agent that converts supervisor task assignments into structured, runnable test-suite artifacts for backend APIs. It keeps the original robust architecture (Smart LTM, supervisor handshake, and multi-input processing) but focuses on producing test-case suites.

## What it does
- Accepts supervised task assignments via POST /execute.
- Analyzes provided project inputs (git repo, zip file, or individual files).
- Infers endpoints, request fields and validation rules.
- Generates a structured inventory of test cases (positive, negative, boundary, auth, method mismatch).
- Produces a runnable Jest test file bundle (zipped) and returns it as base64 in the response for quick download.

## How to use (quick)

1. Install dependencies:
```powershell
npm install
```

2. Create a `.env` file (optional, for Gemini language detection):
```text
GEMINI_API_KEY=your_google_gemini_key_here
PORT=3000
```

3. Start the agent:
```powershell
npm start
```

4. Send a supervisor-style handshake to `/execute` (example):
```json
{
  "message_id": "unique-id-123",
  "sender": "supervisor",
  "recipient": "agent",
  "type": "task_assignment",
  "results/task": {
    "task_type": "generate_test_cases",
    "payload": {
      "api": "/login",
      "method": "POST",
      "fields": ["email", "password"],
      "requires_auth": true
    }
  }
}
```

The response will include `results/task.generated_test_cases` and `results/task.test_suite_zip_base64` which is a ZIP (base64) containing `tests/generated.test.js` for Jest + Supertest.

## Notes & recommendations
- The repo now returns a zipped Jest test file as part of the agent response for immediate download and execution.
- For production-grade test generation you should:
  - Expand mapping from test-case JSON to multi-file test suites and fixtures.
  - Add configurable templates for different target frameworks (pytest, JUnit, etc.).
  - Add CI workflows to run generated tests automatically and collect coverage.

## Development
- The Express `app` is exported for easier testing (import without starting server).
- Core helpers are in `app.js` for now; consider refactoring into `lib/` modules for better testability.

---

Created by the project maintainer.

# Contributing

Thank you for improving SAIF.

## Ground Rules

- Keep SAIF focused on authorized testing/staging environments.
- Do not add exploit execution that bypasses the existing policy and confirmation model.
- Prefer deterministic evidence over AI-only claims.
- Add or update tests for dashboard, database, and reporting changes.

## Local Checks

```bash
./saif.sh setup
./saif.sh init-db
.venv/bin/python -m unittest discover tests
```

## Pull Requests

Describe the use case, safety assumptions, schema changes, and any report/dashboard impact.

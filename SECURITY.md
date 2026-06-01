# Security Policy

## Reporting Vulnerabilities

Please report vulnerabilities in SAIF privately to the maintainer. Add a project security contact before public release.

Do not include secrets, tokens, production evidence, or customer data in public issues.

## Supported Versions

SAIF is under active development. Security fixes target the current main branch until versioned releases begin.

## Security Considerations

- The dashboard binds to `127.0.0.1` by default.
- Do not expose the dashboard publicly without authentication.
- Reports may contain sensitive evidence.
- Secrets are masked by default.
- Evidence and reports should not be committed to Git.

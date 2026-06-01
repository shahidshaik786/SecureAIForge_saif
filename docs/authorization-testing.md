# Authorization Testing

Authorization testing requires authenticated context.

SAIF tracks:
- Authorization matrix
- BOLA/IDOR
- BFLA
- Cross-account replay where two accounts or roles exist

If two sessions or object identifiers are missing, SAIF records missing prerequisites instead of silently skipping coverage.

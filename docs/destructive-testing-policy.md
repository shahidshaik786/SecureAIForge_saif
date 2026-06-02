# Destructive Testing Policy

SAIF keeps application profile and execution profile separate.

Application profile examples:
- `auto`
- `crapi`
- `generic-rest`
- `web-api`

Execution profile / destructive test policy examples:
- `disabled`: do not execute destructive actions.
- `detect_only`: detect potentially destructive methods or flows without executing them.
- `test_owned_only`: run only against objects created for the test.
- `manual_confirmation`: require human confirmation before destructive steps.
- `lab_full_allowed`: **Destructive Test Cases - Full Authorized Scan**.

Do not describe destructive execution as a crAPI mode. crAPI is an application profile only.

Use destructive execution profiles only in lab, staging, or explicitly approved environments.

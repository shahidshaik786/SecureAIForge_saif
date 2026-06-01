# Destructive Testing Policy

SAIF exposes destructive testing as an explicit operator policy.

- `disabled`: do not execute destructive actions.
- `detect_only`: detect potentially destructive methods or flows without executing them.
- `test_owned_only`: run only against objects created for the test.
- `manual_confirmation`: require human confirmation before destructive steps.
- `lab_full_allowed`: lab-only mode for intentionally vulnerable targets such as crAPI.

Use destructive modes only in lab, staging, or explicitly approved environments.

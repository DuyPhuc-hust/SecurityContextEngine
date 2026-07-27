# Safety policy

- Treat the declared primary target as the only active-test target.
- Treat related domains and services as passive-only unless explicit approval updates policy.
- Use test accounts, test objects, rate limits, and non-destructive methods.
- Do not exfiltrate, persist, or display secrets or PII; redact evidence artifacts.
- Do not claim exploitation without a control case, proof case, or clearly labeled equivalent evidence.
- Preserve the original source/revision during validation and record blockers as `VALIDATION_BLOCKED`.

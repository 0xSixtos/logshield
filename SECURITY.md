# Security policy

LogShield 0.1 is an early review aid. Pattern matching does not guarantee that all secrets will be detected. A missed arbitrary string is not automatically a security vulnerability.

## Reporting

Use GitHub's **Security → Report a vulnerability** if private reporting is enabled. Otherwise open an issue asking for a private reporting channel without disclosing exploit details or sensitive data. Do not post real credentials, private logs, personal data, or production tokens in public issues.

Security-relevant issues include unintended transmission of input, execution of input as code, export of stale results presented as current, and malformed output that contradicts the stated JSON guarantees. Include a minimal fictional fixture, browser version, reproduction steps, and actual impact.

There is no bounty program or promise of payment for this repository.

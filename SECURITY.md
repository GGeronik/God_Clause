# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | Yes                |
| 1.x     | Security fixes only|
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in God Clause, **please do not open a public issue**.

Instead, report it privately:

1. **Email**: Send details to **security@god-clause.dev**
2. **Subject**: `[SECURITY] Brief description`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - **Critical** (RCE, auth bypass, audit chain tampering): Patch within 72 hours
  - **High** (data exposure, policy bypass): Patch within 1 week
  - **Medium** (information disclosure, DoS): Patch within 2 weeks
  - **Low**: Next scheduled release

## Scope

The following are in scope for security reports:

- Policy evaluation bypass (rules not enforced correctly)
- Audit chain integrity violations (hash chain tampering)
- DSSE signature verification bypass
- HMAC signing weaknesses
- Authentication/authorization bypass in the REST API
- Injection vulnerabilities in contract parsing
- Denial of service via crafted contracts or inputs

## Out of Scope

- Vulnerabilities in dependencies (report upstream, but notify us)
- Issues requiring physical access to the server
- Social engineering attacks
- Misconfiguration of deployment (e.g., running without HMAC secret)

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter notifies us privately
2. We confirm and develop a fix
3. We release the fix and publish a security advisory
4. Reporter may publish details 30 days after the fix is released

## Recognition

We credit security researchers in our release notes and CHANGELOG (unless they prefer anonymity).

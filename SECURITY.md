# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please report it responsibly. Do not open a public GitHub issue.

**Option 1 - Email:** Send details to security@aegis-defi.com

**Option 2 - GitHub:** Open a [private security advisory](https://github.com/StanleytheGoat/aegis/security/advisories/new)

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours of receiving your report
- **Initial assessment:** Within 5 business days
- **Resolution target:** Depends on severity, but we aim to patch critical issues within 14 days

We will keep you informed throughout the process and credit you in the fix (unless you prefer to remain anonymous).

## Scope

The following components are in scope for security reports:

- **MCP server** - Core server code (`src/`)
- **Smart contracts** - AegisGateway and AegisSafetyHook deployed on Base mainnet (`contracts/`)
- **npm package** - `aegis-defi` published on npm
- **Landing page** - The Aegis marketing site (`site/`)
- **Configuration and deployment** - Hardhat configs, deployment scripts, CI/CD pipelines

## Out of Scope

The following are not eligible for security reports:

- Third-party dependencies (report these to the upstream maintainer)
- Social engineering attacks against contributors or users
- Denial of service attacks
- Issues in forked or modified versions of Aegis
- Vulnerabilities that require physical access to a user's device
- Issues already disclosed publicly or known to us

## Safe Harbor

We consider security research conducted in good faith to be authorized activity. We will not pursue legal action against researchers who:

- Act in good faith and follow this policy
- Avoid accessing or modifying other users' data
- Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue
- Report findings promptly and do not disclose them publicly before a fix is available
- Do not disrupt the availability of Aegis services

## Preferred Languages

We accept vulnerability reports in English.

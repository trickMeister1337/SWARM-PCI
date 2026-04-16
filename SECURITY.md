# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ |
| Older versions | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in SWARM-PCI, please **do not** open a public issue.

Instead, report it privately to:

- **Email:** security@your-org.com
- **Subject:** `[SWARM-PCI Security] Brief description`

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)
- Your contact information for follow-up

### What to expect

- Acknowledgment within 48 hours
- Initial assessment within 7 days
- Regular updates on remediation progress
- Credit in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices for Users

When using SWARM-PCI:

1. **Only scan authorized targets** — unauthorized scanning may be illegal
2. **Protect credentials** — use `chmod 600` on `creds.txt` and move to a vault after use
3. **Review before production use** — test profile and rate limits in staging first
4. **Keep tools updated** — run `nuclei -update-templates` regularly
5. **Secure scan outputs** — reports contain vulnerability details and should be protected
6. **Use authenticated scans** — required for PCI DSS 4.0 Req 11.3.1.2 compliance

## Scope

This security policy covers:

- The `pci_scan.sh` main script
- The `setup_ubuntu.sh` installation script
- Report generation code
- Example configuration files

It does NOT cover:

- Upstream tools (nmap, nuclei, ZAP, testssl) — report to their maintainers
- User misconfigurations or unauthorized usage
- Third-party integrations

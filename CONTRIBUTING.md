# Contributing to SWARM-PCI

Thank you for your interest in contributing to SWARM-PCI! This document outlines the process for contributing to the project.

## Code of Conduct

Be respectful, professional, and security-conscious. This is a security tool — please handle it accordingly.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:

1. Check the [Issues](../../issues) page to avoid duplicates
2. Verify the bug is reproducible with the latest version
3. Include in your report:
   - OS and version (`uname -a`)
   - Bash version (`bash --version`)
   - Tool versions (`nmap --version`, `nuclei -version`, etc.)
   - Full command that triggered the bug
   - Complete error output
   - Expected vs actual behavior

### Suggesting Features

Feature requests should:

- Align with PCI DSS 4.0 compliance goals
- Explain the use case and benefit
- Specify which PCI requirement(s) it addresses

### Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/issue-description
   ```
3. **Make your changes** following the code style below
4. **Test thoroughly** (see Testing section)
5. **Commit** with clear messages:
   ```
   feat: add support for new TLS cipher check (Req 4.2.1)
   fix: correct nmap timeout handling on large CIDRs
   docs: update README with new -p profile examples
   ```
6. **Push** to your fork and open a **Pull Request**

## Code Style

### Bash

- Use `#!/usr/bin/env bash` shebang
- Do NOT use `set -e` (causes silent failures in scan scripts)
- Use `set -uo pipefail` instead
- Quote all variables: `"$var"` not `$var`
- Use `|| true` after greps in command substitution
- Use `flock` for concurrent file writes
- 4-space indentation

### Python

- Python 3.8+ compatible
- Follow PEP 8
- Use f-strings for formatting
- Handle JSON parsing errors gracefully

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` code refactoring
- `perf:` performance improvement
- `test:` adding tests
- `chore:` maintenance tasks

## Testing

Before submitting a PR, test:

1. **Syntax check**:
   ```bash
   bash -n pci_scan.sh
   ```

2. **Dry run** against a safe target (e.g., `scanme.nmap.org`):
   ```bash
   bash pci_scan.sh -t https://scanme.nmap.org -p web-only --no-zap
   ```

3. **Parallel execution** with multiple targets:
   ```bash
   bash pci_scan.sh -f test_targets.txt
   ```

4. **Report generation**:
   - Verify the HTML report opens correctly
   - Check all sections render properly
   - Confirm PCI requirement mapping is accurate

## Adding PCI Checks

When adding a new compliance check:

1. Identify the PCI DSS 4.0 requirement it addresses
2. Add the check to the appropriate phase in `pci_scan.sh`
3. Use `add_finding` with:
   - Correct severity (`critical`, `high`, `medium`, `low`, `info`)
   - Correct `pci_req` (e.g., `"Req 4.2.1"`)
   - Clear title and description
   - Actionable remediation with PCI reference
4. Update the README's PCI DSS Coverage table
5. Test the check with findings and without

Example:

```bash
add_finding "high" "Req 4.2.1" \
    "Weak cipher suite detected: ${cipher}" \
    "${host}:${port}" \
    "The server accepts weak cipher suite ${cipher}." \
    "${evidence}" \
    "Disable weak cipher. Ref: PCI DSS 4.0 Req 4.2.1" \
    "testssl"
```

## Security

- **Never commit credentials** — use `.gitignore` rules
- **Never include real CDE targets** in examples
- Report security issues privately to the maintainers, not via public issues

## Questions?

Open a [Discussion](../../discussions) for questions about:
- How to use specific features
- PCI DSS interpretation
- Contribution ideas

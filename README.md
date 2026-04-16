<div align="center">

# 🛡️ SWARM-PCI

### PCI DSS 4.0 Internal Compliance Scanner

*Automated internal vulnerability scanner mapped to PCI DSS 4.0 requirements*

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![PCI DSS](https://img.shields.io/badge/PCI_DSS-4.0-00599C)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production-success)

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Requirements](#-pci-dss-40-coverage) •
[Report](#-report) •
[Contributing](#-contributing)

</div>

---

## 📋 Overview

**SWARM-PCI** is an automated internal vulnerability scanner designed to support **PCI DSS 4.0 quarterly compliance scans** (Requirement 11.3.1). It chains industry-standard security tools through 7 parallel phases and consolidates findings into a single self-contained HTML report, with each vulnerability mapped to its corresponding PCI DSS 4.0 requirement.

Built for security teams who need a repeatable, auditable, and fast internal scanning process to complement external ASV scans (Req 11.3.2).

```
nmap → testssl → curl/ssh → auth scan → nuclei → OWASP ZAP → HTML report
                              ↓
                      All findings mapped to PCI DSS 4.0
```

> ⚠️ **Note:** SWARM-PCI is designed for **internal** scans only. External-facing CDE systems must be scanned by a PCI SSC Approved Scanning Vendor (ASV) per Requirement 11.3.2.

---

## ✨ Features

### 🎯 PCI DSS 4.0 Mapping
- Findings automatically tagged with PCI requirement (Req 1.3, 2.2, 4.2.1, 6.2.4, 6.3.3, 8.3.1, 11.3.1.2)
- Report grouped by requirement with PASS/REVIEW/FAIL status per requirement
- Coverage for requirements 1, 2, 4, 6, 8, and 11

### ⚡ Parallel Execution
- Up to **8 targets scanned simultaneously**
- Atomic finding writes with `flock` protection
- ~70% faster than serial equivalent for multi-target scans

### 🔍 Deep Assessment
- **Network discovery** — nmap with service detection, 31 ports including common DB/admin services
- **TLS/SSL audit** — testssl.sh with protocol, cipher, vulnerability, and HSTS checks
- **Config audit** — security headers, banner disclosure, weak SSH algorithms
- **Authenticated scan** — supports Req 11.3.1.2 (credentialed scanning)
- **Vuln scan** — Nuclei with PCI-specific templates (CVE, default-login, misconfig, OWASP Top 10)
- **Web app scan** — OWASP ZAP Spider + Active Scan
- **Smart deduplication** — Low/Info findings grouped to reduce noise

### 📊 Production-Ready Report
- Hero PASS/REVIEW/FAIL banner for auditor-friendly status
- Vulnerabilities organized by PCI requirement
- 3-horizon remediation plan (H1: 0-30d, H2: 30-90d, H3: 90d+)
- Self-contained HTML (no external dependencies)
- Quarterly history tracking for audit trail

---

## 📦 Installation

### Quick setup on Ubuntu 22.04+

```bash
git clone https://github.com/YOUR_USERNAME/swarm-pci.git
cd swarm-pci
chmod +x pci_scan.sh setup_ubuntu.sh
sudo bash setup_ubuntu.sh
```

The setup script installs:
- `nmap`, `jq`, `sshpass`, `nikto` via apt
- Go tools: `nuclei` + template updates
- `testssl.sh` (cloned from upstream)
- OWASP ZAP via snap

### Manual installation

<details>
<summary>Click to expand</summary>

```bash
# System packages
sudo apt update && sudo apt install -y nmap jq sshpass curl python3 golang-go nikto

# Go-based tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh
sudo ln -sf ~/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# OWASP ZAP
sudo snap install zaproxy --classic
# OR download from https://www.zaproxy.org/download/
```

</details>

### Requirements

| Tool | Purpose | Required |
|------|---------|----------|
| `bash` 5.0+ | Script runtime | ✅ |
| `curl` | Connectivity + header checks | ✅ |
| `python3` 3.8+ | Report generation + parsing | ✅ |
| `nmap` | Port scan + service detection | ✅ |
| `testssl.sh` | TLS/SSL audit (Req 4.2.1) | Recommended |
| `nuclei` | Template-based vuln scan | Recommended |
| `zaproxy` | Active web app scan | Recommended |
| `jq` | JSON processing | Optional |
| `sshpass` | Authenticated SSH scans | Optional |

---

## 🚀 Usage

### Scan a single target

```bash
bash pci_scan.sh -t https://payments.example.com
```

### Scan from a targets file

```bash
bash pci_scan.sh -f cde_targets.txt
```

**Targets file format** (`cde_targets.txt`):
```
# type  target                              label
web     https://payments.example.com         CDE-Payment-Gateway
web     https://api.payments.example.com     CDE-Payment-API
infra   10.0.1.0/24                          CDE-Database-Segment
both    192.168.1.50                         CDE-Admin-Panel
```

### Authenticated scan (PCI DSS 4.0 Req 11.3.1.2)

```bash
bash pci_scan.sh -f cde_targets.txt -c creds.txt
```

**Credentials file format** (`creds.txt`):
```
# service  host             port  username      password
ssh        10.0.2.10        22    pci_scanner   P@ssw0rd
https      192.168.1.50     443   admin         <password>
```

> ⚠️ Store `creds.txt` with `chmod 600` and move to a secure vault after use.

### Options

```
Usage: bash pci_scan.sh [options]

  -f FILE       Targets file (one per line)
  -t TARGET     Single target (URL, IP, or CIDR)
  -o DIR        Output directory
  -p PROFILE    Scan profile: full | quick | web-only | infra-only
  -c FILE       Credentials file for authenticated scan
  --no-zap      Skip OWASP ZAP phase
  --no-nuclei   Skip Nuclei phase
  -h            Show help
```

### Examples

```bash
# Full scan (default profile)
bash pci_scan.sh -f cde_targets.txt

# Quick web-only scan
bash pci_scan.sh -t https://payments.example.com -p web-only

# Infrastructure-only (no web app scan)
bash pci_scan.sh -f targets.txt -p infra-only --no-zap

# Authenticated scan for full Req 11.3.1.2 compliance
bash pci_scan.sh -f targets.txt -c creds.txt
```

---

## 📋 PCI DSS 4.0 Coverage

SWARM-PCI assesses the following PCI DSS 4.0 requirements:

| Requirement | Description | Phase |
|-------------|-------------|-------|
| **Req 1.3** | Network security controls | 1 — nmap |
| **Req 2.2** | Secure configurations | 1, 3 — nmap + curl |
| **Req 2.2.2** | No default credentials | 5 — nuclei |
| **Req 2.2.7** | Information disclosure | 3 — curl |
| **Req 4.2.1** | Strong cryptography (TLS/SSL) | 2 — testssl |
| **Req 6.2.4** | Secure application development | 3, 5, 6 — curl + nuclei + ZAP |
| **Req 6.3.3** | Known vulnerability remediation | 5 — nuclei |
| **Req 8.3.1** | Strong authentication | 3 — SSH check |
| **Req 8.6.1** | System account management | 4 — authenticated scan |
| **Req 11.3.1** | Internal quarterly scans | All phases |
| **Req 11.3.1.2** | Authenticated scanning (new in 4.0) | 4 — auth scan |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SWARM-PCI Pipeline                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────┐                                          │
│   │   Targets    │                                          │
│   │   file/CLI   │                                          │
│   └──────┬───────┘                                          │
│          │                                                  │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 1: Network Discovery   (parallel x8)      │      │
│   │  nmap -sV -sC --script=...                       │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 2: TLS/SSL Audit       (parallel x8)      │      │
│   │  testssl.sh --protocols --std --vulnerable       │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 3: Config Audit        (parallel x8)      │      │
│   │  Security headers + SSH algorithms               │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 4: Authenticated Scan  (sequential)       │      │
│   │  SSH/HTTP credentialed checks                    │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 5: Vulnerability Scan  (nuclei parallel)  │      │
│   │  nuclei -l targets.txt -bs 8                     │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 6: Web App Scan        (sequential)       │      │
│   │  OWASP ZAP Spider + Active Scan                  │      │
│   └──────┬───────────────────────────────────────────┘      │
│          ▼                                                  │
│   ┌──────────────────────────────────────────────────┐      │
│   │  Phase 7: Report Generation                      │      │
│   │  → HTML with PCI requirement grouping            │      │
│   └──────────────────────────────────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Output structure

```
pci_scan_20260416_143022/
├── relatorio_pci_dss.html       ← main report (open in browser)
├── raw/
│   ├── findings.jsonl           ← all findings (JSONL)
│   ├── scan_meta.json           ← scan metadata
│   ├── nmap_*.txt               ← nmap results per host
│   ├── nmap_*.xml               ← nmap XML output
│   ├── testssl_*.json           ← testssl JSON per host
│   ├── nuclei_all.json          ← nuclei consolidated
│   └── zap_*.json               ← ZAP alerts per target
├── evidence/
│   └── auth_*.txt               ← authenticated scan evidence
└── history/
    └── pci_dss_2026-Q2.html     ← quarterly archive
```

---

## 📊 Report

The HTML report includes:

1. **Hero Status Banner** — Large PASS / REVIEW / FAIL badge with requirement compliance summary
2. **Compact Severity Chips** — Quick severity counts without dominating the view
3. **Vulnerabilities by PCI Requirement** — Each requirement in its own section with:
   - Color-coded status header (red=FAIL, orange=REVIEW, green=PASS)
   - Full cards for Critical/High/Medium findings with evidence and remediation
   - Collapsible table for Low/Info findings
4. **3-Horizon Remediation Plan** — H1 (0-30d), H2 (30-90d), H3 (continuous)
5. **Footer** — Audit metadata and compliance context

### Severity → PCI DSS status mapping

| Finding Severity | Requirement Status |
|------------------|---------------------|
| Critical / High | ❌ FAIL — immediate remediation |
| Medium | ⚠️ REVIEW — planned remediation |
| Low / Info only | ✅ PASS — in compliance |

---

## ⚙️ Configuration

Edit variables at the top of `pci_scan.sh`:

```bash
ZAP_PORT=8081                # OWASP ZAP daemon port
ZAP_SPIDER_TIMEOUT=0         # 0 = run to 100% completion
ZAP_SCAN_TIMEOUT=0           # 0 = run to 100% completion
NUCLEI_RATE_LIMIT=30         # requests/second per target
NUCLEI_CONCURRENCY=5         # parallel templates per target
NMAP_TIMING="T3"             # T3 = normal (safe for production)
TESTSSL_TIMEOUT=300          # seconds per target
MAX_PARALLEL=8               # max concurrent hosts
```

### Rate limit guidance

| Environment | Rate Limit | MAX_PARALLEL |
|-------------|------------|--------------|
| Production / sensitive | 20-30 | 2-4 |
| Staging / default | 50 | 4-8 |
| Internal lab | 100-150 | 8 |

---

## 🧪 Quarterly Scan Workflow

Recommended workflow to meet **PCI DSS 4.0 Req 11.3.1** (quarterly internal scans):

1. **Scope definition** — Update `cde_targets.txt` with all CDE systems
2. **Credentials preparation** — Prepare `creds.txt` for authenticated scans (Req 11.3.1.2)
3. **Execute scan** — `bash pci_scan.sh -f cde_targets.txt -c creds.txt`
4. **Review report** — Address findings per 3-horizon plan
5. **Remediation** — Fix all Critical/High findings
6. **Rescan** — Verify remediation with `bash pci_scan.sh ...`
7. **Archive** — Report auto-saved in `history/pci_dss_YYYY-QN.html` for audit

---

## 🛡️ Security Notes

- **Never run on targets you don't have authorization to scan**
- Credentials files must be `chmod 600` and stored in a vault after use
- ZAP Active Scan sends real attack payloads — test in non-production first
- Review `NMAP_TIMING` and rate limits before scanning production CDE systems
- External-facing scans must be performed by an ASV (Requirement 11.3.2)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development setup

```bash
git clone https://github.com/YOUR_USERNAME/swarm-pci.git
cd swarm-pci
sudo bash setup_ubuntu.sh
bash pci_scan.sh -t https://your-test-target.com -p web-only
```

---

## 🐛 Known Issues & Limitations

- ZAP runs sequentially across targets (daemon is single-instance)
- `-sS` SYN scan requires root; fallback to `-sT` otherwise
- `testssl.sh` first run may take 40-90s per target (normal)
- Large CIDR ranges should be split into smaller targets for performance

---

## 📚 References

- [PCI DSS 4.0 Standard](https://www.pcisecuritystandards.org/document_library/)
- [PCI DSS 4.0 Requirement 11](https://www.pcisecuritystandards.org/) — Testing
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [testssl.sh Documentation](https://testssl.sh/)
- [OWASP ZAP API](https://www.zaproxy.org/docs/api/)

---

## ⚠️ Disclaimer

> SWARM-PCI is intended for **authorized security testing only**.
>
> Users are responsible for ensuring they have explicit written authorization to scan any target system. The authors assume no liability for misuse of this tool.
>
> This tool **supplements** but does not replace:
> - Approved Scanning Vendor (ASV) scans for external systems (Req 11.3.2)
> - Annual penetration testing (Req 11.4)
> - Qualified Security Assessor (QSA) audits

---

<div align="center">

**Built by [Omnibees Security Intelligence](https://github.com/YOUR_USERNAME)** 🐝

*Part of the SWARM security toolkit*

⭐ Star this repo if you find it useful!

</div>

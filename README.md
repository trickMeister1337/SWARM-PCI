# PCI Scan — PCI DSS 4.0.1 Internal Compliance Scanner

[![PCI DSS](https://img.shields.io/badge/PCI%20DSS-4.0.1-1a3a4f)](https://www.pcisecuritystandards.org/)
[![Bash](https://img.shields.io/badge/bash-%3E%3D4.4-4eaa25)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/license-Internal-lightgrey)]()
[![Version](https://img.shields.io/badge/version-2.1.0-blue)]()

> Scanner interno de compliance PCI DSS 4.0.1 desenvolvido pela **trickMeister1337e**.
> Orquestra **nmap**, **testssl**, **nuclei**, **OWASP ZAP**, **trivy**, **ssh-audit**, **prowler** e checagens próprias para gerar um relatório acionável (HTML + CSV + SARIF) com evidências, contadores corretos por severidade, dedup inteligente e SLA tracking (Req 6.3.3).

---

## 📋 Índice

- [Cobertura PCI DSS 4.0.1](#-cobertura-pci-dss-401)
- [O que NÃO substitui](#-o-que-não-substitui)
- [Arquitetura do scan](#-arquitetura-do-scan-10-fases)
- [Instalação](#-instalação)
  - [Dependências obrigatórias](#dependências-obrigatórias)
  - [Dependências opcionais](#dependências-opcionais-recomendadas)
  - [Instalação rápida (Debian/Ubuntu)](#instalação-rápida-debianubuntu)
  - [Instalação rápida (RHEL/Fedora)](#instalação-rápida-rhelfedora)
  - [Instalação rápida (macOS)](#instalação-rápida-macos)
  - [Docker (opcional)](#docker-opcional)
- [Uso](#-uso)
  - [CLI completa](#cli-completa)
  - [Formato do arquivo de alvos](#formato-do-arquivo-de-alvos)
  - [Formato do arquivo de credenciais](#formato-do-arquivo-de-credenciais)
  - [Exemplos práticos](#exemplos-práticos)
- [Saída e relatórios](#-saída-e-relatórios)
- [Lógica de severidade, dedup e SLA](#-lógica-de-severidade-dedup-e-sla)
- [Variáveis de ambiente](#-variáveis-de-ambiente)
- [Chain of Custody / Auditoria](#-chain-of-custody--auditoria)
- [CI/CD](#-cicd)
- [Troubleshooting](#-troubleshooting)
- [Changelog v2.1.0](#-changelog-v210)
- [Roadmap](#-roadmap)
- [Licença](#-licença)

---

## ✅ Cobertura PCI DSS 4.0.1

| Requisito | O que o scan verifica | Ferramenta |
|-----------|----------------------|------------|
| **Req 1.3** | Serviços inseguros expostos no CDE (FTP, Telnet, SMB, etc.) | nmap |
| **Req 2.2** | Hardening / config padrão / banners expostos | nmap, curl |
| **Req 2.2.4** | FTP anônimo, serviços desnecessários | nmap |
| **Req 2.2.7** | RDP sem NLA, version disclosure | nmap, curl |
| **Req 3.5.1** | PAN exposto em respostas HTTP (Luhn-validated) | detector próprio |
| **Req 4.2.1** | TLS obsoleto (SSLv2/v3, TLS 1.0/1.1, RC4, 3DES, SWEET32, Heartbleed, POODLE…) | testssl |
| **Req 4.2.1.1** | Inventário de certificados, expiração, chaves fracas, SHA-1/MD5 | openssl |
| **Req 5.4.1** | SPF/DKIM/DMARC/MTA-STS (defesa anti-phishing) | dig |
| **Req 6.2.4** | XSS, SQLi, CSRF, IDOR, security headers ausentes | nuclei, ZAP |
| **Req 6.3.1** | Subdomain takeover | nuclei |
| **Req 6.3.3** | CVEs conhecidos + **SLA de 30 dias** para Críticas/Altas | nuclei, ssh-audit |
| **Req 6.4.2** | WAF presente em apps web públicas | wafw00f |
| **Req 6.4.3** | Inventário e integridade de scripts em páginas de checkout (anti-Magecart) | detector próprio (SHA-384 + diff) |
| **Req 8.3.1** | Senhas em texto plano, MFA fraco, PasswordAuthentication SSH | ssh-audit, policy |
| **Req 8.6.1** | Login direto root (PermitRootLogin) | ssh-audit autenticado |
| **Req 11.3.1** | Scan trimestral interno autenticado | toda a stack |
| **Req 11.3.1.2** | Scan **autenticado** (SSH/HTTP) — exigência 4.0 | módulo de creds |
| **Req 11.3.1.3** | Re-scan / diff vs scan anterior | comparador `-d` |
| **Req 11.4.5** | Teste de **segmentação de rede** (CDE vs não-CDE) | nmap remoto via SSH |
| **Req 11.6.1** | Detecção de tampering em página de pagamento | hash SHA-384 + diff |
| **Req 12.5.2** | Validação de escopo (PAN onde não deveria) | detector próprio |

---

## ⚠ O que NÃO substitui

Este scanner é uma **camada interna**. Você ainda precisa de:

- **Req 11.3.2** — ASV scan externo (Qualys, Tenable, Trustwave…)
- **Req 11.4** — Pentest com equipe humana
- **Req 7, 9, 10, 12** — Controles administrativos, físicos, logging e políticas

---

## 🧩 Arquitetura do scan (10 fases)

```
┌─────────────────────────────────────────────────────────────────┐
│  Fase 1  │ Network discovery     │ nmap -sV -sC + scripts        │
│  Fase 2  │ TLS audit + cert inv. │ testssl + openssl s_client    │
│  Fase 3  │ Config audit          │ headers HTTP + ssh-audit + DNS│
│  Fase 4  │ Authenticated scan    │ SSH/HTTP com creds (Req 11.3.1.2)│
│  Fase 5  │ Vulnerability scan    │ nuclei + trivy + WAF detect   │
│  Fase 6  │ Web app scan          │ OWASP ZAP (spider + active)   │
│  Fase 7  │ PCI-specific          │ PAN/Luhn + checkout integrity + segmentation │
│  Fase 8  │ Cloud posture         │ prowler / kube-bench (opt)    │
│  Fase 9  │ Dedup + diff + SLA    │ fingerprint + CVE age check   │
│  Fase 10 │ Reports               │ HTML + CSV + SARIF + manifest │
└─────────────────────────────────────────────────────────────────┘
```

Findings são gravados em JSONL atomicamente (via `flock`) por todas as fases em paralelo, depois deduplicados por `sha1(title|cve|cwe|pci_req)` preservando todos os targets/evidências.

---

## 📦 Instalação

### Dependências obrigatórias

| Pacote | Por quê |
|--------|---------|
| `bash` ≥ 4.4 | Arrays associativos, `flock` |
| `curl` | HTTP probes, headers, ZAP API |
| `python3` ≥ 3.8 | Parsers JSON, dedup, relatórios |
| `nmap` | Discovery de portas/serviços |

### Dependências opcionais (recomendadas)

| Pacote | Fase | O que habilita |
|--------|------|----------------|
| `testssl.sh` | 2 | Auditoria TLS completa (Req 4.2.1) |
| `openssl` | 2 | Inventário de certificados |
| `dig` (bind-utils / dnsutils) | 3 | SPF/DMARC/MTA-STS |
| `ssh-audit` | 3 | KEX/cipher SSH fracos |
| `wafw00f` | 5 | Detecção de WAF (Req 6.4.2) |
| `nuclei` (ProjectDiscovery) | 5 | Templates CVE/misconfig/exposure |
| `trivy` (Aqua) | 5 | SBOM + CVE em pacotes |
| `zaproxy` (OWASP ZAP) | 6 | Spider + active scan web |
| `sshpass` | 4 | Auth SSH por senha (legacy — prefira chave) |
| `jq` | dev | Inspeção do JSONL |
| `prowler` | 8 | Cloud posture (AWS/Azure/GCP) |
| `kube-bench` | 8 | CIS Kubernetes |

### Instalação rápida (Debian/Ubuntu)

```bash
# Obrigatórias
sudo apt update
sudo apt install -y bash curl python3 python3-pip nmap

# Opcionais — sistema
sudo apt install -y testssl.sh openssl dnsutils ssh-audit wafw00f sshpass jq

# Nuclei
GO_BIN="${HOME}/go/bin"
mkdir -p "$GO_BIN"
curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
  | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 \
  | xargs curl -L -o /tmp/nuclei.zip
unzip -o /tmp/nuclei.zip -d "$GO_BIN" && rm /tmp/nuclei.zip
nuclei -update-templates

# Trivy
sudo apt install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy

# OWASP ZAP
sudo snap install zaproxy --classic
# (alt) baixar de https://www.zaproxy.org/download/

# Prowler (opcional, Python)
pip install --user prowler

# Adicione ao PATH (se necessário)
echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Instalação rápida (RHEL/Fedora)

```bash
sudo dnf install -y bash curl python3 nmap openssl bind-utils jq
# testssl.sh manual:
git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/testssl.sh
sudo ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
# Nuclei / Trivy: idem Debian (binários estáticos)
```

### Instalação rápida (macOS)

```bash
brew install bash nmap openssl testssl jq dig
brew install nuclei trivy wafw00f
brew install --cask owasp-zap
```

### Docker (opcional)

Crie um `Dockerfile` minimalista com toda a stack:

```dockerfile
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl python3 nmap openssl testssl.sh dnsutils \
    ssh-audit wafw00f sshpass jq ca-certificates wget unzip \
 && rm -rf /var/lib/apt/lists/*
# nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    -o /tmp/n.zip && unzip /tmp/n.zip -d /usr/local/bin && rm /tmp/n.zip \
 && nuclei -update-templates
# trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin
COPY pci_scan.sh /usr/local/bin/pci_scan
RUN chmod +x /usr/local/bin/pci_scan
ENTRYPOINT ["pci_scan"]
```

```bash
docker build -t pci-scan:2.1 .
docker run --rm -v "$PWD/scan_output:/out" -v "$PWD/targets.txt:/targets.txt:ro" \
  pci-scan:2.1 -f /targets.txt -o /out -p full
```

---

## 🚀 Uso

### CLI completa

```
bash pci_scan.sh -f <targets_file> [opções]
bash pci_scan.sh -t <target> [opções]
```

| Flag | Descrição |
|------|-----------|
| `-f FILE` | Arquivo com lista de alvos (formato abaixo) |
| `-t TARGET` | Alvo único (IP, CIDR ou URL) |
| `-o DIR` | Diretório de output (default: `pci_scan_<timestamp>`) |
| `-p PROFILE` | `full` \| `quick` \| `web-only` \| `infra-only` (default: `full`) |
| `-c FILE` | Arquivo de credenciais para scan autenticado (Req 11.3.1.2) — **chmod 600** |
| `-d DIR` | Diretório de scan anterior (para diff e SLA tracking) |
| `--full-ports` | nmap `-p-` (todas as 65535 portas TCP) |
| `--udp` | nmap UDP top-100 (requer root) |
| `--segmentation HOST` | Testa segmentação saindo de HOST via SSH (Req 11.4.5) |
| `--prowler PROVIDER` | `aws` \| `azure` \| `gcp` \| `kubernetes` |
| `--no-zap` | Pular OWASP ZAP |
| `--no-nuclei` | Pular nuclei |
| `--no-trivy` | Pular trivy |
| `--no-dns-audit` | Pular SPF/DMARC/MTA-STS |
| `--no-pan-detection` | Pular detector PAN/Luhn |
| `--no-cert-inventory` | Pular inventário de certificados |
| `-h`, `--help` | Ajuda |

### Formato do arquivo de alvos

```
# tipo  alvo                          rótulo        extras
web     https://payments.example.com  CDE-Web       checkout=true
web     https://api.example.com       CDE-API
infra   10.0.1.0/24                   CDE-DB
infra   192.168.1.50                  CDE-App
both    10.0.2.10                     Bastion
# linhas iniciadas com '#' são comentários
```

- **Tipos:** `web` (URL HTTP/HTTPS), `infra` (IP/CIDR), `both` (ambos os scans).
- **`checkout=true`** ativa Req 6.4.3 (inventário SHA-384 + diff de scripts) na URL.

### Formato do arquivo de credenciais

> ⚠ **Permissão obrigatória: `chmod 600`** (o script ajusta automaticamente se for menos restrito).

```
# tipo  host         porta  usuário   segredo                        método
ssh     10.0.1.5     22     scanner   KEY:/root/.ssh/id_ed25519      key
ssh     10.0.1.6     22     scanner   ENV:SSH_PASS                   env
http    pay.ex.com   443    admin     ENV:HTTP_PASS                  env
# NUNCA armazene senhas em texto plano. Use KEY: ou ENV:.
```

| Prefixo | Significado |
|---------|-------------|
| `KEY:/path/to/id` | Caminho de chave privada SSH |
| `ENV:VAR_NAME` | Lê o segredo da variável de ambiente |
| _(texto puro)_ | **Detectado e bloqueado** — gera finding alto (Req 8.3.1) |

### Exemplos práticos

**Scan trimestral completo (full profile, autenticado, com diff vs trimestre anterior):**
```bash
export SSH_PASS="$(vault kv get -field=password secret/scanner)"
bash pci_scan.sh \
  -f targets.txt \
  -c creds.txt \
  -d ./pci_scan_2025Q4 \
  -p full \
  -o ./pci_scan_2026Q1
```

**Scan rápido só web (CI nightly):**
```bash
bash pci_scan.sh -t https://staging.app.com -p web-only --no-trivy
```

**Scan completo com todas as portas TCP + UDP (requer root):**
```bash
sudo bash pci_scan.sh -f targets.txt --full-ports --udp -p full
```

**Teste de segmentação (Req 11.4.5):**
```bash
# Roda nmap a partir do bastion-non-cde para tentar alcançar o CDE
bash pci_scan.sh -f cde_hosts.txt --segmentation bastion-non-cde.example.com
```

**Cloud posture (AWS) + Kubernetes:**
```bash
bash pci_scan.sh -f targets.txt --prowler aws
bash pci_scan.sh -f targets.txt --prowler kubernetes
```

---

## 📊 Saída e relatórios

```
pci_scan_<timestamp>/
├── relatorio_pci_dss.html         ← Relatório executivo (HTML standalone)
├── MANIFEST.sha256                ← Integridade de todos os artefatos
├── exports/
│   ├── findings.csv               ← 1 linha por (vulnerabilidade × target) — para tickets
│   └── findings.sarif             ← SARIF v2.1.0 (DefectDojo, GitHub Code Scanning…)
├── raw/
│   ├── findings.jsonl             ← Findings brutos (todas as fases)
│   ├── findings_dedup.jsonl       ← Findings deduplicados (1 por vulnerabilidade)
│   ├── diff.json                  ← New / fixed / persisting / SLA breaches
│   ├── nmap_<host>.{txt,xml}
│   ├── testssl_<host>.json
│   ├── nuclei_all.json
│   ├── zap_<host>.json
│   ├── cert_inventory.json
│   ├── kube-bench.json
│   └── scan_meta.json             ← Chain of custody (SHA-256, operador, timestamp)
├── evidence/
│   └── auth_ssh_<host>.txt        ← chmod 600 — saída do scan autenticado
├── checkout_baseline/
│   └── <url>.json                 ← SHA-384 dos scripts (Req 6.4.3)
└── history/
    ├── pci_dss_<quarter>.html
    └── scan_log.txt
```

**Status de compliance** (calculado a partir das vulnerabilidades únicas):

| Status | Critério |
|--------|----------|
| **PASS** | Sem críticas, altas ou médias |
| **REVIEW** | Apenas médias |
| **FAIL** | ≥ 1 crítica ou alta |

---

## 🧠 Lógica de severidade, dedup e SLA

### Mapa de severidade

| Origem | Crítica | Alta | Média | Baixa | Info |
|--------|---------|------|-------|-------|------|
| **Nuclei** | severity=critical (ou high+CVSS≥9.0) | high | medium | low | info |
| **ZAP** | _(nenhum — ZAP não tem nível "crítico")_ | risk=3 (high) com confidence≥medium | risk=2 ou risk=3 com confidence baixa | risk=1 | risk=0 |
| **TLS / testssl** | SSLv2/v3, Heartbleed | TLS 1.0/1.1, 3DES, RC4, POODLE | BEAST, LUCKY13, HSTS missing | informativos | OK |
| **Cert** | Expirado | Expira <30d, RSA<2048, SHA-1/MD5 | Expira <90d | — | — |
| **PAN** | **sempre crítica** (Luhn-validated em resposta HTTP) | — | — | — | — |
| **Checkout integrity** | Hash mudou (Magecart) | Script novo desde último scan | — | — | — |

### Dedup

Fingerprint = `sha1(title[:80] | cve | cwe | pci_req)[:12]`

- Mesma vulnerabilidade em **N hosts** = **1 finding** com array `targets[]` e `evidences[]` (até 25 evidências preservadas).
- `occurrences` = número total de instâncias.
- O CSV explode de volta em N linhas para facilitar abertura de tickets.

### SLA (Req 6.3.3)

CVEs **críticos/altos** abertos há mais de **30 dias** (estimado pelo ano do CVE-ID, meio do ano):
- Recebem flag `sla_breach: true`
- Severity é elevada para `critical` no relatório
- Aparecem em destaque na faixa **H0 — SLA BREACH** do Plano de Remediação

### Diff vs scan anterior (Req 11.3.1.3)

Passe `-d <dir_anterior>` para gerar:
- **Novos** — fingerprints que não existiam antes
- **Persistentes** — fingerprints presentes nos dois
- **Corrigidos** — fingerprints do scan anterior ausentes agora
- **SLA breaches** — corte ≥30 dias

---

## 🔐 Variáveis de ambiente

| Variável | Uso |
|----------|-----|
| `SSH_PASS` | Senha SSH para entradas `ENV:SSH_PASS` no creds file |
| `HTTP_PASS` | Senha HTTP para entradas `ENV:HTTP_PASS` |
| `*` | Qualquer variável referenciada como `ENV:VAR_NAME` |

> **Boa prática:** injete via Vault, AWS Secrets Manager ou similar — nunca exporte direto no shell.

```bash
export SSH_PASS="$(vault kv get -field=password kv/scanner/ssh)"
export HTTP_PASS="$(aws secretsmanager get-secret-value --secret-id scanner/http --query SecretString --output text)"
bash pci_scan.sh -f targets.txt -c creds.txt
```

---

## 🪪 Chain of Custody / Auditoria

Cada execução gera um `scan_meta.json` com:

- `scan_id` (timestamp + PID)
- `scanner_sha256` — hash do próprio script
- `operator` (`user@host`), `operator_ip`
- `scan_date_iso` (UTC)

E o `MANIFEST.sha256` lista o hash de **todos** os artefatos gerados, permitindo provar integridade ao auditor.

Adicionalmente, eventos `PHASE_START / PHASE_END / SCAN_START / SCAN_END` são enviados para o **syslog local** (`logger -t pci_scan`).

---

## 🤖 CI/CD

### GitHub Actions (exemplo)

```yaml
name: PCI Scan
on:
  schedule:
    - cron: '0 3 1 */3 *'   # trimestral
  workflow_dispatch:

jobs:
  pci-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install deps
        run: |
          sudo apt-get update
          sudo apt-get install -y nmap testssl.sh dnsutils ssh-audit jq
          curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/n.zip
          unzip /tmp/n.zip -d /usr/local/bin && nuclei -update-templates
      - name: Run scan
        env:
          SSH_PASS: ${{ secrets.SCANNER_SSH_PASS }}
        run: bash pci_scan.sh -f targets.txt -c creds.txt -p full -o ./out
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./out/exports/findings.sarif
      - name: Archive report
        uses: actions/upload-artifact@v4
        with:
          name: pci-report
          path: ./out
```

### Integração com DefectDojo

```bash
curl -X POST "https://defectdojo.example.com/api/v2/import-scan/" \
  -H "Authorization: Token $DD_TOKEN" \
  -F "scan_type=SARIF" \
  -F "engagement=42" \
  -F "file=@./out/exports/findings.sarif"
```

---

## 🛠 Troubleshooting

| Sintoma | Causa provável | Fix |
|---------|----------------|-----|
| `Faltando: nmap` | Dependência obrigatória ausente | Instale via apt/dnf/brew |
| ZAP fica em "Aguardando..." 180s | Java ausente, porta 8081 ocupada | `sudo lsof -i:8081`, `apt install default-jre` |
| `testssl indisponível` | Não está no PATH | `which testssl.sh`, exportar PATH |
| Scan SSH falha em todos os hosts | Chave sem permissão `600` ou usuário errado | `chmod 600 ~/.ssh/id_*`, validar `ssh -i ... user@host` manualmente |
| 0 findings de nuclei | Templates desatualizados | `nuclei -update-templates` |
| `nmap -sS` falha | Sem root → cai automaticamente para `-sT` | Rode com `sudo` para SYN scan completo |
| `--udp` ignorado | Requer root | `sudo bash pci_scan.sh ... --udp` |
| `Credencial em texto plano` | Senha sem `KEY:` ou `ENV:` no creds | Migrar para `ENV:VAR` ou chave SSH |
| Dedup não agrupa esperado | Title difere entre tools | É by design — fingerprint inclui `pci_req+cwe+cve` |

Logs verbosos:
```bash
bash -x pci_scan.sh -t https://example.com 2> scan.debug.log
```

---

## 📜 Changelog v2.1.0

> Veja a discussão completa do refactor no commit history.

**Bugs corrigidos:**
- ZAP `risk=3` (High) era mapeado como `critical` — inflava contadores e disparava FAIL global indevido.
- Dedup destrutivo: agrupava por `(title+target)` e descartava evidências de outros hosts.
- SLA breach injetava findings duplicados pós-dedup, distorcendo o total.
- Findings `low`/`info` eram silenciosamente escondidos do HTML.
- Plano de remediação contava _cards_ em vez de ocorrências reais por host.

**Melhorias:**
- Dedup por `(title|cve|cwe|pci_req)` preservando todos os targets e até 25 evidências.
- CSV: 1 linha por `(vuln × target)` com `fingerprint`, `sla_breach`, `cve_age_days`.
- SARIF: `message` agora inclui evidência + remediação (consumido por DefectDojo/GitHub).
- Nuclei: evidência rica (`matched-at + extracted-results + matcher-name + curl-command`) + auto-upgrade `high→critical` quando CVSS ≥ 9.0.
- ZAP: severidade modulada por `confidence` para reduzir falsos positivos.
- Console exibe breakdown por severidade (únicas/ocorrências) ao final.
- Plano de Remediação ganha faixa **H0 — SLA BREACH** em destaque.

---

## 🗺 Roadmap

- [ ] CVE age via API NVD (em vez de heurística pelo ano do CVE-ID)
- [ ] PAN detector com crawl integrado ao spider do ZAP
- [ ] Whitelist de riscos aceitos (`accepted_risks.yaml`) — Req 12.3.1
- [ ] Push automático para Jira/DefectDojo via SARIF
- [ ] Output JSONL particionado por requisito PCI
- [ ] `nmap --script vuln` na fase 1 (CVEs de banner-grab)
- [ ] Suporte nativo a Trivy `rootfs` em hosts autenticados

---

## 📄 Licença

Distribuição externa, fork público ou redistribuição requerem autorização da equipe de segurança.

---

## 👤 Autor / Mantenedor

**[@trickMeister1337](https://github.com/trickMeister1337)**

Issues e melhorias: abra um PR ou issue no repositório.

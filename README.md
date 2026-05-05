# PCI SCAN v2 — PCI DSS 4.0.1 Internal Compliance Scanner

Este repositório contém o **PCI SCAN v2**, uma ferramenta de automação para auditoria técnica de conformidade interna com o padrão **PCI DSS 4.0.1**. Desenvolvido para facilitar a identificação de vulnerabilidades e falhas de configuração em ambientes CDE (Cardholder Data Environment).

> [!IMPORTANT]
> Este script é uma ferramenta de auxílio à conformidade interna. Ele **NÃO** substitui o scan externo obrigatório por um ASV (Approved Scanning Vendor) (Req 11.3.2) nem o Teste de Invasão anual (Req 11.4).

---

## 🚀 Funcionalidades

O script automatiza a coleta de evidências e testes técnicos para diversos requisitos do PCI DSS 4.0.1:

| Requisito | Descrição da Cobertura |
| :--- | :--- |
| **Req 1.3** | Verificação de regras de firewall e fluxos de rede. |
| **Req 2.2** | Identificação de serviços desnecessários e configurações padrão (Hardening). |
| **Req 3.5** | Detecção de armazenamento de PAN (Primary Account Number) em texto claro. |
| **Req 4.2.1** | Auditoria de protocolos de criptografia em trânsito (TLS/SSL). |
| **Req 6.2.4** | Identificação de vulnerabilidades de software conhecidas. |
| **Req 6.4.3** | Integridade de scripts em páginas de checkout. |
| **Req 11.3.1.x** | Scans de vulnerabilidades internos (autenticados e não autenticados). |
| **Req 11.4.5** | Testes de segmentação de rede. |
| **Req 11.6.1** | Detecção de alterações não autorizadas em cabeçalhos HTTP e páginas. |

### Diferenciais:
- **Relatórios Multiformato:** Gera saídas em **HTML (interativo)**, **CSV** e **SARIF v2.1.0**.
- **Deduplicação Inteligente:** Consolida achados de múltiplas ferramentas para evitar ruído.
- **Plano de Remediação:** Sugere prazos (H1, H2, H3) baseados na severidade e requisitos PCI.
- **Manifesto de Integridade:** Gera hashes SHA-256 de todos os relatórios para garantir a não violação da evidência.

---

## 🛠️ Instalação e Dependências

O script utiliza diversas ferramentas consagradas de segurança. Para o funcionamento pleno, instale as seguintes dependências:

### Obrigatórias
- **Bash 4+**
- **Python 3.x**
- **curl**
- **nmap**

### Recomendadas (para cobertura total)
- **Nuclei:** Scans de templates e CVEs.
- **OWASP ZAP:** DAST para aplicações web.
- **Trivy:** Auditoria de containers, IaC e SBOM.
- **testssl.sh:** Auditoria profunda de TLS/SSL.
- **jq:** Processamento de JSON.
- **Prowler / Kube-bench:** Auditoria de Cloud (AWS/Azure/GCP) e Kubernetes.

### Exemplo de instalação (Ubuntu/Debian):
```bash
sudo apt update && sudo apt install -y nmap curl python3 jq
# Para ferramentas específicas, siga as instruções oficiais:
# Nuclei: projectdiscovery.io
# ZAP: zapproxy.org
# Trivy: aquasecurity.github.io/trivy
```

---

## 💻 Como Usar

### 1. Preparar Alvos
Crie um arquivo (ex: `targets.txt`) seguindo o formato:
```text
web   https://pagamentos.empresa.com   CDE-Web   checkout=true
infra 10.0.1.0/24                      CDE-DB
both  192.168.1.50                     CDE-App
```

### 2. Executar o Scan
```bash
# Scan completo (Padrão)
bash pci_scan.sh -f targets.txt

# Scan de alvo único
bash pci_scan.sh -t 10.0.1.10

# Scan rápido (pula auditoria DNS e inventário de certificados)
bash pci_scan.sh -f targets.txt -p quick

# Teste de segmentação (Req 11.4.5)
bash pci_scan.sh -f targets.txt --segmentation 172.16.0.1
```

### Opções Principais:
- `-p PROFILE`: `full` | `quick` | `web-only` | `infra-only`
- `-c FILE`: Arquivo de credenciais para scans autenticados (Req 11.3.1.2).
- `--full-ports`: Varre todas as 65535 portas TCP.
- `--no-zap`, `--no-nuclei`, `--no-trivy`: Pula ferramentas específicas.

---

## 📊 Resultados

Os resultados são organizados por data no diretório de output (padrão: `./results/`):
- `report.html`: Dashboard visual para gestores e auditores.
- `findings.csv`: Lista técnica para importação em planilhas.
- `scan.sarif`: Integração com ferramentas de CI/CD e IDEs.
- `MANIFEST.sha256`: Prova de integridade dos arquivos gerados.

---

## 👤 Autor
Desenvolvido por **trickMeister1337**

---
*Este projeto é mantido para fins de conformidade e segurança. Contribuições são bem-vindas via Pull Requests.*

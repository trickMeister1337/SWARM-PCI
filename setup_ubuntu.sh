#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PCI SCAN — Setup de Dependências (Ubuntu 22.04/24.04)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  PCI SCAN — Instalação de Dependências (Ubuntu)${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo ""

# ─── 1. APT packages ───
echo -e "${BLUE}[1/5]${NC} Instalando pacotes via apt..."
sudo apt update -qq
sudo apt install -y nmap jq sshpass curl python3 golang-go nikto

# ─── 2. Go tools (nuclei, httpx, subfinder) ───
echo -e "${BLUE}[2/5]${NC} Instalando ferramentas Go..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo -e "${GREEN}  ✓ nuclei${NC}"

# Atualizar templates nuclei
nuclei -update-templates -silent 2>/dev/null || true
echo -e "${GREEN}  ✓ nuclei templates atualizados${NC}"

# ─── 3. testssl.sh ───
echo -e "${BLUE}[3/5]${NC} Instalando testssl.sh..."
if ! command -v testssl.sh &>/dev/null && ! command -v testssl &>/dev/null; then
    TESTSSL_DIR="$HOME/tools/testssl.sh"
    if [[ ! -d "$TESTSSL_DIR" ]]; then
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR"
    fi
    sudo ln -sf "$TESTSSL_DIR/testssl.sh" /usr/local/bin/testssl.sh
    echo -e "${GREEN}  ✓ testssl.sh instalado${NC}"
else
    echo -e "${GREEN}  ✓ testssl.sh já presente${NC}"
fi

# ─── 4. OWASP ZAP ───
echo -e "${BLUE}[4/5]${NC} Instalando OWASP ZAP..."
if ! command -v zaproxy &>/dev/null; then
    # Tentar via snap primeiro (mais fácil no Ubuntu)
    if command -v snap &>/dev/null; then
        sudo snap install zaproxy --classic
        echo -e "${GREEN}  ✓ zaproxy instalado via snap${NC}"
    else
        echo -e "${YELLOW}  ! snap não disponível — instalar ZAP manualmente:${NC}"
        echo "    https://www.zaproxy.org/download/"
    fi
else
    echo -e "${GREEN}  ✓ zaproxy já presente${NC}"
fi

# ─── 5. PATH persistente ───
echo -e "${BLUE}[5/5]${NC} Configurando PATH..."
BASHRC="$HOME/.bashrc"
grep -q 'go/bin' "$BASHRC" 2>/dev/null || echo 'export PATH=$PATH:$HOME/go/bin' >> "$BASHRC"
grep -q 'local/bin' "$BASHRC" 2>/dev/null || echo 'export PATH=$PATH:$HOME/.local/bin' >> "$BASHRC"

# ─── Validação final ───
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VALIDAÇÃO${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

TOOLS=("bash" "curl" "python3" "nmap" "jq" "sshpass" "testssl.sh" "nuclei" "zaproxy" "nikto")
ALL_OK=1

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        VER=$($tool --version 2>/dev/null | head -1 || echo "OK")
        echo -e "  ${GREEN}✓${NC} $tool — $VER"
    else
        echo -e "  ${RED}✗${NC} $tool — NÃO ENCONTRADO"
        ALL_OK=0
    fi
done

echo ""
if [[ $ALL_OK -eq 1 ]]; then
    echo -e "${GREEN}${BOLD}Tudo pronto! Rodar: bash pci_scan.sh -f targets.txt${NC}"
else
    echo -e "${YELLOW}Algumas ferramentas faltam — o script vai pular as fases correspondentes.${NC}"
    echo -e "${YELLOW}Feche e abra um novo terminal para carregar o PATH atualizado.${NC}"
fi

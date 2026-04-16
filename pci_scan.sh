#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PCI SCAN — PCI DSS 4.0 Internal Compliance Scanner
#  Omnibees Security Intelligence
# ═══════════════════════════════════════════════════════════════
# Covers: Req 2 (Secure Config), Req 4 (Cryptography),
#         Req 6 (Secure Systems), Req 11 (Regular Testing)
# ═══════════════════════════════════════════════════════════════

set -uo pipefail  # Não usar -e: scan scripts chamam ferramentas que retornam non-zero normalmente

# ─── Colors ───
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'

# ─── Configuration ───
ZAP_PORT=8081
ZAP_HOST="127.0.0.1"
ZAP_SPIDER_TIMEOUT=600      # 10 minutos
ZAP_SCAN_TIMEOUT=1800       # 30 minutos
ZAP_STARTUP_TIMEOUT=180
NUCLEI_RATE_LIMIT=30
NUCLEI_CONCURRENCY=5
NMAP_TIMING="T3"
TESTSSL_TIMEOUT=300
MAX_PARALLEL=8
SCAN_DATE=$(date +"%Y%m%d_%H%M%S")
SCAN_DATE_HUMAN=$(date +"%d/%m/%Y %H:%M:%S")
QUARTER=$(date +"%Y-Q$(( ($(date +%-m) - 1) / 3 + 1 ))")

# ─── PATH Setup ───
for p in "$HOME/go/bin" "/root/go/bin" "$HOME/.local/bin" "/usr/local/bin"; do
    [[ -d "$p" ]] && [[ ":$PATH:" != *":$p:"* ]] && export PATH="$PATH:$p"
done

# ─── Root detection (affects nmap scan type) ───
IS_ROOT=0
[[ "$(id -u)" -eq 0 ]] && IS_ROOT=1

# ─── Initialize timer var ───
PHASE_START=0

# ═══════════════════════════════════════════════════════════════
#  USAGE
# ═══════════════════════════════════════════════════════════════
usage() {
    echo -e "${BOLD}PCI SCAN — PCI DSS 4.0 Internal Compliance Scanner${NC}"
    echo ""
    echo -e "  ${CYAN}Uso:${NC}"
    echo "    bash pci_scan.sh -f <targets_file> [opções]"
    echo "    bash pci_scan.sh -t <target> [opções]"
    echo "    bash pci_scan.sh -c <config.yaml> [opções]"
    echo ""
    echo -e "  ${CYAN}Opções:${NC}"
    echo "    -f FILE    Arquivo com lista de alvos (um por linha)"
    echo "    -t TARGET  Alvo único (IP, CIDR ou URL)"
    echo "    -c CONFIG  Arquivo de configuração YAML"
    echo "    -o DIR     Diretório de output (default: pci_scan_YYYYMMDD)"
    echo "    -p PROFILE Perfil: full|quick|web-only|infra-only (default: full)"
    echo "    --no-zap   Pular OWASP ZAP"
    echo "    --no-nuclei Pular Nuclei"
    echo "    --no-lynis Pular Lynis (hardening)"
    echo "    --no-trivy Pular Trivy (CVEs)"
    echo "    -h         Mostrar ajuda"
    exit 0
}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════
log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_fail()  { echo -e "${RED}[✗]${NC} $1"; }
log_skip()  { echo -e "${YELLOW}[○]${NC} $1"; }

phase_header() {
    local phase="$1" title="$2"
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  FASE ${phase}: ${title}${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

timer_start() { PHASE_START=$(date +%s); }
timer_end() {
    local elapsed=$(( $(date +%s) - PHASE_START ))
    echo -e "${GREEN}[✓] Fase concluída em ${elapsed}s${NC}"
}

extract_domain() {
    echo "$1" | sed -E 's|https?://||;s|/.*||;s|:.*||'
}

is_url() { [[ "$1" =~ ^https?:// ]]; }
is_cidr() { [[ "$1" =~ /[0-9]+$ ]]; }

# ZAP API helper
zap_api_call() {
    local endpoint="$1" params="${2:-}"
    local url="http://${ZAP_HOST}:${ZAP_PORT}/JSON/${endpoint}/"
    [[ -n "$params" ]] && url="${url}?${params}"
    curl -s --max-time 30 "$url" 2>/dev/null
}

wait_for_zap() {
    log_info "Aguardando ZAP ficar pronto (max ${ZAP_STARTUP_TIMEOUT}s)..."
    local elapsed=0
    while [[ $elapsed -lt $ZAP_STARTUP_TIMEOUT ]]; do
        if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
            log_ok "ZAP pronto"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        printf "\r${BLUE}[*] Aguardando... %d/${ZAP_STARTUP_TIMEOUT}s${NC}" "$elapsed"
    done
    echo ""
    return 1
}

# Melhorada: detecta progresso estagnado e cancela o scan automaticamente
wait_for_zap_progress() {
    local endpoint="$1" scan_id="$2" timeout="$3" label="$4"
    local elapsed=0 progress=0 last_progress=-1 stall_count=0

    while true; do
        progress=$(zap_api_call "$endpoint" "scanId=${scan_id}" 2>/dev/null \
                   | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
        progress=${progress:-0}
        printf "\r${BLUE}[*] ${label}: %s%%${NC}  " "$progress"

        [[ "$progress" == "100" ]] && break

        # Se ficar 5 iterações (50s) sem mudar o progresso, assume travamento
        if [[ "$progress" == "$last_progress" ]]; then
            stall_count=$((stall_count + 1))
        else
            stall_count=0
        fi
        last_progress=$progress

        if [[ $stall_count -ge 5 ]]; then
            echo ""
            log_warn "${label} parece travado (progresso estagnado em ${progress}%). Cancelando scan..."
            zap_api_call "${endpoint%/*}/action/stop" "scanId=${scan_id}" >/dev/null 2>&1
            return 1
        fi

        if [[ "$timeout" -gt 0 && "$elapsed" -ge "$timeout" ]]; then
            echo ""
            log_warn "${label} timeout após ${timeout}s"
            zap_api_call "${endpoint%/*}/action/stop" "scanId=${scan_id}" >/dev/null 2>&1
            return 1
        fi

        sleep 10
        elapsed=$((elapsed + 10))
    done
    echo ""
    log_ok "${label} concluído"
    return 0
}

# ═══════════════════════════════════════════════════════════════
#  PARSE ARGUMENTS
# ═══════════════════════════════════════════════════════════════
TARGETS_FILE=""
SINGLE_TARGET=""
OUTDIR=""
PROFILE="full"
CREDS_FILE=""
SKIP_ZAP=0
SKIP_NUCLEI=0
SKIP_LYNIS=0
SKIP_TRIVY=0
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f) TARGETS_FILE="$2"; shift 2 ;;
        -t) SINGLE_TARGET="$2"; shift 2 ;;
        -c) CONFIG_FILE="$2"; shift 2 ;;
        -o) OUTDIR="$2"; shift 2 ;;
        -p) PROFILE="$2"; shift 2 ;;
        --no-zap) SKIP_ZAP=1; shift ;;
        --no-nuclei) SKIP_NUCLEI=1; shift ;;
        --no-lynis) SKIP_LYNIS=1; shift ;;
        --no-trivy) SKIP_TRIVY=1; shift ;;
        -h|--help) usage ;;
        *) echo "Opção desconhecida: $1"; usage ;;
    esac
done

# ─── Load configuration from YAML if provided ───
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    if command -v yq &>/dev/null; then
        log_info "Carregando configuração de $CONFIG_FILE"
        [[ -z "$TARGETS_FILE" && -z "$SINGLE_TARGET" ]] && {
            TARGETS_FILE=$(yq -r '.targets.file // ""' "$CONFIG_FILE")
            SINGLE_TARGET=$(yq -r '.targets.single // ""' "$CONFIG_FILE")
        }
        [[ -z "$OUTDIR" ]] && OUTDIR=$(yq -r '.scan.output_dir // ""' "$CONFIG_FILE")
        [[ "$PROFILE" == "full" ]] && PROFILE=$(yq -r '.scan.profile // "full"' "$CONFIG_FILE")
        MAX_PARALLEL=$(yq -r '.scan.max_parallel // 8' "$CONFIG_FILE")
        NMAP_TIMING=$(yq -r '.scan.nmap_timing // "T3"' "$CONFIG_FILE")
        [[ $SKIP_ZAP -eq 0 ]] && {
            ZAP_ENABLED=$(yq -r '.scan.zap.enabled // true' "$CONFIG_FILE")
            [[ "$ZAP_ENABLED" == "false" ]] && SKIP_ZAP=1
        }
        [[ $SKIP_NUCLEI -eq 0 ]] && {
            NUCLEI_ENABLED=$(yq -r '.scan.nuclei.enabled // true' "$CONFIG_FILE")
            [[ "$NUCLEI_ENABLED" == "false" ]] && SKIP_NUCLEI=1
        }
        [[ $SKIP_LYNIS -eq 0 ]] && {
            LYNIS_ENABLED=$(yq -r '.scan.lynis.enabled // true' "$CONFIG_FILE")
            [[ "$LYNIS_ENABLED" == "false" ]] && SKIP_LYNIS=1
        }
        [[ $SKIP_TRIVY -eq 0 ]] && {
            TRIVY_ENABLED=$(yq -r '.scan.trivy.enabled // true' "$CONFIG_FILE")
            [[ "$TRIVY_ENABLED" == "false" ]] && SKIP_TRIVY=1
        }
        [[ -z "$CREDS_FILE" ]] && CREDS_FILE=$(yq -r '.scan.authenticated_scan.creds_file // ""' "$CONFIG_FILE")
    else
        log_warn "yq não encontrado, ignorando $CONFIG_FILE"
    fi
fi

if [[ -z "$TARGETS_FILE" && -z "$SINGLE_TARGET" ]]; then
    echo -e "${RED}Erro: Especifique -f <arquivo> ou -t <alvo> ou -c <config.yaml>${NC}"
    usage
fi

# ─── Setup output directory ───
[[ -z "$OUTDIR" ]] && OUTDIR="pci_scan_${SCAN_DATE}"
mkdir -p "$OUTDIR/raw" "$OUTDIR/evidence" "$OUTDIR/history"

# ═══════════════════════════════════════════════════════════════
#  PARSE TARGETS
# ═══════════════════════════════════════════════════════════════
declare -a WEB_TARGETS=()
declare -a INFRA_TARGETS=()
declare -A TARGET_LABELS=()

if [[ -n "$SINGLE_TARGET" ]]; then
    if is_url "$SINGLE_TARGET"; then
        WEB_TARGETS+=("$SINGLE_TARGET")
        TARGET_LABELS["$SINGLE_TARGET"]="single-target"
    else
        INFRA_TARGETS+=("$SINGLE_TARGET")
        TARGET_LABELS["$SINGLE_TARGET"]="single-target"
    fi
elif [[ -n "$TARGETS_FILE" ]]; then
    if [[ ! -f "$TARGETS_FILE" ]]; then
        echo -e "${RED}Erro: Arquivo não encontrado: ${TARGETS_FILE}${NC}"
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/#.*//' | xargs)
        [[ -z "$line" ]] && continue
        local_type=$(echo "$line" | awk '{print $1}')
        local_target=$(echo "$line" | awk '{print $2}')
        local_label=$(echo "$line" | awk '{print $3}')
        [[ -z "$local_label" ]] && local_label="$local_target"
        TARGET_LABELS["$local_target"]="$local_label"
        case "$local_type" in
            web)   WEB_TARGETS+=("$local_target") ;;
            infra) INFRA_TARGETS+=("$local_target") ;;
            both)
                WEB_TARGETS+=("$local_target")
                INFRA_TARGETS+=("$local_target")
                ;;
            *)
                if is_url "$local_target"; then
                    WEB_TARGETS+=("$local_target")
                else
                    INFRA_TARGETS+=("$local_target")
                fi
                ;;
        esac
    done < "$TARGETS_FILE"
fi

TOTAL_TARGETS=$(( ${#WEB_TARGETS[@]} + ${#INFRA_TARGETS[@]} ))

case "$PROFILE" in
    web-only) INFRA_TARGETS=() ;;
    infra-only) WEB_TARGETS=(); SKIP_ZAP=1 ;;
esac

# ═══════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
 ╔═══════════════════════════════════════════════════════════╗
 ║   ██████╗  ██████╗██╗    ███████╗ ██████╗ █████╗ ███╗   ║
 ║   ██╔══██╗██╔════╝██║    ██╔════╝██╔════╝██╔══██╗████╗  ║
 ║   ██████╔╝██║     ██║    ███████╗██║     ███████║██╔██╗  ║
 ║   ██╔═══╝ ██║     ██║    ╚════██║██║     ██╔══██║██║╚██╗ ║
 ║   ██║     ╚██████╗██║    ███████║╚██████╗██║  ██║██║ ╚██║║
 ║   ╚═╝      ╚═════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═║
 ║          PCI DSS 4.0 — Internal Compliance Scanner       ║
 ║                  Omnibees Security Intel                  ║
 ╚═══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

echo -e "${BOLD}[+] Perfil     :${NC} $PROFILE"
echo -e "${BOLD}[+] Trimestre  :${NC} $QUARTER"
echo -e "${BOLD}[+] Alvos Web  :${NC} ${#WEB_TARGETS[@]}"
echo -e "${BOLD}[+] Alvos Infra:${NC} ${#INFRA_TARGETS[@]}"
echo -e "${BOLD}[+] Autenticado:${NC} $([ -n "$CREDS_FILE" ] && echo "Sim (Req 11.3.1.2)" || echo "Não")"
echo -e "${BOLD}[+] Diretório  :${NC} $OUTDIR"
echo -e "${BOLD}[+] Iniciado   :${NC} $SCAN_DATE_HUMAN"

cat > "$OUTDIR/raw/scan_meta.json" << METAEOF
{
  "scan_date": "$SCAN_DATE_HUMAN",
  "quarter": "$QUARTER",
  "profile": "$PROFILE",
  "authenticated": $([ -n "$CREDS_FILE" ] && echo "true" || echo "false"),
  "web_targets": ${#WEB_TARGETS[@]},
  "infra_targets": ${#INFRA_TARGETS[@]},
  "pci_dss_version": "4.0"
}
METAEOF

# ═══════════════════════════════════════════════════════════════
#  TOOL VALIDATION
# ═══════════════════════════════════════════════════════════════
echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VALIDAÇÃO DE FERRAMENTAS${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

TOOLS_AVAILABLE=()
TOOLS_MISSING=()

check_tool() {
    local name="$1" required="${2:-optional}"
    if command -v "$name" &>/dev/null; then
        log_ok "$name encontrado"
        TOOLS_AVAILABLE+=("$name")
        return 0
    else
        if [[ "$required" == "required" ]]; then
            log_fail "$name NÃO encontrado (OBRIGATÓRIO)"
            TOOLS_MISSING+=("$name")
        else
            log_skip "$name não encontrado (fase será ignorada)"
        fi
        return 1
    fi
}

check_tool "curl" "required"
check_tool "python3" "required"
check_tool "nmap" "required"
check_tool "jq" "optional"
check_tool "testssl.sh" "optional" || check_tool "testssl" "optional"
check_tool "nuclei" "optional"
check_tool "zaproxy" "optional"
check_tool "nikto" "optional"
check_tool "sshpass" "optional"
check_tool "lynis" "optional"
check_tool "trivy" "optional"
check_tool "yq" "optional"

TESTSSL_CMD=""
if command -v testssl.sh &>/dev/null; then
    TESTSSL_CMD="testssl.sh"
elif command -v testssl &>/dev/null; then
    TESTSSL_CMD="testssl"
fi

if [[ ${#TOOLS_MISSING[@]} -gt 0 ]]; then
    log_fail "Ferramentas obrigatórias em falta: ${TOOLS_MISSING[*]}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════
#  FINDINGS COLLECTOR
# ═══════════════════════════════════════════════════════════════
FINDINGS_FILE="$OUTDIR/raw/findings.jsonl"
> "$FINDINGS_FILE"

add_finding() {
    local severity="$1" pci_req="$2" title="$3" target="$4" \
          detail="$5" evidence="${6:-}" remediation="${7:-}" \
          tool="${8:-manual}" cve="${9:-}" cvss="${10:-0.0}"
    (
        flock -x 200
        python3 -c "
import json, sys
finding = {
    'severity': sys.argv[1],
    'pci_req': sys.argv[2],
    'title': sys.argv[3],
    'target': sys.argv[4],
    'detail': sys.argv[5],
    'evidence': sys.argv[6],
    'remediation': sys.argv[7],
    'tool': sys.argv[8],
    'cve': sys.argv[9],
    'cvss': float(sys.argv[10]) if sys.argv[10] else 0.0
}
print(json.dumps(finding))
" "$severity" "$pci_req" "$title" "$target" "$detail" "$evidence" "$remediation" "$tool" "$cve" "$cvss" >> "$FINDINGS_FILE"
    ) 200>"$FINDINGS_FILE.lock"
}
export -f add_finding

# ═══════════════════════════════════════════════════════════════
#  FASE 1: NETWORK DISCOVERY (Req 1, 2) — PARALELO
# ═══════════════════════════════════════════════════════════════
phase_header "1/7" "DESCOBERTA DE REDE E PORTAS (Req 1, 2)"
timer_start

ALL_TARGETS=()
for t in "${INFRA_TARGETS[@]+"${INFRA_TARGETS[@]}"}" "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
    local_host="$t"
    is_url "$t" && local_host=$(extract_domain "$t")
    already=0
    for existing in "${ALL_TARGETS[@]+"${ALL_TARGETS[@]}"}"; do
        [[ "$existing" == "$local_host" ]] && already=1 && break
    done
    [[ $already -eq 0 ]] && ALL_TARGETS+=("$local_host")
done

if [[ ${#ALL_TARGETS[@]} -eq 0 ]]; then
    log_fail "Nenhum alvo válido encontrado. Verifique -f ou -t."
    exit 1
fi

NMAP_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,8888,9090,9200,9300,11211,27017"

if [[ $IS_ROOT -eq 1 ]]; then
    NMAP_SCAN_TYPE="-sS"
else
    NMAP_SCAN_TYPE="-sT"
    log_warn "Executando como não-root — usando TCP connect scan (-sT). Para SYN scan, execute com sudo."
fi

export OUTDIR FINDINGS_FILE NMAP_PORTS NMAP_SCAN_TYPE NMAP_TIMING
export RED GREEN YELLOW BLUE CYAN NC BOLD

_phase1_process_host() {
    local host="$1"
    local NMAP_OUT="$OUTDIR/raw/nmap_${host//[\/:]/_}.txt"
    local NMAP_XML="$OUTDIR/raw/nmap_${host//[\/:]/_}.xml"

    echo -e "${BLUE}[*]${NC} [nmap] ${host}..."

    nmap $NMAP_SCAN_TYPE -sV -sC \
         -p "$NMAP_PORTS" \
         --script="banner,ssl-cert,ssl-enum-ciphers,http-title,http-server-header,ftp-anon,ssh-auth-methods,smb-security-mode,rdp-enum-encryption" \
         -$NMAP_TIMING \
         --defeat-rst-ratelimit \
         -oN "$NMAP_OUT" \
         -oX "$NMAP_XML" \
         "$host" >/dev/null 2>&1 || true

    if [[ ! -s "$NMAP_OUT" ]]; then
        echo -e "${YELLOW}[!]${NC} [nmap] ${host} — sem resultados"
        return 0
    fi

    local open_ports
    open_ports=$(grep -c "open" "$NMAP_OUT" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${NC} [nmap] ${host} — ${open_ports} porta(s) aberta(s)"

    local INSECURE_SERVICES=("21/tcp:FTP" "23/tcp:Telnet" "25/tcp:SMTP" "111/tcp:RPCbind" "135/tcp:MS-RPC" "139/tcp:NetBIOS" "445/tcp:SMB" "5900/tcp:VNC")
    while IFS= read -r port_line; do
        local port_num svc svc_port svc_name svc_num
        port_num=$(echo "$port_line" | awk -F/ '{print $1}')
        for svc in "${INSECURE_SERVICES[@]}"; do
            svc_port="${svc%%:*}"
            svc_name="${svc##*:}"
            svc_num="${svc_port%%/*}"
            if [[ "$port_num" == "$svc_num" ]]; then
                add_finding "high" "Req 1.3, 2.2" \
                    "Serviço inseguro/desnecessário: ${svc_name} (porta ${svc_num})" \
                    "$host" \
                    "Porta ${svc_port} aberta com serviço ${svc_name}. Serviços inseguros ou desnecessários não devem estar expostos no CDE." \
                    "$port_line" \
                    "Desabilitar o serviço ${svc_name} ou restringir acesso via firewall. Ref: PCI DSS 4.0 Req 1.3.1, 2.2.4" \
                    "nmap"
            fi
        done
    done < <(grep "open" "$NMAP_OUT" 2>/dev/null | grep -v "^#\|^Nmap\|^Host\|^Service\|^PORT\|^Starting" || true)

    if grep -qi "rdp.*open" "$NMAP_OUT" 2>/dev/null; then
        if ! grep -qi "CredSSP\|NLA" "$NMAP_OUT" 2>/dev/null; then
            add_finding "high" "Req 2.2" \
                "RDP sem NLA (Network Level Authentication)" \
                "$host:3389" \
                "RDP detectado sem NLA habilitado, permitindo ataques de força bruta e Man-in-the-Middle." \
                "$(grep -i rdp "$NMAP_OUT" 2>/dev/null | head -5 || true)" \
                "Habilitar NLA no RDP. Ref: PCI DSS 4.0 Req 2.2.7" \
                "nmap"
        fi
    fi

    if grep -qi "ftp-anon: Anonymous FTP login allowed" "$NMAP_OUT" 2>/dev/null; then
        add_finding "critical" "Req 2.2" \
            "FTP anônimo habilitado" \
            "$host:21" \
            "Servidor FTP permite login anônimo, expondo potencialmente dados do CDE." \
            "$(grep -A3 "ftp-anon" "$NMAP_OUT" 2>/dev/null || true)" \
            "Desabilitar acesso FTP anônimo. Considerar migrar para SFTP. Ref: PCI DSS 4.0 Req 2.2.4" \
            "nmap"
    fi
}
export -f _phase1_process_host

log_info "Iniciando ${#ALL_TARGETS[@]} host(s) em paralelo (max ${MAX_PARALLEL})..."
printf '%s\n' "${ALL_TARGETS[@]}" | \
    xargs -n 1 -P "$MAX_PARALLEL" -I {} bash -c '_phase1_process_host "$@"' _ {}

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 2: TLS/SSL AUDIT (Req 4) — PARALELO
# ═══════════════════════════════════════════════════════════════
phase_header "2/7" "AUDITORIA TLS/SSL (Req 4)"
timer_start

if [[ -n "$TESTSSL_CMD" ]]; then
    TLS_TARGETS=()
    for t in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
        TLS_TARGETS+=("$(extract_domain "$t")")
    done
    for t in "${INFRA_TARGETS[@]+"${INFRA_TARGETS[@]}"}"; do
        if grep -q "443/tcp.*open" "$OUTDIR/raw/nmap_${t//[\/:]/_}.txt" 2>/dev/null; then
            TLS_TARGETS+=("$t")
        fi
    done

    TESTSSL_PARSER="$OUTDIR/raw/_parse_testssl.py"
    cat > "$TESTSSL_PARSER" << 'PYPARSER'
import json, sys

testssl_file = sys.argv[1]
host = sys.argv[2]
findings_file = sys.argv[3]

try:
    with open(testssl_file, 'r') as f:
        data = json.load(f)
except:
    sys.exit(0)

findings = []
for item in data if isinstance(data, list) else []:
    item_id = item.get('id', '')
    severity_str = item.get('severity', 'OK').upper()
    finding_text = item.get('finding', '')
    if severity_str in ('OK', 'INFO', 'NOT'):
        continue
    sev_map = {'LOW': 'low', 'MEDIUM': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical', 'WARN': 'medium'}
    pci_severity = sev_map.get(severity_str, 'info')
    pci_req = "Req 4.2.1"
    remediation = "Atualizar configuracao TLS conforme PCI DSS 4.0 Req 4.2.1"

    if 'SSLv2' in finding_text or 'SSLv3' in finding_text:
        title = f"Protocolo SSL obsoleto detectado: {finding_text[:60]}"
        pci_severity = 'critical'
        remediation = "Desabilitar SSLv2/SSLv3. Apenas TLS 1.2+ eh permitido. Ref: PCI DSS 4.0 Req 4.2.1, Appendix A2"
    elif 'TLS 1.0' in finding_text:
        title = "TLS 1.0 detectado (obsoleto)"
        pci_severity = 'high'
        remediation = "Desabilitar TLS 1.0. Apenas TLS 1.2+ eh permitido. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'TLS 1.1' in finding_text:
        title = "TLS 1.1 detectado (obsoleto)"
        pci_severity = 'high'
        remediation = "Desabilitar TLS 1.1. Apenas TLS 1.2+ eh permitido. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'SWEET32' in item_id or '3DES' in finding_text or 'DES-CBC' in finding_text:
        title = f"Cifra fraca detectada: {finding_text[:60]}"
        pci_severity = 'high'
        remediation = "Remover cifras 3DES/DES. Usar AES-128/256 ou ChaCha20. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'RC4' in finding_text:
        title = "Cifra RC4 detectada"
        pci_severity = 'high'
        remediation = "Remover RC4. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'HEARTBLEED' in item_id.upper():
        title = "Heartbleed (CVE-2014-0160)"
        pci_severity = 'critical'
        remediation = "Atualizar OpenSSL imediatamente. Ref: PCI DSS 4.0 Req 6.3.3"
    elif 'POODLE' in item_id.upper():
        title = "POODLE vulnerability"
        pci_severity = 'high'
        remediation = "Desabilitar SSLv3 e CBC mode fallback. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'BEAST' in item_id.upper():
        title = "BEAST vulnerability"
        pci_severity = 'medium'
        remediation = "Priorizar cifras TLS 1.2+ e desabilitar CBC em TLS 1.0. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'LUCKY13' in item_id.upper():
        title = "LUCKY13 vulnerability"
        pci_severity = 'medium'
        remediation = "Migrar para AEAD ciphers (GCM/ChaCha20). Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'cert' in item_id.lower() and ('expired' in finding_text.lower() or 'not valid' in finding_text.lower()):
        title = "Certificado TLS invalido/expirado"
        pci_severity = 'high'
        remediation = "Renovar certificado TLS. Ref: PCI DSS 4.0 Req 4.2.1"
    elif 'HSTS' in item_id.upper():
        title = "HSTS nao configurado"
        pci_severity = 'medium'
        remediation = "Configurar HTTP Strict Transport Security com max-age >= 31536000. Ref: PCI DSS 4.0 Req 4.2.1"
    else:
        title = f"TLS: {item_id} - {finding_text[:80]}"

    findings.append({
        'severity': pci_severity, 'pci_req': pci_req, 'title': title,
        'target': host, 'detail': finding_text,
        'evidence': f"testssl id={item_id}",
        'remediation': remediation, 'tool': 'testssl',
        'cve': item.get('cve', ''), 'cvss': 0.0
    })

import fcntl
with open(findings_file, 'a') as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    for finding in findings:
        f.write(json.dumps(finding) + '\n')
    fcntl.flock(f, fcntl.LOCK_UN)

print(f"  -> {len(findings)} finding(s) TLS/SSL para {host}")
PYPARSER

    export TESTSSL_CMD TESTSSL_TIMEOUT TESTSSL_PARSER

    _phase2_process_host() {
        local host="$1"
        local TESTSSL_OUT="$OUTDIR/raw/testssl_${host//[\/:]/_}.json"
        local TESTSSL_LOG="$OUTDIR/raw/testssl_${host//[\/:]/_}.txt"

        echo -e "${BLUE}[*]${NC} [testssl] ${host}..."
        timeout "$TESTSSL_TIMEOUT" $TESTSSL_CMD \
            --jsonfile "$TESTSSL_OUT" \
            --logfile "$TESTSSL_LOG" \
            --protocols --std --headers --vulnerable \
            --severity LOW --quiet \
            "$host" >/dev/null 2>&1 || true

        if [[ -f "$TESTSSL_OUT" ]]; then
            echo -e "${GREEN}[✓]${NC} [testssl] ${host} concluído"
            python3 "$TESTSSL_PARSER" "$TESTSSL_OUT" "$host" "$FINDINGS_FILE" 2>/dev/null || true
        else
            echo -e "${YELLOW}[!]${NC} [testssl] ${host} sem output"
        fi
    }
    export -f _phase2_process_host

    log_info "Iniciando ${#TLS_TARGETS[@]} testssl em paralelo (max ${MAX_PARALLEL})..."
    printf '%s\n' "${TLS_TARGETS[@]}" | \
        xargs -n 1 -P "$MAX_PARALLEL" -I {} bash -c '_phase2_process_host "$@"' _ {}
else
    log_skip "testssl não disponível — auditoria TLS/SSL ignorada"
fi

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 3: CONFIGURATION AUDIT (Req 2) — PARALELO (OTIMIZADA COM XML)
# ═══════════════════════════════════════════════════════════════
phase_header "3/7" "AUDITORIA DE CONFIGURAÇÃO (Req 2)"
timer_start

_phase3_process_host() {
    local host="$1"
    echo -e "${BLUE}[*]${NC} [config] ${host}..."

    local NMAP_XML="$OUTDIR/raw/nmap_${host//[\/:]/_}.xml"
    if [[ ! -f "$NMAP_XML" ]]; then
        echo -e "${YELLOW}[!]${NC} XML do nmap não encontrado para $host, pulando config"
        return
    fi

    local http_ports=$(python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('$NMAP_XML')
root = tree.getroot()
ports = []
for port in root.findall('.//port'):
    if port.find('state').get('state') == 'open':
        service = port.find('service')
        if service is not None:
            name = service.get('name', '')
            if name in ('http', 'https', 'http-alt', 'ssl/http'):
                ports.append((port.get('portid'), name))
print(','.join([f'{p}:{s}' for p,s in ports]))
" 2>/dev/null)

    if [[ -z "$http_ports" ]]; then
        echo -e "${GREEN}[✓]${NC} [config] ${host} sem portas HTTP abertas"
    else
        IFS=',' read -ra PORT_ARRAY <<< "$http_ports"
        for entry in "${PORT_ARRAY[@]}"; do
            port="${entry%:*}"
            svc="${entry#*:}"
            PROTO="http"
            [[ "$svc" == "https" || "$svc" == "ssl/http" ]] && PROTO="https"

            HEADERS=$(curl -skI --connect-timeout 3 --max-time 5 "${PROTO}://${host}:${port}" 2>/dev/null || true)
            [[ -z "$HEADERS" ]] && continue

            SERVER_HDR=$(echo "$HEADERS" | grep -i "^server:" | head -1 || true)
            if [[ -n "$SERVER_HDR" ]] && echo "$SERVER_HDR" | grep -qiE "[0-9]+\.[0-9]+"; then
                add_finding "low" "Req 2.2.7" \
                    "Server version disclosure: $(echo "$SERVER_HDR" | tr -d '\r')" \
                    "${host}:${port}" \
                    "O header Server expõe versão do software, facilitando ataques direcionados." \
                    "$(echo "$SERVER_HDR" | tr -d '\r')" \
                    "Remover versão do header Server. Ref: PCI DSS 4.0 Req 2.2.7" \
                    "curl"
            fi

            POWERED_HDR=$(echo "$HEADERS" | grep -i "^x-powered-by:" | head -1 || true)
            if [[ -n "$POWERED_HDR" ]]; then
                add_finding "low" "Req 2.2.7" \
                    "X-Powered-By disclosure: $(echo "$POWERED_HDR" | tr -d '\r')" \
                    "${host}:${port}" \
                    "O header X-Powered-By expõe tecnologia do backend." \
                    "$(echo "$POWERED_HDR" | tr -d '\r')" \
                    "Remover header X-Powered-By. Ref: PCI DSS 4.0 Req 2.2.7" \
                    "curl"
            fi

            MISSING_HEADERS=()
            echo "$HEADERS" | grep -qi "strict-transport-security" || MISSING_HEADERS+=("Strict-Transport-Security")
            echo "$HEADERS" | grep -qi "x-content-type-options" || MISSING_HEADERS+=("X-Content-Type-Options")
            echo "$HEADERS" | grep -qi "x-frame-options\|content-security-policy.*frame-ancestors" || MISSING_HEADERS+=("X-Frame-Options")
            echo "$HEADERS" | grep -qi "content-security-policy" || MISSING_HEADERS+=("Content-Security-Policy")
            echo "$HEADERS" | grep -qi "x-xss-protection\|content-security-policy" || MISSING_HEADERS+=("X-XSS-Protection")
            echo "$HEADERS" | grep -qi "referrer-policy" || MISSING_HEADERS+=("Referrer-Policy")
            echo "$HEADERS" | grep -qi "permissions-policy\|feature-policy" || MISSING_HEADERS+=("Permissions-Policy")

            if [[ ${#MISSING_HEADERS[@]} -gt 0 ]]; then
                local_sev="medium"
                [[ ${#MISSING_HEADERS[@]} -ge 4 ]] && local_sev="high"
                add_finding "$local_sev" "Req 6.2.4" \
                    "Security headers ausentes (${#MISSING_HEADERS[@]})" \
                    "${PROTO}://${host}:${port}" \
                    "Headers faltando: ${MISSING_HEADERS[*]}" \
                    "$(echo "$HEADERS" | head -15)" \
                    "Implementar todos os security headers recomendados. Ref: PCI DSS 4.0 Req 6.2.4, OWASP Secure Headers" \
                    "curl"
            fi
        done
    fi

    if grep -q "22/tcp.*open" "$OUTDIR/raw/nmap_${host//[\/:]/_}.txt" 2>/dev/null; then
        local SSH_OUT
        SSH_OUT=$(timeout 8 ssh -o BatchMode=yes \
                  -o ConnectTimeout=5 \
                  -o StrictHostKeyChecking=no \
                  -o PasswordAuthentication=no \
                  -v "$host" true 2>&1 || true)

        if echo "$SSH_OUT" | grep -qi "diffie-hellman-group1-sha1\|ssh-dss\|arcfour\|blowfish\|cast128\|3des-cbc"; then
            add_finding "high" "Req 2.2, 4.2.1" \
                "Algoritmos SSH fracos detectados" \
                "${host}:22" \
                "SSH aceita algoritmos criptográficos inseguros (DH Group1, SSH-DSS, arcfour, 3DES)." \
                "$(echo "$SSH_OUT" | grep -i "kex\|cipher\|mac" | head -10 || true)" \
                "Desabilitar algoritmos fracos no sshd_config. Ref: PCI DSS 4.0 Req 2.2, 4.2.1" \
                "ssh"
        fi

        if echo "$SSH_OUT" | grep -qi "password.*yes\|keyboard-interactive.*yes"; then
            add_finding "info" "Req 2.2, 8.3" \
                "SSH aceita autenticação por senha" \
                "${host}:22" \
                "SSH permite autenticação por senha além de chave pública." \
                "" \
                "Considerar desabilitar PasswordAuthentication no sshd_config. Ref: PCI DSS 4.0 Req 8.3.1" \
                "ssh"
        fi
    fi

    echo -e "${GREEN}[✓]${NC} [config] ${host} concluído"
}
export -f _phase3_process_host

log_info "Iniciando ${#ALL_TARGETS[@]} config audits em paralelo (max ${MAX_PARALLEL})..."
printf '%s\n' "${ALL_TARGETS[@]}" | \
    xargs -n 1 -P "$MAX_PARALLEL" -I {} bash -c '_phase3_process_host "$@"' _ {}

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 4: AUTHENTICATED SCAN + LYNIS + TRIVY
# ═══════════════════════════════════════════════════════════════
phase_header "4/7" "SCAN AUTENTICADO + HARDENING + CVEs (Req 11.3.1.2, 2.2, 6.3.3)"
timer_start

if [[ -n "$CREDS_FILE" && -f "$CREDS_FILE" ]]; then
    log_info "Executando scans autenticados conforme Req 11.3.1.2..."
    AUTH_SCAN_COUNT=0

    while IFS= read -r cred_line || [[ -n "$cred_line" ]]; do
        cred_line=$(echo "$cred_line" | sed 's/#.*//' | xargs)
        [[ -z "$cred_line" ]] && continue

        SVC=$(echo "$cred_line" | awk '{print $1}')
        CHOST=$(echo "$cred_line" | awk '{print $2}')
        CPORT=$(echo "$cred_line" | awk '{print $3}')
        CUSER=$(echo "$cred_line" | awk '{print $4}')
        CPASS=$(echo "$cred_line" | awk '{print $5}')

        case "$SVC" in
            ssh)
                log_info "SSH autenticado → ${CHOST}:${CPORT}..."
                if command -v sshpass &>/dev/null; then
                    AUTH_RESULT=$(sshpass -p "$CPASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                        -p "$CPORT" "${CUSER}@${CHOST}" \
                        "uname -a; cat /etc/os-release 2>/dev/null; dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50; ss -tlnp 2>/dev/null; cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^\$'" \
                        2>/dev/null || echo "AUTH_FAILED")

                    if [[ "$AUTH_RESULT" != "AUTH_FAILED" ]]; then
                        log_ok "SSH autenticado OK: ${CHOST}"
                        echo "$AUTH_RESULT" > "$OUTDIR/evidence/auth_ssh_${CHOST//[\/:]/_}.txt"
                        AUTH_SCAN_COUNT=$((AUTH_SCAN_COUNT + 1))

                        if echo "$AUTH_RESULT" | grep -qi "security\|CVE\|vuln"; then
                            add_finding "medium" "Req 6.3.3" \
                                "Pacotes potencialmente desatualizados" \
                                "$CHOST" \
                                "Scan autenticado detectou pacotes que podem precisar de atualização." \
                                "$(echo "$AUTH_RESULT" | head -20)" \
                                "Verificar e aplicar patches de segurança. Ref: PCI DSS 4.0 Req 6.3.3" \
                                "ssh-auth"
                        fi

                        if echo "$AUTH_RESULT" | grep -qi "PermitRootLogin.*yes"; then
                            add_finding "high" "Req 2.2, 8.6" \
                                "SSH permite login root" \
                                "${CHOST}:${CPORT}" \
                                "PermitRootLogin está habilitado no sshd_config." \
                                "PermitRootLogin yes" \
                                "Definir PermitRootLogin no em /etc/ssh/sshd_config. Ref: PCI DSS 4.0 Req 8.6.1" \
                                "ssh-auth"
                        fi

                        # Lynis
                        if [[ ${SKIP_LYNIS} -eq 0 ]] && command -v lynis &>/dev/null; then
                            log_info "Executando Lynis via SSH em ${CHOST}..."
                            LYNIS_OUT="$OUTDIR/evidence/lynis_${CHOST//[\/:]/_}.txt"
                            sshpass -p "$CPASS" ssh -o StrictHostKeyChecking=no -p "$CPORT" "${CUSER}@${CHOST}" \
                                "lynis audit system --quick --no-colors" > "$LYNIS_OUT" 2>/dev/null

                            if grep -q "Warning\|Suggestion" "$LYNIS_OUT"; then
                                while IFS= read -r line; do
                                    if [[ "$line" =~ ^Warning|^Suggestion ]]; then
                                        add_finding "medium" "Req 2.2" \
                                            "Lynis: $(echo "$line" | cut -d']' -f2- | xargs)" \
                                            "$CHOST" \
                                            "Hardening do sistema pode ser melhorado." \
                                            "$line" \
                                            "Aplicar recomendações do Lynis. Ref: PCI DSS 4.0 Req 2.2" \
                                            "lynis"
                                    fi
                                done < <(grep -E "^(Warning|Suggestion)" "$LYNIS_OUT" | head -20)
                            fi
                            log_ok "Lynis concluído para ${CHOST}"
                        fi

                        # Trivy
                        if [[ ${SKIP_TRIVY} -eq 0 ]] && command -v trivy &>/dev/null; then
                            log_info "Executando Trivy (rootfs) via SSH em ${CHOST}..."
                            TRIVY_OUT="$OUTDIR/raw/trivy_${CHOST//[\/:]/_}.json"
                            sshpass -p "$CPASS" ssh -o StrictHostKeyChecking=no -p "$CPORT" "${CUSER}@${CHOST}" \
                                "trivy rootfs --format json --exit-code 0 /" > "$TRIVY_OUT" 2>/dev/null

                            if [[ -s "$TRIVY_OUT" ]]; then
                                python3 - "$TRIVY_OUT" "$FINDINGS_FILE" "$CHOST" << 'TRIVYPARSE'
import json, sys

trivy_file = sys.argv[1]
findings_file = sys.argv[2]
host = sys.argv[3]

try:
    with open(trivy_file, 'r') as f:
        data = json.load(f)
except:
    sys.exit(0)

count = 0
with open(findings_file, 'a') as ff:
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            sev = vuln.get('Severity', 'UNKNOWN').upper()
            sev_map = {'CRITICAL':'critical', 'HIGH':'high', 'MEDIUM':'medium', 'LOW':'low'}
            severity = sev_map.get(sev, 'info')
            cve = vuln.get('VulnerabilityID', '')
            title = f"{cve}: {vuln.get('Title', '')[:80]}"
            detail = vuln.get('Description', '')
            fixed = vuln.get('FixedVersion', 'N/A')
            remediation = f"Atualizar para versão corrigida: {fixed}. Ref: PCI DSS 4.0 Req 6.3.3"
            finding = {
                'severity': severity,
                'pci_req': 'Req 6.3.3',
                'title': title,
                'target': host,
                'detail': detail,
                'evidence': f"CVE: {cve}",
                'remediation': remediation,
                'tool': 'trivy',
                'cve': cve,
                'cvss': 0.0
            }
            ff.write(json.dumps(finding) + '\n')
            count += 1

print(f"  -> {count} findings Trivy para {host}")
TRIVYPARSE
                            fi
                            log_ok "Trivy concluído para ${CHOST}"
                        fi
                    else
                        log_warn "Falha na autenticação SSH: ${CHOST}"
                    fi
                else
                    log_warn "sshpass não disponível — SSH autenticado ignorado"
                fi
                ;;
            http|https)
                log_info "HTTP autenticado → ${CHOST}:${CPORT}..."
                PROTO="$SVC"
                AUTH_HEADERS=$(curl -skI --max-time 15 -u "${CUSER}:${CPASS}" \
                    "${PROTO}://${CHOST}:${CPORT}/" 2>/dev/null || true)
                if echo "$AUTH_HEADERS" | grep -q "200\|301\|302"; then
                    log_ok "HTTP autenticado OK: ${CHOST}"
                    echo "$AUTH_HEADERS" > "$OUTDIR/evidence/auth_http_${CHOST//[\/:]/_}.txt"
                    AUTH_SCAN_COUNT=$((AUTH_SCAN_COUNT + 1))
                else
                    log_warn "Falha na autenticação HTTP: ${CHOST}"
                fi
                ;;
        esac
    done < "$CREDS_FILE"

    log_ok "${AUTH_SCAN_COUNT} scan(s) autenticado(s) concluído(s)"
    echo "$AUTH_SCAN_COUNT" > "$OUTDIR/raw/auth_scan_count.txt"
else
    log_warn "Sem arquivo de credenciais — scan autenticado não executado"
    log_warn "PCI DSS 4.0 Req 11.3.1.2 EXIGE scan autenticado. Use -c <creds_file>"
    add_finding "info" "Req 11.3.1.2" \
        "Scan autenticado não executado" \
        "ALL" \
        "PCI DSS 4.0 Req 11.3.1.2 exige scan autenticado interno. Este scan foi executado sem credenciais." \
        "" \
        "Executar novamente com -c <arquivo_credenciais> para compliance total. Ref: PCI DSS 4.0 Req 11.3.1.2" \
        "policy"
fi

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 5: VULNERABILITY SCAN — NUCLEI
# ═══════════════════════════════════════════════════════════════
phase_header "5/7" "SCAN DE VULNERABILIDADES (NUCLEI - Req 6, 11)"
timer_start

if command -v nuclei &>/dev/null && [[ $SKIP_NUCLEI -eq 0 ]]; then
    log_info "Nuclei scan com templates PCI-relevantes (modo multi-target)..."

    PCI_TAGS="cve,default-login,misconfig,exposure,tech,token,unauth,sqli,xss,rce,lfi,rfi,ssrf,ssti,idor"

    NUCLEI_TARGETS_FILE="$OUTDIR/raw/_nuclei_targets.txt"
    > "$NUCLEI_TARGETS_FILE"
    for target in "${ALL_TARGETS[@]}"; do
        NUCLEI_TARGET="$target"
        for wt in "${WEB_TARGETS[@]+"${WEB_TARGETS[@]}"}"; do
            if [[ "$(extract_domain "$wt")" == "$target" ]]; then
                NUCLEI_TARGET="$wt"
                break
            fi
        done
        echo "$NUCLEI_TARGET" >> "$NUCLEI_TARGETS_FILE"
    done

    log_info "Executando nuclei em ${#ALL_TARGETS[@]} alvo(s) simultaneamente..."
    NUCLEI_OUT="$OUTDIR/raw/nuclei_all.json"

    nuclei -l "$NUCLEI_TARGETS_FILE" \
           -tags "$PCI_TAGS" \
           -rate-limit "$NUCLEI_RATE_LIMIT" \
           -c "$NUCLEI_CONCURRENCY" \
           -bs "$MAX_PARALLEL" \
           -jsonl -o "$NUCLEI_OUT" \
           -silent --no-interactsh -timeout 10 >/dev/null 2>&1 || true

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT" 2>/dev/null | tr -d ' ')
    NUCLEI_COUNT=${NUCLEI_COUNT:-0}

    if [[ "$NUCLEI_COUNT" -eq 0 ]]; then
        log_warn "Nuclei (filtrado): 0 findings. Tentando scan completo..."
        nuclei -l "$NUCLEI_TARGETS_FILE" \
               -rate-limit "$NUCLEI_RATE_LIMIT" \
               -c "$NUCLEI_CONCURRENCY" \
               -bs "$MAX_PARALLEL" \
               -jsonl -o "$NUCLEI_OUT" \
               -silent --no-interactsh -timeout 10 >/dev/null 2>&1 || true
        NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT" 2>/dev/null | tr -d ' ')
        NUCLEI_COUNT=${NUCLEI_COUNT:-0}
    fi

    log_ok "nuclei: ${NUCLEI_COUNT} finding(s) total"

    if [[ "$NUCLEI_COUNT" -gt 0 ]]; then
        python3 - "$NUCLEI_OUT" "$FINDINGS_FILE" << 'PYEOF'
import json, sys

nuclei_file = sys.argv[1]
findings_file = sys.argv[2]

sev_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'info': 'info', 'unknown': 'info'}

def get_pci_req(tags, template_id):
    tags_str = ','.join(tags) if isinstance(tags, list) else str(tags)
    if any(t in tags_str for t in ['default-login', 'default-credentials']):
        return "Req 2.2.2"
    if any(t in tags_str for t in ['cve', 'rce', 'sqli']):
        return "Req 6.3.3, 11.3.1"
    if any(t in tags_str for t in ['xss', 'ssti', 'ssrf', 'lfi', 'rfi', 'idor']):
        return "Req 6.2.4"
    if any(t in tags_str for t in ['misconfig', 'exposure']):
        return "Req 2.2"
    if any(t in tags_str for t in ['ssl', 'tls']):
        return "Req 4.2.1"
    return "Req 11.3.1"

count = 0
with open(nuclei_file, 'r') as nf, open(findings_file, 'a') as ff:
    for line in nf:
        try:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                continue

            info = item.get('info', {})
            if not isinstance(info, dict):
                info = {}
            severity = sev_map.get(info.get('severity', 'info'), 'info')
            tags = info.get('tags', [])
            if not isinstance(tags, list):
                tags = [str(tags)] if tags else []
            template_id = str(item.get('template-id', ''))

            cve_id = ''
            classification = info.get('classification', {})
            if isinstance(classification, dict):
                cve_list = classification.get('cve-id', [])
                if cve_list:
                    cve_id = cve_list[0] if isinstance(cve_list, list) else str(cve_list)

            cvss = 0.0
            if isinstance(classification, dict):
                cvss_score = classification.get('cvss-score', 0)
                if cvss_score:
                    try:
                        cvss = float(cvss_score)
                    except (ValueError, TypeError):
                        cvss = 0.0

            finding = {
                'severity': severity,
                'pci_req': get_pci_req(tags, template_id),
                'title': str(info.get('name', template_id)),
                'target': str(item.get('matched-at', item.get('host', ''))),
                'detail': str(info.get('description', '')),
                'evidence': str(item.get('curl-command', '')),
                'remediation': str(info.get('remediation', f"Corrigir vulnerabilidade {template_id}. Ref: PCI DSS 4.0")),
                'tool': 'nuclei',
                'cve': str(cve_id),
                'cvss': cvss
            }
            ff.write(json.dumps(finding) + '\n')
            count += 1
        except Exception as e:
            import sys as _sys
            print(f"  [warn] linha ignorada: {e}", file=_sys.stderr)
            continue

print(f"  -> {count} finding(s) nuclei mapeados para PCI")
PYEOF
    fi
else
    log_skip "nuclei não disponível ou --no-nuclei — scan de vulnerabilidades ignorado"
fi

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 6: WEB APPLICATION SCAN — OWASP ZAP (Req 6) - COM AJUSTES
# ═══════════════════════════════════════════════════════════════
phase_header "6/7" "SCAN DE APLICAÇÃO WEB — OWASP ZAP (Req 6)"
timer_start

if command -v zaproxy &>/dev/null && [[ $SKIP_ZAP -eq 0 ]] && [[ ${#WEB_TARGETS[@]} -gt 0 ]]; then

    ZAP_STARTED_BY_SCRIPT=0
    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        log_ok "ZAP já rodando — reutilizando"
    else
        pkill -f "zaproxy.*-daemon" 2>/dev/null || true
        rm -f "$HOME/.ZAP/zap.lock" 2>/dev/null || true
        sleep 2

        ZAP_CONFIG="$HOME/.ZAP/config.xml"
        if [[ -f "$ZAP_CONFIG" ]]; then
            grep -q "<n>127.0.0.1</n>" "$ZAP_CONFIG" 2>/dev/null || \
                sed -i 's|</addrs>|<n>127.0.0.1</n></addrs>|g' "$ZAP_CONFIG" 2>/dev/null || true
            grep -q "<n>localhost</n>" "$ZAP_CONFIG" 2>/dev/null || \
                sed -i 's|</addrs>|<n>localhost</n></addrs>|g' "$ZAP_CONFIG" 2>/dev/null || true
        fi

        log_info "Iniciando OWASP ZAP daemon..."
        zaproxy -daemon \
                -host "$ZAP_HOST" \
                -port "$ZAP_PORT" \
                -config api.disablekey=true \
                -config api.addrs.addr.name=127.0.0.1 \
                -config api.addrs.addr.regex=true \
                -config connection.dnsTtlSuccessfulQueries=-1 \
                -config certificate.ignoreErrors=true \
                > "$OUTDIR/raw/zap_daemon.log" 2>&1 &

        ZAP_STARTED_BY_SCRIPT=1
        if ! wait_for_zap; then
            log_fail "ZAP não iniciou — pulando fase 6"
            log_warn "Verificar log: $OUTDIR/raw/zap_daemon.log"
            ZAP_STARTED_BY_SCRIPT=0
        fi
    fi

    if zap_api_call "core/view/version" "" 2>/dev/null | grep -q "version"; then
        # Determinar se devemos executar spider ou pular
        # Se não houver credenciais configuradas para este alvo, pulamos o spider
        HAS_AUTH_FOR_HOST() {
            local host="$1"
            if [[ -n "$CREDS_FILE" && -f "$CREDS_FILE" ]]; then
                # Verificar se existe entrada http/https para este host
                grep -qE "^(http|https)\s+${host}(\s+|$)" "$CREDS_FILE" 2>/dev/null
                return $?
            fi
            return 1
        }

        for web_target in "${WEB_TARGETS[@]}"; do
            log_info "ZAP scan → ${web_target}..."

            ENCODED_URL=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$web_target")
            TARGET_HOST=$(extract_domain "$web_target")

            # Decidir se executa spider
            if HAS_AUTH_FOR_HOST "$TARGET_HOST" || [[ "$web_target" == *"auth."* ]]; then
                log_warn "Alvo parece exigir autenticação (ou auth.bee2pay.com). Pulando Spider para evitar travamento."
                SKIP_SPIDER_FOR_THIS=1
            else
                SKIP_SPIDER_FOR_THIS=0
            fi

            if [[ $SKIP_SPIDER_FOR_THIS -eq 0 ]]; then
                log_info "Spider..."
                SPIDER_ID=$(zap_api_call "spider/action/scan" "url=${ENCODED_URL}" \
                            | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)

                if wait_for_zap_progress "spider/view/status" "${SPIDER_ID:-0}" "$ZAP_SPIDER_TIMEOUT" "Spider"; then
                    log_ok "Spider concluído com sucesso"
                else
                    log_warn "Spider falhou ou foi cancelado. Prosseguindo com Active Scan mesmo assim..."
                fi
            else
                log_info "Spider ignorado (alvo exige autenticação ou sem credenciais)."
            fi

            # Active Scan sempre executa
            log_info "Active Scan..."
            SCAN_ID=$(zap_api_call "ascan/action/scan" "url=${ENCODED_URL}&recurse=true" \
                      | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan','0'))" 2>/dev/null)
            wait_for_zap_progress "ascan/view/status" "${SCAN_ID:-0}" "$ZAP_SCAN_TIMEOUT" "Active Scan"

            ZAP_ALERTS="$OUTDIR/raw/zap_${web_target//[\/:]/_}.json"
            curl -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/alerts/?baseurl=${ENCODED_URL}" \
                > "$ZAP_ALERTS" 2>/dev/null

            ALERT_COUNT=$(python3 -c "import json; d=json.load(open('$ZAP_ALERTS')); print(len(d.get('alerts',[])))" 2>/dev/null || echo "0")
            log_ok "ZAP: ${ALERT_COUNT} alerta(s) para ${web_target}"

            python3 - "$ZAP_ALERTS" "$FINDINGS_FILE" << 'PYEOF'
import json, sys

zap_file = sys.argv[1]
findings_file = sys.argv[2]

risk_map = {'3': 'critical', '2': 'high', '1': 'medium', '0': 'low'}
cwe_pci_map = {
    '89': 'Req 6.2.4', '79': 'Req 6.2.4', '22': 'Req 6.2.4',
    '352': 'Req 6.2.4', '200': 'Req 2.2.7', '614': 'Req 4.2.1',
    '693': 'Req 6.2.4', '16': 'Req 2.2', '525': 'Req 6.2.4',
    '829': 'Req 6.2.4',
}

try:
    with open(zap_file, 'r') as f:
        data = json.load(f)
except:
    sys.exit(0)

alerts = data.get('alerts', [])
count = 0

with open(findings_file, 'a') as ff:
    for alert in alerts:
        risk = str(alert.get('risk', '0'))
        severity = risk_map.get(risk, 'info')
        cwe_id = str(alert.get('cweid', ''))
        pci_req = cwe_pci_map.get(cwe_id, 'Req 6.2.4')
        cve = ''
        refs = alert.get('reference', '')
        if 'CVE-' in refs:
            import re
            cve_match = re.search(r'(CVE-\d{4}-\d+)', refs)
            if cve_match:
                cve = cve_match.group(1)
        finding = {
            'severity': severity,
            'pci_req': pci_req,
            'title': alert.get('alert', alert.get('name', 'ZAP Alert')),
            'target': alert.get('url', ''),
            'detail': alert.get('description', ''),
            'evidence': alert.get('evidence', '') or alert.get('attack', ''),
            'remediation': alert.get('solution', 'Corrigir conforme OWASP. Ref: PCI DSS 4.0 Req 6.2.4'),
            'tool': 'zap',
            'cve': cve,
            'cvss': 0.0
        }
        ff.write(json.dumps(finding) + '\n')
        count += 1

print(f"  → {count} finding(s) ZAP mapeados para PCI")
PYEOF
        done

        if [[ $ZAP_STARTED_BY_SCRIPT -eq 1 ]]; then
            zap_api_call "core/action/shutdown" "" 2>/dev/null || true
            log_info "ZAP encerrado"
        fi
    fi
else
    if [[ ${#WEB_TARGETS[@]} -eq 0 ]]; then
        log_skip "Sem alvos web — ZAP não necessário"
    elif [[ $SKIP_ZAP -eq 1 ]]; then
        log_skip "--no-zap — ZAP ignorado"
    else
        log_skip "zaproxy não disponível"
    fi
fi

timer_end

# ═══════════════════════════════════════════════════════════════
#  FASE 7: REPORT GENERATION
# ═══════════════════════════════════════════════════════════════
phase_header "7/7" "GERAÇÃO DE RELATÓRIO PCI DSS 4.0"
timer_start

REPORT_FILE="$OUTDIR/relatorio_pci_dss.html"

python3 - "$FINDINGS_FILE" "$REPORT_FILE" "$OUTDIR/raw/scan_meta.json" "$QUARTER" "$MAX_PARALLEL" << 'PYREPORT'
import json, sys, html as htmlmod
from collections import Counter, defaultdict

findings_file = sys.argv[1]
report_file = sys.argv[2]
meta_file = sys.argv[3]
quarter = sys.argv[4]
max_parallel = sys.argv[5]

with open(meta_file) as f:
    meta = json.load(f)

findings = []
with open(findings_file) as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                findings.append(json.loads(line))
            except:
                pass

seen = set()
deduped = []
for fi in findings:
    key = (fi.get('title',''), fi.get('target',''))
    if key not in seen:
        seen.add(key)
        deduped.append(fi)
findings = deduped

sev_order = ['critical', 'high', 'medium', 'low', 'info']
sev_counts = Counter(fi.get('severity','info') for fi in findings)
sev_labels_map = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
sev_colors = {'critical':'#7a2e2e','high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','info':'#6e8f72'}

req_groups = defaultdict(list)
for fi in findings:
    primary_req = fi.get('pci_req','Outros').split(',')[0].strip()
    req_groups[primary_req].append(fi)

req_meta = {
    'Req 1.3': ('Req 1.3 — Controles de Segurança de Rede', 'Acesso ao CDE restrito, NSC configurados'),
    'Req 1.3, 2.2': ('Req 1.3, 2.2 — Serviços Inseguros', 'Serviços desnecessários no CDE'),
    'Req 2.2': ('Req 2.2 — Configurações Seguras', 'Hardening de sistemas e serviços'),
    'Req 2.2.2': ('Req 2.2.2 — Credenciais Padrão', 'Senhas de fábrica devem ser alteradas'),
    'Req 2.2.7': ('Req 2.2.7 — Divulgação de Informação', 'Banners e versões expostas'),
    'Req 4.2.1': ('Req 4.2.1 — Criptografia Forte (TLS/SSL)', 'Apenas TLS 1.2+, cifras fortes, cert válido'),
    'Req 6.2.4': ('Req 6.2.4 — Segurança de Aplicação', 'OWASP Top 10, security headers, input validation'),
    'Req 6.3.3': ('Req 6.3.3 — Patches e Atualizações', 'CVEs conhecidos devem ser corrigidos'),
    'Req 6.3.3, 11.3.1': ('Req 6.3.3 — Patches e Atualizações', 'CVEs conhecidos devem ser corrigidos'),
    'Req 8.3.1': ('Req 8.3.1 — Autenticação Forte', 'Métodos seguros de autenticação'),
    'Req 8.6.1': ('Req 8.6.1 — Contas de Sistema', 'Gerenciamento de contas privilegiadas'),
    'Req 11.3.1': ('Req 11.3.1 — Scan Interno', 'Scan trimestral de vulnerabilidades'),
    'Req 11.3.1.2': ('Req 11.3.1.2 — Scan Autenticado', 'Novo requisito PCI DSS 4.0'),
    'Req 2.2, 4.2.1': ('Req 2.2 — Config + Criptografia', 'Algoritmos fracos, protocolos inseguros'),
    'Req 2.2, 8.3': ('Req 2.2, 8.3 — Config + Auth', 'Configuração de autenticação'),
    'Req 2.2, 8.6': ('Req 2.2, 8.6 — Config + Contas', 'Login root, contas administrativas'),
}

def req_status(req_findings):
    c = sum(1 for fi in req_findings if fi.get('severity') == 'critical')
    h = sum(1 for fi in req_findings if fi.get('severity') == 'high')
    m = sum(1 for fi in req_findings if fi.get('severity') == 'medium')
    if c + h > 0:
        return 'FAIL', '#7a2e2e'
    elif m > 0:
        return 'REVIEW', '#d4833a'
    else:
        return 'PASS', '#27ae60'

weights = {'critical': 40, 'high': 20, 'medium': 5, 'low': 1, 'info': 0}
raw_score = sum(weights.get(fi.get('severity','info'), 0) for fi in findings)
risk_score = min(100, raw_score)

has_crit_high = sev_counts.get('critical', 0) + sev_counts.get('high', 0) > 0
has_medium = sev_counts.get('medium', 0) > 0

if has_crit_high:
    scan_status = "FAIL"
    status_color = '#7a2e2e'
    status_bg = '#fdecec'
    status_detail = "Ambiente NÃO conforme — vulnerabilidades Críticas/Altas encontradas exigem remediação antes do próximo ciclo trimestral"
elif has_medium:
    scan_status = "REVIEW"
    status_color = '#d4833a'
    status_bg = '#fdf6ec'
    status_detail = "Ambiente em revisão — vulnerabilidades Médias identificadas devem ser tratadas no plano de remediação"
else:
    scan_status = "PASS"
    status_color = '#27ae60'
    status_bg = '#ecfdec'
    status_detail = "Ambiente em conformidade com PCI DSS 4.0 para este ciclo trimestral"

req_status_counts = {'PASS': 0, 'REVIEW': 0, 'FAIL': 0}
for req_findings in req_groups.values():
    st, _ = req_status(req_findings)
    req_status_counts[st] += 1

total_reqs = len(req_groups)

def esc(s):
    if not isinstance(s, str): s = str(s)
    return htmlmod.escape(s)

def sev_badge(sev):
    c = sev_colors.get(sev, "#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sev.upper()}</span>'

def tool_badge(tool):
    colors = {"nmap":"#2563EB","nuclei":"#3498db","zap":"#e74c3c","testssl":"#0891b2","curl":"#6b7280","ssh":"#059669","ssh-auth":"#059669","lynis":"#8e44ad","trivy":"#d35400","policy":"#d4833a","manual":"#6b7280"}
    c = colors.get(tool, "#666")
    return f'<span class="source-badge" style="background:{c};color:white">{esc(tool)}</span>'

P = []

P.append(f'''<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>PCI DSS 4.0 — {quarter}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}

.status-hero{{background:{status_bg};border:3px solid {status_color};border-radius:12px;padding:40px 30px;margin:20px 0 30px;text-align:center}}
.status-hero .label{{font-size:13px;color:#666;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px}}
.status-hero .badge{{font-size:64px;font-weight:900;color:{status_color};letter-spacing:6px;margin:0}}
.status-hero .detail{{font-size:16px;color:#444;margin-top:12px;max-width:700px;margin-left:auto;margin-right:auto}}
.status-hero .req-bar{{display:flex;justify-content:center;gap:30px;margin-top:24px;font-size:14px}}
.status-hero .req-bar div{{padding:6px 16px;border-radius:20px;background:white;border:1px solid #ddd}}
.status-hero .req-bar .pass{{color:#27ae60;font-weight:bold}}
.status-hero .req-bar .review{{color:#d4833a;font-weight:bold}}
.status-hero .req-bar .fail{{color:#7a2e2e;font-weight:bold}}

.sev-summary{{display:flex;gap:10px;margin:20px 0;flex-wrap:wrap;justify-content:center}}
.sev-chip{{display:flex;align-items:center;gap:8px;padding:8px 16px;background:#f8f9fa;border:1px solid #e0e0e0;border-radius:20px;font-size:13px}}
.sev-chip .dot{{width:10px;height:10px;border-radius:50%}}
.sev-chip .count{{font-weight:bold;font-size:16px}}

.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}

.req-section{{margin:30px 0;border:1px solid #e0e0e0;border-radius:10px;overflow:hidden}}
.req-section-header{{padding:18px 22px;color:white;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}}
.req-section-header .title{{font-size:18px;font-weight:bold;margin:0}}
.req-section-header .desc{{font-size:13px;opacity:.9;margin:4px 0 0}}
.req-section-header .status{{background:white;color:#333;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:bold;white-space:nowrap}}
.req-section-body{{padding:20px}}
.req-status-fail{{background:linear-gradient(135deg,#7a2e2e,#a04545)}}
.req-status-review{{background:linear-gradient(135deg,#d4833a,#e09f5e)}}
.req-status-pass{{background:linear-gradient(135deg,#27ae60,#4cc27d)}}

.vuln{{border:1px solid #ddd;margin:15px 0;padding:18px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}
.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}
.vuln.low{{border-left:10px solid #4a7c8c}}
.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0;font-size:15px}}
.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}

table{{width:100%;border-collapse:collapse;margin:10px 0}}
th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}
h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px;margin-top:30px}}

code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
.evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto}}
.remed-box{{background:#e8f8e8;border-left:4px solid #27ae60;padding:10px 14px;font-size:13px;margin-top:6px;border-radius:4px}}

.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}

@media print{{body{{background:white;padding:0}}.container{{box-shadow:none}}.vuln,.req-section{{break-inside:avoid}}}}
</style></head><body><div class="container">
<div class="header"><h1>PCI DSS 4.0 — Relatório de Compliance</h1>
<p>Scan Interno de Vulnerabilidades — <strong>Omnibees Security Intelligence</strong></p>
<p>Trimestre: <strong>{quarter}</strong> &nbsp;|&nbsp; Data: {meta.get("scan_date","N/A")} &nbsp;|&nbsp;
Perfil: {meta.get("profile","full")} &nbsp;|&nbsp; Autenticado: {"Sim ✓" if meta.get("authenticated") else "Não ✗"} &nbsp;|&nbsp;
Alvos: {meta.get("web_targets",0)} web + {meta.get("infra_targets",0)} infra &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">''')

P.append(f'''<div class="status-hero">
  <div class="label">STATUS DE COMPLIANCE PCI DSS 4.0</div>
  <div class="badge">{scan_status}</div>
  <div class="detail">{status_detail}</div>
  <div class="req-bar">
    <div><span class="pass">✓ {req_status_counts["PASS"]}</span> em conformidade</div>
    <div><span class="review">⚠ {req_status_counts["REVIEW"]}</span> em revisão</div>
    <div><span class="fail">✗ {req_status_counts["FAIL"]}</span> não conformes</div>
  </div>
</div>''')

P.append('<div class="sev-summary">')
for sev in sev_order:
    count = sev_counts.get(sev, 0)
    if count > 0:
        P.append(f'<div class="sev-chip"><span class="dot" style="background:{sev_colors[sev]}"></span>{sev_labels_map[sev]} <span class="count" style="color:{sev_colors[sev]}">{count}</span></div>')
P.append('</div>')

P.append(f'''<div class="info-box">
<p><strong>Total de Findings:</strong> {len(findings)} &nbsp;|&nbsp;
<strong>Requisitos PCI Avaliados:</strong> {total_reqs} &nbsp;|&nbsp;
<strong>Risk Score:</strong> {risk_score}/100</p>
<p><strong>Ferramentas:</strong> nmap + Nuclei + OWASP ZAP + testssl + Lynis + Trivy &nbsp;|&nbsp;
<strong>Scan Paralelo:</strong> Ativado ({max_parallel} threads)</p>
</div>''')

P.append('<h2>Vulnerabilidades por Requisito PCI DSS</h2>')

def req_sort_key(req_key):
    findings_list = req_groups[req_key]
    st, _ = req_status(findings_list)
    sort_map = {'FAIL': 0, 'REVIEW': 1, 'PASS': 2}
    return (sort_map.get(st, 3), req_key)

sorted_reqs = sorted(req_groups.keys(), key=req_sort_key)

for req_key in sorted_reqs:
    req_findings = req_groups[req_key]
    title, desc = req_meta.get(req_key, (req_key, 'PCI DSS 4.0 requirement'))
    st, st_color = req_status(req_findings)
    st_class = f"req-status-{st.lower()}"
    st_icon = {'PASS': '✓', 'REVIEW': '⚠', 'FAIL': '✗'}[st]

    req_sev_count = Counter(fi.get('severity','info') for fi in req_findings)
    sev_summary = " · ".join(f"{sev_labels_map[s]}: {req_sev_count[s]}" for s in sev_order if req_sev_count.get(s,0) > 0)

    P.append(f'''<div class="req-section">
  <div class="req-section-header {st_class}">
    <div>
      <div class="title">{esc(title)}</div>
      <div class="desc">{esc(desc)} &nbsp;|&nbsp; {esc(sev_summary)}</div>
    </div>
    <div class="status">{st_icon} {st}</div>
  </div>
  <div class="req-section-body">''')

    sorted_findings = sorted(req_findings, key=lambda x: sev_order.index(x.get('severity','info')))
    main_findings = [fi for fi in sorted_findings if fi.get('severity') in ('critical','high','medium')]
    aux_findings = [fi for fi in sorted_findings if fi.get('severity') in ('low','info')]

    if main_findings:
        for fi in main_findings:
            sev = fi.get('severity','info')
            cve_part = ''
            if fi.get('cve'):
                cve_part = f'<br><small style="color:#555">{esc(fi["cve"])}</small>'
            cvss_part = ''
            if fi.get('cvss') and fi.get('cvss',0) > 0:
                cvss_part = f' <span style="background:{sev_colors[sev]};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">CVSS {fi["cvss"]}</span>'

            P.append(f'''    <div class="vuln {sev}">
      <h3>{esc(fi.get("title","(sem título)"))} {tool_badge(fi.get("tool","manual"))} {sev_badge(sev)}{cvss_part}{cve_part}</h3>
      <table>
        <tr><th style="width:120px">Alvo</th><td><code>{esc(fi.get("target",""))}</code></td></tr>
        <tr><th>Descrição</th><td>{esc(fi.get("detail","")[:500])}</td></tr>''')
            if fi.get('evidence'):
                P.append(f'        <tr><th>Evidência</th><td><div class="evidence-box">{esc(fi["evidence"][:1500])}</div></td></tr>')
            P.append(f'        <tr><th>Recomendação</th><td><div class="remed-box">💡 {esc(fi.get("remediation",""))}</div></td></tr>')
            P.append('      </table>\n    </div>')

    if aux_findings:
        P.append(f'''    <details style="margin-top:15px">
      <summary style="cursor:pointer;padding:10px;background:#f8f9fa;border-radius:6px;font-weight:600;color:#666">
        Findings Baixos e Informativos ({len(aux_findings)})
      </summary>
      <table style="margin-top:10px">
        <thead><tr><th style="width:80px">Sev</th><th>Finding</th><th>Alvo</th><th style="width:80px">Tool</th></tr></thead>
        <tbody>''')
        for fi in aux_findings:
            sev = fi.get('severity','info')
            P.append(f'          <tr><td>{sev_badge(sev)}</td><td>{esc(fi.get("title","")[:100])}</td><td style="font-family:monospace;font-size:12px">{esc(fi.get("target","")[:60])}</td><td>{esc(fi.get("tool",""))}</td></tr>')
        P.append('        </tbody>\n      </table>\n    </details>')

    if not main_findings and not aux_findings:
        P.append('    <p style="color:#27ae60;font-weight:600;margin:10px 0">✓ Nenhum finding neste requisito</p>')

    P.append('  </div>\n</div>')

P.append(f'''<h2>Plano de Remediação — 3 Horizontes</h2>
<table>
<thead><tr><th style="width:180px">Horizonte</th><th style="width:120px">Prazo</th><th>Ação</th><th style="width:100px">Findings</th></tr></thead>
<tbody>
<tr><td><strong>H1 — Imediato</strong></td><td>0–30 dias</td><td>Corrigir todas as vulnerabilidades Críticas e Altas. Re-scan obrigatório após correção.</td><td style="color:#7a2e2e;font-weight:bold;text-align:center;font-size:18px">{sev_counts.get("critical",0) + sev_counts.get("high",0)}</td></tr>
<tr><td><strong>H2 — Curto prazo</strong></td><td>30–90 dias</td><td>Corrigir findings Médios e implementar hardening. Aplicar security headers, desabilitar protocolos obsoletos.</td><td style="color:#d4833a;font-weight:bold;text-align:center;font-size:18px">{sev_counts.get("medium",0)}</td></tr>
<tr><td><strong>H3 — Contínuo</strong></td><td>90+ dias</td><td>Endereçar Low/Info e manter ciclo de scans trimestrais conforme Req 11.3.1.</td><td style="color:#4a7c8c;font-weight:bold;text-align:center;font-size:18px">{sev_counts.get("low",0) + sev_counts.get("info",0)}</td></tr>
</tbody></table>''')

P.append(f'''</div>
<div class="footer">
<p><strong>CONFIDENCIAL — USO INTERNO</strong></p>
<p>PCI DSS 4.0 Internal Compliance Scan | {quarter} | Requisitos cobertos: 1, 2, 4, 6, 8, 11</p>
<p>Scans externos ASV (Req 11.3.2) realizados separadamente</p>
<p>SWARM — Omnibees Security Intelligence</p>
</div></div></body></html>''')

html_out = '\n'.join(P)
with open(report_file, 'w') as f:
    f.write(html_out)

print(f"Relatório: {report_file}")
print(f"Findings: {len(findings)} | C={sev_counts.get('critical',0)} H={sev_counts.get('high',0)} M={sev_counts.get('medium',0)} L={sev_counts.get('low',0)} I={sev_counts.get('info',0)}")
print(f"Status: {scan_status} | Requisitos: {total_reqs} (PASS={req_status_counts['PASS']} REVIEW={req_status_counts['REVIEW']} FAIL={req_status_counts['FAIL']})")
PYREPORT
timer_end

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
TOTAL_FINDINGS=$(wc -l < "$FINDINGS_FILE" 2>/dev/null | tr -d ' ')
TOTAL_FINDINGS=${TOTAL_FINDINGS:-0}

SCAN_END=$(date +"%d/%m/%Y %H:%M:%S")
SCAN_DURATION=$SECONDS

echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RESUMO PCI SCAN${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[+] Relatório :${NC} $REPORT_FILE"
echo -e "${BOLD}[+] Findings  :${NC} $TOTAL_FINDINGS"
echo -e "${BOLD}[+] Duração   :${NC} ${SCAN_DURATION}s"
echo -e "${BOLD}[+] Concluído :${NC} $SCAN_END"
echo ""
echo -e "${GREEN}Abrir relatório: ${BOLD}xdg-open ${REPORT_FILE}${NC}"
echo ""

cp "$REPORT_FILE" "$OUTDIR/history/pci_dss_${QUARTER}.html" 2>/dev/null || true
echo "$SCAN_DATE_HUMAN | $TOTAL_FINDINGS findings | Profile: $PROFILE" >> "$OUTDIR/history/scan_log.txt"

echo -e "${MAGENTA}[PCI DSS 4.0] Próximo scan trimestral: executar dentro de 90 dias${NC}"
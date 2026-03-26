#!/bin/bash
# ============================================================================
# Jeffrey Toolkit v1.0 — Clean Deployment
# Qwen 3.5 27B Q8 op llama.cpp (compiled from source)
# Target: RHEL 10, 64GB RAM, /data partition, Apache + Basic Auth
#
# Verwacht in dezelfde directory als dit script:
#   - llama.cpp-master.zip         (GitHub → Code → Download ZIP)
#   - Qwen3.5-27B-Q8_0.gguf       (unsloth/Qwen3.5-27B-GGUF)
#   - jeffrey-v1.0-qwen35.html    (Jeffrey Toolkit HTML)
# ============================================================================
set -euo pipefail

# --- Configuration (aligned with v1.0.3 paths) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="/data/toolkit"
MODEL_DIR="/data/models"
LLAMA_BINARY_DIR="/opt/llama-server"
APACHE_CONF="/etc/httpd/conf.d/jeffrey.conf"
HTPASSWD="/etc/httpd/.htpasswd"
LLAMA_PORT="8081"
APACHE_PORT="8080"

# Source files
LLAMA_ZIP="${SCRIPT_DIR}/llama.cpp-master.zip"
MODEL_FILE="${SCRIPT_DIR}/Qwen3.5-27B-Q8_0.gguf"
HTML_FILE="${SCRIPT_DIR}/jeffrey-v1.0-qwen35.html"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "═══════════════════════════════════════"
echo "  Jeffrey Toolkit v1.0 — Clean Deploy"
echo "  Qwen 3.5 27B Q8 + llama.cpp"
echo "═══════════════════════════════════════"
echo ""

[[ $EUID -eq 0 ]] || fail "Dit script moet als root uitgevoerd worden (sudo)"

# ═══════════════════════════════════════
# STAP 1: PRE-FLIGHT CHECKS
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 1: Pre-flight checks"
echo "═══════════════════════════════════════"

TOTAL_RAM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
log "RAM: ${TOTAL_RAM_GB} GB"
[[ $TOTAL_RAM_GB -ge 48 ]] || fail "Minimaal 48 GB RAM vereist (gevonden: ${TOTAL_RAM_GB} GB)"

[[ -d "/data" ]] || fail "/data partitie niet gevonden"
DATA_FREE_GB=$(df -BG "/data" | awk 'NR==2 {print $4}' | tr -d 'G')
log "/data vrije ruimte: ${DATA_FREE_GB} GB"

[[ -f "$LLAMA_ZIP" ]] || fail "llama.cpp-master.zip niet gevonden in ${SCRIPT_DIR}"
[[ -f "$MODEL_FILE" ]] || fail "Qwen3.5-27B-Q8_0.gguf niet gevonden in ${SCRIPT_DIR}"
[[ -f "$HTML_FILE" ]] || fail "jeffrey-v1.0-qwen35.html niet gevonden in ${SCRIPT_DIR}"
log "Alle bronbestanden gevonden"

for cmd in unzip cmake gcc g++ make; do
    command -v $cmd &>/dev/null || {
        warn "${cmd} niet gevonden, installeren..."
        dnf install -y unzip cmake gcc gcc-c++ make 2>/dev/null || \
            fail "Kan build tools niet installeren: dnf install unzip cmake gcc gcc-c++ make"
        break
    }
done
log "Build tools beschikbaar"

echo ""
# ═══════════════════════════════════════
# STAP 2: CLEANUP OUDE INSTALLATIE
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 2: Opruimen oude installatie"
echo "═══════════════════════════════════════"

# Backup bestaande gebruikers
if [[ -f "$HTPASSWD" ]]; then
    cp "$HTPASSWD" "/root/htpasswd.backup.$(date +%Y%m%d-%H%M%S)"
    log "Gebruikers gebackupt naar /root/"
fi

# Stop services
if systemctl is-active --quiet llama-server 2>/dev/null; then
    systemctl stop llama-server
    log "llama-server gestopt"
fi
pkill -f llama-server 2>/dev/null || true

if systemctl is-active --quiet httpd 2>/dev/null; then
    systemctl stop httpd
    log "Apache gestopt"
fi

# Verwijder oude llama-server binary
if [[ -d "/opt/llama-server" ]]; then
    rm -rf /opt/llama-server
    log "Oude binary verwijderd: /opt/llama-server/"
fi

# Verwijder oude systemd service
if [[ -f /etc/systemd/system/llama-server.service ]]; then
    systemctl disable llama-server 2>/dev/null || true
    rm -f /etc/systemd/system/llama-server.service
    log "Oude systemd service verwijderd"
fi

# Verwijder ALLE oude Apache configs (alle varianten uit eerdere versies)
for conf in jeffrey.conf jeffrey-proxy.conf jeffrey-llama.conf llama-proxy.conf; do
    if [[ -f "/etc/httpd/conf.d/${conf}" ]]; then
        rm -f "/etc/httpd/conf.d/${conf}"
        log "Oude Apache config verwijderd: ${conf}"
    fi
done

# Verwijder oude HTML
rm -f "${TOOLKIT_DIR}/index.html" 2>/dev/null || true
rm -f /var/www/html/index.html 2>/dev/null || true

# Verwijder oude build rommel
rm -rf /tmp/llama.cpp-master /tmp/llama-build 2>/dev/null || true
rm -rf /data/llama.cpp 2>/dev/null || true

# Vraag of oud Q5 model verwijderd mag worden
if [[ -f "${MODEL_DIR}/Qwen_Qwen3.5-27B-Q5_K_M.gguf" ]]; then
    echo ""
    echo -e "${YELLOW}Oud model gevonden: Qwen_Qwen3.5-27B-Q5_K_M.gguf (~19 GB)${NC}"
    read -p "Oud Q5 model verwijderen? (j/n): " DEL_OLD
    if [[ "$DEL_OLD" == "j" ]]; then
        rm -f "${MODEL_DIR}/Qwen_Qwen3.5-27B-Q5_K_M.gguf"
        log "Oud Q5 model verwijderd"
    else
        warn "Oud model bewaard"
    fi
fi

# Verwijder oude logs
rm -f /var/log/llama-server.log 2>/dev/null || true

systemctl daemon-reload
log "Cleanup voltooid"

echo ""
# ═══════════════════════════════════════
# STAP 3: COMPILEER LLAMA.CPP
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 3: llama.cpp compileren"
echo "═══════════════════════════════════════"
echo "Dit duurt 10-15 minuten..."

cd /tmp
rm -rf llama.cpp-master 2>/dev/null
unzip -q "$LLAMA_ZIP"

# Zoek uitgepakte directory
EXTRACTED=$(find /tmp -maxdepth 1 -type d -name "llama*" | head -1)
[[ -n "$EXTRACTED" ]] || fail "Kon uitgepakte llama.cpp directory niet vinden"

cd "$EXTRACTED"

# Controleer Qwen 3.5 support
if grep -rq "qwen3_5\|qwen35" src/ 2>/dev/null; then
    log "Qwen 3.5 support geverifieerd in source"
else
    warn "Kon Qwen 3.5 support niet bevestigen — compilatie gaat door"
fi

echo "CMake configuratie..."
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DGGML_CUDA=OFF \
    -DGGML_BLAS=OFF \
    -DGGML_NATIVE=OFF \
    -DGGML_LLAMAFILE=OFF \
    -DGGML_STATIC=ON \
    > /dev/null 2>&1

echo "Compileren met $(nproc) threads..."
cmake --build build --config Release -j "$(nproc)" --target llama-server llama-cli 2>&1 | tail -5

[[ -f build/bin/llama-server ]] || fail "llama-server niet gecompileerd — check build output"
log "llama-server gecompileerd"

# Installeer binary
mkdir -p "$LLAMA_BINARY_DIR"
cp build/bin/llama-server "${LLAMA_BINARY_DIR}/llama-server"
cp build/bin/llama-cli "${LLAMA_BINARY_DIR}/llama-cli" 2>/dev/null || true
chmod +x "${LLAMA_BINARY_DIR}/llama-server"

# Check dependencies
MISSING=$(ldd "${LLAMA_BINARY_DIR}/llama-server" 2>&1 | grep "not found" || true)
if [[ -n "$MISSING" ]]; then
    warn "Ontbrekende libraries: ${MISSING}"
else
    log "Binary dependencies OK"
fi

# Opruimen build
rm -rf /tmp/llama.cpp-master 2>/dev/null
log "Build opgeruimd"

echo ""
# ═══════════════════════════════════════
# STAP 4: MODEL INSTALLEREN
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 4: Model installeren"
echo "═══════════════════════════════════════"

mkdir -p "$MODEL_DIR"

if [[ -f "${MODEL_DIR}/Qwen3.5-27B-Q8_0.gguf" ]]; then
    log "Model bestaat al in ${MODEL_DIR}"
else
    log "Model verplaatsen naar ${MODEL_DIR} (28.6 GB)..."
    mv "$MODEL_FILE" "${MODEL_DIR}/Qwen3.5-27B-Q8_0.gguf"
fi

log "Model: $(ls -lh ${MODEL_DIR}/Qwen3.5-27B-Q8_0.gguf | awk '{print $5}')"

echo ""
# ═══════════════════════════════════════
# STAP 5: SYSTEMD SERVICE
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 5: Systemd service aanmaken"
echo "═══════════════════════════════════════"

PHYS_CORES=$(lscpu | awk '/^Core\(s\) per socket/ {c=$4} /^Socket\(s\)/ {s=$2} END {print c*s}')
THREADS=${PHYS_CORES:-$(nproc)}

cat > /etc/systemd/system/llama-server.service << EOF
[Unit]
Description=Jeffrey Toolkit — llama.cpp Server (Qwen 3.5 27B Q8)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${LLAMA_BINARY_DIR}
ExecStart=${LLAMA_BINARY_DIR}/llama-server \\
    --model ${MODEL_DIR}/Qwen3.5-27B-Q8_0.gguf \\
    --host 127.0.0.1 \\
    --port ${LLAMA_PORT} \\
    --ctx-size 4096 \\
    --threads ${THREADS} \\
    --flash-attn \\
    --chat-template chatml \\
    --chat-template-kwargs '{"enable_thinking": false}'
StandardOutput=append:/var/log/llama-server.log
StandardError=append:/var/log/llama-server.log
Restart=always
RestartSec=10
TimeoutStartSec=600
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable llama-server
log "Service aangemaakt (${THREADS} threads, thinking=off)"

echo ""
# ═══════════════════════════════════════
# STAP 6: HTML + APACHE
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 6: HTML + Apache configureren"
echo "═══════════════════════════════════════"

mkdir -p "$TOOLKIT_DIR"

cp "$HTML_FILE" "${TOOLKIT_DIR}/index.html"
chown apache:apache "${TOOLKIT_DIR}/index.html"
chmod 644 "${TOOLKIT_DIR}/index.html"
log "HTML gedeployed naar ${TOOLKIT_DIR}/index.html"

cat > "$APACHE_CONF" << 'APACHECONF'
Listen 8080

ProxyTimeout 600
Timeout 600

<VirtualHost *:8080>
    ServerName localhost
    DocumentRoot /data/toolkit

    <Directory /data/toolkit>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    <Location /api/chat>
        AuthType Basic
        AuthName "Jeffrey Toolkit — SOC Access Only"
        AuthUserFile /etc/httpd/.htpasswd
        Require valid-user
    </Location>

    ProxyPreserveHost On
    ProxyPass /api/chat http://127.0.0.1:8081/v1/chat/completions
    ProxyPassReverse /api/chat http://127.0.0.1:8081/v1/chat/completions

    ProxyPass /health http://127.0.0.1:8081/health
    ProxyPassReverse /health http://127.0.0.1:8081/health

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"

    ErrorLog /var/log/httpd/jeffrey_error.log
    CustomLog /var/log/httpd/jeffrey_access.log combined
</VirtualHost>
APACHECONF
log "Apache config aangemaakt"

# Herstel gebruikers
if ls /root/htpasswd.backup.* 1>/dev/null 2>&1; then
    LATEST_BACKUP=$(ls -t /root/htpasswd.backup.* | head -1)
    cp "$LATEST_BACKUP" "$HTPASSWD"
    USERCOUNT=$(wc -l < "$HTPASSWD")
    log "Gebruikers hersteld uit backup (${USERCOUNT} accounts)"
else
    warn "Geen gebruikers backup gevonden"
    echo ""
    read -p "Eerste gebruiker aanmaken? (j/n): " CREATE_USER
    if [[ "$CREATE_USER" == "j" ]]; then
        read -p "Gebruikersnaam: " FIRST_USER
        if [[ -n "$FIRST_USER" ]]; then
            FIRST_PASS=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
            htpasswd -bc "$HTPASSWD" "$FIRST_USER" "$FIRST_PASS"
            echo ""
            echo -e "  Gebruiker:  ${BLUE}${FIRST_USER}${NC}"
            echo -e "  Wachtwoord: ${BLUE}${FIRST_PASS}${NC}"
            echo -e "  ${YELLOW}BEWAAR DIT WACHTWOORD!${NC}"
            echo ""
        fi
    fi
fi

# SELinux
if command -v semanage &>/dev/null; then
    semanage fcontext -a -t httpd_sys_content_t "/data/toolkit(/.*)?" 2>/dev/null || true
    restorecon -R /data/toolkit
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    log "SELinux geconfigureerd"
fi

# Firewall
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=${APACHE_PORT}/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    log "Firewall poort ${APACHE_PORT} geopend"
fi

echo ""
# ═══════════════════════════════════════
# STAP 7: SERVICES STARTEN
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 7: Services starten"
echo "═══════════════════════════════════════"

echo "llama-server starten (model laden duurt 1-2 minuten)..."
systemctl start llama-server

for i in $(seq 1 180); do
    if curl -s "http://127.0.0.1:${LLAMA_PORT}/health" 2>/dev/null | grep -q "ok"; then
        log "llama-server gereed!"
        break
    fi
    if grep -q "FATAL\|Segmentation" /var/log/llama-server.log 2>/dev/null; then
        fail "Model laden mislukt — check: tail -50 /var/log/llama-server.log"
    fi
    if [[ $((i % 15)) -eq 0 ]]; then
        echo "  Nog aan het laden... (${i} seconden)"
    fi
    sleep 1
done

[[ -f /etc/httpd/conf.d/welcome.conf ]] && mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf.bak 2>/dev/null || true
httpd -t 2>/dev/null || warn "Apache config test gaf waarschuwing"
systemctl enable httpd
systemctl start httpd
log "Apache gestart"

echo ""
# ═══════════════════════════════════════
# STAP 8: VERIFICATIE
# ═══════════════════════════════════════
echo "═══════════════════════════════════════"
echo "STAP 8: Verificatie"
echo "═══════════════════════════════════════"

ERRORS=0
systemctl is-active --quiet llama-server && log "llama-server draait" || { warn "llama-server draait NIET"; ERRORS=$((ERRORS+1)); }
systemctl is-active --quiet httpd && log "Apache draait" || { warn "Apache draait NIET"; ERRORS=$((ERRORS+1)); }

ss -tuln | grep -q ":${LLAMA_PORT}" && log "Poort ${LLAMA_PORT} luistert" || { warn "Poort ${LLAMA_PORT} luistert NIET"; ERRORS=$((ERRORS+1)); }
ss -tuln | grep -q ":${APACHE_PORT}" && log "Poort ${APACHE_PORT} luistert" || { warn "Poort ${APACHE_PORT} luistert NIET"; ERRORS=$((ERRORS+1)); }

echo ""
echo "Schijfruimte /data:"
df -h /data | tail -1
echo ""
echo "Bestanden:"
ls -lh "${MODEL_DIR}/"*.gguf 2>/dev/null || true
ls -lh "${LLAMA_BINARY_DIR}/llama-server" 2>/dev/null || true
ls -lh "${TOOLKIT_DIR}/index.html" 2>/dev/null || true

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo "═══════════════════════════════════════"
    echo "  DEPLOYMENT GESLAAGD!"
    echo "═══════════════════════════════════════"
else
    echo "═══════════════════════════════════════"
    echo "  VOLTOOID MET ${ERRORS} WAARSCHUWING(EN)"
    echo "═══════════════════════════════════════"
fi
echo ""
echo "  URL:   http://$(hostname -I | awk '{print $1}'):${APACHE_PORT}"
echo "  Model: Qwen 3.5 27B Q8 (unsloth)"
echo ""
echo "  Commando's:"
echo "    journalctl -u llama-server -f"
echo "    systemctl restart llama-server"
echo "    htpasswd /etc/httpd/.htpasswd <user>"
echo ""

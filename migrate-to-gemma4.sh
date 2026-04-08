#!/bin/bash
# ============================================================================
# Jeffrey Toolkit — Migratie van Qwen 3.5 naar Gemma 4 26B-A4B
# 
# Wat dit script doet:
#   1. Backup huidige systemd override (om terug te kunnen)
#   2. Verplaatst Gemma 4 model naar /data/models/
#   3. Update systemd override met juiste parameters voor Gemma
#   4. Herstart llama-server
#   5. Verifieert dat het werkt
#
# Wat dit script NIET doet:
#   - Verwijdert het oude Qwen model NIET (terugschakelen blijft mogelijk)
#   - Wijzigt Apache, htpasswd, of andere services NIET
#   - Wijzigt de HTML NIET (model identiteit zit in system prompt)
# ============================================================================
set -euo pipefail

# Verwacht: model bestand staat in /data/toolkit/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_FILE="${SCRIPT_DIR}/gemma-4-26B-A4B-it-MXFP4_MOE.gguf"
MODEL_DIR="/data/models"
TARGET_MODEL="${MODEL_DIR}/gemma-4-26B-A4B-it-MXFP4_MOE.gguf"
OVERRIDE_DIR="/etc/systemd/system/llama-server.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/override.conf"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════"
echo "  Migratie: Qwen 3.5 → Gemma 4 26B-A4B (MoE)"
echo "═══════════════════════════════════════════════"
echo ""

[[ $EUID -eq 0 ]] || fail "Dit script moet als root uitgevoerd worden (sudo)"

# ─── STAP 1: Pre-flight checks ───
echo "STAP 1: Pre-flight checks"

[[ -f "$MODEL_FILE" ]] || fail "Model niet gevonden: $MODEL_FILE"

MODEL_SIZE=$(ls -lh "$MODEL_FILE" | awk '{print $5}')
log "Model gevonden: $MODEL_SIZE"

DATA_FREE_GB=$(df -BG "/data" | awk 'NR==2 {print $4}' | tr -d 'G')
[[ $DATA_FREE_GB -ge 20 ]] || fail "Te weinig schijfruimte in /data (${DATA_FREE_GB} GB)"
log "/data vrije ruimte: ${DATA_FREE_GB} GB"

[[ -f /opt/llama-server/llama-server ]] || fail "llama-server binary niet gevonden"
log "llama-server binary aanwezig"

# ─── STAP 2: Backup huidige config ───
echo ""
echo "STAP 2: Backup huidige systemd override"

if [[ -f "$OVERRIDE_FILE" ]]; then
    BACKUP="${OVERRIDE_FILE}.qwen-backup-$(date +%Y%m%d-%H%M%S)"
    cp "$OVERRIDE_FILE" "$BACKUP"
    log "Backup gemaakt: $BACKUP"
    echo "    Terugschakelen kan met: sudo cp $BACKUP $OVERRIDE_FILE && sudo systemctl daemon-reload && sudo systemctl restart llama-server"
else
    warn "Geen bestaande override gevonden, nieuwe wordt aangemaakt"
    mkdir -p "$OVERRIDE_DIR"
fi

# ─── STAP 3: Model verplaatsen ───
echo ""
echo "STAP 3: Model installeren"

if [[ -f "$TARGET_MODEL" ]]; then
    warn "Model bestaat al in $MODEL_DIR — overslaan"
else
    log "Model verplaatsen naar $MODEL_DIR..."
    mv "$MODEL_FILE" "$TARGET_MODEL"
    log "Model geïnstalleerd: $(ls -lh $TARGET_MODEL | awk '{print $5}')"
fi

# ─── STAP 4: Systemd override aanmaken ───
echo ""
echo "STAP 4: Systemd override voor Gemma 4 aanmaken"

cat > "$OVERRIDE_FILE" << 'EOF'
[Service]
ExecStart=
ExecStart=/opt/llama-server/llama-server --model /data/models/gemma-4-26B-A4B-it-MXFP4_MOE.gguf --host 127.0.0.1 --port 8081 --ctx-size 16384 --threads 16 --flash-attn on --chat-template gemma --temp 1.0 --top-k 64 --top-p 0.95 --min-p 0.0
EOF
log "Override geschreven: $OVERRIDE_FILE"
echo ""
echo "    Belangrijke wijzigingen ten opzichte van Qwen:"
echo "    - Model: gemma-4-26B-A4B-it-MXFP4_MOE.gguf"
echo "    - Chat template: gemma (was: chatml)"
echo "    - Sampling: temp=1.0, top-k=64, top-p=0.95 (Gemma optimaal)"
echo ""

# ─── STAP 5: Service herladen en starten ───
echo "STAP 5: llama-server herstarten"

systemctl daemon-reload
log "systemd daemon herladen"

systemctl restart llama-server
log "llama-server herstart commando verzonden"

echo ""
echo "Wachten tot model geladen is (kan 1-3 minuten duren bij MoE)..."

LOADED=false
for i in $(seq 1 240); do
    if curl -s "http://127.0.0.1:8081/health" 2>/dev/null | grep -q "ok"; then
        LOADED=true
        log "Gemma 4 is geladen en gereed!"
        break
    fi
    if grep -q "FATAL\|Segmentation\|error loading" /var/log/llama-server.log 2>/dev/null | tail -5; then
        echo ""
        warn "Mogelijk probleem gedetecteerd in logs — laatste 10 regels:"
        tail -10 /var/log/llama-server.log
    fi
    if [[ $((i % 15)) -eq 0 ]]; then
        echo "    Nog aan het laden... (${i} seconden)"
    fi
    sleep 1
done

if [[ "$LOADED" != "true" ]]; then
    echo ""
    warn "Server reageert niet na 4 minuten. Check logs:"
    echo "    sudo journalctl -u llama-server -n 50"
    echo "    sudo tail -50 /var/log/llama-server.log"
    echo ""
    echo "Terugschakelen naar Qwen:"
    echo "    sudo cp ${OVERRIDE_FILE}.qwen-backup-* $OVERRIDE_FILE"
    echo "    sudo systemctl daemon-reload && sudo systemctl restart llama-server"
    exit 1
fi

# ─── STAP 6: Test de API ───
echo ""
echo "STAP 6: API test met identiteits-check"

RESPONSE=$(curl -s -X POST http://127.0.0.1:8081/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"system","content":"Je bent Jeffrey, een SOC intelligence assistent."},{"role":"user","content":"Hoe heet je?"}],"max_tokens":50}' \
    2>/dev/null)

if echo "$RESPONSE" | grep -qi "jeffrey"; then
    log "Model reageert correct als Jeffrey"
elif echo "$RESPONSE" | grep -qi "gemma"; then
    warn "Model identificeert zich als 'Gemma' — system prompt heeft mogelijk extra aanscherping nodig"
else
    log "API werkt, response ontvangen"
fi

# ─── KLAAR ───
echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Migratie naar Gemma 4 voltooid!"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Model:    Gemma 4 26B-A4B (MXFP4 MoE)"
echo "  Snelheid: Verwacht ~8-10 tok/s (was ~3 tok/s)"
echo "  RAM:      ~18-20 GB (was ~32 GB)"
echo "  URL:      http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "  Test in browser met een SIEM query — verwacht 15-25 sec response."
echo ""
echo "  Terugschakelen naar Qwen indien nodig:"
echo "    LATEST_BACKUP=\$(ls -t ${OVERRIDE_FILE}.qwen-backup-* | head -1)"
echo "    sudo cp \"\$LATEST_BACKUP\" $OVERRIDE_FILE"
echo "    sudo systemctl daemon-reload && sudo systemctl restart llama-server"
echo ""
echo "  Het oude Qwen model staat nog in /data/models/ (verwijder pas na succesvolle test):"
echo "    ls -lh /data/models/"
echo ""

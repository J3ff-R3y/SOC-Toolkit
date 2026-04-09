#!/bin/bash
# ============================================================================
# Jeffrey Toolkit — Migratie naar Qwen 3.5 35B-A3B (MoE + Vision)
#
# Voordelen:
#   - MoE: 3B actieve parameters van 35B totaal, ~3x snelheidswinst
#   - Vision: screenshots en afbeeldingen analyseren
#   - Bewezen stabiele Qwen familie in llama.cpp
#
# Vereist in dezelfde directory als dit script:
#   - Qwen3.5-35B-A3B-MXFP4_MOE.gguf (of andere quant)
#   - mmproj-F16.gguf (of F32/BF16)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_NAME="Qwen3.5-35B-A3B-MXFP4_MOE.gguf"
MMPROJ_NAME="mmproj-F16.gguf"
MODEL_FILE="${SCRIPT_DIR}/${MODEL_NAME}"
MMPROJ_FILE="${SCRIPT_DIR}/${MMPROJ_NAME}"
MODEL_DIR="/data/models"
TARGET_MODEL="${MODEL_DIR}/${MODEL_NAME}"
TARGET_MMPROJ="${MODEL_DIR}/${MMPROJ_NAME}"
OVERRIDE_DIR="/etc/systemd/system/llama-server.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/override.conf"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Migratie: Qwen 3.5 27B → Qwen 3.5 35B-A3B (MoE + Vision)"
echo "═══════════════════════════════════════════════════════"
echo ""

[[ $EUID -eq 0 ]] || fail "Moet als root draaien (sudo)"

# ─── STAP 1: Pre-flight ───
echo "STAP 1: Pre-flight checks"

if [[ ! -f "$MODEL_FILE" ]] && [[ -f "${MODEL_DIR}/${MODEL_NAME}" ]]; then
    MODEL_FILE="${MODEL_DIR}/${MODEL_NAME}"
elif [[ ! -f "$MODEL_FILE" ]]; then
    ALT=$(ls "${SCRIPT_DIR}"/Qwen3.5-35B-A3B*.gguf 2>/dev/null | grep -v mmproj | head -1)
    [[ -n "$ALT" ]] || fail "Hoofdmodel niet gevonden in $SCRIPT_DIR"
    MODEL_FILE="$ALT"
    MODEL_NAME="$(basename "$ALT")"
    TARGET_MODEL="${MODEL_DIR}/${MODEL_NAME}"
fi
log "Hoofdmodel: $MODEL_NAME ($(ls -lh $MODEL_FILE | awk '{print $5}'))"

if [[ ! -f "$MMPROJ_FILE" ]] && [[ -f "${MODEL_DIR}/${MMPROJ_NAME}" ]]; then
    MMPROJ_FILE="${MODEL_DIR}/${MMPROJ_NAME}"
elif [[ ! -f "$MMPROJ_FILE" ]]; then
    ALT=$(ls "${SCRIPT_DIR}"/mmproj*.gguf 2>/dev/null | head -1)
    if [[ -n "$ALT" ]]; then
        MMPROJ_FILE="$ALT"
        MMPROJ_NAME="$(basename "$ALT")"
        TARGET_MMPROJ="${MODEL_DIR}/${MMPROJ_NAME}"
    else
        warn "Geen mmproj gevonden — ZONDER vision support"
        MMPROJ_FILE=""
    fi
fi
[[ -n "$MMPROJ_FILE" ]] && log "Vision projector: $MMPROJ_NAME ($(ls -lh $MMPROJ_FILE | awk '{print $5}'))"

[[ -f /opt/llama-server/llama-server ]] || fail "llama-server binary niet gevonden"
log "llama-server binary aanwezig"

# ─── STAP 2: Backup ───
echo ""
echo "STAP 2: Backup huidige config"
if [[ -f "$OVERRIDE_FILE" ]]; then
    BACKUP="${OVERRIDE_FILE}.qwen27b-backup-$(date +%Y%m%d-%H%M%S)"
    cp "$OVERRIDE_FILE" "$BACKUP"
    log "Backup: $BACKUP"
else
    mkdir -p "$OVERRIDE_DIR"
fi

# ─── STAP 3: Modellen verplaatsen ───
echo ""
echo "STAP 3: Modellen installeren"
if [[ "$MODEL_FILE" != "$TARGET_MODEL" ]] && [[ ! -f "$TARGET_MODEL" ]]; then
    mv "$MODEL_FILE" "$TARGET_MODEL"
    log "Hoofdmodel verplaatst"
else
    log "Hoofdmodel al op zijn plek"
fi
if [[ -n "$MMPROJ_FILE" ]] && [[ "$MMPROJ_FILE" != "$TARGET_MMPROJ" ]] && [[ ! -f "$TARGET_MMPROJ" ]]; then
    mv "$MMPROJ_FILE" "$TARGET_MMPROJ"
    log "mmproj verplaatst"
elif [[ -n "$MMPROJ_FILE" ]]; then
    log "mmproj al op zijn plek"
fi

# ─── STAP 4: Override ───
echo ""
echo "STAP 4: Systemd override aanmaken"
VISION_ENABLED=false
if [[ -n "$MMPROJ_FILE" ]] && [[ -f "$TARGET_MMPROJ" ]]; then
    cat > "$OVERRIDE_FILE" << EOF
[Service]
ExecStart=
ExecStart=/opt/llama-server/llama-server --model ${TARGET_MODEL} --mmproj ${TARGET_MMPROJ} --host 127.0.0.1 --port 8081 --ctx-size 16384 --threads 16 --flash-attn on --chat-template chatml --parallel 1
EOF
    VISION_ENABLED=true
    log "Override MET vision support"
else
    cat > "$OVERRIDE_FILE" << EOF
[Service]
ExecStart=
ExecStart=/opt/llama-server/llama-server --model ${TARGET_MODEL} --host 127.0.0.1 --port 8081 --ctx-size 16384 --threads 16 --flash-attn on --chat-template chatml --parallel 1
EOF
    log "Override ZONDER vision"
fi

# ─── STAP 5: Herstart ───
echo ""
echo "STAP 5: llama-server herstarten"
systemctl daemon-reload
systemctl restart llama-server
log "Herstart commando verzonden"

echo ""
echo "Wachten tot model geladen is (MoE + vision encoder kan 2-4 min duren)..."
LOADED=false
for i in $(seq 1 300); do
    if curl -s "http://127.0.0.1:8081/health" 2>/dev/null | grep -q "ok"; then
        LOADED=true
        log "Model is gereed!"
        break
    fi
    [[ $((i % 20)) -eq 0 ]] && echo "    Nog aan het laden... (${i}s)"
    sleep 1
done

if [[ "$LOADED" != "true" ]]; then
    warn "Server reageert niet na 5 minuten. Check logs:"
    echo "    sudo tail -50 /var/log/llama-server.log"
    echo ""
    echo "Terugschakelen:"
    echo "    LATEST=\$(ls -t ${OVERRIDE_FILE}.qwen27b-backup-* | head -1)"
    echo "    sudo cp \"\$LATEST\" $OVERRIDE_FILE"
    echo "    sudo systemctl daemon-reload && sudo systemctl restart llama-server"
    exit 1
fi

# ─── STAP 6: Test ───
echo ""
echo "STAP 6: API test"
RESPONSE=$(curl -s -X POST http://127.0.0.1:8081/v1/chat/completions \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"system","content":"Je bent Jeffrey, een SOC assistent."},{"role":"user","content":"Hoe heet je?"}],"max_tokens":50}' 2>/dev/null)

if echo "$RESPONSE" | grep -qi "jeffrey"; then
    log "Model reageert correct als Jeffrey"
elif [[ -n "$RESPONSE" ]]; then
    log "API werkt, response ontvangen"
fi

# ─── KLAAR ───
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ Migratie voltooid!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Model:    Qwen 3.5 35B-A3B (MoE, 3B active)"
[[ "$VISION_ENABLED" == "true" ]] && echo "  Vision:   ACTIEF — screenshots/afbeeldingen mogelijk"
echo "  Snelheid: Verwacht ~8-12 tok/s (was ~3 tok/s)"
echo ""
echo "  Test:"
echo "    1. Simpele vraag: 'Hoe heet je?' (moet snel zijn)"
echo "    2. SIEM query (verwacht ~15-25 sec)"
[[ "$VISION_ENABLED" == "true" ]] && echo "    3. Upload screenshot via 📎 en vraag analyse"
echo ""
echo "  Rollback naar Qwen 3.5 27B:"
echo "    LATEST=\$(ls -t ${OVERRIDE_FILE}.qwen27b-backup-* | head -1)"
echo "    sudo cp \"\$LATEST\" $OVERRIDE_FILE"
echo "    sudo systemctl daemon-reload && sudo systemctl restart llama-server"
echo ""
echo "  Oude model opruimen na succesvolle test:"
echo "    sudo rm /data/models/Qwen3.5-27B-Q8_0.gguf"
echo ""

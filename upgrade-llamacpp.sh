#!/bin/bash
# ============================================================================
# Jeffrey Toolkit — llama.cpp Upgrade voor Gemma 4 support
#
# Wat dit script doet:
#   1. Stopt llama-server tijdelijk
#   2. Backup huidige binary
#   3. Compileert nieuwe llama.cpp uit ZIP in /data/toolkit/
#   4. Vervangt binary
#   5. Herstart llama-server (op huidige model — Qwen of Gemma)
#
# Wat dit script NIET doet:
#   - Wijzigt model, systemd override, Apache, of HTML
#   - Verandert iets aan de werking als llama-server al draait
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLAMA_ZIP="${SCRIPT_DIR}/llama.cpp-master.zip"
BINARY_DIR="/opt/llama-server"
BUILD_DIR="/tmp/llama-upgrade-$$"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════"
echo "  llama.cpp Upgrade — voor Gemma 4 support"
echo "═══════════════════════════════════════════════"
echo ""

[[ $EUID -eq 0 ]] || fail "Dit script moet als root uitgevoerd worden (sudo)"

# ─── STAP 1: Pre-flight ───
echo "STAP 1: Pre-flight checks"

[[ -f "$LLAMA_ZIP" ]] || fail "ZIP niet gevonden: $LLAMA_ZIP"
ZIP_SIZE=$(ls -lh "$LLAMA_ZIP" | awk '{print $5}')
log "ZIP gevonden: $ZIP_SIZE"

for cmd in unzip cmake gcc g++ make; do
    command -v $cmd &>/dev/null || fail "Build tool ontbreekt: $cmd"
done
log "Build tools beschikbaar"

# ─── STAP 2: Backup huidige binary ───
echo ""
echo "STAP 2: Backup huidige binary"

if [[ -f "${BINARY_DIR}/llama-server" ]]; then
    BACKUP="${BINARY_DIR}/llama-server.backup-$(date +%Y%m%d-%H%M%S)"
    cp "${BINARY_DIR}/llama-server" "$BACKUP"
    log "Backup: $BACKUP"
    echo "    Terugschakelen indien nodig:"
    echo "    sudo systemctl stop llama-server"
    echo "    sudo cp $BACKUP ${BINARY_DIR}/llama-server"
    echo "    sudo systemctl start llama-server"
else
    warn "Geen bestaande binary gevonden"
fi

# ─── STAP 3: Stop llama-server ───
echo ""
echo "STAP 3: llama-server stoppen"

if systemctl is-active --quiet llama-server; then
    systemctl stop llama-server
    log "llama-server gestopt"
else
    warn "llama-server draait niet"
fi

# ─── STAP 4: Compileren ───
echo ""
echo "STAP 4: llama.cpp compileren (10-15 minuten)"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

unzip -q "$LLAMA_ZIP"
EXTRACTED=$(find . -maxdepth 1 -type d -name "llama*" | head -1)
[[ -n "$EXTRACTED" ]] || fail "Kon uitgepakte directory niet vinden"
cd "$EXTRACTED"

# Verifieer Gemma 4 support
if grep -rq "gemma4\|GEMMA4" src/ 2>/dev/null; then
    log "Gemma 4 support gevonden in source"
else
    warn "Gemma 4 referentie niet gevonden — compilatie gaat door, maar mogelijk te oude versie"
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

echo "Compileren met $(nproc) threads (dit duurt even)..."
cmake --build build --config Release -j "$(nproc)" --target llama-server llama-cli 2>&1 | tail -5

[[ -f build/bin/llama-server ]] || fail "Compilatie mislukt — llama-server binary niet aangemaakt"
log "Nieuwe binary gecompileerd"

# ─── STAP 5: Installeren ───
echo ""
echo "STAP 5: Nieuwe binary installeren"

cp build/bin/llama-server "${BINARY_DIR}/llama-server"
cp build/bin/llama-cli "${BINARY_DIR}/llama-cli" 2>/dev/null || true
chmod +x "${BINARY_DIR}/llama-server"
log "Binary geïnstalleerd in ${BINARY_DIR}/"

# Check dependencies
MISSING=$(ldd "${BINARY_DIR}/llama-server" 2>&1 | grep "not found" || true)
if [[ -n "$MISSING" ]]; then
    warn "Library dependencies ontbreken:"
    echo "$MISSING"
else
    log "Library dependencies OK"
fi

# Cleanup build directory
cd /
rm -rf "$BUILD_DIR"
log "Build directory opgeruimd"

# ─── STAP 6: llama-server herstarten ───
echo ""
echo "STAP 6: llama-server herstarten"

systemctl start llama-server
log "Start commando verzonden"

echo "Wachten tot model geladen is..."
LOADED=false
for i in $(seq 1 240); do
    if curl -s "http://127.0.0.1:8081/health" 2>/dev/null | grep -q "ok"; then
        LOADED=true
        log "llama-server is gereed!"
        break
    fi
    if [[ $((i % 15)) -eq 0 ]]; then
        echo "    Nog aan het laden... (${i} seconden)"
    fi
    sleep 1
done

if [[ "$LOADED" != "true" ]]; then
    warn "Server reageert niet na 4 minuten"
    echo "Check logs:"
    echo "    sudo tail -50 /var/log/llama-server.log"
    exit 1
fi

# ─── KLAAR ───
echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ llama.cpp upgrade voltooid!"
echo "═══════════════════════════════════════════════"
echo ""
echo "  De server draait nu op de nieuwe binary met het huidige model."
echo ""
echo "  Volgende stap — Gemma 4 migratie opnieuw uitvoeren:"
echo "    sudo /data/toolkit/migrate-to-gemma4.sh"
echo ""
echo "  De oude binary backup staat in:"
echo "    ${BINARY_DIR}/llama-server.backup-*"
echo ""

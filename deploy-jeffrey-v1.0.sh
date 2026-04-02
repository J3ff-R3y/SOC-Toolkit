#!/bin/bash
# =================================================================
# Jeffrey Toolkit v1.0 Enterprise Deployment
# Target OS: RHEL 10 | Model: Qwen 3.5 27B Q8_0
# =================================================================

BASE_DIR="/data/toolkit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="/data/models"
BINARY_DIR="/opt/llama-server"
HTPASSWD_FILE="/etc/httpd/.htpasswd"
APACHE_CONF="/etc/httpd/conf.d/jeffrey.conf"
MODEL_FILE="Qwen3.5-27B-Q8_0.gguf"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🚀 Start Jeffrey Toolkit v1.0 enterprise installatie...${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Dit script moet als root worden uitgevoerd.${NC}"
   exit 1
fi

if [ -f "$HTPASSWD_FILE" ]; then
    cp "$HTPASSWD_FILE" /tmp/.jeffrey_htpasswd_bak
fi

echo "🧹 Oude omgeving opruimen..."
systemctl stop llama-server 2>/dev/null
systemctl disable llama-server 2>/dev/null
rm -rf "$BINARY_DIR"
find "$BASE_DIR" -maxdepth 1 -type f ! -name 'deploy-jeffrey-v1.0.sh' ! -name 'llama.cpp-master.zip' ! -name "$MODEL_FILE" ! -name 'jeffrey-v1.0-qwen35.html' -delete
mkdir -p "$MODEL_DIR" "$BINARY_DIR"

echo "🏗️ Compileren van llama.cpp uit source..."
dnf install -y cmake gcc-c++ make unzip
if [ -f "$BASE_DIR/llama.cpp-master.zip" ]; then
    unzip -q "$BASE_DIR/llama.cpp-master.zip" -d /tmp/llama_build
    cd /tmp/llama_build/llama.cpp-master
    mkdir build && cd build
    cmake .. -DGGML_NATIVE=ON -DGGML_AVX2=ON -DCMAKE_BUILD_TYPE=Release
    cmake --build . --config Release -j $(nproc)
    cp bin/llama-server "$BINARY_DIR/llama-server"
    rm -rf /tmp/llama_build
else
    echo -e "${RED}❌ FOUT: llama.cpp-master.zip niet gevonden in $BASE_DIR${NC}"
    exit 1
fi

if [ -f "$BASE_DIR/$MODEL_FILE" ]; then
    mv "$BASE_DIR/$MODEL_FILE" "$MODEL_DIR/$MODEL_FILE"
fi

echo "🌐 Apache reverse proxy configureren..."
cat <<EOF > "$APACHE_CONF"
Listen 8080

ProxyTimeout 900
Timeout 900
RequestReadTimeout header=60 body=900

<VirtualHost *:8080>
    DocumentRoot "$BASE_DIR"

    <Directory "$BASE_DIR">
        Options -Indexes +FollowSymLinks
        AllowOverride None
        AuthType Basic
        AuthName "Jeffrey Toolkit Login"
        AuthUserFile "$HTPASSWD_FILE"
        Require valid-user
    </Directory>

    <Location /api/chat>
        AuthType Basic
        AuthName "Jeffrey Toolkit Login"
        AuthUserFile "$HTPASSWD_FILE"
        Require valid-user
    </Location>

    ProxyPreserveHost On
    ProxyPass /api/chat http://127.0.0.1:8081/v1/chat/completions flushpackets=on
    ProxyPassReverse /api/chat http://127.0.0.1:8081/v1/chat/completions

    ProxyPass /health http://127.0.0.1:8081/health
    ProxyPassReverse /health http://127.0.0.1:8081/health

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"

    ErrorLog /var/log/httpd/jeffrey_error.log
    CustomLog /var/log/httpd/jeffrey_access.log combined
</VirtualHost>
EOF

cat <<EOF > /etc/systemd/system/llama-server.service
[Unit]
Description=Jeffrey AI Backend
After=network.target

[Service]
Type=simple
User=root
ExecStart=$BINARY_DIR/llama-server --model $MODEL_DIR/$MODEL_FILE --host 127.0.0.1 --port 8081 --ctx-size 16384 --threads 16 --flash-attn on --chat-template chatml
StandardOutput=append:/var/log/llama-server.log
StandardError=append:/var/log/llama-server.log
Restart=always
RestartSec=5
TimeoutStartSec=600
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

if [ -f /tmp/.jeffrey_htpasswd_bak ]; then
    mv /tmp/.jeffrey_htpasswd_bak "$HTPASSWD_FILE"
    chown apache:apache "$HTPASSWD_FILE"
    chmod 600 "$HTPASSWD_FILE"
fi

chown -R apache:apache "$BASE_DIR"

# Deploy HTML
if [ -f "$SCRIPT_DIR/jeffrey-v1.0-qwen35.html" ]; then
    cp "$SCRIPT_DIR/jeffrey-v1.0-qwen35.html" "$BASE_DIR/index.html"
    chown apache:apache "$BASE_DIR/index.html"
    echo "✅ HTML gedeployed"
else
    echo -e "${RED}⚠ HTML niet gevonden — kopieer handmatig naar $BASE_DIR/index.html${NC}"
fi

# SELinux
if command -v semanage &>/dev/null; then
    semanage fcontext -a -t httpd_sys_content_t "/data/toolkit(/.*)?" 2>/dev/null || true
    restorecon -R /data/toolkit
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    echo "✅ SELinux geconfigureerd"
fi

# Firewall
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=8080/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "✅ Firewall poort 8080 geopend"
fi

systemctl daemon-reload
systemctl enable --now llama-server
systemctl restart httpd

echo ""
echo -e "${GREEN}🏁 Jeffrey is succesvol gedeployd!${NC}"
echo ""
echo "  URL: http://$(hostname -I | awk '{print $1}'):8080"
echo "  Logs: journalctl -u llama-server -f"
echo "  Users: htpasswd /etc/httpd/.htpasswd <username>"
echo ""
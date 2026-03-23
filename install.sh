#!/usr/bin/env bash
# install.sh — Deploy GoWAF on Fedora. Run as root or with sudo.
# Usage: sudo ./systemd/install.sh
set -euo pipefail

BINARY_SRC="./waf"
BINARY_DST="/usr/local/bin/waf"
CONFIG_DIR="/etc/gowaf"
SERVICE_FILE="/etc/systemd/system/gowaf.service"
WAF_USER="gowaf"

# 1. Build if needed
if [[ ! -f "$BINARY_SRC" ]]; then
  echo "==> Binary not found — building…"
  ./build.sh
fi

# 2. Create service user
if ! id "$WAF_USER" &>/dev/null; then
  echo "==> Creating service user '$WAF_USER'…"
  useradd -r -s /sbin/nologin -d /var/empty -M "$WAF_USER"
fi

# 3. Install binary
echo "==> Installing binary to $BINARY_DST…"
install -o root -g root -m 755 "$BINARY_SRC" "$BINARY_DST"

# 4. Config directory
mkdir -p "$CONFIG_DIR"
for f in config.yaml rules/waf_rules.yaml rules/bad_bots.txt; do
  dst="$CONFIG_DIR/$(basename $f)"
  if [[ ! -f "$dst" ]]; then
    cp "$f" "$dst" && echo "  installed $dst"
  else
    echo "  kept existing $dst"
  fi
done

# 5. Generate token secret if not already set
ENV_FILE="$CONFIG_DIR/environment"
if [[ ! -f "$ENV_FILE" ]] || grep -q "CHANGE_ME" "$ENV_FILE"; then
  echo "==> Generating token secret…"
  SECRET=$(openssl rand -hex 32)
  printf "GOWAF_TOKEN_SECRET=%s\n" "$SECRET" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "  wrote $ENV_FILE"
fi

# 6. Ownership
chown -R "$WAF_USER:$WAF_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*.yaml "$CONFIG_DIR"/*.txt 2>/dev/null || true
chmod 600 "$ENV_FILE"

# 7. Systemd
cp systemd/gowaf.service "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable gowaf

# 8. Start / restart
if systemctl is-active --quiet gowaf; then
  systemctl restart gowaf
else
  systemctl start gowaf
fi
sleep 1
systemctl status gowaf --no-pager -l

echo ""
echo "==> GoWAF deployed."
echo "    Logs:    journalctl -u gowaf -f"
echo "    Config:  $CONFIG_DIR/config.yaml"
echo "    Metrics: http://127.0.0.1:9101/metrics"
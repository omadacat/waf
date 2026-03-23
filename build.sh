#!/usr/bin/env bash
# build.sh — Build GoWAF static binary
# Usage:
#   ./build.sh              — compile only
#   ./build.sh --install    — compile + install to /usr/local/bin + restart service
set -euo pipefail

BINARY="waf"
INSTALL_PATH="/usr/local/bin/waf"
MODULE="git.omada.cafe/atf/waf"
MAIN="./cmd/waf"

echo "==> Tidying modules…"
go mod tidy

echo "==> Building (CGO_ENABLED=0, static)…"
CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go build \
    -ldflags="-s -w -X ${MODULE}/internal/version.Version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -trimpath \
    -o "${BINARY}" \
    "${MAIN}"

echo "==> Binary: $(du -sh ${BINARY} | cut -f1)"
echo "==> Build complete: ./${BINARY}"

if [[ "${1:-}" == "--install" ]]; then
  echo "==> Installing to ${INSTALL_PATH}…"
  sudo install -o root -g root -m 755 "${BINARY}" "${INSTALL_PATH}"
  if systemctl is-active --quiet gowaf 2>/dev/null; then
    echo "==> Restarting gowaf service…"
    sudo systemctl restart gowaf
    sleep 1
    sudo systemctl status gowaf --no-pager -l
  else
    echo "==> Service not running — start with: sudo systemctl start gowaf"
  fi
fi
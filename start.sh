#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .env ]]; then
    echo "[ERROR] .env file not found. Run ./prepare.sh to setup the environment variables."
    exit 1
fi

docker compose build --no-cache
docker compose up -d

echo "[+] Containers started."
echo "[+] FTP available at:    ftp://127.0.0.1:$(grep FTP_PORT .env | cut -d= -f2)"
echo "[+] Portal available at: http://127.0.0.1:$(grep PORTAL_PORT .env | cut -d= -f2)"

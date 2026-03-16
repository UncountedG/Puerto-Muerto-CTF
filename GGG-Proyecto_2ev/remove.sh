#!/usr/bin/env bash
set -euo pipefail

docker compose down --rmi local --volumes --remove-orphans

echo "[+] Containers, images and volumes removed."
echo "[+] Run start.sh to rebuild, or prepare.sh first to generate new flags."

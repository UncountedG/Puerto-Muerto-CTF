#!/usr/bin/env bash

# Root-level preparation script for the Puerto Muerto CTF machine.
# Responsibilities:
#   - Accept optional parameters for machine name, internal port, and external port.
#   - Generate randomized flag values for the three challenge flags.
#   - Derive a master flag that is revealed only when all three flags are submitted correctly.
#   - Write all configuration values into a .env file consumed by docker-compose.
#   - Set executable permissions on all shell scripts in the project.

set -euo pipefail

MACHINE_NAME="${1:-puerto-muerto}"
FTP_PORT="${2:-2121}"
HTTP_PORT="${3:-8090}"
SSH_PORT="${4:-2222}"
PORTAL_PORT="${5:-3000}"


FLAG1="G3CUBO{$(openssl rand -hex 16)}"
FLAG2="G3CUBO{$(openssl rand -hex 16)}"
FLAG3="G3CUBO{$(openssl rand -hex 16)}"
MASTER_FLAG="G3CUBO{puerto_muerto_$(openssl rand -hex 16)}"

FLAG1_HASH=$(echo -n "$FLAG1" | sha256sum | awk '{print $1}')
FLAG2_HASH=$(echo -n "$FLAG2" | sha256sum | awk '{print $1}')
FLAG3_HASH=$(echo -n "$FLAG3" | sha256sum | awk '{print $1}')

echo "${MACHINE_NAME}-system" > dockername.txt

cat > .env <<EOF
MACHINE_NAME=${MACHINE_NAME}
FTP_PORT=${FTP_PORT}
HTTP_PORT=${HTTP_PORT}
SSH_PORT=${SSH_PORT}
PORTAL_PORT=${PORTAL_PORT}
FLAG1=${FLAG1}
FLAG2=${FLAG2}
FLAG3=${FLAG3}
MASTER_FLAG=${MASTER_FLAG}
FLAG1_HASH=${FLAG1_HASH}
FLAG2_HASH=${FLAG2_HASH}
FLAG3_HASH=${FLAG3_HASH}
EOF



echo "$FLAG1" > flag/flag1.txt
echo "$FLAG2" > flag/flag2.txt
echo "$FLAG3" > flag/flag3.txt 

chmod +x prepare.sh
chmod +x start.sh
chmod +x stop.sh
chmod +x remove.sh
chmod +x clearenv.sh
chmod +x machine/src/prepare.sh
chmod +x machine/src/execute.sh
chmod +x portal/src/prepare.sh
chmod +x portal/src/execute.sh
chmod +x solution/solve.sh

echo "[+] Environment prepared for machine: ${MACHINE_NAME}"
echo "[+] FTP port:    ${FTP_PORT}"
echo "[+] HTTP port:   ${HTTP_PORT}"
echo "[+] SSH port:    ${SSH_PORT}"
echo "[+] Portal port: ${PORTAL_PORT}"
echo "[+] Flag 1: ${FLAG1}"
echo "[+] Flag 2: ${FLAG2}"
echo "[+] Flag 3: ${FLAG3}"
echo "[+] Master Flag: ${MASTER_FLAG}"
echo "[+] .env and flag files written successfully."

#!/usr/bin/env bash

# Stops the Puerto Muerto CTF machine and portal containers without removing them.
# Container state and submitted flags in the SQLite database are preserved.

set -euo pipefail

docker compose stop

echo "[+] Containers stopped."

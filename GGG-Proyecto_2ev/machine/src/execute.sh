#!/usr/bin/env bash


# Container entrypoint script for the Puerto Muerto challenge machine.
# This script executes every time the container starts via the Dockerfile ENTRYPOINT directive.
# Responsibilities:
#   - Inject the real flag values from environment variables into their target locations.
#   - Generate the SSH key pair for porter and derive the key passphrase from the
#     FTP README.txt modification timestamp, establishing the hash-decoding challenge.
#   - Rewrite service configuration files with the runtime port values from environment variables.
#   - Apply iptables baseline rules to block SSH and HTTP ports by default.
#   - Start all required services: vsftpd, knockd, Flask, OpenSSH, cron.
#   - Enter an infinite loop to prevent the container from exiting.


set -euo pipefail


# ---------------------------------------------------------------------------
# Environment variable validation
# ---------------------------------------------------------------------------


# All port variables must be present. If any are missing the container exits
# immediately with a descriptive error rather than starting in a broken state.


REQUIRED_VARS=(
    "FLAG1"
    "FLAG2"
    "FLAG3"
    "FTP_PORT"
    "SSH_PORT"
    "HTTP_PORT"
)


for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "[ERROR] Required environment variable '${var}' is not set."
        exit 1
    fi
done


# ---------------------------------------------------------------------------
# SIGEPORT database initialization
# ---------------------------------------------------------------------------


# The database is created fresh on every container start so that FLAG1 is
# always current and any residual state from a previous run is discarded.
# Schema:
#   inspectors       — credentials for the login page (static records, never displayed to player).
#   manifests        — decoy vessel records displayed in the internal panel after login.
#   classified_cargo — hidden table never referenced by the UI; holds FLAG1.
#                      Only reachable via UNION-based injection on the vessel search parameter.


rm -f /opt/sigeport/db/sigeport.db


sqlite3 /opt/sigeport/db/sigeport.db <<SQL
CREATE TABLE inspectors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    inspector_id TEXT NOT NULL UNIQUE,
    access_code  TEXT NOT NULL,
    name         TEXT NOT NULL
);


CREATE TABLE manifests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vessel_name  TEXT NOT NULL,
    origin       TEXT NOT NULL,
    destination  TEXT NOT NULL,
    status       TEXT NOT NULL
);


CREATE TABLE classified_cargo (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_ref TEXT NOT NULL,
    cargo_type   TEXT NOT NULL,
    clearance    TEXT NOT NULL
);


INSERT INTO inspectors (inspector_id, access_code, name) VALUES
    ('INS-001', 'atlas2021',      'Carlos Mendoza'),
    ('INS-002', 'marea#99',       'Lucia Ferrer'),
    ('INS-003', 'darsena77',      'Chema Alonso'),
    ('INS-004', 'brisa_2020',     'Elena Marquez'),
    ('INS-005', 'porton_2021',    'David Torres'),
    ('INS-006', 'muelle_2021',    'Ana Lopez'),
    ('PM-007',  'Mu3lle#Norte19', 'Sofia Ramirez');


INSERT INTO manifests (vessel_name, origin, destination, status) VALUES
    ('Estrella del Norte', 'Rotterdam',    'Puerto Muerto', 'Descargado'),
    ('Mar Adentro',        'Marsella',     'Puerto Muerto', 'En tránsito'),
    ('Viento Sur',         'Casablanca',   'Puerto Muerto', 'Retenido'),
    ('Rio Oscuro',         'Buenos Aires', 'Puerto Muerto', 'Descargado'),
    ('Santa Catalina',     'Dakar',        'Puerto Muerto', 'Pendiente');


INSERT INTO classified_cargo (manifest_ref, cargo_type, clearance) VALUES
    ('PM-2021-0047', 'Equipamiento técnico clasificado', '${FLAG1}');
SQL


chown www-data:www-data /opt/sigeport/db/sigeport.db
chmod 640 /opt/sigeport/db/sigeport.db


# Derive the Flag 2 encryption key from the exact byte size of README.txt on
# the FTP server. The SIZE command in the FTP protocol exposes this value
# natively, which is the mechanism the student must discover to decrypt the flag.
# README.txt has a deterministic size (1005 bytes) since it is a static build-time
# heredoc. The derived key is therefore stable across container restarts.
README_SIZE=$(stat -c%s /srv/ftp/README.txt)
FLAG2_KEY=$(echo -n "${README_SIZE}" | sha256sum | awk '{print $1}')

# Encrypt Flag 2 in AES-256-CBC mode with PBKDF2 key stretching.
# The flag value comes from the FLAG2 environment variable injected by docker-compose.
# The plaintext is piped directly into openssl — it is never written to disk.
printf '%s' "${FLAG2}" | openssl enc -aes-256-cbc \
    -pbkdf2 \
    -out /home/porter/flag2.enc \
    -pass pass:"${FLAG2_KEY}"

chown porter:porter /home/porter/flag2.enc
chmod 640 /home/porter/flag2.enc


# FLAG3 is written to root's home directory, readable only by root.
echo "${FLAG3}" > /root/flag3.txt
chmod 600 /root/flag3.txt


# ---------------------------------------------------------------------------
# SSH key generation and passphrase derivation
# ---------------------------------------------------------------------------


# The passphrase for porter's SSH private key is derived from the SHA256 hash
# of the MDTM timestamp of README.txt on the FTP server. The MDTM command
# returns a timestamp in the format YYYYMMDDHHmmss. The student must:
#   1. Connect to FTP anonymously.
#   2. Issue: quote MDTM README.txt
#   3. Hash the returned timestamp value with SHA256.
#   4. Use that hash as the passphrase to decrypt maintenance.key.


FTP_README_MTIME=$(stat -c '%Y' /srv/ftp/README.txt)
FTP_MDTM_TIMESTAMP=$(date -d "@${FTP_README_MTIME}" +"%Y%m%d%H%M%S")
PASSPHRASE=$(echo -n "${FTP_MDTM_TIMESTAMP}" | sha256sum | awk '{print $1}')


mkdir -p /home/porter/.ssh
rm -f /home/porter/.ssh/maintenance.key /home/porter/.ssh/maintenance.key.pub


# Generate a 4096-bit RSA key in PEM format using the timestamp-derived passphrase.
# The -m PEM flag ensures broad compatibility across OpenSSH client versions.
ssh-keygen -t rsa -b 4096 \
    -m PEM \
    -N "${PASSPHRASE}" \
    -f /home/porter/.ssh/maintenance.key \
    -C "porter@puerto-muerto" \
    -q


# Remove any stale authorized_keys before writing the freshly generated public key.
# A leftover file from a previous container run would allow the old key to authenticate,
# which would mismatch the newly generated maintenance.key on the FTP server.
rm -f /home/porter/.ssh/authorized_keys
cp /home/porter/.ssh/maintenance.key.pub /home/porter/.ssh/authorized_keys


# Publish the encrypted private key to FTP so the student can download it.
cp /home/porter/.ssh/maintenance.key /srv/ftp/private/maintenance.key


chown -R porter:porter /home/porter/.ssh
chmod 700 /home/porter/.ssh
chmod 600 /home/porter/.ssh/maintenance.key
chmod 644 /home/porter/.ssh/maintenance.key.pub
chmod 644 /home/porter/.ssh/authorized_keys
chmod 644 /srv/ftp/private/maintenance.key


# ---------------------------------------------------------------------------
# Runtime service configuration rewrite
# ---------------------------------------------------------------------------


# With network_mode: host the container shares the host network stack directly.
# Every service must bind to the exact port specified by the instructor via the
# environment variables — there is no Docker NAT layer to remap ports.
# These sed calls overwrite the placeholder values written by prepare.sh
# with the actual runtime values before the services are started.


# vsftpd: overwrite the listen_port directive with the external FTP port.
sed -i "s/^listen_port=.*/listen_port=${FTP_PORT}/" /etc/vsftpd.conf

# vsftpd: overwrite the PASV port range comment to document the live config.
# The pasv_min_port and pasv_max_port values are fixed and do not require
# rewriting — they are not affected by the external port assignment.


# sshd: overwrite the Port directive with the external SSH port.
sed -i "s/^Port .*/Port ${SSH_PORT}/" /etc/ssh/sshd_config


# knockd: overwrite both dport references so the iptables commands it fires
# open and close the correct runtime ports, not the build-time placeholders.
sed -i "s/--dport 2222/--dport ${SSH_PORT}/g" /etc/knockd.conf
sed -i "s/--dport 8080/--dport ${HTTP_PORT}/g" /etc/knockd.conf


# ---------------------------------------------------------------------------
# iptables baseline rules
# ---------------------------------------------------------------------------


# Removal order is critical: INPUT references must be deleted before the
# KNOCK_ACCEPT chain itself can be flushed and removed. Reversing this order
# causes iptables -X to fail silently, leaving the chain intact.


# Step 1: Remove INPUT rules that reference KNOCK_ACCEPT first.
iptables -D INPUT -p tcp --dport "${SSH_PORT}" -j KNOCK_ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${HTTP_PORT}" -j KNOCK_ACCEPT 2>/dev/null || true


# Step 2: Remove DROP rules from previous runs.
iptables -D INPUT -p tcp --dport "${SSH_PORT}" -j DROP 2>/dev/null || true
iptables -D INPUT -p tcp --dport "${HTTP_PORT}" -j DROP 2>/dev/null || true


# Step 3: Now the chain has no references — flush and delete it safely.
iptables -F KNOCK_ACCEPT 2>/dev/null || true
iptables -X KNOCK_ACCEPT 2>/dev/null || true


# Step 4: Recreate the chain clean.
iptables -N KNOCK_ACCEPT 2>/dev/null || true


# Step 4b: Allow packets belonging to already-established or related connections.
# Without this rule, knockd's stop_command removes the ACCEPT rule and drops
# any active SSH session mid-flight when the cmd_timeout expires.
iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


# Step 5: Insert the jump rules and the fallback DROP rules.
iptables -I INPUT 2 -p tcp --dport "${SSH_PORT}" -j KNOCK_ACCEPT
iptables -I INPUT 2 -p tcp --dport "${HTTP_PORT}" -j KNOCK_ACCEPT


iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j DROP
iptables -A INPUT -p tcp --dport "${HTTP_PORT}" -j DROP


# ---------------------------------------------------------------------------
# Service startup
# ---------------------------------------------------------------------------


# vsftpd: anonymous FTP server exposing the initial breadcrumbs.
service vsftpd start
echo "[+] vsftpd started on port ${FTP_PORT}"


# knockd: port knock daemon listening for the sequence 1006 -> 2175 -> 7331.
# With network_mode: host the default route interface is the physical host
# interface, which is exactly where the knock packets arrive.
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
knockd -d -i "${IFACE}" -c /etc/knockd.conf
echo "[+] knockd started on interface ${IFACE}"


# Flask application: serves the SIGEPORT vulnerable portal.
# Runs as www-data to match the file ownership set during prepare.sh.
# DB_PATH and HTTP_PORT are passed explicitly so app.py remains decoupled
# from both the filesystem layout and the port assignment.
su -s /bin/bash www-data -c "DB_PATH=/opt/sigeport/db/sigeport.db HTTP_PORT=${HTTP_PORT} python3 /opt/sigeport/app.py" &
echo "[+] SIGEPORT Flask app started on port ${HTTP_PORT}"


# OpenSSH daemon: accepts connections on the runtime SSH port after successful knock.
/usr/sbin/sshd
echo "[+] sshd started on port ${SSH_PORT}"


# cron daemon: required for the root-level cron job that portadmin can hijack.
service cron start
echo "[+] cron started"


# ---------------------------------------------------------------------------
# Keepalive loop
# ---------------------------------------------------------------------------


# The container must not exit. This loop also emits a periodic heartbeat
# to stdout so that docker logs reflects that the container is alive.


echo "[+] Puerto Muerto machine is ready."
echo "[+] FTP available on port ${FTP_PORT}."
echo "[+] Ports ${SSH_PORT} and ${HTTP_PORT} are locked. Knock to unlock."


while true; do
    sleep 60
    echo "[heartbeat] $(date '+%Y-%m-%d %H:%M:%S') - services running"
done

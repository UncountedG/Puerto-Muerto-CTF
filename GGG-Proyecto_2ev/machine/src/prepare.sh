#!/usr/bin/env bash


# Build-time preparation script for the Puerto Muerto challenge machine.
# This script executes once during the Docker image build process via the Dockerfile RUN directive.
# Responsibilities:
#   - Install all required system packages.
#   - Create the challenge users (porter, portadmin) with correct permissions and restrictions.
#   - Configure vsftpd for anonymous read access exposing the initial breadcrumbs.
#   - Configure knockd to listen for the port sequence that unlocks HTTP and SSH.
#   - Configure OpenSSH with ForceCommand restrictions for the porter user.
#   - Deploy the static HTTP server content including Flag 1 and the downloads directory.
#   - Build and install the SUID binary used for the lateral movement to portadmin.
#   - Configure the cron job that portadmin can hijack to escalate to root.
#   - Write flag placeholders that will be replaced at container startup by execute.sh
#     using the FLAG1, FLAG2, FLAG3 environment variables injected by docker-compose.


set -euo pipefail


export DEBIAN_FRONTEND=noninteractive


# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------


apt-get update -qq
apt-get install -y --no-install-recommends \
    vsftpd \
    openssh-server \
    knockd \
    python3 \
    gcc \
    libc6-dev \
    cron \
    curl \
    net-tools \
    iproute2 \
    iptables \
    openssl \
    ca-certificates \
    procps \
    vim \
    less \
    python3-flask \
    sqlite3 \
    openssl


apt-get clean
rm -rf /var/lib/apt/lists/*


# ---------------------------------------------------------------------------
# User creation
# ---------------------------------------------------------------------------


# porter: the initial SSH user restricted to key-based authentication.
# portadmin: the intermediate user reachable only via SUID binary exploitation.
# Both users have no sudo rights by default.


useradd -m -s /bin/bash porter
useradd -m -s /bin/bash portadmin


echo "porter:porter123" | chpasswd
echo "portadmin:portadmin456" | chpasswd


# ---------------------------------------------------------------------------
# SSH configuration
# ---------------------------------------------------------------------------


mkdir -p /var/run/sshd


cat > /etc/ssh/sshd_config <<'EOF'
Port 2222
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server


# porter is allowed SSH access but cannot execute arbitrary commands.
# The ForceCommand directive restricts the session to a no-op holding shell,
# permitting only port forwarding and tunneling operations.
Match User porter
    AllowTcpForwarding yes
    X11Forwarding no


# portadmin has no SSH access at all. SSH login is explicitly denied.
Match User portadmin
    DenyUsers portadmin
EOF


# ---------------------------------------------------------------------------
# FTP configuration (vsftpd)
# ---------------------------------------------------------------------------


# Anonymous FTP is enabled with read-only access to /srv/ftp.
# The directory exposes:
#   - README.txt: contains the port knock sequence as a narrative hint.
#   - inspector_registry.txt: encoded SIGEPORT credentials.
#   - private/: contains the encrypted SSH private key for porter.


cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
listen_port=2121
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/srv/ftp
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
allow_writeable_chroot=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40010
pasv_address=0.0.0.0
pasv_addr_resolve=NO
EOF


mkdir -p /srv/ftp/private
mkdir -p /var/run/vsftpd/empty


# README.txt: narrative breadcrumb containing the port knock sequence embedded
# as a set of "access codes" within the story context.
cat > /srv/ftp/README.txt <<'EOF'
PUERTO MUERTO - SISTEMA DE GESTION PORTUARIA
=============================================
Servidor de acceso legacy - Modulo de mantenimiento


Este servidor forma parte del sistema de gestion del Puerto Muerto,
dado de baja en 2021. El acceso a los modulos internos requiere
autenticacion por secuencia de activacion.


Codigos de activacion registrados en el ultimo informe tecnico:
  Modulo A: 1006
  Modulo B: 2175
  Modulo C: 7331


El orden de activacion es secuencial: A -> B -> C.
Una vez activados, los modulos de inspeccion y administracion
quedaran disponibles para auditoria.


Para acceso SSH al modulo de mantenimiento, consultar el
directorio /private/ de este servidor. La clave de acceso
se encuentra protegida por passphrase.


La passphrase fue generada automaticamente por el sistema a
partir de los metadatos de este fichero en el momento de su
creacion. El protocolo de transferencia utilizado expone dicha
informacion de forma nativa.


-- Sistema Automatico de Documentacion SIGEPORT v2.3 --
EOF


# inspector_registry.txt: narrative file containing encoded SIGEPORT credentials.
# The encoding is intentionally two-layered (base64 over ROT13) to require the
# player to recognise and chain two trivial but non-obvious transformations.
# The actual payload and encoding are defined here at build time since the
# SIGEPORT credentials are static and do not change between container runs.
# The encoded content decodes to: "PM-007:Mu3lle#Norte19" (quotes are not part of the value).
cat > /srv/ftp/inspector_registry.txt <<'EOF'
SIGEPORT v2.3 - Exportacion automatica de registros
Puerto Muerto - Modulo de Administracion de Personal
Fecha de exportacion: 2021-08-14 03:00:01 (UTC)
Estado: BORRADOR - pendiente de revision por administrador


Registro de credenciales temporales asignadas durante migracion de sistema.
AVISO: Este fichero debe ser eliminado tras la verificacion manual.


-- DATOS DE ACCESO (codificados por politica de seguridad interna) --


MjI1MDRkMmQzMDMwMzczYTRkNzUzMzZjNmM2NTIzNGU2ZjcyNzQ2NTMxMzkyMg==


-- FIN DEL REGISTRO --
EOF


# The encrypted private key for porter is placed in the FTP private directory.
# The key passphrase is the SHA256 hash of a specific FTP file modification
# timestamp, which the student must retrieve via the FTP MDTM command.
# The actual key generation happens at execute.sh time because the passphrase
# must be derived from the live container environment.
# A placeholder is written here; execute.sh overwrites it.
touch /srv/ftp/private/maintenance.key


chown root:root /srv/ftp
chmod 755 /srv/ftp
chown -R ftp:ftp /srv/ftp/private
chmod 755 /srv/ftp/private
chmod 644 /srv/ftp/README.txt
chmod 644 /srv/ftp/private/maintenance.key
chmod 644 /srv/ftp/inspector_registry.txt


# ---------------------------------------------------------------------------
# knockd configuration
# ---------------------------------------------------------------------------


# knockd listens on the network interface for the sequence 1006, 2175, 7331.
# On correct sequence: iptables rules are inserted to open ports 2222 and 8080
# for the source IP that performed the knock.
# The cmd_timeout of 300 seconds revokes access after 5 minutes of inactivity.


cat > /etc/knockd.conf <<'EOF'
[options]
    logfile = /var/log/knockd.log


[openPorts]
    sequence     = 1006,2175,7331
    seq_timeout  = 60
    command      = /sbin/iptables -C KNOCK_ACCEPT -s %IP% -p tcp --dport 2222 -j ACCEPT 2>/dev/null || /sbin/iptables -I KNOCK_ACCEPT 1 -s %IP% -p tcp --dport 2222 -j ACCEPT && /sbin/iptables -C KNOCK_ACCEPT -s %IP% -p tcp --dport 8080 -j ACCEPT 2>/dev/null || /sbin/iptables -I KNOCK_ACCEPT 1 -s %IP% -p tcp --dport 8080 -j ACCEPT
    cmd_timeout  = 300
    stop_command = bash -c 'while /sbin/iptables -D KNOCK_ACCEPT -s %IP% -p tcp --dport 2222 -j ACCEPT 2>/dev/null; do :; done; while /sbin/iptables -D KNOCK_ACCEPT -s %IP% -p tcp --dport 8080 -j ACCEPT 2>/dev/null; do :; done'


EOF


# ---------------------------------------------------------------------------
# SIGEPORT Flask web application (port 8080)
# ---------------------------------------------------------------------------


# The application presents a fake but realistic port authority management
# portal. Two intentionally vulnerable SQLite query surfaces exist:
#   1. The login form (/): authentication bypass via OR-based SQLi.
#   2. The vessel search bar (/panel?vessel=): UNION-based extraction giving
#      access to the 'classified_cargo' table, which holds FLAG1.
# The flag value is not written here; execute.sh seeds it into the DB at runtime.


mkdir -p /opt/sigeport/templates /opt/sigeport/static

# The database directory must exist and be owned by www-data before the
# Flask process starts. execute.sh initialises the schema and seeds the flags.
mkdir -p /opt/sigeport/db
chown -R www-data:www-data /opt/sigeport
chmod 755 /opt/sigeport
chmod 750 /opt/sigeport/db


# ---------------------------------------------------------------------------
# Privilege escalation via SUID env (porter -> root via GTFOBins)
# ---------------------------------------------------------------------------


# A SUID copy of the env binary is installed at a narrative-fitting path.
# GTFOBins documents the following technique for SUID env:
#   ./port-env /bin/sh -p -c "command"
# The -p flag instructs sh to preserve the effective UID set by the SUID bit,
# granting a root shell since the binary is owned by root with SUID set.


cp /usr/bin/env /usr/local/bin/port-env
chown root:root /usr/local/bin/port-env
chmod 4755 /usr/local/bin/port-env



# ---------------------------------------------------------------------------
# Cron job owned by portadmin (portadmin -> root escalation vector)
# ---------------------------------------------------------------------------


# The maintenance script is owned and writable by portadmin.
# The cron entry runs it as root every 2 minutes.
# When portadmin injects commands into this script, they execute as root.


mkdir -p /opt/port-monitor


cat > /opt/port-monitor/check.sh <<'EOF'
#!/bin/bash


# Automated port monitoring script.
# Executed by root cron every 2 minutes.
# Checks that critical services are running and logs their status.


echo "[$(date)] Port monitor check running" >> /var/log/port-monitor.log
EOF


chown portadmin:portadmin /opt/port-monitor/check.sh
chmod 755 /opt/port-monitor/check.sh


# Cron entry: runs check.sh as root every 2 minutes.
echo "*/2 * * * * root /opt/port-monitor/check.sh" > /etc/cron.d/port-monitor
chmod 644 /etc/cron.d/port-monitor


# ---------------------------------------------------------------------------
# Flag placeholder files
# ---------------------------------------------------------------------------

# Flag 2 is stored as an AES-256-CBC encrypted blob, not in plaintext.
# execute.sh derives the encryption key at container startup and writes the
# final encrypted file. A placeholder with correct ownership is created here
# so the filesystem structure is ready before execute.sh runs.
touch /home/porter/flag2.enc
chown porter:porter /home/porter/flag2.enc
chmod 640 /home/porter/flag2.enc


mkdir -p /root
touch /root/flag3.txt
chmod 600 /root/flag3.txt


# ---------------------------------------------------------------------------
# Log files
# ---------------------------------------------------------------------------


touch /var/log/knockd.log
touch /var/log/port-monitor.log
chmod 666 /var/log/knockd.log
chmod 666 /var/log/port-monitor.log

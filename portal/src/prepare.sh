#!/usr/bin/env bash

# Build-time preparation script for the Puerto Muerto CTF portal container.
# This script executes once during the Docker image build process via the Dockerfile RUN directive.
# Responsibilities:
#   - Install required Python packages for the Flask portal application.
#   - Initialize the SQLite database schema used to persist flag submission state.
#   - Set correct ownership and permissions on the application directory.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Python dependency installation
# ---------------------------------------------------------------------------

pip install --no-cache-dir \
    flask==3.0.3 \
    gunicorn==22.0.0

# ---------------------------------------------------------------------------
# Application directory structure
# ---------------------------------------------------------------------------

mkdir -p /app/data

# ---------------------------------------------------------------------------
# SQLite database initialization
# ---------------------------------------------------------------------------

# The database persists flag submission state across page reloads.
# A single table tracks which of the three flags have been correctly submitted.
# The schema uses a fixed set of three rows identified by flag_id (1, 2, 3).
# The solved column is a boolean integer (0 = unsolved, 1 = solved).

python3 - <<'PYEOF'
import sqlite3
import os

db_path = "/app/data/portal.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS flags (
        flag_id   INTEGER PRIMARY KEY,
        solved    INTEGER NOT NULL DEFAULT 0,
        submitted TEXT
    )
""")

cursor.execute("INSERT OR IGNORE INTO flags (flag_id, solved) VALUES (1, 0)")
cursor.execute("INSERT OR IGNORE INTO flags (flag_id, solved) VALUES (2, 0)")
cursor.execute("INSERT OR IGNORE INTO flags (flag_id, solved) VALUES (3, 0)")

conn.commit()
conn.close()

print("[+] SQLite database initialized at", db_path)
PYEOF

# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

chmod -R 755 /app
chmod 666 /app/data/portal.db

# ---------------------------------------------------------------------------
# Secret key generation
# ---------------------------------------------------------------------------

# A cryptographically random 64-character hex string is generated once at
# build time and written to /app/secret_key. The execute.sh script reads
# it at container startup and exports it as SECRET_KEY so all Gunicorn
# workers share the same value, preventing session cookie invalidation
# across worker processes.

python3 -c "import secrets; print(secrets.token_hex(32))" > /app/secret_key
chmod 600 /app/secret_key
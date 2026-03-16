#!/usr/bin/env bash

# Container entrypoint script for the Puerto Muerto CTF portal.
# This script executes every time the portal container starts via the Dockerfile ENTRYPOINT directive.
# Responsibilities:
#   - Validate that all required environment variables are present before starting the application.
#   - Export environment variables so that the Flask application can access them at runtime.
#   - Start the Gunicorn WSGI server binding to all interfaces on port 3000.

set -euo pipefail

# ---------------------------------------------------------------------------
# Environment variable validation
# ---------------------------------------------------------------------------

# All five variables must be present. If any are missing the container exits
# immediately with a descriptive error rather than starting in a broken state.

REQUIRED_VARS=(
    "FLAG1_HASH"
    "FLAG2_HASH"
    "FLAG3_HASH"
    "MASTER_FLAG"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "[ERROR] Required environment variable '${var}' is not set."
        echo "[ERROR] Ensure prepare.sh was executed before building the containers."
        exit 1
    fi
done

echo "[+] All required environment variables are present."

# ---------------------------------------------------------------------------
# Export variables for Gunicorn worker processes
# ---------------------------------------------------------------------------

export FLAG1_HASH
export FLAG2_HASH
export FLAG3_HASH
export MASTER_FLAG

# ---------------------------------------------------------------------------
# Gunicorn startup
# ---------------------------------------------------------------------------

# Gunicorn serves the Flask application with 4 worker processes.
# Workers use the sync worker class which is appropriate for this I/O-light
# SQLite-backed application. The timeout is set to 30 seconds to handle
# any transient delays in SQLite access under concurrent submissions.
# Access logs are written to stdout so they appear in docker logs output.

echo "[+] Starting Puerto Muerto CTF Portal on port 3000..."

# ---------------------------------------------------------------------------
# Secret key loading
# ---------------------------------------------------------------------------

# Read the secret key generated during prepare.sh and export it so all
# Gunicorn worker processes inherit the same value via the environment.
# Without this all workers generate independent keys, invalidating session
# cookies between requests routed to different workers.

if [[ -f /app/secret_key ]]; then
    SECRET_KEY=$(cat /app/secret_key)
    export SECRET_KEY
    echo "[+] Secret key loaded."
else
    echo "[ERROR] /app/secret_key not found. Was prepare.sh executed?"
    exit 1
fi

exec gunicorn \
    --bind 0.0.0.0:3000 \
    --workers 1 \
    --worker-class sync \
    --timeout 30 \
    --access-logfile - \
    --error-logfile - \
    --chdir /app \
    app:app
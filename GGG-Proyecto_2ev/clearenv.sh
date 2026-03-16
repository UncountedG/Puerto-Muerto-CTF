#!/usr/bin/env bash

# Removes the generated .env file and dockername.txt.
# Also clears the flag files so they are not left with stale values.
# Run prepare.sh after this to generate a completely fresh deployment.

set -euo pipefail

rm -f .env
rm -f dockername.txt
rm -f flag/flag1.txt
rm -f flag/flag2.txt
rm -f flag/flag3.txt

echo "[+] Environment cleared."
echo "[+] Run prepare.sh to generate a fresh deployment."

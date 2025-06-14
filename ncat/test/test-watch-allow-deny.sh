#!/bin/sh
# Test automatic reloading of allow/deny files with --watch-allow-deny

set -e

PORT=41001
TMP_ALLOW=$(mktemp ncat_allow_XXXX)
trap 'rm -f "$TMP_ALLOW"; kill $SERVER_PID 2>/dev/null || true' EXIT

# Initial allow rule permits localhost
printf "127.0.0.1\n" > "$TMP_ALLOW"

# Start Ncat server in background
../ncat -l $PORT --keep-open --recv-only --allowfile "$TMP_ALLOW" --watch-allow-deny &
SERVER_PID=$!

# Give it a moment to start
sleep 1

# First connection should succeed
if ! ../ncat 127.0.0.1 $PORT -z 2>/dev/null; then
  echo "Initial connection unexpectedly failed"
  exit 1
fi

# Overwrite allow file removing localhost
printf "192.0.2.1\n" > "$TMP_ALLOW"
# Wait for watcher to pick up change
sleep 2

# Second connection should fail
if ../ncat 127.0.0.1 $PORT -z 2>/dev/null; then
  echo "Connection succeeded even after removing localhost from allowfile"
  exit 1
fi

echo "PASS watch-allow-deny"
exit 0
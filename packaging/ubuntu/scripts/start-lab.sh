#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DATA="${NEXXUS_DATA:-$HOME/.nexxus-rs}"
BIN="$ROOT/nexxus"
if [ -x /usr/local/bin/nexxus ]; then
  BIN=/usr/local/bin/nexxus
elif [ -x "${HOME}/.local/bin/nexxus" ]; then
  BIN="${HOME}/.local/bin/nexxus"
fi
mkdir -p "$DATA"
echo "Старт. Журнал: $DATA/node.log" | tee -a "$ROOT/lab-test.log"
exec "$BIN" start --data "$DATA" --listen 0.0.0.0 --port 4377 --name "$(hostname -s 2>/dev/null || hostname)"

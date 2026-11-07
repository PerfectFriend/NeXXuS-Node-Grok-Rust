#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DATA="${NEXXUS_DATA:-$HOME/.nexxus-rs}"
LOG="$ROOT/lab-test.log"
BIN="$ROOT/nexxus"
if [ -x /usr/local/bin/nexxus ]; then BIN=/usr/local/bin/nexxus; fi
CONTACT="${1:-}"
if [ -z "$CONTACT" ]; then
  echo "нужен контакт второй ноды" | tee -a "$LOG"
  exit 2
fi
FP=$(printf '%s' "$CONTACT" | cut -d: -f3)
{
  echo "when $(date -Is 2>/dev/null || date)"
  echo "dial $CONTACT"
  "$BIN" ctl --data "$DATA" dial "$CONTACT"
  printf 'nexxus-lab %s\n' "$(hostname)" > "$DATA/lab-hello.txt"
  echo "put"
  "$BIN" ctl --data "$DATA" put "$DATA/lab-hello.txt"
  echo "chat"
  "$BIN" ctl --data "$DATA" chat "$FP" "hello from $(hostname)"
  sleep 3
  echo "status"
  "$BIN" ctl --data "$DATA" status
  echo "files"
  "$BIN" ctl --data "$DATA" files
  echo "chats"
  "$BIN" ctl --data "$DATA" chats
} 2>&1 | tee -a "$LOG"

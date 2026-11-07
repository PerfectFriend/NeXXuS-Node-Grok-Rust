#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
LOG="$ROOT/install.log"
{
  echo "when $(date -Is 2>/dev/null || date)"
  echo "user $(id)"
  echo "uname $(uname -a)"
  if [ ! -x "$ROOT/nexxus" ]; then
    echo "err нет файла nexxus рядом со скриптом"
    exit 1
  fi
  if [ "$(id -u)" -eq 0 ]; then
    install -m 0755 "$ROOT/nexxus" /usr/local/bin/nexxus
    echo "BIN=/usr/local/bin/nexxus"
  else
    mkdir -p "${HOME}/.local/bin"
    install -m 0755 "$ROOT/nexxus" "${HOME}/.local/bin/nexxus"
    echo "BIN=${HOME}/.local/bin/nexxus"
    echo "NOTE без root в /usr/local/bin не ставил. Добавьте ~/.local/bin в PATH или запускайте $ROOT/nexxus"
  fi
  "$ROOT/nexxus" version
  echo "OK"
} 2>&1 | tee "$LOG"

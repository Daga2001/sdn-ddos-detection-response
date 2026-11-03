#!/bin/sh
# Drop-in for ryu-manager: the lab runner always appends sdn_ddos.controller.app,
# this runs our mode-selectable subclass instead (same OpenFlow options).
set -eu
for last; do :; done
if [ "$last" != "sdn_ddos.controller.app" ]; then
  echo "ryu-modes: unexpected last argument: $last" >&2
  exit 2
fi
remaining=$(($# - 1))
while [ "$remaining" -gt 0 ]; do
  set -- "$@" "$1"
  shift
  remaining=$((remaining - 1))
done
shift
exec "${RYU_MANAGER_BIN:-/opt/ryu/bin/ryu-manager}" "$@" sdn_ddos.controller.app_modes

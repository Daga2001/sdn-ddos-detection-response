#!/usr/bin/env bash
set -euo pipefail
if [[ ! -d /sys/module/openvswitch ]]; then
  echo 'Open vSwitch kernel support is not loaded. Run make lab-doctor on the Linux host.' >&2
  exit 1
fi
mkdir -p /run/openvswitch /var/lib/openvswitch
# These paths belong to this container only; no host OVS or network namespaces.
/usr/share/openvswitch/scripts/ovs-ctl --system-id=random --no-ovs-vswitchd start
/usr/share/openvswitch/scripts/ovs-ctl --no-ovsdb-server start
/opt/lab/bin/uvicorn sdn_ddos.lab.worker:create_app --factory --host 0.0.0.0 --port 9001 --no-access-log &
lab_worker_pid=$!
cleanup() {
  kill -TERM "$lab_worker_pid" 2>/dev/null || true
  wait "$lab_worker_pid" 2>/dev/null || true
  /usr/share/openvswitch/scripts/ovs-ctl stop
}
trap cleanup EXIT
trap 'exit 0' TERM INT
wait "$lab_worker_pid"

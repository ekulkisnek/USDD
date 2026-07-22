#!/usr/bin/env bash
set -u

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <run-directory> <worker-pid>" >&2
    exit 2
fi
run_dir=$1
worker_pid=$2
health="$run_dir/health.log"

while kill -0 "$worker_pid" 2>/dev/null; do
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [[ -s "$run_dir/prover.pid" ]]; then
        sample_pid=$(cat "$run_dir/prover.pid")
    else
        sample_pid=$worker_pid
    fi
    process=$(ps -p "$sample_pid" -o pid=,etimes=,time=,%cpu=,%mem=,rss=,stat= 2>/dev/null | xargs)
    read -r available swap_free < <(
        awk '/MemAvailable:/ {available=$2} /SwapFree:/ {swap=$2} END {print available, swap}' /proc/meminfo
    )
    disk=$(df -Pk "$run_dir" | awk 'NR == 2 {print $4}')
    printf '%s process="%s" mem_available_kib=%s swap_free_kib=%s disk_free_kib=%s\n' \
        "$now" "$process" "$available" "$swap_free" "$disk" >>"$health"
    sleep 60
done

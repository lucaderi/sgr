#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
metrics_dir="$project_dir/monitoring/node_exporter"
node_exporter_pid=""

cleanup() {
  trap - EXIT INT TERM
  if [[ -n "$node_exporter_pid" ]] && kill -0 "$node_exporter_pid" 2>/dev/null; then
    kill "$node_exporter_pid"
    wait "$node_exporter_pid" 2>/dev/null || true
  fi
  docker compose --project-directory "$project_dir" \
    -f "$project_dir/compose.yaml" down >/dev/null 2>&1 || true
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for command in docker make; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 1
  }
done

for exporter in prometheus-node-exporter prometheus_node_exporter node_exporter; do
  if command -v "$exporter" >/dev/null; then
    node_exporter_command="$exporter"
    break
  fi
done
[[ -n "${node_exporter_command:-}" ]] || {
  echo "Missing node_exporter executable" >&2
  exit 1
}

mkdir -p "$metrics_dir" \
  "$project_dir/monitoring/prometheus" \
  "$project_dir/monitoring/grafana"

make -C "$project_dir"
docker compose --project-directory "$project_dir" \
  -f "$project_dir/compose.yaml" config --quiet

"$node_exporter_command" \
  --web.listen-address=0.0.0.0:9100 \
  --collector.textfile.directory="$metrics_dir" &
node_exporter_pid=$!
sleep 1
kill -0 "$node_exporter_pid" 2>/dev/null || {
  echo "node_exporter failed to start; port 9100 may already be in use" >&2
  exit 1
}

docker compose --project-directory "$project_dir" \
  -f "$project_dir/compose.yaml" up -d

sudo "$project_dir/netmon" \
  --interval 5 \
  --output "$metrics_dir/netmon.prom" \
  --verbose

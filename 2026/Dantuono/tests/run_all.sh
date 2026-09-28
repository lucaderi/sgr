#!/usr/bin/env bash
set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

tests=(
  test_tcp.sh
  test_loopback.sh
  test_udp.sh
  test_open_close.sh
)

passed=0

for test in "${tests[@]}"; do
  echo
  echo "==> $test"
  if "$TEST_DIR/$test"; then
    ((passed += 1))
  else
    echo
    echo "[FAIL] Test suite interrotta su $test" >&2
    exit 1
  fi
done

echo
echo "$passed/${#tests[@]} test superati."

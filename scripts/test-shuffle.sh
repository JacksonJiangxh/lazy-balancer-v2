#!/usr/bin/env bash
# 顺序依赖门：固定 seed 保留已知排列，额外随机 seed 扩大未来用例的排列面。
# 每次失败都打印含 seed 与超时的完整复放命令。
set -euo pipefail

cd "$(dirname "$0")/.."

packages=("$@")
if [[ ${#packages[@]} -eq 0 ]]; then
  packages=(./internal/handlers ./internal/services ./internal/middleware ./internal/db ./internal/taskengine)
fi

seeds=(1792946460835645000 1)
if [[ -n "${SHUFFLE_GATE_SEEDS:-}" ]]; then
  read -r -a seeds <<<"$SHUFFLE_GATE_SEEDS"
fi
random_seed="${SHUFFLE_GATE_RANDOM_SEED:-$(date +%s)}"
if [[ "$random_seed" != "0" ]]; then
  seeds+=("$random_seed")
fi
shuffle_timeout=900s

echo "== go test -shuffle (seeds: ${seeds[*]}, timeout: ${shuffle_timeout}) =="
for seed in "${seeds[@]}"; do
  echo "-- -shuffle=${seed} ${packages[*]}"
  set +e
  go test -count=1 -shuffle="$seed" -timeout="$shuffle_timeout" "${packages[@]}"
  shuffle_rc=$?
  set -e
  if [[ $shuffle_rc -ne 0 ]]; then
    echo "顺序依赖门失败（rc=${shuffle_rc}）：按同一 seed 复放——" >&2
    echo "  go test -count=1 -shuffle=${seed} -timeout=${shuffle_timeout} ${packages[*]}" >&2
    echo "先查共享全局态（包级缓存/测试 seam/健康位）的写侧与清理侧配对，勿改 seed 绕过。" >&2
    exit "$shuffle_rc"
  fi
done

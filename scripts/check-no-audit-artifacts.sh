#!/usr/bin/env bash
# 公网仓库守卫：审计过程记录与轮次测试不得入库。
# 历史文件已迁移到本地 .omp/legacy-audit/（.omp/ 已被忽略）。
set -euo pipefail
cd "$(dirname "$0")/.."

patterns='(^|/)docs/audit/|(^|/)(audit[0-9]+|audit_round[0-9]+|r[0-9]+|round[0-9]+)[^/]*_test\.(go|ts)$|(^|/)[^/]*_(audit[0-9]+|r[0-9]+|round[0-9]+)[^/]*_test\.(go|ts)$|(^|/)[^/]*_(r|round)[0-9]+[^/]*_test\.(go|ts)$'
bad=$(git ls-files | grep -E "$patterns" || true)
if [[ -n "$bad" ]]; then
  echo "ERROR: 审计记录/轮次测试不得提交到公网仓库：" >&2
  echo "$bad" >&2
  exit 1
fi
echo "no audit artifacts tracked"

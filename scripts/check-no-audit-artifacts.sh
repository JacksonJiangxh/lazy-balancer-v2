#!/usr/bin/env bash
# 公网仓库守卫：审计过程记录与轮次测试不得入库。
# 历史文件已迁移到本地 .omp/legacy-audit/（.omp/ 已被忽略）。
set -euo pipefail
cd "$(dirname "$0")/.."

patterns='(^|/)docs/audit/|(^|/)(audit[0-9]+|audit_round[0-9]+|r[0-9]+|round[0-9]+)[^/]*(_test\.(go|ts)|\.spec\.ts)$|(^|/)[^/]*_(audit[0-9]+|r[0-9]+|round[0-9]+)[^/]*(_test\.(go|ts)|\.spec\.ts)$|(^|/)[^/]*_(r|round)[0-9]+[^/]*(_test\.(go|ts)|\.spec\.ts)$'
bad=$(git ls-files | grep -E "$patterns" || true)
if [[ -n "$bad" ]]; then
  echo "ERROR: 审计记录/轮次测试不得提交到公网仓库：" >&2
  echo "$bad" >&2
  exit 1
fi
content_patterns='第 ?[0-9]+ ?轮|\bRound ?[0-9]+\b|\bR[0-9]{2}\b|\bA[0-9]{2}\b|\bAudit[0-9]+\b|\bSYS[0-9]+|\bSEC[0-9]+|\bHP[0-9]+|\bCL[0-9]+'
# 只检查注释与测试函数名；测试夹具字符串可合法包含 A86 等产品语义标识。
content=$(git grep -nE "^(func Test(Audit[0-9]|A[0-9]{2}|R[0-9]{2}|Round[0-9]|L7))|^[[:space:]]*(//|\\*|/\\*).*($content_patterns)" -- '*.go' '*.ts' '*.vue' '*.js' || true)
if [[ -n "$content" ]]; then
  echo "ERROR: 审计编号/轮次元数据不得提交到公网仓库：" >&2
  echo "$content" >&2
  exit 1
fi
echo "no audit artifacts tracked"

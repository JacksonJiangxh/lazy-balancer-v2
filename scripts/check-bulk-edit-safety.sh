#!/usr/bin/env bash
# 批量源码编辑安全守卫（事故：2026-10-23 全仓正则删空括号导致 1294 文件损坏）。
#
# 两道检查：
#   A. 脚本静态面：scripts/ 下同时具备「遍历源码」与「写盘替换」的脚本必须支持
#      只读模式（--dry-run / DRY_RUN），否则拒绝。
#   B. 变更形态面：对当前变更集（staged > worktree > HEAD^..HEAD）统计空括号
#      `()` / `（）` 的删除量；一次删除 ≥100 且新增不足其 1/5，判为「批量删括号」
#      事故形态。阈值可用 BULK_PAREN_MIN / BULK_PAREN_RATIO 覆盖。
#
# 用法：bash scripts/check-bulk-edit-safety.sh [--self-test]
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$script_dir/.." && pwd)"
cd "$root"

paren_min="${BULK_PAREN_MIN:-100}"
paren_ratio="${BULK_PAREN_RATIO:-5}" # removed > added*ratio 视为异常

scan_scripts() {
  local bad=0 f
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local traverses=0 writes=0 dry=0
    grep -Eq '(os\.walk|os\.scandir|glob\.glob|Path\([^)]*\)\.glob|find[[:space:]].*-name|for[[:space:]].*in[[:space:]].*\*\.(go|ts|vue))' "$f" && traverses=1 || true
    grep -Eq '(re\.sub|re\.compile|sed[[:space:]]+-i|open\([^)]*["'\'']w|writeFileSync|writeFile\()' "$f" && writes=1 || true
    grep -Eq -- '(--dry-run|DRY_RUN)' "$f" && dry=1 || true
    if (( traverses && writes && !dry )); then
      echo "ERROR: 批量改写脚本缺少 --dry-run 只读模式：$f" >&2
      bad=1
    fi
  done < <(git ls-files 'scripts/*.sh' 'scripts/*.py' | grep -v 'check-bulk-edit-safety.sh' || true)
  return "$bad"
}

diff_range() {
  if ! git diff --cached --quiet; then
    echo "--cached"
  elif ! git diff --quiet; then
    echo "WORKTREE"
  elif git rev-parse -q --verify HEAD^ >/dev/null 2>&1; then
    echo "HEAD^..HEAD"
  else
    echo ""
  fi
}

count_parens() {
  python3 - "$1" "$2" <<'PY'
import subprocess, sys
rng, tok = sys.argv[1], sys.argv[2]
paths = ['--', '*.go', '*.ts', '*.vue', '*.js', '*.css']
if rng == 'WORKTREE':
    args = ['git', 'diff', '-U0', '--no-color'] + paths
elif rng == '--cached':
    args = ['git', 'diff', '--cached', '-U0', '--no-color'] + paths
else:
    args = ['git', 'diff', '-U0', '--no-color', rng] + paths
body = subprocess.run(args, capture_output=True, text=True).stdout
added = sum(line.count(tok) for line in body.splitlines() if line.startswith('+') and not line.startswith('+++'))
removed = sum(line.count(tok) for line in body.splitlines() if line.startswith('-') and not line.startswith('---'))
print(added, removed)
PY
}

check_diff_shape() {
  local range; range="$(diff_range)"
  if [[ -z "${range}" ]]; then
    echo "bulk-edit safety: 无可检查的变更集（干净 HEAD）"
    return 0
  fi
  local shapes bad=0
  for tok in '()' '（）'; do
    read -r added removed <<<"$(count_parens "${range}" "$tok")"
    if (( removed >= paren_min )) && (( removed > added * paren_ratio )); then
      echo "ERROR: 变更集疑似批量删除空括号「$tok」：删除 $removed，新增 $added（范围：${range}）" >&2
      bad=1
    fi
  done
  if (( bad == 0 )); then
    echo "bulk-edit safety: 变更形态正常（${range}）"
  fi
  return "$bad"
}

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/bulk-edit-safety-selftest.sh"
fi

status=0
scan_scripts || status=1
check_diff_shape || status=1
exit "$status"

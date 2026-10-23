#!/usr/bin/env bash
# 批量源码编辑安全守卫（事故：2026-10-23 全仓正则删空括号导致 1294 文件损坏）。
#
# 两道检查：
#   A. 脚本静态面：scripts/ 下同时具备「遍历源码」与「写盘替换」的脚本必须支持
#      只读模式（--dry-run / DRY_RUN），否则拒绝。写盘特征覆盖非紧邻 -i 的
#      常见形态（sed -E -i / sed -e … -i / perl -pi -e / python -c）——只认
#      「sed -i 紧邻」等于对最常见的批量改写作业形态失效。
#   B. 变更形态面：对当前变更集（staged 与 worktree 各查一段，两者皆空时查
#      HEAD^..HEAD）统计空括号
#      `()` / `（）` 的删除量；一次删除 ≥100 且新增不足其 1/5，判为「批量删括号」
#      事故形态。阈值可用 BULK_PAREN_MIN / BULK_PAREN_RATIO 覆盖。
#      该通道依赖 python3 计数：缺失或统计失败一律 fail-closed（拒绝静默通过），
#      与 check-no-audit-artifacts.sh 对缺 perl 的取向一致。
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
    # 写盘特征必须覆盖「非紧邻 -i」的全部常见形态（sed -E -i / sed -e … -i /
    # perl -pi -e / python -c）：紧邻匹配漏掉它们等于第一道闸门对最常见的
    # 批量改写作业形态失效（事故形态正是「全仓 sed/perl 正则替换」）。
    grep -Eq '(re\.sub|re\.compile|sed[^|;&]*[[:space:]](-[A-Za-z]*i|--in-place)|perl[[:space:]][^|;&]*-[A-Za-z]*i|python[0-9.]*[[:space:]]+-c|shutil\.(copy|move)|\.write_text\(|open\([^)]*["'\'']w|writeFileSync|writeFile\()' "$f" && writes=1 || true
    grep -Eq -- '(--dry-run|DRY_RUN)' "$f" && dry=1 || true
    if (( traverses && writes && !dry )); then
      echo "ERROR: 批量改写脚本缺少 --dry-run 只读模式：$f" >&2
      bad=1
    fi
  done < <(git ls-files 'scripts/*.sh' 'scripts/*.py' | grep -v 'check-bulk-edit-safety.sh' | grep -v '^scripts/tests/' || true)
  return "$bad"
}

# diff_ranges 列出全部需要检查的变更集（每行一个），而不是互斥取一段：
# 常见的「部分暂存」工作流下 staged 非空会让未暂存改动完全跳过通道 B——
# 而第二段改动往往正是批量变换。
diff_ranges() {
  local any=0
  if ! git diff --cached --quiet; then
    echo "--cached"
    any=1
  fi
  if ! git diff --quiet; then
    echo "WORKTREE"
    any=1
  fi
  if (( any == 0 )) && git rev-parse -q --verify HEAD^ >/dev/null 2>&1; then
    echo "HEAD^..HEAD"
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
proc = subprocess.run(args, capture_output=True, text=True)
if proc.returncode != 0:
    sys.stderr.write(proc.stderr)
    sys.exit(1)
added = sum(line.count(tok) for line in proc.stdout.splitlines() if line.startswith('+') and not line.startswith('+++'))
removed = sum(line.count(tok) for line in proc.stdout.splitlines() if line.startswith('-') and not line.startswith('---'))
print(added, removed)
PY
}

check_diff_shape() {
  local ranges; ranges="$(diff_ranges)"
  if [[ -z "${ranges}" ]]; then
    echo "bulk-edit safety: 无可检查的变更集（干净 HEAD）"
    return 0
  fi
  # fail-closed：统计依赖 python3。缺失时旧实现让 read 拿到空值、阈值按 0
  # 处理，通道 B 静默失效并打印「变更形态正常」——门禁在最需要时变绿。
  # 与 check-no-audit-artifacts.sh 对缺 perl 的取向对齐：拒绝静默通过。
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: 需要 python3 统计变更形态（缺失时拒绝静默通过）" >&2
    return 1
  fi
  local bad=0 range tok counts added removed
  while IFS= read -r range; do
    [[ -n "${range}" ]] || continue
    for tok in '()' '（）'; do
      # 统计命令自身失败（python3 运行时错误 / git diff 失败）同样 fail-closed：
      # 命令替换失败不会触发 set -e（read 自身成功），必须显式判定。
      if ! counts="$(count_parens "${range}" "$tok")"; then
        echo "ERROR: 变更形态统计失败（范围：${range}，形态：「$tok」）" >&2
        return 1
      fi
      read -r added removed <<<"${counts}"
      if [[ -z "${added}" || -z "${removed}" ]]; then
        echo "ERROR: 变更形态统计输出异常（范围：${range}，形态：「$tok」）" >&2
        return 1
      fi
      if (( removed >= paren_min )) && (( removed > added * paren_ratio )); then
        echo "ERROR: 变更集疑似批量删除空括号「$tok」：删除 $removed，新增 $added（范围：${range}）" >&2
        bad=1
      fi
    done
    if (( bad == 0 )); then
      echo "bulk-edit safety: 变更形态正常（${range}）"
    fi
  done <<<"${ranges}"
  return "$bad"
}

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/bulk-edit-safety-selftest.sh"
fi

status=0
scan_scripts || status=1
check_diff_shape || status=1
exit "$status"

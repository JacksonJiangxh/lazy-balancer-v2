#!/bin/bash
# check-doc-anchors.sh —— 校验代码内 `详见 docs/... §N` 锚点是否真实可跳转
#
# 用途：注释外置（TASK-2026-1111-03 H1）后，代码里只留「一句话结论 + 锚点」。
#       锚点若指向不存在的文件或章节，知识就真的丢了（比不写注释更糟：读者以为有落点）。
#       本脚本把「锚点可跳转」变成机械判据，防止外置悄悄退化成信息丢失。
#
# 判据（全部满足才算 PASS）：
#   1. 代码内每个锚点引用的 `docs/**.md` 文件存在；
#   2. 该文件内存在对应标题：`## §N` / `### §N`（或 `## N.N` 形态）；
#   3. 反向检查：`docs/fork-notes/` 下每份文档须在 README.md 索引里列出（防孤岛）。
#
# 扫描范围：*.go *.ts *.vue *.sh（排除 docs/ 自身、node_modules、dist）
# 依赖：git + bash + awk + grep + sort（无 jq、无网络、无逐文件 fork）
#
# 用法：
#   bash scripts/check-doc-anchors.sh          # 校验全仓
#   bash scripts/check-doc-anchors.sh --list    # 额外打印每条锚点（调试用）
#
# 退出码：0=PASS，1=有锚点不可达/未索引，2=用法或环境错误

set -u
SELF=${BASH_SOURCE[0]:-$0}
cd "$(dirname "$SELF")/.." || exit 2
ROOT=$(pwd)

LIST_ONLY=0
[[ ${1:-} == "--list" ]] && LIST_ONLY=1

echo "== check-doc-anchors =="
echo "repo: $ROOT"

# 扫描范围：代码文件。docs/ 自身不扫（否则文档里举例的锚点会自我指认）。
# 注：不用 mapfile（本环境 `bash` 可能是 zsh 别名；保持 bash/zsh 双兼容）。
files=$(
  git ls-files -- '*.go' '*.ts' '*.vue' '*.sh' 2>/dev/null \
    | grep -vE '^(docs|node_modules|web/node_modules)/' \
    | grep -vE '(^|/)dist/' \
    | grep -vE '^scripts/check-doc-anchors\.sh$' \
    | sort
)
file_count=$(printf '%s\n' "$files" | grep -c .)
echo "scanned files: $file_count"

# 抽锚点（整表一次 grep -o，线性、不逐文件 fork）：
# 锚点形如  docs/fork-notes/xxx.md §3   /  docs/x.md §2.4
anchors=$(
  printf '%s\n' "$files" \
    | ( cd "$ROOT" && tr '\n' '\0' | xargs -0 grep -h -o -E 'docs/[A-Za-z0-9_./-]+\.md[^)]*§[0-9]+(\.[0-9]+)?' 2>/dev/null ) \
    | sed -E 's#^(docs/[A-Za-z0-9_./-]+\.md).*§([0-9]+(\.[0-9]+)?)$#\1|\2#' \
    | grep -E '^docs/[^|]+\|[0-9]' \
    | sort -u
)

if [[ -z $anchors ]]; then
  echo "anchors found: 0"
  echo "（若尚无注释外置产物，这是正常结果；若有 docs/fork-notes/ 却 0 锚点，说明外置未接线）"
  echo "ANCHORS: PASS"
  exit 0
fi

anchor_count=0
bad=0
# 锚点集合已排序去重，逐条验可达（数量级：数十条，可接受）
while IFS= read -r key; do
  [[ -z $key ]] && continue
  doc=${key%%|*}
  sec=${key##*|}
  anchor_count=$((anchor_count + 1))

  if [[ ! -f $doc ]]; then
    echo "MISSING FILE: $doc  (§$sec)"
    bad=$((bad + 1))
    continue
  fi

  # 标题接受三种等价写法（本仓并存）：
  #   `## §3`      —— fork-notes 与多数新文档
  #   `## 3 ...`   —— 数字编号形态（如 docs/task-engine-standard.md 的 `## 4. 控制面`）
  #   `## 3.1 ...` —— 子节
  if printf '%s' "$sec" | grep -q '\.'; then
    pat="^#{2,4}[[:space:]]+(§)?${sec}([[:space:]]|$)"
  else
    pat="^#{2,4}[[:space:]]+(§)?${sec}([[:space:].]|$)"
  fi

  if ! grep -qE "$pat" "$doc"; then
    echo "MISSING ANCHOR: $doc  §$sec  (no heading matching /$pat/)"
    bad=$((bad + 1))
    continue
  fi

  [[ $LIST_ONLY -eq 1 ]] && echo "OK  $doc §$sec"
done <<EOF
$anchors
EOF

echo "anchors found: $anchor_count"

# 反向检查：fork-notes 下每份文档须被 README 索引（防止外置文档变孤岛）
if [[ -d docs/fork-notes ]]; then
  notes_total=0
  for nf in docs/fork-notes/*.md; do
    [[ -f $nf ]] || continue
    base=$(basename "$nf")
    [[ $base == "README.md" ]] && continue
    notes_total=$((notes_total + 1))
    if ! grep -q "$base" docs/fork-notes/README.md; then
      echo "NOT INDEXED: docs/fork-notes/$base  (not listed in README.md)"
      bad=$((bad + 1))
    fi
  done
  echo "fork-notes docs: $notes_total (all must be indexed in README.md)"
fi

if [[ $bad -gt 0 ]]; then
  echo "ANCHORS: FAIL ($bad problem(s))"
  exit 1
fi

echo "ANCHORS: PASS"
exit 0

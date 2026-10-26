#!/usr/bin/env bash
# Dockerfile backend 阶段「显式 COPY 清单」门禁。
#
# 为什么必须按阶段切块：xcaddy-builder 阶段同样 COPY caddygeoip/、caddydeps/、
# wafiplist/、geoipnames/（--with 载体）。若把整份 Dockerfile 的 COPY 源汇总成
# 一张清单，删掉 backend 阶段的同名 COPY 后断言仍被前一阶段满足——问题只在镜像
# 构建期（go mod download 解析 replace / go build 缺包）暴露，门禁给假绿。
# 本脚本按 `^FROM ... AS <stage>` 切块，只取 backend 块内的 COPY。
#
# 断言：
#   1) 存在 backend 阶段且块内至少一条 COPY（解析退化不许以空清单通过）；
#   2) go.mod / go.sum 在清单内（go build 必需；复制目录只带内容，模块文件必须显式）；
#   3) 顶层 Go 目录在清单内（新增顶层目录必须同步清单）。目录派生用
#      `git ls-files --cached --others --exclude-standard`——受控 + 未跟踪同扫，
#      与同仓 shell/gofmt 门同口径：新目录还没 git add 时就能红，而不是等到
#      提交后才红、真正漏 COPY 只在镜像构建期报缺包。
#
# 用法：bash scripts/check-dockerfile-copy-manifest.sh [--self-test] [Dockerfile]
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/dockerfile-copy-gate-selftest.sh"
fi

cd "$script_dir/.."
dockerfile="${1:-Dockerfile}"
if [[ ! -f "$dockerfile" ]]; then
  echo "ERROR: 找不到 Dockerfile：$dockerfile" >&2
  exit 1
fi

backend_stage=backend

# 阶段切块解析：输出 backend 阶段内（不含后续 FROM 之后）的 COPY 指令，续行已拼接。
stage_copy_lines="$(
  awk -v target="$backend_stage" '
    BEGIN { in_stage = 0; buf = "" }
    {
      line = $0
      if (buf != "") {
        sub(/\\[ \t]*$/, "", line)
        buf = buf " " line
        if ($0 ~ /\\[ \t]*$/) next
        print buf
        buf = ""
        next
      }
      if (line ~ /^[ \t]*#/) next
      if (toupper(line) ~ /^[ \t]*FROM[ \t]/) {
        n = split(line, tok, /[ \t]+/)
        alias = ""
        for (i = 1; i <= n; i++) {
          if (toupper(tok[i]) == "AS") alias = tok[i + 1]
        }
        in_stage = (alias == target)
        next
      }
      if (!in_stage) next
      if (toupper(line) ~ /^[ \t]*COPY[ \t]/) {
        if (line ~ /\\[ \t]*$/) {
          sub(/\\[ \t]*$/, "", line)
          buf = line
          next
        }
        print line
      }
    }
    END { if (buf != "") print buf }
  ' "$dockerfile"
)"

copy_dirs=()
while IFS= read -r instr; do
  [[ -z "$instr" ]] && continue
  read -r -a toks <<< "$instr"
  srcs=()
  is_from=0
  skip_next=0
  for ((i = 1; i < ${#toks[@]}; i++)); do
    tok="${toks[i]}"
    if ((skip_next)); then
      skip_next=0
      continue
    fi
    case "$tok" in
      --from) is_from=1; skip_next=1 ;;
      --from=*) is_from=1 ;;
      --*) ;;                       # --chown / --chmod / --link 等标志
      *) srcs+=("$tok") ;;
    esac
  done
  # --from 的源来自其它阶段/镜像，不是构建上下文里的清单项。
  ((is_from)) && continue
  (( ${#srcs[@]} < 2 )) && continue  # 末位是目标路径，不计入源
  for ((i = 0; i < ${#srcs[@]} - 1; i++)); do
    dir="${srcs[i]%/}"
    [[ -z "$dir" || "$dir" == "." ]] && continue
    copy_dirs+=("$dir")
  done
done <<<"$stage_copy_lines"

if (( ${#copy_dirs[@]} == 0 )); then
  echo "ERROR: 未解析到 backend 阶段的显式 COPY 清单（需要 'FROM ... AS $backend_stage' 且块内有 COPY）" >&2
  exit 1
fi

for required in go.mod go.sum; do
  printf '%s\n' "${copy_dirs[@]}" | grep -qxF "$required" || {
    echo "ERROR: Dockerfile backend COPY 清单缺少 $required" >&2
    echo "清单=[${copy_dirs[*]}]" >&2
    exit 1
  }
done

top_go_dirs="$(git ls-files --cached --others --exclude-standard '*.go' | awk -F/ 'NF>1{print $1}' | LC_ALL=C sort -u)"
missing_dirs=""
while IFS= read -r dir; do
  [[ -z "$dir" ]] && continue
  printf '%s\n' "${copy_dirs[@]}" | grep -qxF "$dir" || missing_dirs+="$dir "
done <<<"$top_go_dirs"
if [[ -n "$missing_dirs" ]]; then
  echo "ERROR: Dockerfile backend COPY 清单缺少顶层 Go 目录：$missing_dirs" >&2
  echo "清单=[${copy_dirs[*]}] 顶层 Go 目录=[${top_go_dirs//$'\n'/ }]" >&2
  exit 1
fi

echo "Dockerfile backend COPY manifest ok (${#copy_dirs[@]} sources)"

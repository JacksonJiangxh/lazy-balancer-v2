#!/bin/bash
# 本地合并机械门（TASK-2026-1110-01 P0，总经理立项）：五项全机械判定，
# 任一失败退出码非 0。pre-commit 调用本脚本；也可手工整跑：
#   /bin/bash scripts/gate.sh
#
# 判定项（全部机械，无人工直觉参与）：
#   1) go build ./... × 7 个 Go 模块（根/caddychain/caddygeoip/wafiplist/
#      caddydeps/caddyl4sec/geoipnames）
#   2) go vet ./...（根模块；子模块随 build 的独立 go.mod 各自 vet 由 CI 兜底，
#      本门覆盖根模块全量包）
#   3) 全仓冲突标记零命中（<<<<<<< / ======= / >>>>>>>）
#   4) 上游 v2.4.2（0cd475ed）全部文件逐路径存在性核对——上一轮假追平的根因
#      防线：上游任何一个路径缺失即红，MISSING 必须为 0
#   5) 版本口径八处锚点 grep（Dockerfile/compose args+双 image tag/README
#      中英构建示例/branding.ts/web_trigger——内部统一 v2.4.2）
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "GATE: 必须在 git 仓库内运行" >&2
  exit 1
}

fail=0
step() { printf '\n== %s ==\n' "$1"; }

# ---- 1) go build × 7 模块 ----
step "1/5 go build x7 modules"
modules=(. ./caddychain ./caddygeoip ./wafiplist ./caddydeps ./caddyl4sec ./geoipnames)
build_ok=0
for m in "${modules[@]}"; do
  if (cd "$m" && go build ./... >/dev/null 2>&1); then
    build_ok=$((build_ok + 1))
  else
    echo "BUILD FAIL: $m" >&2
    (cd "$m" && go build ./...) >&2
    fail=1
  fi
done
echo "modules build OK=$build_ok/7 (expect 7)"
[[ $build_ok -eq 7 ]] || fail=1

# ---- 2) go vet ----
step "2/5 go vet ./..."
if go vet ./... 2>&1; then
  echo "vet OK"
else
  echo "VET FAIL" >&2
  fail=1
fi

# ---- 3) 冲突标记零命中 ----
step "3/5 conflict markers"
# 工作区口径：git grep 扫已跟踪文件 + --others 补未跟踪（含 --exclude-standard
# 忽略集），任一命中即红。注意排除本脚本自身与 .git。
conflict_hits="$(git grep -nE '^(<<<<<<<|=======$|>>>>>>>)' -- . ':(exclude)scripts/gate.sh' 2>/dev/null)"
untracked_conflict="$(git ls-files --others --exclude-standard \
  | while IFS= read -r f; do
      [[ -f "$f" ]] && grep -nE '^(<<<<<<<|=======$|>>>>>>>)' -- "$f" 2>/dev/null | sed "s|^|$f:|"
    done)"
if [[ -n "$conflict_hits$untracked_conflict" ]]; then
  echo "CONFLICT MARKERS FOUND:" >&2
  printf '%s\n%s\n' "$conflict_hits" "$untracked_conflict" | sed '/^$/d' >&2
  fail=1
else
  echo "conflict markers: 0"
fi

# ---- 4) 上游 2095 路径存在性核对 ----
step "4/5 upstream v2.4.2 path existence (0cd475ed)"
UPSTREAM_COMMIT=0cd475ed
if ! git cat-file -e "${UPSTREAM_COMMIT}^{commit}" 2>/dev/null; then
  echo "FATAL: 上游锚点提交 $UPSTREAM_COMMIT 不在对象库（无法核对）" >&2
  fail=1
else
  missing=0
  total=0
  # 逐路径机械核对：上游树里的每个路径必须在本工作区存在（文件或目录）。
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    total=$((total + 1))
    if [[ ! -e "$p" ]]; then
      echo "MISSING: $p" >&2
      missing=$((missing + 1))
    fi
  done < <(git ls-tree -r --name-only "$UPSTREAM_COMMIT")
  echo "upstream paths total=$total missing=$missing (expect MISSING=0)"
  [[ $missing -eq 0 ]] || fail=1
fi

# ---- 5) 版本口径八处 ----
step "5/5 version anchors (v2.4.2 x8)"
ver="v2.4.2"
check_anchor() {
  local desc="$1" file="$2" pattern="$3" expect="$4"
  local got
  got="$(grep -cE -- "$pattern" "$file" 2>/dev/null || true)"
  if [[ "$got" != "$expect" ]]; then
    echo "VERSION ANCHOR FAIL: $desc ($file): 期望 $expect 处命中 '$pattern'，实际 $got" >&2
    fail=1
  else
    echo "ok  $desc"
  fi
}
check_anchor "Dockerfile ARG VERSION"        "Dockerfile"            "^ARG VERSION=${ver}$"                     1
check_anchor "compose build.args.VERSION"    "docker-compose.yml"    "^        VERSION: ${ver}$"                1
check_anchor "compose image tags (x2)"       "docker-compose.yml"    "image: v55448330/lazy-balancer-v2:${ver}$" 2
check_anchor "README.md build-arg 示例"      "README.md"             "--build-arg VERSION=${ver}"               1
check_anchor "README.md 镜像 tag 声明"       "README.md"             "v55448330/lazy-balancer-v2:${ver}-beta"   1
check_anchor "README.en.md build-arg 示例"   "README.en.md"          "--build-arg VERSION=${ver}"               1
check_anchor "README.en.md 镜像 tag 声明"    "README.en.md"          "v55448330/lazy-balancer-v2:${ver}-beta"   1
check_anchor "branding.ts appVersion 回退值" "web/src/utils/branding.ts" "export const appVersion = ref\('${ver}'\)" 1
check_anchor "web_trigger 构建按钮默认值"    ".cnb/web_trigger.yml"  "default: ${ver}$"                         1

printf '\n'
if [[ $fail -eq 0 ]]; then
  echo "GATE: PASS"
else
  echo "GATE: FAIL（任一判定失败，禁止提交）"
fi
exit $fail

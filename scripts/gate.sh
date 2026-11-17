#!/bin/bash
# 本地合并机械门（合并任务机械门，总经理立项签发）：六项全机械判定，
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
#   5) 版本口径锚点 grep：9 类锚点 / 10 处命中点 / 6 个文件
#      （去重文件：Dockerfile/compose args+双 image tag/README.md/README.en.md/
#      branding.ts/web_trigger——内部统一 v2.4.2；compose 双 image tag 例外：
#      只认 repo 名 + tag 字面现 latest，不随发版递增）。**口径定义**：「锚点」= 一次
#      check_anchor 调用（一个文件 + 一条期望模式 + 期望命中数）；「命中点」=
#      该模式下应命中的行数。同一模式要求多行时按处计（如 compose 的
#      image tag 是 1 类锚点、2 处命中），故锚点数与命中点数是两个量，
#      合计 9 / 10，勿混算、勿只引用单个数字
#   6) internal/handlers 全量单测（-timeout 15m 是超时上限，非目标值——该包
#      全量裸跑实测 578-622s，go test 默认 600s 水位会误杀正常轮次；实际耗时
#      超 10m 仅告警不判败，超上限才失败）
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "GATE: 必须在 git 仓库内运行" >&2
  exit 1
}

fail=0
step() { printf '\n== %s ==\n' "$1"; }

# ---- 1) go build × 7 模块 ----
step "1/6 go build x7 modules"
gate_modules=(. ./caddychain ./caddygeoip ./wafiplist ./caddydeps ./caddyl4sec ./geoipnames)
build_ok=0
for m in "${gate_modules[@]}"; do
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
step "2/6 go vet ./..."
if go vet ./... 2>&1; then
  echo "vet OK"
else
  echo "VET FAIL" >&2
  fail=1
fi

# ---- 3) 冲突标记零命中 ----
step "3/6 conflict markers"
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
step "4/6 upstream v2.4.2 path existence (0cd475ed)"
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

# ---- 5) 版本口径锚点：v2.4.2 + compose :latest，9 类锚点 / 10 处命中 / 6 个文件 ----
step "5/6 version anchors (v2.4.2 + compose :latest: 9 anchors / 10 hits / 6 files)"
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
# 镜像 tag 类锚点只认 repo 名 + tag 字面 latest（\S* 吞掉任意 registry 前缀）：
# compose 两处 image 已切 :latest（最近一次稳定版），不随发版递增，版本防线
# 由其余八锚点承担；命中数要求不放宽（compose 仍必须恰好 2 处）。行尾 latest$
# 锚定：真 image 行以 :latest 结尾，:vX.Y.Z-beta 等 -beta 变体不被误命中；行首
# 限定 ^[[:space:]]*：只认行首缩进后紧跟 image: 关键字的真配置行，注释或正文
# 里出现的同款 tag 字面因行首是 # 或别的字符而不误命中。
check_anchor "compose image tags (x2)"       "docker-compose.yml"    "^[[:space:]]*image: \S*lazy-balancer-v2:latest$"  2
# build-arg 锚点只加行首 ^ *、**不加行尾 $**：右边界是版本号后一个空格，而非行尾
# ——v2.4.2-beta 等变体在版本号后是 `-` 而非空格，故不被本锚点误命中；真实示例行
# 版本号后本就跟着空格（续行反斜杠/注释之前），加 $ 反而会漏检。
check_anchor "README.md build-arg 示例"      "README.md"             "^ *--build-arg VERSION=${ver} "           1
check_anchor "README.md 镜像 tag 声明"       "README.md"             "^[[:space:]]*-t \S*lazy-balancer-v2:${ver}-beta"  1
check_anchor "README.en.md build-arg 示例"   "README.en.md"          "^ *--build-arg VERSION=${ver} "           1
check_anchor "README.en.md 镜像 tag 声明"    "README.en.md"          "^[[:space:]]*-t \S*lazy-balancer-v2:${ver}-beta"  1
check_anchor "branding.ts appVersion 回退值" "web/src/utils/branding.ts" "export const appVersion = ref\('${ver}'\)" 1
check_anchor "web_trigger 构建按钮默认值"    ".cnb/web_trigger.yml"  "default: ${ver}$"                         1

# ---- 6) internal/handlers 全量单测 ----
# -timeout 15m 是**超时上限**而非目标值：该包全量裸跑实测 578-622s，贴近 go test
# 默认 600s 水位——不加显式上限时正常轮次会被默认超时误杀。告警阈值 10m（与
# 默认水位同口径）只提示、不判败：回归变慢要先看见，但失败线仍是 15m 上限。
# -count=1 关掉测试结果缓存：本门要的是「这一轮真跑过」的证据，缓存命中会以
# 十几秒的假通过冒充全量真跑（T1 首试已发生，该轮作废重跑）。代价是此后每次
# 整跑 gate 都要真跑 handlers 全量约 10 分钟，属期望行为，不是回归变慢。
# 同理，第 141 行的 10m WARN 此后每轮必现——真跑耗时天然越过告警线，
# 属预期，勿据此判失败（失败线仍是 15m 超时上限）。
step "6/6 go test ./internal/handlers"
handlers_start=$SECONDS
if go test ./internal/handlers -count=1 -timeout 15m; then
  handlers_elapsed=$((SECONDS - handlers_start))
  printf 'handlers tests OK (%dm%02ds)\n' $((handlers_elapsed / 60)) $((handlers_elapsed % 60))
  if [[ $handlers_elapsed -ge $((10 * 60)) ]]; then
    echo "WARN: handlers 包单测实际耗时 ${handlers_elapsed}s 已超 10m 告警阈值（不判失败，超时上限才是失败线）——请关注是否回归变慢" >&2
  fi
else
  echo "HANDLERS TEST FAIL" >&2
  fail=1
fi

printf '\n'
if [[ $fail -eq 0 ]]; then
  echo "GATE: PASS"
else
  echo "GATE: FAIL（任一判定失败，禁止提交）"
fi
exit $fail

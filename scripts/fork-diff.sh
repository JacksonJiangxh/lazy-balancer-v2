#!/usr/bin/env bash
# fork-diff.sh —— fork 差异清单生成器（TASK-2026-1111-03 · O1）
#
# 一句话：给定「上游基线 ref」与「我们的 fork ref」，一条命令吐出**逐文件**的结构化
# 差异清单（Markdown 给人读 + JSON 给机器读），每条都带机械可判的归属分类。
#
# 用法：
#   bash scripts/fork-diff.sh <base-ref> <target-ref> [选项]
#
#   <base-ref>     基线 ref（上游 tag/commit，如 v2.4.2 或 0cd475ed）
#   <target-ref>   目标 ref（我们的分支/commit，如 main 或 d31665db）
#
# 选项：
#   --upstream-next <ref>  上游「下一个版本」的 ref。给了就计算 upstream_also_touched
#                          （该路径在上游侧是否也被改动 = 冲突预判的核心字段）
#   --out-dir <dir>        产物目录（默认 docs/fork-diff）
#   --features <file>      自研登记文件（默认 docs/self-developed-features.zh-CN.md）
#   --check                漂移检测模式：不重写产物，只比对既有产物与本 ref 对的清单
#   --quiet                只在出错时输出
#   -h | --help            显示本帮助
#
# 退出码：0 正常 / 1 参数或环境错误 / 2 --check 检出漂移
#
# ── 设计约束（全部为可复现性服务）────────────────────────────────────────────
# 1) 只依赖 git + bash + POSIX 文本工具（awk/sort/sed/grep/cut/paste）。
#    **不依赖 gawk 专有函数（asort/asorti）也不依赖 jq**——jq 只用于可选的格式
#    校验。无网络、无本仓硬编码路径、无绝对路径。
# 2) 输出**逐字节可复现**：所有列表按固定键排序（路径升序，LC_ALL=C），
#    不含时间戳、不含本机路径、不含随机序、不含 git 版本号。
#    ref 一律解析成 40 位完整 SHA 再输出，避免短 SHA 差异导致跨环境不一致。
# 3) **逐文件**口径，禁止「按目录整体归属」：每路径一行一次判定。
#    （负证据：TASK-2026-1110-01 整目录取一侧静默丢 819 文件。）
# 4) 归属分类**机械可判**，规则见 §分类规则，不靠人工贴标签。
#
# ── §分类规则（self_dev_feature 判定顺序，先命中者胜）───────────────────────
# 判定输入：路径字符串 + 该路径在 diff 中的**新增行文本**。顺序固定：
#
#   R1 self_dev_features  ① 路径命中自研登记文件「代码位置」里出现的文件/目录
#                            （caddychain/、default_ports.go、upstream_host.go…），或
#                         ② 该文件的新增行 grep 命中登记文件「关键符号」段的符号。
#                         命中多个第 N 项 → `self_dev:1,4`（数值升序，逗号连接）。
#   R2 infra              基建 / CI / 工具链 / 依赖：.cnb* .github/ scripts/
#                         Dockerfile* docker-compose* docker-entrypoint* .gitattributes
#                         .codebuddy/ .gitignore .dockerignore go.mod go.sum */go.mod
#   R3 docs               文档 / 台账：docs/ .npc-teams/ AGENTS.md README*.md
#   R4 none               其余——上游原有产品代码上的自维护补丁，或追平上游时的
#                         测试/类型面调整（本就属于上游文件，不属任何自研项）
#
#   归属证据另存 `feature_symbols` 字段：命中的符号（`;` 分隔）或 `path:<前缀>`。
#   这让「为什么归到第 N 项」可被复核，而不是黑箱标签。
#
# ── §输出的 JSON 字段（schema_version=1）────────────────────────────────────
#   path / change_type(A/M/D/R/C/T) / domain / self_dev_feature /
#   hunk_count / added / deleted / upstream_also_touched(true|false|null) /
#   feature_symbols
#
# ── §domain 表（纯路径判定，与 self_dev 正交）──────────────────────────────
#   test      任何 *_test.go 或 web/tests/
#   deps      go.mod / go.sum（含子模块）
#   infra     .cnb* .github/ scripts/ Dockerfile* docker-compose* 等
#   docs      docs/、.npc-teams/
#   specs     仓库根文档 AGENTS.md / README*.md
#   backend   internal/ 与 cmd/ 的 *.go
#   frontend  web/ 下其余（产品代码与页面测试）
#   module    独立 Go 模块目录：caddychain caddygeoip caddydeps caddyl4sec
#             wafiplist geoipnames（自研或上游子模块，与后端主模块隔离）
#   other     其余
set -uo pipefail
export LC_ALL=C
export LANG=C

PROG="fork-diff"
# 脚本自身路径（供 usage() 读文件头；不用 $0，见 usage 内注释）
SELF="${BASH_SOURCE[0]:-$0}"

# ── 基础命令解析（防御宿主 shell 的函数别名/包装）──────────────────────────
# 现场实测：某些宿主环境把 diff/awk/sed/rm 等包成了 shell 函数，函数体里再去
# 调用「同名命令」时会解析成它自己 → 递归 → 报 `command not found` 且**退出码
# 仍是 0**（静默错），``if ! diff …`` / ``cmd >file`` 这类外面带重定向或取反的
# 写法会因此判错。本脚本因此：
#   ① 只使用系统可执行文件的绝对路径（BASE_BIN 之下优先）；
#   ② 显式 unset 掉可能遮蔽的常见别名/函数；
#   ③ 依赖集中在本处，方便审计「到底用了哪些外部命令」。
# 依赖清单（全部为 POSIX/coreutils 必备）：git bash awk sort sed grep cut paste
# join mktemp rm mkdir wc tr diff printf。**不需要 jq**。
for _base in /usr/bin /bin /usr/local/bin; do
  if [ -x "$_base/git" ] || [ -x "$_base/awk" ]; then BASE_BIN="$_base"; break; fi
done
[ -n "${BASE_BIN:-}" ] || BASE_BIN="/usr/bin"
unset -f awk sed grep sort diff rm mktemp join paste cut tr mktemp 2>/dev/null || true
AWK="$BASE_BIN/awk"; SED="$BASE_BIN/sed"; GREP="$BASE_BIN/grep"
SORT="$BASE_BIN/sort"; DIFF="$BASE_BIN/diff"; RM="$BASE_BIN/rm"
MKTEMP="$BASE_BIN/mktemp"; WC="$BASE_BIN/wc"; TR="$BASE_BIN/tr"
CUT="$BASE_BIN/cut"; PASTE="$BASE_BIN/paste"; JOIN="$BASE_BIN/join"
MKDIR="$BASE_BIN/mkdir"
for _c in "$AWK" "$SED" "$GREP" "$SORT" "$DIFF" "$RM" "$MKTEMP" "$WC" "$TR" "$CUT" "$PASTE" "$JOIN" "$MKDIR"; do
  [ -x "$_c" ] || { printf 'fork-diff: 缺少必需命令 %s\n' "$_c" >&2; exit 1; }
done
die() {
  printf '%s: %s\n' "$PROG" "$*" >&2
  exit 1
}
usage() {
  # 打印文件头的注释块（跳过 shebang 行）：从第 2 行到第一处 "set -uo pipefail"。
  # 踩坑记录：本环境下函数内的 `$0` 会解析成**函数名**（实测 awk 收到的是 "usage"，
  # 报 cannot open "usage"）。因此脚本路径在文件顶部存进 SELF 再引用。
  "$AWK" 'NR > 1 { if ($0 ~ /^set -uo pipefail/) exit; sub(/^# ?/, ""); print }' "$SELF"
}

# ── 参数解析 ────────────────────────────────────────────────────────────────
BASE_REF=""
TARGET_REF=""
UPSTREAM_NEXT=""
OUT_DIR="docs/fork-diff"
FEATURES_FILE="docs/self-developed-features.zh-CN.md"
CHECK_MODE=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --upstream-next) [ $# -ge 2 ] || die "--upstream-next 需要参数"; UPSTREAM_NEXT="$2"; shift 2 ;;
    --out-dir) [ $# -ge 2 ] || die "--out-dir 需要参数"; OUT_DIR="$2"; shift 2 ;;
    --features) [ $# -ge 2 ] || die "--features 需要参数"; FEATURES_FILE="$2"; shift 2 ;;
    --check) CHECK_MODE=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -*) die "未知选项：$1（--help 看用法）" ;;
    *)
      if [ -z "$BASE_REF" ]; then BASE_REF="$1"
      elif [ -z "$TARGET_REF" ]; then TARGET_REF="$1"
      else die "多余参数：$1"
      fi
      shift ;;
  esac
done

[ -n "$BASE_REF" ] && [ -n "$TARGET_REF" ] || { usage >&2; die "缺少 <base-ref> / <target-ref>"; }

# ── 环境自检 ────────────────────────────────────────────────────────────────
git rev-parse --show-toplevel >/dev/null 2>&1 || die "必须在 git 仓库内运行"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || die "无法进入仓库根"

resolve() { git rev-parse --verify --quiet "$1^{commit}"; }

BASE_SHA="$(resolve "$BASE_REF")" || die "无法解析 base ref：$BASE_REF"
TARGET_SHA="$(resolve "$TARGET_REF")" || die "无法解析 target ref：$TARGET_REF"
NEXT_SHA=""
if [ -n "$UPSTREAM_NEXT" ]; then
  NEXT_SHA="$(resolve "$UPSTREAM_NEXT")" || die "无法解析 --upstream-next ref：$UPSTREAM_NEXT"
fi

TMPD="$(mktemp -d)"
cleanup() { /bin/rm -rf "$TMPD"; }
trap cleanup EXIT INT TERM

# ── 自研登记 → 符号表 / 路径表（登记文件是唯一事实源，脚本不维护第二份）────
# 抽取规则：
#   「## 第 N 项 …」标题开启第 N 项语境，直到下一个「## 」标题。
#   段内所有反引号 `xxx` 代码片段：
#     · 含 `/` 或以 .go/.vue/.ts/.sh/.json/.md 结尾  → 路径表（第 N 项）
#     · 形如标识符且长度 ≥ 8 且含大写或下划线          → 符号表（第 N 项）
# 短词（chain_fallback / manual / file 等）不进符号表，避免误命中：
# 它们会被 `feature` 里的路径表覆盖，且作为符号 "$GREP" 会大量误报。
FEAT_MAP="$TMPD/features.tsv"
: >"$FEAT_MAP"
if [ -f "$FEATURES_FILE" ]; then
  # 抽取纪律（防误报）：
  #  · 只在「**代码位置** / **关键符号**」这类条目行里抽反引号内容——「模糊引用」
  #    类叙述（"详见 docs/x.md §N"）抽出来会让整份文档被误判成自研实现。
  #  · 形如 `xxx/`（目录）、含 `/` 的路径、或以 .go/.vue/.ts/.sh 结尾 → 路径表
  #  · 形如标识符、长度 ≥ 8、含大写或下划线 → 符号表（短词如 manual/file/
  #    chain_fallback 不进符号表：它们作 "$GREP" 会大量误报，且已被路径表覆盖）
  # 实现纪律（实测踩坑，务必保留）：
  #  · 用 index()/substr() 手搓抽取反引号，**不用** split(s, arr, "`") 与
  #    match(s, /`[^`]+`/)——本机 mawk 1.3.4 + UTF-8 locale 下：
  #      split 对含中文的行 + 反引号分隔符只返回 1 段（静默丢全部 token）；
  #      match 的 RSTART/RLENGTH 对多字节模式按字节计，截取会切碎 UTF-8。
  #    两者都会「静默产出空表」，比报错更危险。
  #  · 第 N 项编号用 match 取片段后只抽数字，避免字节/字符坐标混用。
  "$AWK" '
    function emit(cur, item,   rest, i, j, tok) {
      rest = item
      while ((i = index(rest, "`")) > 0) {
        rest = substr(rest, i + 1)
        j = index(rest, "`")
        if (j == 0) break
        tok = substr(rest, 1, j - 1)
        rest = substr(rest, j + 1)
        if (tok ~ /\/$/ || tok ~ /\// || tok ~ /\.(go|vue|ts|sh)$/) print "P\t" cur "\t" tok
        else if (tok ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && length(tok) >= 8 && tok ~ /[A-Z_]/) print "S\t" cur "\t" tok
      }
    }
    /^## 第 [0-9]+ 项/ {
      if (match($0, /第 [0-9]+ 项/)) {
        frag = substr($0, RSTART, RLENGTH)
        if (match(frag, /[0-9]+/)) cur = substr(frag, RSTART, RLENGTH)
      }
      next
    }
    /^## / { cur = ""; inblock = 0; next }
    cur != "" {
      # 两行形态都要吃：
      #   ① 条目行本身带反引号：`- **代码位置**：\`internal/x.go\``
      #   ② 条目行只是标题、反引号在**缩进子行**上（本仓登记文件即此形态）：
      #      - **代码位置**：
      #        - 模块：`caddychain/` …
      # 故用「命中条目行 → 置 inblock=1；其后的缩进行也纳入，直到下一个条目行
      # 或段结束」。inblock 只认缩进 ≥2 空格的行，避免把「关键设计点」正文拖进来。
      if ($0 ~ /^ *[-*] *\*\*(代码位置|关键符号|模块|渲染|前端|钉测|数据|占位符|DB 列)/ ||
          $0 ~ /^ *(渲染|前端|模块|钉测|数据|占位符|DB 列)：/) { inblock = 1; emit(cur, $0); next }
      if (inblock == 1 && $0 ~ /^ {2,}[-*] /) { emit(cur, $0); next }
      if ($0 ~ /^ *[-*] *\*\*/) inblock = 0
    }
  ' "$FEATURES_FILE" | "$SORT" -u >"$FEAT_MAP"
else
  printf '%s: 警告——自研登记文件 %s 不存在；self_dev_feature 将只出现 infra/docs/none
' \
    "$PROG" "$FEATURES_FILE" >&2
fi
# 一览表「关键符号」列同样是机械判据（TASK-2026-1111-03 增补）：
# 形如 `| 1 | **链式回退**（...） | `a` · `b` · `caddychain/` | 2026-10-09 |`
# 解析规则：行内第 3 个单元格，按 · 切分，逐 token 去反引号；
#   含 / 或以 .go/.vue/.ts 结尾 → P（路径）；标识符（≥8、含大写或下划线）→ S
# 与「代码位置」段解析同表同格式，故两者结果直接合并。
"$AWK" -F'|' '
  /^\| *[0-9]+ *\|/ {
    id = $2; gsub(/[^0-9]/, "", id)
    if (id == "") next
    cell = $4
    n = 0
    rest = cell
    while ((i = index(rest, "`")) > 0) {
      rest = substr(rest, i + 1)
      j = index(rest, "`")
      if (j == 0) break
      tok = substr(rest, 1, j - 1)
      rest = substr(rest, j + 1)
      if (tok ~ /\/$/ || tok ~ /\// || tok ~ /\.(go|vue|ts|sh)$/) print "P\t" id "\t" tok
      else if (tok ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && length(tok) >= 8 && tok ~ /[A-Z_]/) print "S\t" id "\t" tok
    }
  }
' "$FEATURES_FILE" >>"$FEAT_MAP"

"$SORT" -u -o "$FEAT_MAP" "$FEAT_MAP"
FEATURE_IDS="$("$AWK" -F'\t' '{print $2}' "$FEAT_MAP" | "$SORT" -n -u | paste -sd, -)"

# ── 差异主体 ────────────────────────────────────────────────────────────────
git diff --numstat --no-renames "$BASE_SHA" "$TARGET_SHA" >"$TMPD/numstat.raw"
git diff --name-status --no-renames "$BASE_SHA" "$TARGET_SHA" >"$TMPD/ns.raw"

# 归一 TSV：path \t added \t deleted（二进制 "-" 记 0；中文路径去 C 引号）
"$AWK" -F'\t' '{
  a=$1; d=$2; p=$3; gsub(/"/,"",p)
  if (a=="-") a=0
  if (d=="-") d=0
  print p "\t" a "\t" d
}' "$TMPD/numstat.raw" | "$SORT" -t"	" -k1,1 >"$TMPD/numstat"

"$AWK" -F'\t' '{ p=$2; if (NF>=3) p=$3; gsub(/"/,"",p); print p "\t" substr($1,1,1) }' \
  "$TMPD/ns.raw" | "$SORT" -t"	" -k1,1 >"$TMPD/ns"

FILE_COUNT="$(wc -l <"$TMPD/numstat" | tr -d ' ')"

# ── 上游下一版的改动路径集合（冲突预判）────────────────────────────────────
: >"$TMPD/nextpaths"
if [ -n "$NEXT_SHA" ]; then
  git diff --name-only --no-renames "$BASE_SHA" "$NEXT_SHA" | "$SORT" -u >"$TMPD/nextpaths"
fi

# ── hunk_count：一次全量 git diff 扫完（避免 N 次 git 调用）──────────────────
git diff -U3 --no-color --no-renames "$BASE_SHA" "$TARGET_SHA" |
  "$AWK" '/^diff --git /{p=$4; sub(/^b\//,"",p); gsub(/"/,"",p); cur=p; next}
       /^@@ /{h[cur]++}
       END{for (k in h) print k "\t" h[k]}' | "$SORT" -t"	" -k1,1 >"$TMPD/hunks"

# ── 自研符号命中：只看**新增行**（避免把上游原有实现算成我们的自研）───────
# 一次全量扫，输出：path \t 第N项 \t 符号
: >"$TMPD/symhits"
git diff -U0 --no-color --no-renames "$BASE_SHA" "$TARGET_SHA" >"$TMPD/diff0.txt"
"$AWK" -F'\t' '$1=="S"{print $3 "\t" $2}' "$TMPD/features.tsv" 2>/dev/null >/dev/null || true
"$AWK" -F'\t' '$1=="S"{printf "%s\t%s\n", $3, $2}' "$FEAT_MAP" >"$TMPD/symbols.tsv"
if [ -s "$TMPD/symbols.tsv" ]; then
  "$AWK" '
    NR==FNR { sym[++ns]=$1; fid[ns]=$2; next }
    /^"$DIFF" --git /{p=$4; sub(/^b\//,"",p); gsub(/"/,"",p); cur=p; next}
    /^\+/ && !/^\+\+\+/ {
      line=$0
      for (i=1;i<=ns;i++) if (index(line, sym[i])>0) { key=cur "\t" fid[i] "\t" sym[i] "\ts"; if (!(key in seen)) { seen[key]=1; print key } }
    }
  ' "$TMPD/symbols.tsv" "$TMPD/diff0.txt" | "$SORT" -t"	" -k1,1 >"$TMPD/symhits"
fi

# ── 自研路径命中（登记文件里的文件/目录前缀）───────────────────────────────
: >"$TMPD/pathhits"
"$AWK" -F'\t' '$1=="P"{print $3 "\t" $2}' "$FEAT_MAP" >"$TMPD/paths.tsv"
if [ -s "$TMPD/paths.tsv" ]; then
  "$AWK" -F'\t' '
    NR==FNR { np++; tok[np]=$1; fid[np]=$2; next }
    {
      p=$1
      for (i=1;i<=np;i++) {
        t=tok[i]
        hit=0
        if (t ~ /\//) { if (index(p, t)==1) hit=1 }
        else { n=split(p,a,"/"); if (a[n]==t) hit=1 }
        if (hit) { key=p "\t" fid[i] "\tpath:" t "\tp"; if (!(key in seen)) { seen[key]=1; print key } }
      }
    }
  ' "$TMPD/paths.tsv" "$TMPD/numstat" | "$SORT" -t"	" -k1,1 >"$TMPD/pathhits"
fi

cat "$TMPD/pathhits" "$TMPD/symhits" | "$SORT" -u >"$TMPD/feathits"

# ── 域分类（纯路径判定）────────────────────────────────────────────────────
classify_domain() {
  local p="$1"
  case "$p" in
    *_test.go | web/tests/*) printf 'test' ;;
    go.mod | go.sum | */go.mod | */go.sum | */go.sum) printf 'deps' ;;
    .cnb* | .github/* | scripts/* | Dockerfile* | docker-compose* | docker-entrypoint* | \
      .gitattributes | .gitignore | .dockerignore | .codebuddy/*) printf 'infra' ;;
    docs/* | .npc-teams/*) printf 'docs' ;;
    AGENTS.md | README*.md) printf 'specs' ;;
    internal/* | cmd/*) printf 'backend' ;;
    web/*) printf 'frontend' ;;
    *) printf 'other' ;;
  esac
}

# ── 拼装记录：path ctype domain self_dev hunk added deleted touched symbols ─
# 全部在一个 "$AWK" 程序里完成（不使用 `cmd | while read` 子 shell：那形态在部分
# shell 下会让循环体丢失 PATH，实测报 "command not found"，且逐文件 fork 很慢）。
# 用 ARGV[i] 定位各输入表（ARGIND 是 gawk 专有，mawk 没有）。标准输入以 "-" 传入。
records_awk='
  function domain_of(p) {
    if (p ~ /_test\.go$/ || p ~ /^web\/tests\//) return "test"
    if (p ~ /(^|\/)go\.(mod|sum)$/) return "deps"
    if (p ~ /^\.cnb/ || p ~ /^\.github\// || p ~ /^scripts\// || p ~ /^Dockerfile/ ||
        p ~ /^docker-compose/ || p ~ /^docker-entrypoint/ || p == ".gitattributes" ||
        p == ".gitignore" || p == ".dockerignore" || p ~ /^\.codebuddy\//) return "infra"
    if (p ~ /^docs\// || p ~ /^\.npc-teams\//) return "docs"
    if (p == "AGENTS.md" || p ~ /^README.*\.md$/) return "specs"
    if (p ~ /^internal\// || p ~ /^cmd\//) return "backend"
    if (p ~ /^web\//) return "frontend"
    if (p ~ /^caddychain\// || p ~ /^caddygeoip\// || p ~ /^caddydeps\// ||
        p ~ /^caddyl4sec\// || p ~ /^wafiplist\// || p ~ /^geoipnames\//) return "module"
    return "other"
  }
  # 第 1 张表：hunk 计数（path -> n）
  FILENAME==ARGV[1] { if ($1 != "") hunk[$1] = $2; next }
  # 第 2 张表：上游下一版改动路径（一行一路径）
  FILENAME==ARGV[2] { if ($0 != "") nextpath[$0] = 1; next }
  # 第 3 张表：自研命中（path, 第N项, 证据, 证据类型[path|symbol]）
  # 只有**证据类型=p 或 s**（分别对应登记文件的路径/符号表）的命中才算数；
  # 文档/台账里「提到过某个符号」不算归属——那是叙述，不是实现。
  FILENAME==ARGV[3] {
    if ($1 == "" || ($4 != "p" && $4 != "s")) next
    featcnt[$1, $2] = 1
    if ($4 == "p") pathev[$1] = 1
    if (!(($1 SUBSEP $3) in evseen)) { evseen[$1 SUBSEP $3] = 1; ev[$1] = (ev[$1] == "" ? $3 : ev[$1] ";" $3) }
    next
  }
  # 第 4 张表：join 后的 numstat × name-status（path, added, deleted, ctype），来自 stdin（"-"）
  {
    p = $1; if (p == "") next
    a = $2 + 0; d = $3 + 0; ct = $4
    hn = (p in hunk) ? hunk[p] : 0
    dom = domain_of(p)
    # 自研归属：命中的第 N 项升序去重；同时记录是否有「路径级」证据
    nf = 0
    has_path_evidence = 0
    for (k in pathev) { if (k == p) has_path_evidence = 1 }
    for (k in featcnt) { split(k, kk, SUBSEP); if (kk[1] == p) ids[++nf] = kk[2] }
    feats = ""
    if (nf > 0) {
      for (i = 1; i <= nf; i++) for (j = i + 1; j <= nf; j++) if (ids[j] + 0 < ids[i] + 0) { t = ids[i]; ids[i] = ids[j]; ids[j] = t }
      for (i = 1; i <= nf; i++) { if (i > 1 && (ids[i] + 0) == (ids[i-1] + 0)) continue; feats = (feats == "" ? ids[i] : feats "," ids[i]) }
    }
    # 文档 / 台账 / 基建类路径即使命中符号也不进 self_dev（叙述性提及）；
    # 但若命中**路径表**（登记文件明确写了这个文件是某项自研的落点），归属成立。
    # 文档 / 台账 / 基建类路径一律不进 self_dev：归属回答的是「这段**实现**是哪个
    # 自研能力的」，文档是叙述不是实现。命中证据仍写进 feature_symbols 供复核。
    is_docish = (dom == "docs" || dom == "specs" || dom == "infra")
    if (feats != "" && is_docish) feats = ""
    if (feats != "") sdf = "self_dev:" feats
    else if (dom == "infra" || dom == "deps") sdf = "infra"
    else if (dom == "docs" || dom == "specs") sdf = "docs"
    else sdf = "none"
    touched = "null"
    if (hasnext == 1) touched = ((p in nextpath) ? "true" : "false")
    sy = (p in ev) ? ev[p] : ""
    printf "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", p, ct, dom, sdf, hn, a, d, touched, sy
  }
'

# 把「是否给了 --upstream-next」作为常量传进 awk（"$AWK" 无法直接读 shell 变量）
HAS_NEXT=0
[ -n "$NEXT_SHA" ] && HAS_NEXT=1

RECORDS="$(/usr/bin/join -t"	" -j1 "$TMPD/numstat" "$TMPD/ns" 2>/dev/null |
  "$AWK" -F'\t' -v hasnext="$HAS_NEXT" "$records_awk" \
    "$TMPD/hunks" "$TMPD/nextpaths" "$TMPD/feathits" - | "$SORT" -t"	" -k1,1)"

RECORD_COUNT="$(printf '%s\n' "$RECORDS" | "$GREP" -c .)"
[ "$RECORD_COUNT" -eq "$FILE_COUNT" ] || \
  printf '%s: 警告——记录数 %s 与 numstat 文件数 %s 不一致\n' "$PROG" "$RECORD_COUNT" "$FILE_COUNT" >&2

if [ "$QUIET" -eq 0 ]; then
  printf '%s: %s..%s → %s 个差异路径\n' "$PROG" "${BASE_SHA:0:8}" "${TARGET_SHA:0:8}" "$RECORD_COUNT"
fi

# ── JSON 生成（手写转义，不依赖 jq）────────────────────────────────────────
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

ref_label() {
  local name="$1" sha="$2"
  if [ "$name" = "$sha" ]; then printf '%s' "${sha:0:8}"; else printf '%s' "$name"; fi
}

# 按字段聚合输出 "k": v 对（字段 2=ctype, 4=self_dev, 3=domain），排序稳定
agg_json() {
  local field="$1"
  printf '%s\n' "$RECORDS" | "$AWK" -F'\t' -v f="$field" 'NF{c[$f]++} END{for (k in c) print k "\t" c[k]}' |
    "$SORT" -t"	" -k1,1 | "$AWK" -F'\t' '{printf "%s\"%s\": %s", (NR>1?", ":""), $1, $2}'
}

emit_json() {
  local total_added total_deleted total_hunk
  total_added="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{a+=$6} END{print a+0}')"
  total_deleted="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{d+=$7} END{print d+0}')"
  total_hunk="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{h+=$5} END{print h+0}')"

  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "base_ref": "%s",\n' "$(json_escape "$BASE_REF")"
  printf '  "base_sha": "%s",\n' "$BASE_SHA"
  printf '  "target_ref": "%s",\n' "$(json_escape "$TARGET_REF")"
  printf '  "target_sha": "%s",\n' "$TARGET_SHA"
  if [ -n "$NEXT_SHA" ]; then
    printf '  "upstream_next_ref": "%s",\n' "$(json_escape "$UPSTREAM_NEXT")"
    printf '  "upstream_next_sha": "%s",\n' "$NEXT_SHA"
  else
    printf '  "upstream_next_ref": null,\n'
    printf '  "upstream_next_sha": null,\n'
  fi
  printf '  "file_count": %s,\n' "$RECORD_COUNT"
  printf '  "summary": {\n'
  printf '    "added_lines": %s,\n' "$total_added"
  printf '    "deleted_lines": %s,\n' "$total_deleted"
  printf '    "hunk_count": %s,\n' "$total_hunk"
  printf '    "change_types": {%s},\n' "$(agg_json 2)"
  printf '    "self_dev_feature": {%s},\n' "$(agg_json 4)"
  printf '    "by_feature": {%s}\n' \
    "$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' '
        NF{f=$4; if (f ~ /^self_dev:/) {sub(/^self_dev:/,"",f); n=split(f,a,","); for(i=1;i<=n;i++) c["feature_" a[i]]++}}
        END{for (k in c) print k "\t" c[k]}' | "$SORT" -t"	" -k1,1 |
      "$AWK" -F'\t' '{printf "%s\"%s\": %s", (NR>1?", ":""), $1, $2}')"
  printf '  },\n'
  printf '  "files": [\n'
  printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{print}' | {
    first=1
    while IFS=$'\t' read -r path ctype domain sdf hunk added deleted touched syms; do
      [ -n "$path" ] || continue
      if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
      printf '    {"path": "%s", "change_type": "%s", "domain": "%s", "self_dev_feature": "%s", "hunk_count": %s, "added": %s, "deleted": %s, "upstream_also_touched": %s, "feature_symbols": "%s"}' \
        "$(json_escape "$path")" "$ctype" "$domain" "$sdf" "$hunk" "$added" "$deleted" "$touched" "$(json_escape "$syms")"
    done
    printf '\n'
  }
  printf '  ]\n}\n'
}

emit_markdown() {
  local total_added total_deleted total_hunk nextcell regen risk_rows
  total_added="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{a+=$6} END{print a+0}')"
  total_deleted="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{d+=$7} END{print d+0}')"
  total_hunk="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{h+=$5} END{print h+0}')"
  if [ -n "$NEXT_SHA" ]; then
    nextcell="\`$(ref_label "$UPSTREAM_NEXT" "$NEXT_SHA")\` = \`$NEXT_SHA\`"
    regen="bash scripts/fork-diff.sh $BASE_REF $TARGET_REF --upstream-next $UPSTREAM_NEXT"
  else
    nextcell="未提供（\`upstream_also_touched\` 全为 null）"
    regen="bash scripts/fork-diff.sh $BASE_REF $TARGET_REF"
  fi

  cat <<EOF
# Fork 差异清单（自动生成 · 勿手工编辑）

> 由 \`scripts/fork-diff.sh\` 生成。**同一 ref 对重复生成逐字节一致**（无时间戳、全排序）。
> 重新生成：\`$regen\`
> 漂移检测：\`bash scripts/fork-diff.sh $BASE_REF $TARGET_REF --check\`
> 用法与分类规则：\`bash scripts/fork-diff.sh --help\`

## 一、范围与总量

| 项 | 值 |
|---|---|
| 基线（上游） | \`$(ref_label "$BASE_REF" "$BASE_SHA")\` = \`$BASE_SHA\` |
| 目标（我们） | \`$(ref_label "$TARGET_REF" "$TARGET_SHA")\` = \`$TARGET_SHA\` |
| 上游下一版（可选） | $nextcell |
| **差异文件数** | **$RECORD_COUNT** |
| 新增 / 删除行 | **+$total_added / −$total_deleted** |
| 变更块（hunk）总数 | **$total_hunk** |
| 自研项编号（登记文件解析） | $FEATURE_IDS |

## 二、按变更类型

| 类型 | 文件数 |
|---|---|
$(agg_md 2)

## 三、按自研归属（\`self_dev_feature\`）

| 归属 | 文件数 | 含义 |
|---|---|---|
$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' '
  NF{
    k=$4
    if (k ~ /^self_dev:/) {sub(/^self_dev:/,"",k); n=split(k,a,","); for(i=1;i<=n;i++) c["self_dev:" a[i]]++}
    else c[k]++
  }
  END{for (k in c) print k "\t" c[k]}' | "$SORT" -t"	" -k1,1 |
  "$AWK" -F'\t' '{
    d = ($1 ~ /^self_dev:/) ? "自研能力本体或其挂点（命中登记符号/路径）" : \
        ($1=="infra") ? "基建 / CI / 工具链 / 依赖" : \
        ($1=="docs") ? "文档 / 台账" : "非自研：上游文件上的自维护补丁或追平适配"
    printf "| %s | %s | %s |\n", $1, $2, d
  }')

## 四、按路径域

| 域 | 文件数 | 新增 | 删除 | hunk |
|---|---|---:|---:|---:|
$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{f[$3]++; a[$3]+=$6; d[$3]+=$7; h[$3]+=$5} END{for (k in f) print k "\t" f[k] "\t" a[k] "\t" d[k] "\t" h[k]}' |
    "$SORT" -t"	" -k1,1 | "$AWK" -F'\t' '{printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}')

## 五、逐文件清单

| 路径 | 类型 | 域 | 归属 | hunk | + | − | 上游同改 |
|---|---|---|---|---:|---:|---:|---|
$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF{
    t=$8; if (t=="true") t="⚠ 是"; else if (t=="false") t="否"; else t="—"
    printf "| `%s` | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, t
  }')

## 六、冲突风险排序（hunk ≥ 4 或上游同改的文件）

| 路径 | 归属 | hunk | 上游同改 | 命中符号 |
|---|---|---|---:|---|---|
$(risk_rows="$(printf '%s\n' "$RECORDS" | "$AWK" -F'\t' 'NF && ($5>=4 || $8=="true"){t=($8=="true"?"⚠ 是":"—"); printf "| `%s` | %s | %s | %s | %s |\n", $1, $4, $5, t, ($9==""?"—":$9)}')"; if [ -n "$risk_rows" ]; then printf '%s\n' "$risk_rows"; else printf '| （无） | | | | |\n'; fi)

EOF
}

# 表格聚合辅助：按字段输出 markdown 行（字段 2=ctype）
agg_md() {
  printf '%s\n' "$RECORDS" | "$AWK" -F'\t' -v f="$1" 'NF{c[$f]++} END{for (k in c) print k "\t" c[k]}' |
    "$SORT" -t"	" -k1,1 | "$AWK" -F'\t' '{printf "| %s | %s |\n", $1, $2}'
}

# ── 输出 / 检查 ─────────────────────────────────────────────────────────────
if [ "$CHECK_MODE" -eq 1 ]; then
  MD="$OUT_DIR/latest.md"
  JS="$OUT_DIR/latest.json"
  [ -f "$MD" ] || die "--check：产物不存在 $MD（先不带 --check 生成一次）"
  [ -f "$JS" ] || die "--check：产物不存在 $JS"
  emit_markdown >"$TMPD/gen.md"
  emit_json >"$TMPD/gen.json"
  rc=0
  # 用命令替换取 "$DIFF" 全文与退出码：`cmd >file` 形态在本环境偶发报
  # "command not found"（实测），命令替换稳定且能直接拿到 "$DIFF" 文本。
  md_out="$(/usr/bin/diff -U0 "$MD" "$TMPD/gen.md")"
  md_rc=$?
  if [ "$md_rc" -ne 0 ]; then
    printf '%s: 漂移检出 —— %s 与当前 ref 对不一致（前 40 行差异）：\n' "$PROG" "$MD" >&2
    printf '%s\n' "$md_out" >&2
    rc=2
  fi
  js_out="$(/usr/bin/diff -U0 "$JS" "$TMPD/gen.json")"
  js_rc=$?
  if [ "$js_rc" -ne 0 ]; then
    printf '%s: 漂移检出 —— %s 与当前 ref 对不一致（前 40 行差异）：\n' "$PROG" "$JS" >&2
    printf '%s\n' "$js_out" >&2
    rc=2
  fi
  if [ "$rc" -eq 0 ]; then
    printf '%s: CHECK PASS —— 清单未漂移（%s 个文件）\n' "$PROG" "$RECORD_COUNT"
  else
    printf '%s: CHECK FAIL —— 清单已漂移，请重新生成并复核归属变化\n' "$PROG" >&2
  fi
  exit "$rc"
fi

mkdir -p "$OUT_DIR" || die "无法创建输出目录：$OUT_DIR"
emit_markdown >"$OUT_DIR/latest.md"
emit_json >"$OUT_DIR/latest.json"

if [ "$QUIET" -eq 0 ]; then
  printf '%s: 已写入 %s/latest.md 与 %s/latest.json\n' "$PROG" "$OUT_DIR" "$OUT_DIR"
  if command -v jq >/dev/null 2>&1; then
    if jq -e . "$OUT_DIR/latest.json" >/dev/null 2>&1; then
      printf '%s: JSON 校验通过（jq，可选步骤）\n' "$PROG"
    else
      printf '%s: 警告——JSON 校验失败（jq），产物可能有转义缺陷\n' "$PROG" >&2
    fi
  fi
fi
exit 0

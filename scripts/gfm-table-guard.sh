#!/usr/bin/env bash
# ============================================================================
# gfm-table-guard.sh — GFM 表行竖线守卫（渲染面机械载体 · 台账 #616 AC-2）
#
# 为什么：GFM 表格数据行里**未转义**的 `|` 被当单元格分隔符 ⇒ 超出表头列数的 cell 被
#   静默丢弃（GitHub Flavored Markdown Spec §4.10 Tables："the excess is ignored"），
#   正文后段读者看不到且**无任何 fail 信号**（体量门/两门判据只覆盖自述面与体量面）。
#   来源：T0 一手 <https://github.github.com/gfm/> §4.10（核验 2026-10-07）。
#   本脚本即 casebook/deployment.md「GFM 表内裸竖线渲染截断」卡 ③ 的机械载体。
#
# ── 判据模型（本版重写 · 台账 #616 两门 P1-1/P1-2 收口）────────────────────────
#   **表识别交给 GFM 参照实现**（`markdown-it-py`，其 table 规则源自 cmark-gfm 表插件语义），
#   本守卫只负责**逐源行比对单元数**：对参照实现判定的每一张真表，取「表头列数」与每个
#   数据行的**源串单元数**（按未转义 `|` 切分）比对，不等即违规。
#
#   为什么不再自研「容器栈近似」：上一版按顶层行建模容器、逐层剥 `^ {0,3}> ?` 与固定缩进，
#   与 GFM 块级容器语义（块引用 / 列表项 / 惰性续行三层交织）**不变量不一致** ⇒ 两头都错：
#     · **fail-open**：`- | A | B |`（表头行带列表标记）、`- a` + 空行 + `    > | A | B |`
#       （列表项内容内块引用）、`> - | A | B |`（块引用内列表项）、嵌套列表等**真表整类漏检**；
#     · **误杀**：`- x` + 未缩进行（列表项惰性续行、GFM 渲染为段落非表）与「分隔行列数 ≠
#       表头列数」（GFM 整块不成表）本无 cell 丢弃，旧实现却判否 ⇒ 打回无缺陷内容、空转自愈。
#   现模型与参照实现**同源**：容器语义、惰性续行、成表条件（表头 ∧ 分隔行同块且列数自洽）
#   全部由参照实现给出，本守卫不再复刻该语义。
#
# ── 判定（二进制）─────────────────────────────────────────────────────────────
#   · 数据行源串单元数 **≠** 表头列数 ⇒ 违规（`>` 表头且超出单元**非空白**＝真丢 cell；
#     `>` 表头但超出单元**为空白**＝无内容丢失、`<` 表头＝补空 cell——后两者按 AC-1 逐字口径
#     判否，属**有意加严**，非等价于 GFM 渲染缺陷，见「覆盖边界」）。
#   · 无竖线的非空行**不作单元比对**（GFM §4.10 Example 202 懒吸收：该行仍是表行、按表头列数补空 cell）。
#
# ── 覆盖边界（据实 · 禁读作「已穷举 / 已全堵」）───────────────────────────────
#   · 成表语义**以参照实现为准**（`markdown-it-py==4.2.0`，锁版本，见下方常量）；参照实现升级
#     换代后本判据的判定域随之变化，故版本**锁定**并在此声明。
#   · 「少于表头列数亦判否」是**有意加严（非等价于 GFM 渲染缺陷）**：GFM 该形态补空 cell、
#     无数据丢失；本判据按台账 #616 AC-1「未转义竖线数 = 表头列数 − 1」逐字口径判否。
#   · 「分隔行列数 ≠ 表头列数」**不判否**（与 §4.10 Example 203 同源：该形态整块不成表、
#     渲染为段落 ⇒ 不存在 cell 丢弃；旧实现判否系误杀）。
#   · 规约外与更深嵌套组合未穷举，不构成本守卫的全覆盖证明。
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   bash scripts/gfm-table-guard.sh            # 扫仓库根（默认）；违规 → exit 1
#   bash scripts/gfm-table-guard.sh <目录>      # 扫指定根（供夹具驱动 / 收尾自检）
#   bash scripts/gfm-table-guard.sh --selftest # 正例(rc=0)/负例(rc≠0) 自证；自证不过 → exit 1
#     负例覆盖：裸竖线 / 无前导竖线且超列 / 块引用内超列 / 嵌套块引用超列 / 少于表头列数 /
#       无竖线行后超列 / **列表项内真表超列** / **嵌套列表内真表超列** /
#       **表头行带列表标记** / **列表项内容内块引用真表** / **块引用内列表项真表** / 扫空 fail-closed。
#     误杀防护正例：围栏 / 缩进代码块 / 表体 4 空格缩进行 / Example 202 原形态 / 列表项内**同列**真表 /
#       **列表项惰性续行（GFM 非表）** / **分隔行列数失配（GFM 非表）**。
#     ★ **变异负向自证（D-1 自身否定 · 橡皮章判否）**：对**本脚本判据块**构造变异副本，
#       逐一实跑其 `--selftest` ⇒ 各副本**必须判红**（rc≠0）；若某变异体仍判绿（删/改判据块仍判过），
#       即橡皮章 ⇒ 自身判红（fail-closed）。变异只作用于判据体（自证段的 `SENTINEL` 标记之前）
#       锚点须在该前缀内唯一命中，锚点漂移即判红。锚点组见下方 `SPEC_*` 清单（**组数以实跑推导、
#       不写死** · D-5）：单元数比对 / 无竖线行保护 / 表区域识别 / **容器前缀剥离（P1-1 承重保护）** /
#       实单元计数（「少于表头」加严方向）。
#     ★ **覆盖完备性（P1-1 教训）**：容器族夹具**成对**——合规件判绿 + 超列件判红，缺一半即覆盖不完备；
#       「判据有判别力」≠「覆盖完备」，只有负例的组会在全绿里掩盖整类误杀。
#     ★ **版本锁定是机制**（P1-3）：见下方 `ensure_ref_impl` —— 导入后断言 `__version__ == REF_VER`。
#
# ── 依赖与离线纪律（据实）──────────────────────────────────────────────────
#   · 唯一的运行期依赖＝参照实现 `markdown-it-py`（锁版本，见下方常量）。**缺失时按锁版本自装**
#     （本仓 CI 实证可联网 + 可 `pip install`：历史构建内 `pip install cmarkgfm` / `npm install
#     markdown-it` 均成功）；**装不上 ⇒ fail-closed（exit 2）**，绝不放行成「无违规」（假绿比红更危险）。
#   · 为什么不自研容器词法器：本项目已用两轮实证——自研「容器栈近似」与 GFM 块级容器语义不变量
#     不一致（真表整类漏检 + 非表误杀双向失真）。判据必须与参照实现**同源**，故显式依赖、不近似。
#
# ── fail-closed（不可检视即判红，不静默放行 · 码位据实）──────────────────────
#   python3 缺失 / 参照实现不可用（缺失且安装失败）/ 扫描根不存在 / 扫描面 0 个 `.md` → exit 2；
#   单文件读失败 → 计为违规 → exit 1。两者**同属判红**（非零即判否），码位差异仅供定位。
# ============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# 参照实现锁版本（成表语义唯一来源；见头注「覆盖边界」）
REF_IMPL="markdown-it-py"
REF_VER="4.2.0"

# ---- 判据本体（内嵌 python3；只做解析与比对，不做任何写操作）----
run_scan() {
  python3 - "$1" <<'PY'
import os, re, sys

def cells(line):
    """按未转义 `|` 切分（`\\|` 计字面竖线、不作分隔符）。"""
    out = []; cur = ''; i = 0; n = len(line)
    while i < n:
        c = line[i]
        if c == '\\' and i + 1 < n and line[i + 1] == '|':
            cur += '|'; i += 2; continue
        if c == '|':
            out.append(cur); cur = ''; i += 1; continue
        cur += c; i += 1
    out.append(cur)
    return out

def strip_outer(cs):
    if cs and cs[0].strip() == '':
        cs = cs[1:]
    if cs and cs[-1].strip() == '':
        cs = cs[:-1]
    return cs

def strip_container(line):
    """剥块级容器前缀（块引用标记 / 列表缩进 / 表体缩进），返回**内容行**。

    两侧须**同源**：表头列数由参照实现给出（其 cell 计数**不含容器前缀**），故数据行也必须
    先剥容器前缀再计 cell，否则行首 `> `/列表缩进被计成一个 cell ⇒ 容器内合规表整类误杀
    （台账 #616 两门 P1-1 实证：`> | A | B |` 恒报「单元数 = 表头列数 + 1」）。
    剥离范围＝GFM 块级容器语法：可重复的 `>`（可跟一个空格）+ 前后不限的 ASCII 空白/缩进。
    """
    return re.sub(r'^[ \t]*(?:>[ \t]?)*', '', line)

def ncols(line):
    return len(strip_outer(cells(line.strip())))

def scan_text(md, text):
    """返回 [(行号(1-based), 说明)]。

    成表区域与表头列数**由参照实现给出**；本函数只在给定区域内逐源行比对单元数。
    """
    lines = text.split('\n')
    toks = md.parse(text)
    out = []
    i = 0; n = len(toks)
    while i < n:
        if toks[i].type != 'table_open':
            i += 1; continue
        tcols = 0; header_lines = set(); body_rows = []; in_head = False
        j = i
        while j < n and toks[j].type != 'table_close':
            t = toks[j]
            if t.type == 'thead_open':
                in_head = True
            elif t.type == 'thead_close':
                in_head = False
            elif t.type == 'th_open':
                tcols += 1
            elif t.type == 'tr_open' and t.map:
                if in_head:
                    header_lines.update(range(t.map[0], t.map[1]))
                else:
                    body_rows.append(t.map)
            j += 1
        for (a, b) in body_rows:
            for ln in range(a, b):
                if ln in header_lines or ln >= len(lines):
                    continue
                src = strip_container(lines[ln])
                if '|' not in src:
                    continue                    # 无竖线行不作单元比对（§4.10 Example 202 懒吸收）
                got = ncols(src)
                if got != tcols:
                    out.append((ln + 1, '数据行单元数 %d ≠ 表头列数 %d' % (got, tcols)))
        i = j + 1
    return out

root = sys.argv[1]
try:
    from markdown_it import MarkdownIt
except Exception as exc:
    sys.stderr.write('不可检视：参照实现 %s 不可用（%s）\n' % ('markdown-it-py', exc))
    sys.exit(2)
md = MarkdownIt('commonmark').enable('table')

if not os.path.isdir(root):
    sys.stderr.write('不可检视：扫描根不存在 %s\n' % root)
    sys.exit(2)
files = []
for base, dirs, names in os.walk(root):
    dirs[:] = [d for d in dirs if d != '.git']
    for nm in sorted(names):
        if nm.endswith('.md'):
            files.append(os.path.join(base, nm))
if not files:
    sys.stderr.write('不可检视：扫描面 0 个 .md（防"扫空即绿"）\n')
    sys.exit(2)
bad = 0
for p in sorted(files):
    try:
        with open(p, encoding='utf-8') as fh:
            text = fh.read()
    except Exception as exc:
        bad += 1
        print('❌ %s:0 unreadable: %s' % (p, exc))
        continue
    for ln, msg in scan_text(md, text):
        bad += 1
        print('❌ %s:%s %s' % (p, ln, msg))
print('---- GFM 表行守卫：扫描 %d 个 .md，违规 %d 处 ----' % (len(files), bad))
sys.exit(1 if bad else 0)
PY
}

# ==== SELFTEST-SECTION ====（以上为判据体；变异自证只作用于本标记之前）====

ensure_ref_impl() {
  # 参照实现缺失 ⇒ 按**锁版本**安装；安装失败 ⇒ fail-closed（exit 2），不静默降级为「无违规」。
  # ★ 版本锁定是**机制**、不是声明（台账 #616 P1-3 收口）：无论自装还是环境已装，导入后**一律断言**
  #   `markdown_it.__version__ == REF_VER`，不符即 fail-closed（exit 2）——否则「锁版本」措辞无载体，
  #   环境版本漂移（成表语义随之变）时门会静默按错误语义判绿。
  command -v python3 >/dev/null 2>&1 || { echo "不可检视：python3 缺失 → 判红（fail-closed）"; exit 2; }
  if ! python3 -c 'import markdown_it' >/dev/null 2>&1; then
    echo "[GFM 表行守卫] 参照实现 ${REF_IMPL} 缺失，按锁版本 ${REF_VER} 安装 …"
    python3 -m pip install --quiet --disable-pip-version-check "${REF_IMPL}==${REF_VER}" >/dev/null 2>&1 \
      || { echo "不可检视：参照实现 ${REF_IMPL}==${REF_VER} 安装失败（网络/源不可用）→ 判红（fail-closed）"; exit 2; }
  fi
  got_ver="$(python3 -c 'import markdown_it; print(markdown_it.__version__)' 2>/dev/null)" || got_ver=""
  [ "$got_ver" = "$REF_VER" ] \
    || { echo "不可检视：参照实现版本 ${got_ver:-未知} ≠ 锁版本 ${REF_VER}（成表语义随版本变化）→ 判红（fail-closed）"; exit 2; }
  return 0
}

if [ "${1:-}" = "--selftest" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "不可检视：python3 缺失 → 判红（fail-closed）"; exit 2; }
  ensure_ref_impl
  T="$(mktemp -d)"; TMP="$T"; export TMP
  trap 'rm -rf "$T"' EXIT
  mkdir -p "$T/clean" "$T/dirty" "$T/mismatch" "$T/fenced" "$T/indented" "$T/indbody" "$T/nopipe" \
           "$T/bq" "$T/bq2" "$T/fewer" "$T/lazy" "$T/ex202" "$T/lst" "$T/lst2" "$T/lstok" \
           "$T/lstlazy" "$T/hdrli" "$T/libq" "$T/bqli" \
           "$T/bqok" "$T/bq2ok" "$T/libqok" "$T/bqliok"
  # 正例：3 列表格 + 字面竖线已转义（`\|`）
  cat > "$T/clean/t.md" <<'MD'
| 列A | 列B | 列C |
|---|---|---|
| a | b | 字面竖线 `\|` 已转义 |
MD
  # 负例：数据行含未转义竖线（超出行内列数）
  cat > "$T/dirty/t.md" <<'MD'
| 列A | 列B | 列C |
|---|---|---|
| a | b | 裸竖线 a|b| c |
MD
  # 正例②：分隔行列数 ≠ 表头列数（GFM §4.10 Example 203 同源：**整块不成表** ⇒ 无 cell 丢弃）⇒ rc=0
  cat > "$T/mismatch/t.md" <<'MD'
| 列A | 列B | 列C |
|---|---|---|---|
| a | b | c |
MD
  # 正例③：围栏代码块内的竖线不构成表格（防误杀）
  cat > "$T/fenced/t.md" <<'MD'
```text
a | b | c
```
MD
  # 正例④：缩进代码块（≥4 空格，渲染 <pre>）内的竖线不构成表格（防误杀）
  cat > "$T/indented/t.md" <<'MD'
前段文字说明：

    a | b | c | d | e
MD
  # 正例⑤：表体之后的 4 空格缩进行渲染为 <pre>、非表行 ⇒ rc=0
  cat > "$T/indbody/t.md" <<'MD'
| A | B |
|---|---|
| a | b |
    | c | d | e |
MD
  # 负例③：表体行**无前导竖线**且超列（GFM §4.10 Example 199）⇒ 必判否
  cat > "$T/nopipe/t.md" <<'MD'
| A | B | C |
|---|---|---|
a | b | c | d | e
MD
  # 负例④：块引用内表格 ⇒ 同判，超列必判否
  cat > "$T/bq/t.md" <<'MD'
> | A | B |
> |---|---|
> | a | b | c | d |
MD
  # 负例⑤：嵌套块引用 `> >` 内表格超列 ⇒ 必判否
  cat > "$T/bq2/t.md" <<'MD'
> > | A | B |
> > |---|---|
> > | a | b | c |
MD
  # 负例⑥：单元数**少于**表头亦判否（AC-1 逐字口径 · 加严非数据丢失）
  cat > "$T/fewer/t.md" <<'MD'
| A | B | C |
|---|---|---|
| a | b |
MD
  # 负例⑦：表行 → **无竖线非空行**（§4.10 Example 202 懒吸收、不终止）→ 超列行 ⇒ 必判否
  cat > "$T/lazy/t.md" <<'MD'
| A | B |
|---|---|
| a | b |
zzz
| c | d | e |
MD
  # 正例⑥：Example 202 原形态（懒吸收行后为同列行）⇒ rc=0（误杀防护）
  cat > "$T/ex202/t.md" <<'MD'
| A | B |
|---|---|
| a | b |
zzz
| c | d |
MD
  # 负例⑧：**列表项内缩进的真表**超列 ⇒ 必判否
  cat > "$T/lst/t.md" <<'MD'
- item

    | A | B |
    |---|---|
    | a | b | c | d |
MD
  # 负例⑨：**嵌套列表**内的真表超列 ⇒ 必判否
  cat > "$T/lst2/t.md" <<'MD'
- a
  - b

      | A | B |
      |---|---|
      | x | y | z |
MD
  # 正例⑦：列表项内**同列**真表 ⇒ rc=0（误杀防护）
  cat > "$T/lstok/t.md" <<'MD'
- item

    | A | B |
    |---|---|
    | a | b |
MD
  # 正例⑧：**列表项惰性续行**（GFM 渲染为段落、非表）⇒ rc=0（P1-2 误杀收口）
  cat > "$T/lstlazy/t.md" <<'MD'
- x
| A | B |
| --- | --- |
| QQ1 | QQ2 | QQ3 |
MD
  # 负例⑩：**表头行带列表标记**（`- | A | B |` + 同缩进分隔行）⇒ 真表超列必判否（P1-1 整类收口）
  cat > "$T/hdrli/t.md" <<'MD'
- | A | B |
  |---|---|
  | 1 | 2 | 3 |
MD
  # 负例⑪：**列表项内容内块引用**真表（`- a` + 空行 + `    > | A | B |`）超列 ⇒ 必判否
  cat > "$T/libq/t.md" <<'MD'
- a

    > | A | B |
    > |---|---|
    > | 1 | 2 | 3 |
MD
  # 负例⑫：**块引用内列表项**真表（`> - | A | B |`）超列 ⇒ 必判否
  cat > "$T/bqli/t.md" <<'MD'
> - | A | B |
>   |---|---|
>   | 1 | 2 | 3 |
MD
  # 正例⑨~⑫（P1-1 误杀收口 · 容器族**成对**补齐）：容器内**合规表**（零 cell 丢弃）⇒ rc=0。
  #   为什么必须有：原自证只覆盖「容器内**超列**」负例（bq/bq2/libq/bqli 均超列），
  #   容器内**合规**件零覆盖 ⇒ P1-1 的「容器前缀计成 cell」整类误杀在全绿里被掩盖。
  #   判据有判别力 ≠ 覆盖完备；容器族夹具须「合规件判绿 / 超列件判红」**成对**铺满。
  cat > "$T/bqok/t.md" <<'MD'
> | A | B |
> |---|---|
> | a | b |
MD
  cat > "$T/bq2ok/t.md" <<'MD'
> > | A | B |
> > |---|---|
> > | 1 | 2 |
MD
  cat > "$T/libqok/t.md" <<'MD'
- a

    > | A | B |
    > |---|---|
    > | 1 | 2 |
MD
  cat > "$T/bqliok/t.md" <<'MD'
> - | A | B |
>   |---|---|
>   | 1 | 2 |
MD
  _gfm_rc() { ( bash "$SELF" "$1" >/dev/null 2>&1 ); echo $?; }
  rc_clean=0;   _gfm_rc "$T/clean"    >/dev/null; rc_clean=$(_gfm_rc "$T/clean")
  rc_dirty=$(_gfm_rc "$T/dirty")
  rc_mismatch=$(_gfm_rc "$T/mismatch")
  rc_fenced=$(_gfm_rc "$T/fenced")
  rc_indented=$(_gfm_rc "$T/indented")
  rc_indbody=$(_gfm_rc "$T/indbody")
  rc_nopipe=$(_gfm_rc "$T/nopipe")
  rc_bq=$(_gfm_rc "$T/bq")
  rc_bq2=$(_gfm_rc "$T/bq2")
  rc_fewer=$(_gfm_rc "$T/fewer")
  rc_lazy=$(_gfm_rc "$T/lazy")
  rc_ex202=$(_gfm_rc "$T/ex202")
  rc_lst=$(_gfm_rc "$T/lst")
  rc_lst2=$(_gfm_rc "$T/lst2")
  rc_lstok=$(_gfm_rc "$T/lstok")
  rc_lstlazy=$(_gfm_rc "$T/lstlazy")
  rc_hdrli=$(_gfm_rc "$T/hdrli")
  rc_libq=$(_gfm_rc "$T/libq")
  rc_bqli=$(_gfm_rc "$T/bqli")
  rc_bqok=$(_gfm_rc "$T/bqok")
  rc_bq2ok=$(_gfm_rc "$T/bq2ok")
  rc_libqok=$(_gfm_rc "$T/libqok")
  rc_bqliok=$(_gfm_rc "$T/bqliok")
  mkdir -p "$T/empty"
  rc_empty=$(_gfm_rc "$T/empty")
  fail=0; _pos_n=0; _neg_n=0
  #   读数**由本轮实跑推导**（D-5「禁写死数量」）：期望 0 且实测 0 ⇒ 正例 +1；期望 ≠0 且实测 ≠0 ⇒ 负例 +1；
  #   任一失守即 `fail=1` ⇒ 下方汇总分支判红（故计数只在全绿时被打印、必与实况一致）。
  _chkrc() {   # _chkrc <期望:0|nz> <实测 rc> <描述>
    if [ "$1" = "0" ]; then
      [ "$2" -eq 0 ] && { _pos_n=$((_pos_n + 1)); return 0; }
    else
      [ "$2" -ne 0 ] && { _neg_n=$((_neg_n + 1)); return 0; }
    fi
    echo "❌ $3"; fail=1
  }
  _chkrc 0  "$rc_clean"    "自证-正例①：合规夹具 rc=$rc_clean（期望 0）"
  _chkrc nz "$rc_dirty"    "自证-负例①：裸竖线夹具 rc=$rc_dirty（期望 ≠0）"
  _chkrc 0  "$rc_mismatch" "自证-正例②：分隔行列数失配（GFM 非表）rc=$rc_mismatch（期望 0 · 误杀防护）"
  _chkrc 0  "$rc_fenced"   "自证-正例③：围栏内竖线夹具 rc=$rc_fenced（期望 0）"
  _chkrc 0  "$rc_indented" "自证-正例④：缩进代码块夹具 rc=$rc_indented（期望 0）"
  _chkrc 0  "$rc_indbody"  "自证-正例⑤：表体后 4 空格缩进行夹具 rc=$rc_indbody（期望 0 · 误杀防护）"
  _chkrc nz "$rc_nopipe"   "自证-负例③：无前导竖线且超列夹具 rc=$rc_nopipe（期望 ≠0）"
  _chkrc nz "$rc_bq"       "自证-负例④：块引用内超列夹具 rc=$rc_bq（期望 ≠0）"
  _chkrc nz "$rc_bq2"      "自证-负例⑤：嵌套块引用内超列夹具 rc=$rc_bq2（期望 ≠0）"
  _chkrc nz "$rc_fewer"    "自证-负例⑥：少于表头列数夹具 rc=$rc_fewer（期望 ≠0）"
  _chkrc nz "$rc_lazy"     "自证-负例⑦：无竖线行后超列夹具 rc=$rc_lazy（期望 ≠0）"
  _chkrc 0  "$rc_ex202"    "自证-正例⑥：Example 202 原形态 rc=$rc_ex202（期望 0）"
  _chkrc nz "$rc_lst"      "自证-负例⑧：列表项内真表超列夹具 rc=$rc_lst（期望 ≠0）"
  _chkrc nz "$rc_lst2"     "自证-负例⑨：嵌套列表内真表超列夹具 rc=$rc_lst2（期望 ≠0）"
  _chkrc 0  "$rc_lstok"    "自证-正例⑦：列表项内同列真表 rc=$rc_lstok（期望 0）"
  _chkrc 0  "$rc_lstlazy"  "自证-正例⑧：列表项惰性续行（GFM 非表）rc=$rc_lstlazy（期望 0 · 误杀防护）"
  _chkrc nz "$rc_hdrli"    "自证-负例⑩：表头行带列表标记的真表超列 rc=$rc_hdrli（期望 ≠0）"
  _chkrc nz "$rc_libq"     "自证-负例⑪：列表项内容内块引用真表超列 rc=$rc_libq（期望 ≠0）"
  _chkrc nz "$rc_bqli"     "自证-负例⑫：块引用内列表项真表超列 rc=$rc_bqli（期望 ≠0）"
  _chkrc 0  "$rc_bqok"     "自证-正例⑨：块引用内**合规**表 rc=$rc_bqok（期望 0 · 容器族成对 · P1-1 误杀防护）"
  _chkrc 0  "$rc_bq2ok"    "自证-正例⑩：嵌套块引用内**合规**表 rc=$rc_bq2ok（期望 0 · 容器族成对）"
  _chkrc 0  "$rc_libqok"   "自证-正例⑪：列表项内容内块引用**合规**表 rc=$rc_libqok（期望 0 · 容器族成对）"
  _chkrc 0  "$rc_bqliok"   "自证-正例⑫：块引用内列表项**合规**表 rc=$rc_bqliok（期望 0 · 容器族成对）"
  _chkrc nz "$rc_empty"    "自证-负例⑬：空扫描面 rc=$rc_empty（期望 ≠0 · fail-closed）"
  if [ "$fail" -ne 0 ]; then
    echo "❌ 自证不通过（正/负例有失守项）→ 判红"
    exit 1
  fi
  echo "✅ 自证通过：正例 ${_pos_n} · 负例 ${_neg_n}（读数由本轮实跑推导 · 非写死）——正例：合规件／分隔列数失配非表／围栏／缩进代码块／表体缩进行／Example 202 原形态／列表内同列／列表项惰性续行非表／容器族合规件；负例：裸竖线／无前导竖线超列／块引用超列／嵌套块引用超列／少于表头／无竖线行后超列／列表内超列／嵌套列表内超列／表头带列表标记／列表项内容内块引用／块引用内列表项／扫空 fail-closed"

# ---- 变异负向自证（D-1 自身否定）：对判据体构造变异副本，实跑其 --selftest，要求逐一判红 ----
#   为什么：只跑正/负例只证明「此刻判对」，证明不了「红因就是判据块」——若判据块被删/被改
#   而夹具仍靠别处副作用判红，自证即橡皮章。故抹除某条判据 ⇒ **该副本自己的 --selftest 必判红**。
SENTINEL='# ==== SELFTEST-SECTION ===='
mutate() {   # mutate <变异规格变量名> <输出文件> ；只改 SENTINEL 之前的判据体，锚点须唯一命中
  python3 - "$SELF" "$2" "$1" "$SENTINEL" >"$TMP/mut.err" 2>&1 <<'PYM'
import sys, io
src_f, out_f, code, sentinel = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
t = io.open(src_f, encoding='utf-8').read()
k = t.index(sentinel)
pre, post = t[:k], t[k:]
g = {'body': pre}
exec(compile(code, '<mut>', 'exec'), g)
assert g['body'] != pre, '变异未生效（锚点命中但判据体未变）'
io.open(out_f, 'w', encoding='utf-8').write(g['body'] + post)
print('ok')
PYM
}
mut_run() {  # mut_run <副本> <名称> ；副本 --selftest 必须判红
  local rc=0
  GFM_SELFTEST_NO_MUT=1 bash "$1" --selftest >"$TMP/mut.$2.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  ✅ 变异负向自证[$2]：副本 --selftest rc=$rc（≠0 · 抹除该判据必判红）"
    return 0
  fi
  echo "  ❌ 变异负向自证[$2]：副本 --selftest rc=0 ⇒ 抹除该判据仍判过（橡皮章）"
  return 1
}
_mut_fail=0
if [ "${GFM_SELFTEST_NO_MUT:-}" != "1" ]; then
  echo "--- 变异负向自证（D-1 自身否定 · 删/改判据块必判红）---"
  #   ①「改判据」抹除单元数比对（裸竖线/无前导竖线超列/列表内超列等夹具应失守）
  SPEC_CMP="
old = '                if got != tcols:'
assert body.count(old) == 1, '锚点未唯一命中'
body = body.replace(old, '                if False:')
"
  #   ②「删等价方向」抹除「无竖线行不作比对」保护 ⇒ Example 202 原形态正例应被误杀判红
  SPEC_SKIP="
old = \"                if '|' not in src:\"
assert body.count(old) == 1, '锚点未唯一命中'
body = body.replace(old, '                if False:')
"
  #   ③「删表区域识别」抹除 table_open 识别 ⇒ 全夹具都不再进比对（负例全失守）
  SPEC_TBL="
old = \"        if toks[i].type != 'table_open':\"
assert body.count(old) == 1, '锚点未唯一命中'
body = body.replace(old, \"        if True:\")
"
  #   ④「删容器处理」抹除容器前缀剥离 ⇒ 容器族**合规件**（bqok/bq2ok/libqok/bqliok）被误杀判红
  #     （P2-1 · 证明本条保护是承重的：改容器处理，容器族正例必失守）
  SPEC_STRIP="
old = '                src = strip_container(lines[ln])'
assert body.count(old) == 1, '锚点未唯一命中'
body = body.replace(old, '                src = lines[ln]')
"
  #   ⑤「删竖线切分加严」抹除「少于表头列数亦判否」——把 fewer 夹具（原判否）放过，
  #     证明本判据块承重于「少于表头」这一有意加严方向（P2-1）
  SPEC_FEWER="
old = '                got = ncols(src)'
assert body.count(old) == 1, '锚点未唯一命中'
body = body.replace(old, '                got = tcols  # 变异：抹除真实比对')
"
  _mut_n=0
  for spec in SPEC_CMP:CMP SPEC_SKIP:SKIP SPEC_TBL:TBL SPEC_STRIP:STRIP SPEC_FEWER:FEWER; do
    nm="${spec%%:*}"; name="${spec##*:}"; _mut_n=$((_mut_n + 1))
    eval "mcode=\$$nm"
    if mutate "$mcode" "$TMP/mut_$name.sh"; then
      mut_run "$TMP/mut_$name.sh" "$name" || _mut_fail=1
    else
      echo "  ❌ 变异负向自证[$name]：变异副本生成失败（锚点漂移）→ 判红：$(head -1 "$TMP/mut.err" 2>/dev/null)"
      _mut_fail=1
    fi
  done
fi
  [ "$_mut_fail" -eq 0 ]   || { echo "❌ 自证-变异负向：有变异副本未判红（判据被删/改后仍判过 = 橡皮章）"; exit 1; }
  if [ "${GFM_SELFTEST_NO_MUT:-}" = "1" ]; then
    #   变异副本自身以 `GFM_SELFTEST_NO_MUT=1` 复跑 ⇒ 不再递归跑变异；此处**不报**变异组数
    #   （避免「副本里打印未跑的变异数」这类无载体断言 · F-135/D-5）。
    echo "✅ 自证通过：正例 ${_pos_n} · 负例 ${_neg_n}（本副本未跑变异负向自证 · 由外层驱动）"
  else
    echo "✅ 自证通过：正/负例全绿（正例 ${_pos_n} · 负例 ${_neg_n}）+ 变异副本 ${_mut_n:-0}/${_mut_n:-0} 判红（删/改判据块必判红 · 非橡皮章）"
  fi
  exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "不可检视：python3 缺失 → 判红（fail-closed）"; exit 2; }
ensure_ref_impl
cd "$ROOT" || exit 2
run_scan "${1:-.}"

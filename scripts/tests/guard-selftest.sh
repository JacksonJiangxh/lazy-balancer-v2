#!/usr/bin/env bash
# scripts/check-no-audit-artifacts.sh 的自检。
#
# 在临时 git 夹具仓里逐形态验证守卫的命中面与误报边界：
#   • 命中面：未跟踪文件、受控文件、各扩展名（Go/TS/MD/SH/YML/SQL/go.mod/
#     Dockerfile/docker-entrypoint.sh/.dockerignore/Caddyfile）、扩展名大小写、
#     含 NUL 字节的文本文件（报错而非整文件跳过）、下划线/小写/
#     连写形态、审计产物文件名、.gitignore 双向校验、轮次引用的各书写形态
#     （裸轮次＋审计动作、斜杠并列、中文数字归属、注释头截断残骸、跨行拆字含
#     续行注释前缀）；
#   • 误报面：百分位、版本串、十六进制摘要/哈希算法名、协议与产品 token、
#     容量边界常量、合法测试函数名、中文“轮播/轮询”、循环轮次表述（心跳/共识/
#     降频/区间/并列打点）、IPv6-only 等网络口径、日志轮转文件名骨架、
#     Windows-1252/Chrome-120 等产品词。
#
# 本文件按设计被守卫的内容扫描豁免（其内容即被测样本），豁免面在
# scripts/check-no-audit-artifacts.sh 中显式限定为这一个路径。
#
# 用法：bash scripts/tests/guard-selftest.sh（或守卫的 --self-test）
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
guard="$repo_root/scripts/check-no-audit-artifacts.sh"

if ! command -v perl >/dev/null 2>&1; then
  echo "SKIP: 需要 perl 才能运行守卫自检" >&2
  exit 1
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/audit-guard-selftest.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

pass=0
fail=0

# 每个用例一套全新夹具：仓库骨架只有守卫脚本与 .gitignore（后者取自真实仓库，
# 这样 .gitignore 双向校验在“一致”基线上成立）。
reset_fixture() {
  rm -rf "$tmp_root"
  mkdir -p "$tmp_root/scripts"
  cp "$guard" "$tmp_root/scripts/check-no-audit-artifacts.sh"
  cp "$repo_root/.gitignore" "$tmp_root/.gitignore"
  git init -q "$tmp_root"
}

run_guard() {
  ( cd "$tmp_root" && bash scripts/check-no-audit-artifacts.sh )
}

# assert_bad <用例名> <输出中必须出现的片段>
assert_bad() {
  local name="$1" needle="$2" out rc
  set +e
  out="$(run_guard 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [$name] 守卫本应失败但通过了" >&2
    fail=$((fail + 1))
    return
  fi
  if [[ -n "$needle" && "$out" != *"$needle"* ]]; then
    echo "FAIL [$name] 守卫失败但输出未提及 ${needle}：" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  echo "ok   [$name] hit: $(printf '%s\n' "$out" | grep -v '^ERROR' | head -1)"
  pass=$((pass + 1))
}

# assert_good <用例名>：守卫必须通过（误报对照）
assert_good() {
  local name="$1" out rc
  set +e
  out="$(run_guard 2>&1)"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "FAIL [$name] 误报：守卫不该失败" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  echo "ok   [$name] no false positive"
  pass=$((pass + 1))
}

mkdir_in() { mkdir -p "$tmp_root/$(dirname "$1")"; }

# ===========================================================================
# 命中面
# ===========================================================================

# 1) 未跟踪文件同样入扫描面（不 git add，直接写）
reset_fixture
mkdir_in internal/handlers/untracked_behavior_test.go
cat >"$tmp_root/internal/handlers/untracked_behavior_test.go" <<'EOF'
package handlers

func Test87_P2_01_nodesImportValidatesAccessURL(t *testing.T) {
}
EOF
assert_bad "untracked file content scan" "untracked_behavior_test.go"

# 2) 下划线/小驼峰测试名形态（受控文件）
reset_fixture
mkdir_in internal/services/conflict_matrix_test.go
cat >"$tmp_root/internal/services/conflict_matrix_test.go" <<'EOF'
package services

func TestP1_1_conflictMatrixDisablesPlaintextSideOfMixedTLSPort(t *testing.T) {
}

func TestU7_P5_2_checkManualCertExpiration_expiryReadFailureLogsAtErrorLevel(t *testing.T) {
}
EOF
git -C "$tmp_root" add -f internal/services/conflict_matrix_test.go
assert_bad "TestP1_/TestU7_ test names" "conflict_matrix_test.go"

# 3) 小写轮次形态（注释行）
reset_fixture
mkdir_in internal/services/round_refs.go
cat >"$tmp_root/internal/services/round_refs.go" <<'EOF'
package services

// 门钉测：r75b 起覆盖；r76 / r77 / r78 追加；r41 与 r53-56 同形态。
func noop() {}
EOF
assert_bad "lowercase rNN forms" "round_refs.go"

# 4) 轮次测试文件名（.ts spec）
reset_fixture
mkdir_in web/src/views/round40_latency.spec.ts
cat >"$tmp_root/web/src/views/round40_latency.spec.ts" <<'EOF'
import { describe } from 'vitest'
describe('latency', () => {})
EOF
git -C "$tmp_root" add -f web/src/views/round40_latency.spec.ts
assert_bad "roundNN spec filename" "round40_latency.spec.ts"

# 5) 审计报告文件名（docs/audit 目录 + 报告文件）
reset_fixture
mkdir_in docs/audit/keep.md
echo "x" >"$tmp_root/docs/audit/keep.md"
git -C "$tmp_root" add -f docs/audit/keep.md
assert_bad "docs/audit/ directory" "docs/audit/keep.md"

reset_fixture
mkdir_in audit89-summary.md
echo "x" >"$tmp_root/audit89-summary.md"
git -C "$tmp_root" add -f audit89-summary.md
assert_bad "auditNN report filename" "audit89-summary.md"

reset_fixture
mkdir -p "$tmp_root/reports/audit85"
echo "x" >"$tmp_root/reports/audit85/notes.md"
git -C "$tmp_root" add -f reports/audit85/notes.md
assert_bad "auditNN directory" "reports/audit85/notes.md"

# 6) 连写形态（无短横线）
reset_fixture
mkdir_in scripts/deploy.sh
cat >"$tmp_root/scripts/deploy.sh" <<'EOF'
#!/usr/bin/env bash
# 平台口径（A83H）：主节点固定 host 网络。
echo ok
EOF
assert_bad "bare concat id form" "scripts/deploy.sh"

# 7) 各扩展名的注释面（Dockerfile/.yml/.sql/.mod/entrypoint/Caddyfile/.dockerignore）
reset_fixture
cat >"$tmp_root/Dockerfile" <<'EOF'
FROM scratch
# 版本号硬编码点之一（FE-8）
EOF
assert_bad "Dockerfile comment" "Dockerfile"

reset_fixture
mkdir_in docker-compose.yml
cat >"$tmp_root/docker-compose.yml" <<'EOF'
# 主从共用配置锚点（INFRA-4）
services: {}
EOF
assert_bad "yaml comment" "docker-compose.yml"

reset_fixture
mkdir_in internal/db/migrate.sql
cat >"$tmp_root/internal/db/migrate.sql" <<'EOF'
-- 索引收敛（PD-01）
SELECT 1;
EOF
assert_bad "sql comment" "internal/db/migrate.sql"

reset_fixture
cat >"$tmp_root/caddydeps-go.mod" <<'EOF'
// placeholder
EOF
mv "$tmp_root/caddydeps-go.mod" "$tmp_root/extra.mod"
cat >"$tmp_root/extra.mod" <<'EOF'
module extra

// 零依赖共享表库（PLUG-N3）
EOF
assert_bad "go.mod comment" "extra.mod"

reset_fixture
cat >"$tmp_root/docker-entrypoint.sh" <<'EOF'
#!/bin/sh
# supervisor pid 标记（U8b-2）
echo ok
EOF
assert_bad "entrypoint comment" "docker-entrypoint.sh"

reset_fixture
mkdir_in config/Caddyfile
cat >"$tmp_root/config/Caddyfile" <<'EOF'
# 两段重试循环合并（INFRA-R1）
{
	admin 127.0.0.1:2019
}
EOF
assert_bad "Caddyfile comment" "config/Caddyfile"

reset_fixture
cat >"$tmp_root/.dockerignore" <<'EOF'
# 本地工具会话目录（U8b-1）
.omp/
EOF
assert_bad ".dockerignore comment" ".dockerignore"

# 8) 跨行拆字：编号被换行拆开
reset_fixture
mkdir_in docs/notes.md
printf '沿革：第 83\n轮引入该行为。\n' >"$tmp_root/docs/notes.md"
assert_bad "cross-line 第 N 轮" "docs/notes.md"

# 9) 裸轮次 + 审计动作（无「第」）
reset_fixture
mkdir_in internal/handlers/stored_rule_gate.go
cat >"$tmp_root/internal/handlers/stored_rule_gate.go" <<'EOF'
package handlers

// 保存门拦新载荷，此门兜直改 DB/69 轮修复前落库的存量。
func noop() {}
EOF
assert_bad "bare N 轮 + audit verb" "internal/handlers/stored_rule_gate.go"

# 10) 斜杠并列轮次
reset_fixture
mkdir_in internal/services/version_triggers_test.go
cat >"$tmp_root/internal/services/version_triggers_test.go" <<'EOF'
package services

// 簿记列不 bump 集群版本（第 25/26 轮审计）——语义列真实变化才 bump。
func TestBookkeepingDoesNotBump(t *testing.T) {}
EOF
assert_bad "slash-parallel 第 N/N 轮" "internal/services/version_triggers_test.go"

# 11) 跨行拆字 + 续行注释前缀
reset_fixture
mkdir_in internal/services/update_round_test.go
printf '// 中止口径镜像另一侧（第\n// 66 轮漏收敛本侧）——须落 skipped 终态。\n' \
  >"$tmp_root/internal/services/update_round_test.go"
assert_bad "cross-line with comment prefix" "internal/services/update_round_test.go"

# 12) 注释头截断残骸：裸轮次收尾于全角标点
reset_fixture
mkdir_in cmd/notes.go
cat >"$tmp_root/cmd/notes.go" <<'EOF'
package main

// 71 轮）：中置空格同族——畸形 Host 不得反射。
func noop() {}
EOF
assert_bad "comment-head round residue" "cmd/notes.go"

# 13) 中文数字轮次 + 审计归属
reset_fixture
mkdir_in internal/services/deny_attribution.go
cat >"$tmp_root/internal/services/deny_attribution.go" <<'EOF'
package services

// 审计 （第五轮）：deny 归因应含 refs 合并集。
func noop() {}
EOF
assert_bad "audit + chinese-numeral round" "internal/services/deny_attribution.go"

# 13b) 扩展名大小写：.MD / .Go 与 .md / .go 同等入扫描面
reset_fixture
mkdir_in docs/NOTES.MD
cat >"$tmp_root/docs/NOTES.MD" <<'EOF'
版本号硬编码点之一（FE-8）
EOF
git -C "$tmp_root" add -f docs/NOTES.MD
assert_bad "uppercase extension scanned" "NOTES.MD"

reset_fixture
mkdir_in internal/x/CONV.GO
cat >"$tmp_root/internal/x/CONV.GO" <<'EOF'
package x

// 版本号硬编码点之一（FE-8）
func noop() {}
EOF
git -C "$tmp_root" add -f internal/x/CONV.GO
assert_bad "uppercase .GO scanned" "CONV.GO"

# 13c) 含 NUL 的文本扩展名文件不得整文件跳过（跳过即逃逸面）——直接红
reset_fixture
mkdir_in docs/payload.md
printf '正常首行\n\x00\n版本号硬编码点之一（FE-8）\n' >"$tmp_root/docs/payload.md"
git -C "$tmp_root" add -f docs/payload.md
assert_bad "NUL-containing text file is not skipped" "NUL"

# 14) .gitignore 双向校验：少一行 / 多一行都失败
reset_fixture
grep -v '^\*\*/r\[0-9\]\*_test\.go$' "$tmp_root/.gitignore" >"$tmp_root/.gitignore.tmp"
mv "$tmp_root/.gitignore.tmp" "$tmp_root/.gitignore"
assert_bad "gitignore missing pattern" "模式表不一致"

reset_fixture
sed -i.bak 's|^\*\*/audit\[0-9\]\*_test\.go$|**/audit[0-9]*_test.go\n**/legacy[0-9]*_test.go|' "$tmp_root/.gitignore"
rm -f "$tmp_root/.gitignore.bak"
assert_bad "gitignore extra pattern" "模式表不一致"

# ===========================================================================
# 误报对照
# ===========================================================================

# 1) 百分位
reset_fixture
mkdir_in docs/metrics.md
cat >"$tmp_root/docs/metrics.md" <<'EOF'
延迟展示 P50 / P95 / P99，面板按 P50-P99 分位聚合；latencyP50 与 latencyP99 均取自同一次采样。
EOF
assert_good "percentiles"

# 2) 版本串
reset_fixture
mkdir_in README.md
cat >"$tmp_root/README.md" <<'EOF'
当前版本 v2.3.8，接口示例里的 version 形如 v2.3.x / v2.3.8-beta。
EOF
assert_good "version strings"

# 3) 十六进制与哈希算法名
reset_fixture
mkdir_in docs/integrity.md
cat >"$tmp_root/docs/integrity.md" <<'EOF'
校验和 6307a9696f5711f84bcb8b25f07894de68a64a0ed4a1cc7e990562dd3084f210，
算法 SHA-256 / HMAC-SHA256，掩码 0xAB12CD，摘要 d8acc96f25ad07c8e3a595a23c797324。
EOF
assert_good "hex digests and hash names"

# 4) 协议与产品 token
reset_fixture
mkdir_in internal/x/tokens.go
cat >"$tmp_root/internal/x/tokens.go" <<'EOF'
package x

// HTTP/3 与 QUIC、TLS 1.3、IPV6 监听、PID1 进程、X509 证书链、ED25519 密钥、
// HS256 签名、UTF-8 编码、DNS-01 质询、AES-256-GCM、X-LB-GeoIP-Country-Code、
// REQUEST-942 规则、LBF1 文件魔数、SHA256 摘要；容量边界 MAX-1 与 MIN-1。
func noop() {}
EOF
assert_good "protocol and product tokens"

# 5) 合法测试函数名（不含编号形态）
reset_fixture
mkdir_in internal/services/legit_test.go
cat >"$tmp_root/internal/services/legit_test.go" <<'EOF'
package services

func TestApplyConfigFromTx(t *testing.T) {}
func TestTLSRuleWithoutCertIsNotPublished(t *testing.T) {}
func TestParseIPv6Address(t *testing.T) {}
func TestWatchdogMatchesTLSCertificateRenderGate(t *testing.T) {}
EOF
assert_good "legit test names"

# 6) 中文“轮播/轮询”不误判
reset_fixture
mkdir_in docs/ui.md
cat >"$tmp_root/docs/ui.md" <<'EOF'
首页轮播与后端轮询相互独立；第 1 轮播位与第 3 轮询间隔都在设置页可调。
EOF
assert_good "carousel and polling wording"

# 7) 循环轮次表述（心跳/共识/降频/并列打点/区间）不误判
reset_fixture
mkdir_in internal/services/loop_rounds.go
cat >"$tmp_root/internal/services/loop_rounds.go" <<'EOF'
package services

// 心跳：小时级一条（60 轮×60s）；连续 2 轮共识即放行；失败 5 轮后降频为
// 每 10 轮一次；有界循环（最多 3 轮）补采尾部；第 0/6 轮打点。
// 第 61-119 轮静默；单次保存最多 3 轮 → 3R；9 轮内应只在第 0/6 轮打点。
func noop() {}
EOF
assert_good "loop round wording"

# 8) 注释头以循环轮次开头也不误判
reset_fixture
mkdir_in internal/services/loop_head_test.go
cat >"$tmp_root/internal/services/loop_head_test.go" <<'EOF'
package services

// 3 轮渲染 → 3R）。批次级一次求值后透传。
func TestLoopHeadComment(t *testing.T) {
	// When 从节点连打两轮心跳窗口（120 轮）
	_ = 0
}
EOF
assert_good "loop round wording at comment head"

# ===========================================================================
# 9) 网络口径与日志文件名骨架（IPv6-only、YYYYMMDD-HHMMSS）不误判
reset_fixture
mkdir_in internal/handlers/ip_family.go
cat >"$tmp_root/internal/handlers/ip_family.go" <<'EOF'
package handlers

// IPv4 优先（页面展示口径不变）；接口只有 IPv6（IPv6-only 主机/容器）。
// 第一个非 link-local/未指定的 IPv6（IPv6-only 主机不再显示为空）。
// rotationCopyTimberjack：<stem>-YYYYMMDD-HHMMSS-size.log[.gz]
func noop() {}
EOF
assert_good "IPv6-only and log filename skeleton"

# 10) 产品词 + 版本号形态（Windows-1252 / Chrome-120）不误判
reset_fixture
mkdir_in docs/charset.md
cat >"$tmp_root/docs/charset.md" <<'EOF'
Charset Windows-1252 与 UA 片段 Chrome-120 均按字节处理，不做转码。
EOF
assert_good "Windows-1252 and Chrome-120"

echo "selftest: $pass passed, $fail failed"
[[ $fail -eq 0 ]]

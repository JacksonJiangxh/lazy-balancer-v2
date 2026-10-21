#!/usr/bin/env bash
# 公网仓库守卫：审计过程记录与轮次测试不得入库。
# 历史文件已迁移到私有审计仓。本脚本由 CI（test-all）与发布链调用。
set -euo pipefail
cd "$(dirname "$0")/.."

# fail-closed：必须在 git 检出内运行——非 git 上下文无法枚举受控文件，拒绝静默通过。
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: 必须在 git 检出内运行本守卫（git rev-parse 失败，拒绝静默通过）" >&2
  exit 1
fi
if ! tracked=$(git ls-files); then
  echo "ERROR: git ls-files 失败——必须在 git 检出内运行本守卫" >&2
  exit 1
fi

# 文件名分支：轮次测试文件 + 审计报告/记录文件（含 .md 形态）。
patterns='(^|/)docs/audit/|(^|/)(audit[0-9]+|audit_round[0-9]+|r[0-9]+|round[0-9]+)[^/]*(_test\.(go|ts)|\.spec\.ts)$|(^|/)[^/]*_(audit[0-9]+|r[0-9]+|round[0-9]+)[^/]*(_test\.(go|ts)|\.spec\.ts)$|(^|/)[^/]*_(r|round)[0-9]+[^/]*(_test\.(go|ts)|\.spec\.ts)$|(^|/)[^/]*(audit|round|审计)[-_]?[0-9]+[^/]*\.(md|markdown|txt)$'
bad=$(printf '%s\n' "$tracked" | grep -E "$patterns" || true)
if [[ -n "$bad" ]]; then
  echo "ERROR: 审计记录/轮次测试不得提交到公网仓库：" >&2
  echo "$bad" >&2
  exit 1
fi

# 内容分支：只扫注释行（含 Vue <!-- --> 与 SQL 内嵌 -- 注释）与测试函数/用例名行；
# 测试夹具字符串（域名/UA/IP/时间戳文件名等数据）不扫。
#
# 审计编号家族通式（历史出现过的全部形态）：
#   (a) 字母+数字+短横线段：CI87-09 / LB42-3 / W87-01 / D1-S3 / L06-01 / B43-3-3 / U13-05
#   (b) 多短横线段：SSA-87-01 / FE40-D1-5 / SVC-80-D1-01 / LBH-B-U1 / H-B1-06
# 合法产品 token 天然不满足（a）——其首段无数字（UTF-8/SHA-256/REQUEST-942/X-LB-*/DNS-01
# 等先经 shield 剥离后再匹配，双保险）。
shield='X-[A-Za-z][A-Za-z0-9-]*|REQUEST-[0-9A-Z-]*|RESPONSE-[0-9A-Z-]*|UTF-8|SHA-256|HMAC-SHA256|DNS-01|A-Za-z0-9|YYYY-MM-DD|NOT-NULL|NULL-[a-z]+|BY-DESIGN|TOP-LEVEL|HTTP-only|TCP-only|HTTP-date|TLS-enabled|TLS-only|VERSION-only|JSON-[A-Za-z]*|IP-control|IP-level|ACME-issued|UPSERT-overwritten|AB-BA|WEB-VIEWS-CORE|P-256|UTC-4|MM-DD|DOM-TOM|CRS-active|P[0-9]{2}(-P?[0-9]{2})?'
family='[A-Z][A-Za-z]{0,7}[0-9][0-9A-Za-z]*(-[0-9A-Za-z]+)+|[A-Z]{2,8}(-[0-9A-Za-z]+){2,}'
legacy='第 ?[0-9]+(\.[0-9]+)? ?轮|(^|[^A-Za-z])(Round ?[0-9]+|R[0-9]{2}|A[0-9]{2}|Audit[0-9]+|SYS[0-9]+|SEC[0-9]+|HP[0-9]+|CL[0-9]+)([^A-Za-z0-9]|$)|审计 [0-9]{2}|审计 [A-Z][0-9]|二十(一|二|三|四|五|六|七|八|九)?次|[A-Za-z][A-Za-z0-9]*-?历史(问题|修复)|历史(问题|修复) [A-Z][0-9]'
lines='^[[:space:]]*(//|\*|/\*|<!--|--)|^[[:space:]]*func Test|^[[:space:]]*(test|it|describe)\('
set +e
content=$(git grep -nE "$lines" -- '*.go' '*.ts' '*.vue' '*.js' '*.css' | sed -E "s/($shield)//g" | grep -E "($family|$legacy)")
rc=$?
set -e
if [[ $rc -gt 1 ]]; then
  echo "ERROR: git grep 失败（exit=$rc）——必须在 git 检出内运行本守卫" >&2
  exit 1
fi
if [[ -n "$content" ]]; then
  echo "ERROR: 审计编号/轮次元数据不得提交到公网仓库：" >&2
  echo "$content" >&2
  exit 1
fi
echo "no audit artifacts tracked"

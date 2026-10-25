#!/usr/bin/env bash
# 修复台账反向核对门：把「提交/台账声称修复」与代码事实对照，防止再次出现
# 「台账说修了、代码没改」。
#
# 用法：
#   scripts/check-fix-claims.sh --self-test
#   scripts/check-fix-claims.sh --ledger <file.tsv> [--commit <rev>]
#
# 台账格式（竖线分隔，首行表头固定；空字段保留）：
#   id|status|evidence|reason
#   - status: fixed | maintained | falsified | retired
#   - fixed 必须有 evidence，多个用 ';' 分隔，支持：
#       code:<path>:<line>:<token>   该行必须包含 token（token 可含空格）
#       test:<TestName>              仓库内必须存在 func <TestName>( 或前端 test('<name>'
#       ftest:<literal>              web/tests 内必须出现该字面量（describe/it 标题等）
#       script:<path>                脚本必须存在（且可执行）
#       spec:<path>                  前端 spec 文件必须存在
#   - ftest/script 的空字面量/空路径一律判失败（grep -F '' 恒命中＝假绿）。
#   - maintained / falsified / retired 必须写非空 reason
#
# --commit 会解析该提交 message 中的 "Fixes: ID[,ID...]" 行，要求每个 ID 在台账
# 中状态为 fixed。没有 Fixes 行的提交不做 ID 断言（仍校验台账自身）。
#
# 退出码：0 全部通过；1 存在未闭合/证据缺失；2 用法或文件错误。
set -euo pipefail

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

root="$(cd "$(dirname "$0")/.." && pwd)"

self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/fix-claims.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/scripts"
  cp "$0" "$tmp/scripts/check-fix-claims.sh"
  mkdir -p "$tmp/internal/demo"
  printf 'package demo\n\nfunc TestDemoBehavior(t *testing.T) {}\n' > "$tmp/internal/demo/demo_test.go"
  printf 'package demo\n\nvar token = "demo-marker"\n' > "$tmp/internal/demo/demo.go"
  # 前端用例与脚本证据形态的夹具：真实命中、可执行、存在但不可执行三形态。
  mkdir -p "$tmp/web/tests"
  printf "test('demo-fixture-title', () => {})\n" > "$tmp/web/tests/demo.spec.ts"
  mkdir -p "$tmp/tools"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/tools/ok.sh"
  chmod +x "$tmp/tools/ok.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/tools/noexec.sh"
  chmod -x "$tmp/tools/noexec.sh"

  # 1) 正例：code 行含 token + test 存在 + maintained 有理由
  cat > "$tmp/ok.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/demo.go:3:demo-marker;test:TestDemoBehavior|
F-2|maintained||user ruled intentional
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok.tsv >/dev/null); then
    echo "SELFTEST FAIL: 正例被拒" >&2; return 1
  fi

  # 2) 反例：code token 不存在
  cat > "$tmp/bad-code.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|code:internal/demo/demo.go:3:not-there|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-code.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: token 不存在却通过" >&2; return 1
  fi

  # 3) 反例：test 不存在
  cat > "$tmp/bad-test.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|test:TestDoesNotExist|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-test.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: 测试不存在却通过" >&2; return 1
  fi

  # 4) 反例：fixed 无证据
  cat > "$tmp/no-evidence.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed||
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger no-evidence.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: fixed 无证据却通过" >&2; return 1
  fi

  # 5) 反例：maintained 无理由
  cat > "$tmp/no-reason.tsv" <<'EOF'
id|status|evidence|reason
F-1|maintained||
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger no-reason.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: maintained 无理由却通过" >&2; return 1
  fi

  # 6) 反例：提交声称 Fixes 但台账状态非 fixed
  (cd "$tmp" && git init -q && git config user.email t@t && git config user.name t && \
    git add -A && git commit -qm "fix: x

Fixes: F-2")
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok.tsv --commit HEAD >/dev/null 2>&1); then
    echo "SELFTEST FAIL: Fixes 声明非 fixed 项却通过" >&2; return 1
  fi

  # 7) 正例：ftest 命中真实前端用例 + script 存在且可执行
  cat > "$tmp/ok-forms.tsv" <<'EOF'
id|status|evidence|reason
F-3|fixed|ftest:demo-fixture-title;script:tools/ok.sh|
EOF
  if ! (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger ok-forms.tsv >/dev/null); then
    echo "SELFTEST FAIL: ftest/script 正例被拒" >&2; return 1
  fi

  # 8) 反例：ftest 字面量在前端用例中不存在
  cat > "$tmp/bad-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:absent-frontend-title|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: ftest 字面量不存在却通过" >&2; return 1
  fi

  # 9) 反例：ftest 空字面量（grep -F '' 恒命中，必须显式拒绝）
  cat > "$tmp/empty-ftest.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|ftest:|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger empty-ftest.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: ftest 空字面量却通过" >&2; return 1
  fi

  # 10) 反例：script 不存在
  cat > "$tmp/bad-script.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|script:tools/absent.sh|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger bad-script.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: script 不存在却通过" >&2; return 1
  fi

  # 11) 反例：script 存在但不可执行
  cat > "$tmp/noexec-script.tsv" <<'EOF'
id|status|evidence|reason
F-1|fixed|script:tools/noexec.sh|
EOF
  if (cd "$tmp" && bash scripts/check-fix-claims.sh --ledger noexec-script.tsv >/dev/null 2>&1); then
    echo "SELFTEST FAIL: script 不可执行却通过" >&2; return 1
  fi

  echo "fix-claims selftest: PASS"
}

ledger=""
commit=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ledger) ledger="${2:-}"; shift 2 ;;
    --commit) commit="${2:-}"; shift 2 ;;
    --self-test) self_test; exit $? ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$ledger" ]; then
  echo "用法错误：需要 --ledger <file.tsv> 或 --self-test" >&2
  exit 2
fi
[ -f "$ledger" ] || { echo "台账不存在: $ledger" >&2; exit 2; }
cd "$root"

fail=0
status_file="$(mktemp "${TMPDIR:-/tmp}/fix-claims-status.XXXXXX")"
trap 'rm -f "$status_file"' EXIT
line_no=0
while IFS='|' read -r id status evidence reason; do
  line_no=$((line_no + 1))
  [ "$line_no" -eq 1 ] && [ "$id" = "id" ] && continue
  [ -z "${id// /}" ] && continue
  case "$status" in
    fixed)
      if [ -z "${evidence// /}" ]; then
        echo "FAIL ${id}: fixed 但无 evidence" >&2
        fail=1
        continue
      fi
      IFS=';' read -ra items <<< "$evidence" || true
      for item in "${items[@]:-}"; do
        item="$(printf '%s' "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$item" ] && continue
        case "$item" in
          code:*)
            rest="${item#code:}"
            path="${rest%%:*}"
            rest="${rest#*:}"
            line="${rest%%:*}"
            token="${rest#*:}"
            if [ ! -f "$path" ]; then
              echo "FAIL ${id}: 证据文件不存在: $path" >&2; fail=1; continue
            fi
            case "$line" in ''|*[!0-9]*) echo "FAIL ${id}: 行号非法: $line" >&2; fail=1; continue;; esac
            if ! sed -n "${line}p" "$path" | grep -Fq -- "$token"; then
              echo "FAIL ${id}: $path:$line 不含 token: $token" >&2; fail=1
            fi
            ;;
          test:*)
            name="${item#test:}"
            if ! grep -RqsE --include='*_test.go' --include='*.spec.ts' "func[[:space:]]+${name}\(|test\(['\"]${name}" .; then
              echo "FAIL ${id}: 测试不存在: $name" >&2; fail=1
            fi
            ;;
          ftest:*)
            literal="${item#ftest:}"
            if [ -z "$literal" ]; then
              echo "FAIL ${id}: ftest 字面量为空（grep -F '' 恒命中，不构成证据）" >&2; fail=1; continue
            fi
            if ! grep -RqsF --include='*.spec.ts' -- "$literal" web/tests; then
              echo "FAIL ${id}: 前端用例不存在: $literal" >&2; fail=1
            fi
            ;;
          spec:*)
            spec="${item#spec:}"
            if [ ! -f "$spec" ]; then
              echo "FAIL ${id}: 前端 spec 不存在: $spec" >&2; fail=1
            fi
            ;;
          script:*)
            script="${item#script:}"
            if [ -z "$script" ]; then
              echo "FAIL ${id}: script 路径为空" >&2; fail=1; continue
            fi
            if [ ! -f "$script" ]; then
              echo "FAIL ${id}: 脚本不存在: $script" >&2; fail=1
            elif [ ! -x "$script" ]; then
              echo "FAIL ${id}: 脚本不可执行: $script" >&2; fail=1
            fi
            ;;
          *)
            echo "FAIL ${id}: 未知证据形态: $item" >&2; fail=1
            ;;
        esac
      done
      ;;
    maintained|falsified|retired)
      if [ -z "${reason// /}" ]; then
        echo "FAIL ${id}: $status 但 reason 为空" >&2; fail=1
      fi
      ;;
    *)
      echo "FAIL ${id}: 非法 status: ${status:-<空>}" >&2; fail=1
      ;;
  esac
  printf '%s\t%s\n' "$id" "$status" >> "$status_file"
done < "$ledger"

if [ -n "$commit" ]; then
  msg="$(git log -1 --format=%B "$commit" 2>/dev/null)" || { echo "无法读取提交 $commit" >&2; exit 2; }
  claims="$(printf '%s\n' "$msg" | sed -n 's/^Fixes:[[:space:]]*//p' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d')"
  for id in $claims; do
    st="$(awk -F'\t' -v id="$id" '$1==id{print $2}' "$status_file" | tail -1)"
    if [ "$st" != "fixed" ]; then
      echo "FAIL 提交声称修复 ${id}，但台账状态=${st:-缺失}" >&2
      fail=1
    fi
  done
fi

if [ "$fail" -ne 0 ]; then
  echo "fix-claims: FAILED" >&2
  exit 1
fi
echo "fix-claims: OK ($((line_no - 1)) 条台账)"

#!/usr/bin/env bash
# scripts/check-dockerfile-copy-manifest.sh 的自检。
#
# 关键边界：xcaddy-builder 阶段也 COPY wafiplist/、geoipnames/。删掉 backend 阶段
# 的同名 COPY 时门禁必须红——按整份 Dockerfile 汇总 COPY 源的实现会在这里给假绿
# （前一阶段满足了断言）。此外覆盖：go.sum 缺失、阶段别名缺失、`COPY . .`、
# 多行续写形态。
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="$repo_root/scripts/check-dockerfile-copy-manifest.sh"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/dockerfile-copy-gate-selftest.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

pass=0
fail=0

# 夹具：临时 git 仓 + 六组顶层 Go 目录（与真实仓库同构）+ 门禁脚本副本
#（门禁 cd 到脚本上级目录，因此副本放在 <tmp>/scripts/ 即作用于夹具仓）。
reset_fixture() {
  rm -rf "$tmp_root"
  mkdir -p "$tmp_root/scripts"
  cp "$gate" "$tmp_root/scripts/check-dockerfile-copy-manifest.sh"
  for dir in cmd internal caddygeoip caddydeps wafiplist geoipnames; do
    mkdir -p "$tmp_root/$dir"
    printf 'package fixture\n' >"$tmp_root/$dir/fixture.go"
  done
  git init -q "$tmp_root"
  git -C "$tmp_root" add -A
}

write_dockerfile() {
  cat >"$tmp_root/Dockerfile"
}

run_gate() {
  ( cd "$tmp_root" && bash scripts/check-dockerfile-copy-manifest.sh )
}

assert_pass() {
  local name="$1" out rc
  set +e
  out="$(run_gate 2>&1)"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "FAIL [$name] 门禁本应通过但失败了：" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  pass=$((pass + 1))
}

assert_fail() {
  local name="$1" needle="$2" out rc
  set +e
  out="$(run_gate 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "FAIL [$name] 门禁本应失败但通过了" >&2
    fail=$((fail + 1))
    return
  fi
  if [[ -n "$needle" && "$out" != *"$needle"* ]]; then
    echo "FAIL [$name] 门禁失败但输出未提及 ${needle}：" >&2
    echo "$out" >&2
    fail=$((fail + 1))
    return
  fi
  pass=$((pass + 1))
}

# 基线形态：xcaddy-builder 阶段与 backend 阶段都复制四个模块目录。
fixture_with_shared_stage_copies() {
  write_dockerfile <<'EOF'
FROM golang:1 AS xcaddy-builder
COPY caddygeoip/ caddygeoip/
COPY caddydeps/ caddydeps/
COPY wafiplist/ wafiplist/
COPY geoipnames/ geoipnames/
RUN xcaddy build

FROM golang:1 AS backend
COPY wafiplist/go.mod wafiplist/go.sum ./wafiplist/
COPY geoipnames/go.mod ./geoipnames/
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY caddygeoip/ ./caddygeoip/
COPY caddydeps/ ./caddydeps/
COPY wafiplist/ ./wafiplist/
COPY geoipnames/ ./geoipnames/
COPY config/ ./config/
RUN go build

FROM alpine:3
COPY --from=backend /app/lazy-balancer /usr/local/bin/lazy-balancer
COPY web/dist /app/ui
EOF
}

# 1) 基线通过
reset_fixture
fixture_with_shared_stage_copies
assert_pass "baseline manifest"

# 2) 删除 backend 的 wafiplist COPY（xcaddy 阶段仍有一份）——必须红
reset_fixture
fixture_with_shared_stage_copies
grep -v '^COPY wafiplist/ ./wafiplist/$' "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "backend wafiplist COPY missing" "wafiplist"

# 3) 删除 backend 的 geoipnames COPY（xcaddy 阶段仍有一份）——必须红
reset_fixture
fixture_with_shared_stage_copies
grep -v '^COPY geoipnames/ ./geoipnames/$' "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "backend geoipnames COPY missing" "geoipnames"

# 4) go.sum 不在清单内——必须红
reset_fixture
fixture_with_shared_stage_copies
sed -e 's|^COPY go.mod go.sum ./$|COPY go.mod ./|' "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "go.sum missing from manifest" "go.sum"

# 5) 阶段别名缺失（切块解析不到 backend）——必须红
reset_fixture
fixture_with_shared_stage_copies
sed -e 's|AS backend|AS build-stage|' "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "backend stage alias missing" "backend"

# 6) 整目录 COPY . . 不能替代显式清单——必须红（顶层 Go 目录无法从 . 判定）
reset_fixture
fixture_with_shared_stage_copies
sed -e 's|^COPY cmd/ ./cmd/$|COPY . .|' \
    -e '/^COPY internal\/ \.\/internal\/$/d' \
    -e '/^COPY caddygeoip\/ \.\/caddygeoip\/$/d' \
    -e '/^COPY caddydeps\/ \.\/caddydeps\/$/d' \
    -e '/^COPY wafiplist\/ \.\/wafiplist\/$/d' \
    -e '/^COPY geoipnames\/ \.\/geoipnames\/$/d' \
    -e '/^COPY config\/ \.\/config\/$/d' \
    "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "COPY . . is not a manifest" "缺少顶层 Go 目录"

# 7) 多行续写的 COPY 形态被正确解析（单行多源 + 续行）
reset_fixture
write_dockerfile <<'EOF'
FROM golang:1 AS xcaddy-builder
COPY wafiplist/ wafiplist/
COPY geoipnames/ geoipnames/

FROM golang:1 AS backend
COPY go.mod go.sum ./
COPY cmd/ internal/ caddygeoip/ caddydeps/ \
     wafiplist/ geoipnames/ config/ ./config/
RUN go build

FROM alpine:3
COPY --from=backend /app/lazy-balancer /usr/local/bin/lazy-balancer
EOF
assert_pass "continuation and multi-source COPY"

# 8) 续行只写在 xcaddy 阶段时不影响 backend 判定——删除 backend 的 cmd/ 必须红
reset_fixture
fixture_with_shared_stage_copies
grep -v '^COPY cmd/ ./cmd/$' "$tmp_root/Dockerfile" >"$tmp_root/Dockerfile.tmp"
mv "$tmp_root/Dockerfile.tmp" "$tmp_root/Dockerfile"
assert_fail "backend cmd COPY missing" "cmd"

echo "copy-gate selftest: $pass passed, $fail failed"
[[ $fail -eq 0 ]]

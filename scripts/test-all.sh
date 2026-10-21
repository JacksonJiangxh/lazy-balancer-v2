#!/usr/bin/env bash
# Full repository verification gate.
# Root `go test ./...` does NOT descend into nested modules, so this script
# must run every module. U18-P3-5：模块清单由 git 跟踪的 go.mod 派生（不再手写
# 清单——新增嵌套模块会静默漏测），并断言与下方显式基线逐项一致：
# 新增/删除模块必须在此处显式确认，否则脚本失败（parity guard）。
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-no-audit-artifacts.sh

# 基线（评审点）：与 git ls-files 派生结果不一致即失败。
baseline_modules=(
  "."
  "caddydeps"
  "caddygeoip"
  "geoipnames"
  "wafiplist"
)

modules=()
while IFS= read -r module; do
  modules+=("$module")
done < <(
  git ls-files 'go.mod' '*/go.mod' \
    | sed -e 's|/go.mod$||' -e 's|^go.mod$|.|' \
    | sort -u
)

if [[ "${modules[*]}" != "${baseline_modules[*]}" ]]; then
  echo "module list drift: git-derived=[${modules[*]}] baseline=[${baseline_modules[*]}]" >&2
  echo "add/remove the module in baseline_modules (and gofmt targets) explicitly" >&2
  exit 1
fi

for module in "${modules[@]}"; do
  echo "== go vet ./... ($module) =="
  (cd "$module" && go vet ./...)
done

echo "== gofmt =="
unformatted="$(gofmt -l internal cmd caddygeoip wafiplist geoipnames caddydeps)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt required:" >&2
  echo "$unformatted" >&2
  exit 1
fi

for module in "${modules[@]}"; do
  echo "== go test ./... -count=1 ($module) =="
  (cd "$module" && go test ./... -count=1)
done

echo "== frontend tests/typecheck/build =="
# vue-tsc 看不到模板编译期错误，发布契约要求真实 vite build
(cd web && npm test && npm run typecheck:test && npm run build:vite)

echo "all verification gates passed"

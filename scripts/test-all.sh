#!/usr/bin/env bash
# Full repository verification gate.
# Root `go test ./...` does NOT descend into nested modules, so this script
# enumerates every module explicitly. Keep the list in sync with `go.mod`
# files at the repository root, `caddygeoip/`, `wafiplist/`, `geoipnames/`
# and `caddydeps/`.
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-no-audit-artifacts.sh

modules=(
  "."
  "caddygeoip"
  "wafiplist"
  "geoipnames"
  "caddydeps"
)

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

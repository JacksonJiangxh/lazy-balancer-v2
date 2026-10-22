#!/usr/bin/env bash
# Full repository verification gate.
# Root `go test ./...` does NOT descend into nested modules, so this script
# must run every module. 模块清单由 git 跟踪的 go.mod 派生（不手写——新增嵌套
# 模块会静默漏测），并与显式基线逐项比对：新增/删除模块必须在此处显式确认，
# 否则脚本失败（parity guard）。
set -euo pipefail

cd "$(dirname "$0")/.."

# 守卫本体 + 守卫自检（自检在临时夹具仓里验证命中面与误报边界——守卫的
# 模式退化必须在这里先红，而不是等到审计产物真的混进公网仓库）。
./scripts/check-no-audit-artifacts.sh
./scripts/tests/guard-selftest.sh

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

# 目录发现 parity：文件系统里任何含 go.mod 的目录都必须入列——git 未跟踪的
# 模块不得静默存在（否则 go vet/go test 漏跑而脚本仍绿）。VCS 元数据、依赖目录、
# 本地工具目录与工作树副本一律剪掉。
discovered_modules="$(
  find . \
    \( -name .git -o -name node_modules -o -name .worktrees -o -name .omp \
       -o -name .agent -o -name .superpowers -o -name .omo -o -name .sisyphus \
       -o -name .opencode -o -name dist \) -prune \
    -o -name go.mod -print \
    | sed -e 's|^\./||' -e 's|/go.mod$||' -e 's|^go.mod$|.|' | LC_ALL=C sort -u
)"
git_modules="$(printf '%s\n' "${modules[@]}" | LC_ALL=C sort -u)"
if [[ "$discovered_modules" != "$git_modules" ]]; then
  echo "module discovery drift: filesystem=[$discovered_modules] git=[$git_modules]" >&2
  echo "untracked module directories must be added to git (or removed)" >&2
  exit 1
fi

for module in "${modules[@]}"; do
  echo "== go vet ./... ($module) =="
  (cd "$module" && go vet ./...)
done

# gofmt 目标由模块清单派生：根模块的 Go 包目录取自 git 跟踪的 .go 文件（排除嵌套
# 模块前缀），嵌套模块直接扫模块目录本身。新增嵌套模块自动入列——不再维护
# 硬编码目录清单（漏列模块会让格式检查静默失效）。
nested_re=""
for module in "${modules[@]}"; do
  [[ "$module" == "." ]] && continue
  nested_re+="${nested_re:+|}${module}"
done

gofmt_targets=()
root_targets=()
if [[ -n "$nested_re" ]]; then
  go_files="$(git ls-files '*.go' | grep -Ev "^(${nested_re})/" || true)"
else
  go_files="$(git ls-files '*.go')"
fi
if [[ -n "$go_files" ]]; then
  while IFS= read -r dir; do
    root_targets+=("$dir")
    gofmt_targets+=("$dir")
  done < <(printf '%s\n' "$go_files" | awk -F/ 'NF>1{print $1} NF==1{print "."}' | LC_ALL=C sort -u)
fi
for module in "${modules[@]}"; do
  [[ "$module" == "." ]] || gofmt_targets+=("$module")
done

# 派生结果与模块清单 parity：每个模块必须至少贡献一个 gofmt 目标。
for module in "${modules[@]}"; do
  if [[ "$module" == "." ]]; then
    if [[ ${#root_targets[@]} -eq 0 ]]; then
      echo "gofmt parity: 根模块未派生任何 Go 包目录（git ls-files '*.go' 为空？）" >&2
      exit 1
    fi
  elif ! printf '%s\n' "${gofmt_targets[@]}" | grep -qxF "$module"; then
    echo "gofmt parity: 模块 $module 未进入 gofmt 目录清单" >&2
    exit 1
  fi
done

echo "== gofmt (${gofmt_targets[*]}) =="
unformatted="$(gofmt -l "${gofmt_targets[@]}")"
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

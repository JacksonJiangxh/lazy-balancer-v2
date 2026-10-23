#!/usr/bin/env bash
# Full repository verification gate.
# Root `go test ./...` does NOT descend into nested modules, so this script
# must run every module. 模块清单由 git 跟踪的 go.mod 派生（不手写——新增嵌套
# 模块会静默漏测），并与显式基线逐项比对：新增/删除模块必须在此处显式确认，
# 否则脚本失败（parity guard）。
set -euo pipefail

cd "$(dirname "$0")/.."

# 守卫本体 + 守卫自检（审计产物/批量编辑两个守卫的自检在临时夹具仓里验证命中面
# 与误报边界——守卫的模式退化必须在这里先红，而不是等到审计产物真的混进公网仓库）。
./scripts/check-no-audit-artifacts.sh
./scripts/check-bulk-edit-safety.sh
./scripts/tests/guard-selftest.sh
./scripts/tests/bulk-edit-safety-selftest.sh

# 启动链工件语法：docker-entrypoint.sh 是每次部署的唯一入口（语法错误 = 面板
# 不可用，且只在容器启动时暴露，此前无任何门禁触碰它）；scripts/ 全部按 bash
# 解析。sh -n / bash -n 只做语法不执行，零成本纯增益。
echo "== shell syntax (entrypoint + scripts) =="
sh -n docker-entrypoint.sh
# 未跟踪的脚本同样入面：「先写脚本 → 跑门禁 → 再 git add」是常见顺序，
# 只看受控文件会让新脚本的语法错误在提交后才暴露（与 gofmt 门同口径）。
while IFS= read -r script; do
  bash -n "$script"
done < <(git ls-files --cached --others --exclude-standard 'scripts/*.sh')

# 出厂引导 Caddyfile 的引擎级校验：内容与 entrypoint heredoc 的同构性由
# cmd/server 的钉测试机械比对（下方 go test 覆盖）；此处校验引擎是否接受。
# caddy 不可用时显式 SKIP（不静默通过），结构比对仍在跑。
echo "== bootstrap Caddyfile engine validation =="
if command -v caddy >/dev/null 2>&1; then
  caddy validate --config config/Caddyfile --adapter caddyfile
else
  echo "SKIP: caddy 不可用——结构同构由 cmd/server/bootstrap_caddyfile_test.go 覆盖，引擎校验未执行"
fi

# 部署工件静态校验：compose 的锚点引用/键名拼错只在 compose up 时暴露
# （logging/ulimits/healthcheck 走 YAML 锚点，extra_hosts 等键名同理）。
# docker 或 compose 子命令不可用时显式 SKIP（不静默通过）。
echo "== compose config validation =="
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose config --quiet
else
  echo "SKIP: docker/compose 不可用——compose 锚点与键名未校验"
fi

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

# 两侧各自排序后比较：模块清单顺序不承载语义（新增字典序在前的模块不应被
# 报成 drift），集合不同才是真 drift。
if [[ "$(printf '%s\n' "${modules[@]}" | LC_ALL=C sort)" != "$(printf '%s\n' "${baseline_modules[@]}" | LC_ALL=C sort)" ]]; then
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

# Dockerfile 后端阶段用显式 COPY 清单（避免 web/docs/scripts 等非 Go 变更 bust
# Go 编译层）——清单漏项只会在镜像构建时才暴露（go build 缺包），故在此比对：
# git 跟踪的顶层 Go 目录必须全部在清单内。
# 门禁本体按 `^FROM ... AS <stage>` 切块，只断言 backend 阶段：xcaddy-builder
# 阶段也 COPY 同名模块目录（--with 载体），整文件汇总会掩盖 backend 侧的漏项。
# 自检在临时夹具仓里验证该边界（删 backend 的 wafiplist/geoipnames 必红）。
echo "== Dockerfile backend COPY manifest =="
./scripts/check-dockerfile-copy-manifest.sh
./scripts/tests/dockerfile-copy-gate-selftest.sh

for module in "${modules[@]}"; do
  echo "== go vet ./... ($module) =="
  (cd "$module" && go vet ./...)
done

# gofmt 目标由模块清单派生：根模块的 Go 包目录取自 git 跟踪 + 未跟踪（未被
# .gitignore 忽略）的 .go 文件（排除嵌套模块前缀），嵌套模块直接扫模块目录本身。
# 含未跟踪文件是刻意的——「先写新文件 → 跑门禁 → 再 git add」是常见顺序，
# 只看受控文件会让格式门在该顺序下给假绿。新增嵌套模块自动入列——不再维护
# 硬编码目录清单（漏列模块会让格式检查静默失效）。
nested_re=""
for module in "${modules[@]}"; do
  [[ "$module" == "." ]] && continue
  nested_re+="${nested_re:+|}${module}"
done

gofmt_targets=()
root_targets=()
if [[ -n "$nested_re" ]]; then
  go_files="$(git ls-files --cached --others --exclude-standard '*.go' | grep -Ev "^(${nested_re})/" || true)"
else
  go_files="$(git ls-files --cached --others --exclude-standard '*.go')"
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

# 镜像构建等价性冒烟：镜像内是 CGO_ENABLED=0 GOOS=linux 交叉编译，与本地
# go test 的构建参数不同（平台/cgo 相关代码路径不进测试面）。四个嵌套模块由
# xcaddy 在镜像内以同一组参数编译插件，其 linux-only 编译错误（构建标签/
# syscall/cgo 分支）此前只在发版构建暴露——按模块清单逐个交叉编译。
# 根模块是 main 包，产物丢 /dev/null；嵌套模块用 go install 配临时 GOBIN，
# 不落仓库（库模块本不产二进制，未来出现 main 包也不会污染工作树）。
echo "== image-build equivalence (GOOS=linux CGO_ENABLED=0 go build) =="
cross_bin="$(mktemp -d "${TMPDIR:-/tmp}/lb-crossbuild.XXXXXX")"
for module in "${modules[@]}"; do
  case "$module" in
    .) CGO_ENABLED=0 GOOS=linux go build -o /dev/null ./cmd/server ;;
    *) (cd "$module" && GOBIN="$cross_bin" CGO_ENABLED=0 GOOS=linux go install ./...) ;;
  esac
done
rm -rf "$cross_bin"

# 竞态门：并发核心（任务引擎 + 中间件限流/白名单缓存 + 进程内 Caddy 协作/
# 监督器探测）此前只在本地手工跑 -race，且 middleware 不在覆盖内——限流桶
# （双层锁 + 换代计数）、API Key 白名单缓存、认证审计限流、MCP 响应缓冲都在
# 这个包里。全量 -race 会把门禁时长成倍拉长，故只覆盖并发密集入口。
echo "== go test -race (concurrency cores) =="
go test -race -count=1 ./internal/taskengine ./internal/middleware ./cmd/...

echo "== frontend tests/typecheck/build =="
# vue-tsc 看不到模板编译期错误，发布契约要求真实 vite build
(cd web && npm test && npm run typecheck:test && npm run build:vite)

echo "all verification gates passed"

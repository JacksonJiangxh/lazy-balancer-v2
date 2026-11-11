#!/bin/bash
# 生产就绪验证（TASK-2026-1111-02 · 回源 Host 自研第 4 项）：
# 证明**生产渲染链吐出的配置能被 Caddy 真实解码链加载**。
#
# 为什么分两步：Caddy 解码链只能在能 import caddy 的模块里跑。本仓主模块
# （lazy-balancer-v2）刻意不依赖 github.com/caddyserver/caddy/v2——Caddy 由
# xcaddy `--with` 单独编译（见 Dockerfile:29-72），因此 internal/services 拿不到
# caddyhttp.Route。故：
#
#   第 1 步（internal/services）：用生产渲染链生成完整配置（混合态 + 自定义
#     路由），断言 lb_upstream_host 节点与三级回退取值，并写出产物。
#     用例：TestEmitConfigForValidate_emitsMixedOriginConfig
#   第 2 步（caddygeoip）：读第 1 步产物，走 Route.UnmarshalJSON →
#     Route.Provision → ctx.LoadModule 按 "handler" 键分派的真实路径。
#     用例：TestCaddyDecodeChain
#
# 用法：/bin/bash scripts/verify-generated-config-decodes.sh
# 退出码非 0 即失败（任一步红都会透出）。
#
# 注意：本脚本只做验证，不参与 gate.sh 判据（gate.sh 判据逻辑属禁改面）。
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "必须在 git 仓库内运行" >&2
  exit 1
}

out="$(mktemp -t gen-caddy-XXXXXX.json)"
trap 'rm -f "$out"' EXIT

fail=0

echo "== 1/2 生成生产配置（internal/services）=="
if CADDY_DECODE_CONFIG_OUT="$out" \
  go test -count=1 -run TestEmitConfigForValidate_emitsMixedOriginConfig -v ./internal/services/; then
  echo "生成侧 OK（产物 $out）"
else
  echo "生成侧 FAIL" >&2
  fail=1
fi

if [[ $fail -eq 0 ]]; then
  echo
  echo "== 2/2 Caddy 真实解码链加载（caddygeoip）=="
  if (cd caddygeoip && CADDY_DECODE_CONFIG_IN="$out" \
    go test -count=1 -run TestCaddyDecodeChain -v .); then
    echo "解码侧 OK"
  else
    echo "解码侧 FAIL" >&2
    fail=1
  fi
fi

echo
if [[ $fail -eq 0 ]]; then
  echo "VERIFY: PASS（生成产物可被 Caddy 解码链加载）"
else
  echo "VERIFY: FAIL" >&2
fi
exit $fail

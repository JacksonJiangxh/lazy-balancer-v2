#!/bin/sh
set -e

# Use /app/data as the single persistent data directory.
export XDG_DATA_HOME=/app/data
mkdir -p /app/data/caddy

# F62-28(第 62 轮审计):Caddy 崩溃监督器——前台运行 Caddy(退出即回收,零僵尸),
# 崩溃自动重启(退避),admin 停止(pause 文件)不重启(尊重用户 stop_caddy 操作)。
# lazy-balancer 的 startCaddy/stopCaddy handler 经 pause 文件与监督器协调:
#   stopCaddy: 先建 pause → admin API 停 → 监督器见 pause 进入等待环
#   startCaddy: 删 pause → 监督器 ≤1s 检测到 → 启动 Caddy(handler 等 admin 就绪)
CADDY_PAUSE_FILE=/tmp/lazy-balancer-caddy-paused

# Initialize database on first run
if [ ! -f /app/data/lazy-balancer.db ]; then
    echo "Initializing database..."
    /usr/local/bin/lazy-balancer --init
fi

# Generate Caddyfile if not exists
if [ ! -f /app/config/Caddyfile ]; then
    # F63-B8-1:镜像内恒有出厂 config/Caddyfile(COPY 进镜像),挂载空目录
    # 覆盖时直接写最小合法配置(admin 端口);原 .dist 分支为死路径(无该文件)
    echo ":2019" > /app/config/Caddyfile
fi

# Set timezone from database if available
if [ -f /app/data/lazy-balancer.db ]; then
    TZ=$(sqlite3 /app/data/lazy-balancer.db "SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1" 2>/dev/null || echo "Asia/Shanghai")
    export TZ
    echo "Timezone: $TZ"
fi

# —— Caddy 监督器(后台子 shell,容器生命周期存活)——
# 设计:
#   • Caddy 前台运行(caddy run 阻塞)——退出即被 shell 回收,零僵尸进程
#   • 退出后查 pause 文件:存在=admin 停止(用户意图),进入等待环
#   • 不存在=崩溃,1s 重启;连续 ≥5 次退避 30s 后重置计数(再给机会)
#   • startCaddy handler 删 pause 后监督器 ≤1s 检测并启动(等待环 1s 粒度)
#   • 容器 stop:PID1(lazy-balancer)退出 → 容器 teardown 杀全部进程(含监督器)
(
  # set +e: 监督器必须扛住 Caddy 的非零退出(被杀/崩溃)——外层 set -e 会在
  # caddy run 返回非零时杀死监督器本身(实测:kill -9 后监督器变僵尸不自愈)
  set +e
  echo $$ > /tmp/lazy-balancer-caddy-supervisor.pid
  # 监督器日志双写: stdout(docker logs) + lazy-balancer.log(运行日志弹框可见,
  # 时间戳格式与 services.Logf 对齐)——用户在基础设置→运行日志可看完整自愈链
  APP_LOG="${LOG_FILE:-/app/logs/lazy-balancer.log}"
  sup_log() {
    LINE="$(date '+%Y/%m/%d %H:%M:%S') [caddy-supervisor] $1"
    echo "$LINE"
    echo "$LINE" >> "$APP_LOG" 2>/dev/null
  }
  CRASHES=0
  while true; do
    # 暂停等待环(admin stop 后持 pause;startCaddy 删除后 ≤1s 退出本环)
    while [ -f "$CADDY_PAUSE_FILE" ]; do
      sleep 1
    done

    sup_log "Starting Caddy..."
    caddy run --config /app/config/Caddyfile --adapter caddyfile &
    CADDY_PID=$!

    # 等 admin 就绪后重应用 last-good 配置(重启后 Caddy 只有 Caddyfile 的
    # 基础形态,443 规则等需经 admin API /load 重放——否则崩溃自愈后 HTTPS 缺失)
    for i in 1 2 3 4 5 6 7 8 9 10; do
      if wget -q -O /dev/null -T 1 http://localhost:2019/config/ 2>/dev/null; then
        if [ -s /app/data/last_good_caddy_config.json ]; then
          if wget -q -O /dev/null -T 5 --header="Content-Type: application/json" \
            --post-file=/app/data/last_good_caddy_config.json \
            http://localhost:2019/load 2>/dev/null; then
            sup_log "Re-applied last known good config (last_good 快照)"
          else
            sup_log "WARN: last-good config re-apply failed"
          fi
        fi
        # trigger 文件:lazy-balancer 侧监听后走与启动完全相同的 DB 渲染→校验→
        # 应用流程(权威修正——last_good 只是快速恢复桥,可能滞后于 DB)
        echo restarted > /tmp/caddy-restarted
        break
      fi
      sleep 1
    done

    # 等待 Caddy 退出(wait 同时回收进程——零僵尸)
    wait $CADDY_PID
    CODE=$?
    sup_log "Caddy exited (code $CODE)"

    # admin 停止(pause 已建)→ 不重启,回等待环
    if [ -f "$CADDY_PAUSE_FILE" ]; then
      sup_log "Admin stop detected, standing by..."
      CRASHES=0
      continue
    fi

    # 崩溃 → 退避重启
    CRASHES=$((CRASHES+1))
    if [ "$CRASHES" -lt 5 ]; then
      sup_log "Crash #$CRASHES, restarting in 1s"
      sleep 1
    else
      sup_log "Crash #$CRASHES, backing off 30s"
      sleep 30
      CRASHES=0
    fi
  done
) &

# Start backend (PID 1 — 容器 stop 时优雅退出,teardown 杀监督器+Caddy)
echo "Starting Lazy Balancer..."
exec /usr/local/bin/lazy-balancer serve

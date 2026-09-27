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
    if [ -f /app/config/Caddyfile.dist ]; then
        cp /app/config/Caddyfile.dist /app/config/Caddyfile
    else
        echo ":2019" > /app/config/Caddyfile
    fi
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
  CRASHES=0
  while true; do
    # 暂停等待环(admin stop 后持 pause;startCaddy 删除后 ≤1s 退出本环)
    while [ -f "$CADDY_PAUSE_FILE" ]; do
      sleep 1
    done

    echo "[caddy-supervisor] Starting Caddy..."
    caddy run --config /app/config/Caddyfile --adapter caddyfile
    CODE=$?
    echo "[caddy-supervisor] Caddy exited (code $CODE)"

    # admin 停止(pause 已建)→ 不重启,回等待环
    if [ -f "$CADDY_PAUSE_FILE" ]; then
      echo "[caddy-supervisor] Admin stop detected, standing by..."
      CRASHES=0
      continue
    fi

    # 崩溃 → 退避重启
    CRASHES=$((CRASHES+1))
    if [ "$CRASHES" -lt 5 ]; then
      echo "[caddy-supervisor] Crash #$CRASHES, restarting in 1s"
      sleep 1
    else
      echo "[caddy-supervisor] Crash #$CRASHES, backing off 30s"
      sleep 30
      CRASHES=0
    fi
  done
) &

# Start backend (PID 1 — 容器 stop 时优雅退出,teardown 杀监督器+Caddy)
echo "Starting Lazy Balancer..."
exec /usr/local/bin/lazy-balancer serve

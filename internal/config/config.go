package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultLogFile = "/app/logs/lazy-balancer.log"

type Config struct {
	// Server
	// Port 是管理面板 HTTP/HTTPS 监听口（PANEL_PORT env / 配置文件 port 字段，
	// 默认 8000）。admin TLS 启用时面板与 admin 同口（见 cmd/server/main.go）。
	Port      int    `json:"port"`
	DataDir   string `json:"data_dir"`
	StaticDir string `json:"static_dir"`
	Version   string `json:"version"`

	// Proxy 默认监听口（HTTP_PORT / HTTPS_PORT env，默认 80/443）。
	// host 网络下这俩就是 Caddy 实际绑定的端口，"换端口"=换监听口，不是端口转发。
	// 语义范围（2026-10-10 用户裁定）：仅影响「默认值/兜底语义」——新建规则向导
	// 默认值、TLS 联动、80/443 保留端口判定、空域名兜底站、HTTP→HTTPS 跳转的
	// Location 自引用判定；存量规则的 listen_port 是持久化数据，不随之迁移。
	HTTPPort  int `json:"http_port"`
	HTTPSPort int `json:"https_port"`

	// Caddy
	// CaddyAdminURL(2026-09-19 第 43 轮 LB43-1 裁定):生产 admin 恒
	// 127.0.0.1:2019(渲染侧 caddy.go 硬编码),本字段(与 caddy_metrics_url)
	// 仅服务测试注入与指标地址;受支持部署不传 -config,恒取默认。
	CaddyAdminURL   string `json:"caddy_admin_url"`
	CaddyMetricsURL string `json:"caddy_metrics_url"`

	// Metrics
	MetricsInterval int `json:"metrics_interval"` // seconds

	// Node
	NodeName string `json:"node_name"`

	// Log
	LogFile string `json:"log_file"` // effective runtime log path (LOG_FILE env or default)

	// JWT
	JWTSecret string `json:"jwt_secret"`

	// Backup: 自动备份落盘目录（调度器仅主节点运行）
	BackupDir string `json:"backup_dir"`
}

func Load(path string) *Config {
	// Default values
	cfg := &Config{
		Port:            envPort("PANEL_PORT", 8000),
		HTTPPort:        envPort("HTTP_PORT", 80),
		HTTPSPort:       envPort("HTTPS_PORT", 443),
		DataDir:         "/app/data",
		StaticDir:       "/app/ui",
		CaddyAdminURL:   "http://localhost:2019",
		CaddyMetricsURL: "http://localhost:2019/metrics",
		MetricsInterval: 30,
		NodeName:        getEnv("NODE_NAME", "node-1"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		Version:         getEnv("APP_VERSION", "v2.3.6"),
		LogFile:         getEnv("LOG_FILE", defaultLogFile),
	}

	// Load from config file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// S-3：配置文件读取失败必须可见（与下方解析失败分支对称）——静默回落
			// 默认值会让「指定了 -config 却没生效」排查无门。
			log.Printf("config: failed to read config file %s (%v); using defaults", path, err)
		} else {
			// Try to parse as JSON (simple approach)
			var fileCfg map[string]interface{}
			if jerr := json.Unmarshal(data, &fileCfg); jerr != nil {
				// R72 二十六次 W3-3：文件存在但解析失败必须可见——静默回落
				// 默认值会让「改了配置没生效」排查无门。
				log.Printf("config: file %s exists but failed to parse (%v); using defaults", path, jerr)
			} else {
				if v, ok := fileCfg["data_dir"].(string); ok && v != "" {
					cfg.DataDir = v
				}
				if v, ok := fileCfg["static_dir"].(string); ok && v != "" {
					cfg.StaticDir = v
				}
				if v, ok := fileCfg["port"].(float64); ok {
					cfg.Port = int(v)
				}
				if v, ok := fileCfg["http_port"].(float64); ok {
					cfg.HTTPPort = int(v)
				}
				if v, ok := fileCfg["https_port"].(float64); ok {
					cfg.HTTPSPort = int(v)
				}
				if v, ok := fileCfg["caddy_admin_url"].(string); ok && v != "" {
					cfg.CaddyAdminURL = v
				}
				if v, ok := fileCfg["caddy_metrics_url"].(string); ok && v != "" {
					cfg.CaddyMetricsURL = v
				}
				if v, ok := fileCfg["metrics_interval"].(float64); ok && v > 0 {
					cfg.MetricsInterval = max(5, int(v))
				}
			}
		}
	}

	// 自动备份目录(v2.3.x):默认挂 DataDir 同级 backup(容器 /app/data → /app/backup，
	// 本地 ./data → ./backup)；BACKUP_DIR env 可覆盖。计算在配置文件解析之后——
	// data_dir 可被文件覆盖，目录锚点必须取最终值。
	cfg.BackupDir = getEnv("BACKUP_DIR", filepath.Join(filepath.Dir(cfg.DataDir), "backup"))

	// JWT secret: env wins; otherwise persist a random one so tokens survive
	// restarts and the secret is never predictable.
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = loadOrCreateJWTSecret(cfg.DataDir)
	}

	// R72 二十六次 W3-3：端口范围校验——port=0 会绑随机端口、>65535 只在
	// 监听时才报错，均早失败为佳。
	// U8b-P5-5（第 65 轮）：校验对称补齐（metrics_interval 有钳位而 port 无）
	if cfg.Port < 1 || cfg.Port > 65535 {
		log.Printf("config: invalid port %d (config file port field); falling back to 8000", cfg.Port)
		cfg.Port = 8000
	}
	// 代理默认口同口径校验：env/配置文件给到非法值（0/负数/>65535）不得静默
	// 渲染出 :0 监听（Caddy 绑随机口）——回退出厂默认并留痕。
	if cfg.HTTPPort < 1 || cfg.HTTPPort > 65535 {
		log.Printf("config: invalid HTTP_PORT %d; falling back to 80", cfg.HTTPPort)
		cfg.HTTPPort = 80
	}
	if cfg.HTTPSPort < 1 || cfg.HTTPSPort > 65535 {
		log.Printf("config: invalid HTTPS_PORT %d; falling back to 443", cfg.HTTPSPort)
		cfg.HTTPSPort = 443
	}
	// 面板口与代理口互斥：同口会让面板规则校验/admin TLS 探测自锁（面板抢占
	// 80 后 Caddy 无法绑），且规则侧 80/443 判定与管理口判定冲突。
	if cfg.HTTPPort == cfg.Port || cfg.HTTPSPort == cfg.Port {
		log.Printf("config: PANEL_PORT %d collides with proxy port (HTTP_PORT=%d HTTPS_PORT=%d); panel keeps %d",
			cfg.Port, cfg.HTTPPort, cfg.HTTPSPort, cfg.Port)
	}

	return cfg
}

// envPort 读取端口类环境变量：未设/非法/越界一律回落默认值（非法值早失败于
// 日志，不静默生效）。
func envPort(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		log.Printf("config: invalid %s=%q; falling back to %d", key, value, defaultValue)
		return defaultValue
	}
	return port
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadOrCreateJWTSecret(dataDir string) string {
	secretPath := filepath.Join(dataDir, "jwt_secret")
	if data, err := os.ReadFile(secretPath); err == nil && len(data) >= 32 {
		return string(data)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成 JWT 密钥失败: %v", err)
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		// N-6：目录创建失败必须可见——此前静默跳过写入，JWT 密钥每次启动
		// 随机重生成（旧令牌全部失效）且零日志信号；与下方写失败分支对称。
		log.Printf("JWT 密钥目录 %s 创建失败（重启后令牌将失效）: %v", dataDir, err)
	} else if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		log.Printf("JWT 密钥写入 %s 失败（重启后令牌将失效）: %v", secretPath, err)
	}
	return secret
}

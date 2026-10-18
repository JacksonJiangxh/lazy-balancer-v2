package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
)

const defaultLogFile = "/app/logs/lazy-balancer.log"

type Config struct {
	// Server
	Port      int    `json:"port"`
	DataDir   string `json:"data_dir"`
	StaticDir string `json:"static_dir"`
	Version   string `json:"version"`

	// Caddy
	// CaddyAdminURL 是生产 Caddy Admin API（配置加载、状态、生命周期与任务
	// 守卫）的唯一地址；CaddyMetricsURL 是所有 Prometheus 指标采集的唯一地址，
	// 两者可指向同机不同端口/路径，指标消费不得再由 admin URL 拼接。
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

// configFileKeys 是配置文件（-config）支持且会被解析的键集合。其余键不参与
// 解析（log_file/jwt_secret/backup_dir/node_name/version 只接受环境变量或
// 默认值），出现在文件中时逐条告警——静默忽略会让「改了配置没生效」无迹可循。
var configFileKeys = map[string]struct{}{
	"data_dir":          {},
	"static_dir":        {},
	"port":              {},
	"caddy_admin_url":   {},
	"caddy_metrics_url": {},
	"metrics_interval":  {},
}

// minJWTSecretBytes 是 JWT/OIDC state 签名密钥的最短长度（HS256 强度下限）。
// 文件通道（loadOrCreateJWTSecret）与环境变量通道共用本阈值——历史问题-2：旧实现
// 只校验文件通道，JWT_SECRET=abc 这类 3 字节密钥可直接绕过。
const minJWTSecretBytes = 32

// metricsIntervalMax 是 metrics_interval 的合理上限（24h）。超出范围的浮点
// 直接转 int 是未定义语义（巨值可能回绕成负数再被静默抬到下限），必须先判界。
const metricsIntervalMax = 86400

// jwtSecretStrongEnough 判定密钥是否满足最短长度。空串（未配置）不走本判定
// ——文件通道会生成随机密钥。
func jwtSecretStrongEnough(secret string) bool { return len(secret) >= minJWTSecretBytes }

// Load 加载运行配置：默认值 → 配置文件（仅 configFileKeys 支持的键）→ 环境变量。
// 配置文件中的未知键逐条 log 告警后忽略；读取/解析失败同样可见（回退默认值）。
func Load(path string) *Config {
	// Default values
	cfg := &Config{
		Port:            8000,
		DataDir:         "/app/data",
		StaticDir:       "/app/ui",
		CaddyAdminURL:   "http://localhost:2019",
		CaddyMetricsURL: "http://localhost:2019/metrics",
		MetricsInterval: 30,
		NodeName:        getEnv("NODE_NAME", "node-1"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		Version:         getEnv("APP_VERSION", "v2.3.8"),
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
				// 历史问题 二十六次 W3-3：文件存在但解析失败必须可见——静默回落
				// 默认值会让「改了配置没生效」排查无门。
				log.Printf("config: file %s exists but failed to parse (%v); using defaults", path, jerr)
			} else {
				// 历史问题（历史）：未知键必须可见——支持键之外的字段不会生效。
				unsupported := make([]string, 0, len(fileCfg))
				for key := range fileCfg {
					if _, supported := configFileKeys[key]; !supported {
						unsupported = append(unsupported, key)
					}
				}
				sort.Strings(unsupported)
				for _, key := range unsupported {
					log.Printf("config: ignoring unsupported config key %q in %s", key, path)
				}
				// 支持键但 JSON 类型错误同样不得静默：沿用默认值的同时逐键告警，
				// 避免 port/data_dir 误配后看似「配置未生效」甚至切到空库。
				invalidTypes := make([]string, 0, len(configFileKeys))
				for key := range configFileKeys {
					value, exists := fileCfg[key]
					if !exists {
						continue
					}
					validType := false
					switch key {
					case "port", "metrics_interval":
						_, validType = value.(float64)
					default:
						_, validType = value.(string)
					}
					if !validType {
						invalidTypes = append(invalidTypes, key)
					}
				}
				sort.Strings(invalidTypes)
				for _, key := range invalidTypes {
					log.Printf("config: invalid type for key %q in %s; using default", key, path)
				}
				if v, ok := fileCfg["data_dir"].(string); ok && v != "" {
					cfg.DataDir = v
				}
				if v, ok := fileCfg["static_dir"].(string); ok && v != "" {
					cfg.StaticDir = v
				}
				if v, ok := fileCfg["port"].(float64); ok {
					// 历史问题-7（历史）：浮点截断不得静默——8000.9→8000 会让
					// 「配置未生效」无从排查。
					if v != math.Trunc(v) {
						log.Printf("config: port %v is not an integer; truncated to %d", v, int(v))
					}
					cfg.Port = int(v)
				}
				if v, ok := fileCfg["caddy_admin_url"].(string); ok && v != "" {
					cfg.CaddyAdminURL = v
				}
				if v, ok := fileCfg["caddy_metrics_url"].(string); ok && v != "" {
					cfg.CaddyMetricsURL = v
				}
				if v, ok := fileCfg["metrics_interval"].(float64); ok {
					// E81/历史问题-4：≤0 与超范围都必须可见（旧实现 0/负值静默回落
					// 默认 30s；巨值 float→int 转换是未定义语义，可能回绕成负数
					// 再被静默抬到 5s 高频采集）。先判界再转换。
					switch {
					case v <= 0:
						log.Printf("config: metrics_interval %v must be positive; using default %d", v, cfg.MetricsInterval)
					case v > metricsIntervalMax:
						log.Printf("config: metrics_interval %v above maximum %d; clamped to %d", v, metricsIntervalMax, metricsIntervalMax)
						cfg.MetricsInterval = metricsIntervalMax
					default:
						// 历史问题-7（历史）：下限钳位与截断均留痕（此前 1 被静默
						// 抬到 5、1.9 被静默截断——看似「配置未生效」）。
						if v < 5 {
							log.Printf("config: metrics_interval %v below minimum 5; clamped to 5", v)
						} else if v != math.Trunc(v) {
							log.Printf("config: metrics_interval %v is not an integer; truncated to %d", v, int(v))
						}
						cfg.MetricsInterval = max(5, int(v))
					}
				}
			}
		}
	}

	// 自动备份目录(v2.3.x):默认挂 DataDir 同级 backup(容器 /app/data → /app/backup，
	// 本地 ./data → ./backup)；BACKUP_DIR env 可覆盖。计算在配置文件解析之后——
	// data_dir 可被文件覆盖，目录锚点必须取最终值。
	// 历史问题：data_dir/backup_dir 进入投影与 @ipListFast 白名单前必须是绝对
	// 路径；相对路径会让 IPListDataDir 越出 AllowedPathPrefix，整份配置被拒。
	if abs, err := filepath.Abs(cfg.DataDir); err == nil {
		cfg.DataDir = abs
	}
	cfg.BackupDir = getEnv("BACKUP_DIR", filepath.Join(filepath.Dir(cfg.DataDir), "backup"))
	if abs, err := filepath.Abs(cfg.BackupDir); err == nil {
		cfg.BackupDir = abs
	}

	// JWT secret: env wins; otherwise persist a random one so tokens survive
	// restarts and the secret is never predictable.
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = loadOrCreateJWTSecret(cfg.DataDir)
	} else if !jwtSecretStrongEnough(cfg.JWTSecret) {
		// 历史问题-2：环境变量通道此前完全不校验长度（文件通道强制 ≥32 并再生）。
		// env 是运维显式输入，不自动替换（替换会让所有令牌静默失效），只告警
		// 可见；强度要求与文件通道同阈值。
		log.Printf("config: JWT_SECRET 环境变量过短（%d 字节 < %d）——JWT HS256 与 OIDC state 签名强度不足，请改用 ≥%d 字节的随机密钥",
			len(cfg.JWTSecret), minJWTSecretBytes, minJWTSecretBytes)
	}

	// 历史问题 二十六次 W3-3：端口范围校验——port=0 会绑随机端口、>65535 只在
	// 监听时才报错，均早失败为佳。
	// U8b-历史问题（历史）：校验对称补齐（metrics_interval 有钳位而 port 无）
	if cfg.Port < 1 || cfg.Port > 65535 {
		log.Printf("config: invalid port %d (config file port field); falling back to 8000", cfg.Port)
		cfg.Port = 8000
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadOrCreateJWTSecret(dataDir string) string {
	secretPath := filepath.Join(dataDir, "jwt_secret")
	if data, err := os.ReadFile(secretPath); err == nil {
		if jwtSecretStrongEnough(string(data)) {
			return string(data)
		}
		if len(data) > 0 {
			// ADNS-N1（历史）：非空过短密钥的覆写必须可见——此前静默
			// 重生成，旧令牌全部失效且零日志信号；与下方目录/写失败分支
			// 及端口回退的可见性准则对齐。空文件等同未初始化，不告警。
			log.Printf("JWT 密钥文件 %s 内容过短（%d 字节 < 32），已重新生成（旧令牌将失效）", secretPath, len(data))
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("生成 JWT 密钥失败: %v", err)
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		// 历史问题：目录创建失败必须可见——此前静默跳过写入，JWT 密钥每次启动
		// 随机重生成（旧令牌全部失效）且零日志信号；与下方写失败分支对称。
		log.Printf("JWT 密钥目录 %s 创建失败（重启后令牌将失效）: %v", dataDir, err)
	} else if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
		log.Printf("JWT 密钥写入 %s 失败（重启后令牌将失效）: %v", secretPath, err)
	}
	return secret
}

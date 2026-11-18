package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// handlers 测试库模板（JJC-20261118-001 B 线）。
//
// 根因与方案（任务令口径）：handlers 全量 596-622s，根因是 db.Initialize
// 测试调用约 1003 次全量迁移（实测单次 fresh Initialize ≈ 135ms）。本文件
// 提供任务令三件套装配路径：
//
//  1. 模板库一次建立（只读）：首个用例触发时经**真实 db.Initialize** 建立
//     一次（全部迁移 + pragma 守卫 + 指纹记录），随后关闭全部句柄——模板
//     自此只读，不共享任何句柄给用例（禁共享模板句柄）。
//  2. 每用例拷贝至独立临时目录：模板目录整体拷入用例 dataDir（-wal/-shm
//     兄弟文件一并拷贝，保留 0600 文件位）；主库直开、不重跑迁移，
//     metrics/audit 走导出的 db.InitializeMetricsDB / db.InitializeAuditDB
//     （保持代际绑定与系统审计 flush 语义，幂等建表在已迁移库上为毫秒级）；
//     内置 system 名单经 db.SeedSystemIPLists 按当前注册表重播（模板建于
//     默认注册表，用例装配前扩展注册表的场景由重播承接，见装配处注释）。
//  3. 按 schema 版本缓存跳过：模板建立时记录 sqlite_master 结构指纹
//     （type+name 排序清单 sha256）+ global_config 单例行存在性；每用例
//     拷贝后回读比对，一致才跳过迁移——不一致显性报错，绝不静默降级。
//
// 边界（机械护栏）：
//   - dataDir 已含主库文件（重启/再迁移模拟）→ 不拷模板，走真实
//     db.Initialize，保持「对既有库再初始化」的生产语义（钉测覆盖）。
//   - 迁移行为验证类测试不进模板，继续真实 Initialize（豁免登记见下）。
//   - 迁移框架本体（internal/db）零改动：本文件只位于 handlers 测试面；
//     主库直开的 DSN/池参数与 db.Initialize 对齐（常量钉住注释 + 直开后
//     pragma 回读校验，任一侧漂移即显性红）。
//
// 动态豁免登记（迁移行为验证类，不进模板，继续真实全量 Initialize）：
//  1. rule_features_test.go TestMigration_upstreamsEnabledNullNormalizedToDisabled
//     —— 同目录二次 Initialize 触发「存量 NULL enabled 上游归一」迁移；
//     用例先建库再降级 schema 播种存量形态，模板拷贝既覆盖播种形态、也
//     掩盖「对既有库再初始化跑迁移」这一被测路径。
//  2. rule_features_test.go TestMigration_lbRulesEnabledNullNormalizedToDisabled
//     —— 同上（lb_rules.enabled NULL 归一）。
//  3. initTestDBFromTemplate 自身「dataDir 已含主库文件 → 回退真实
//     Initialize」分支保持重启/再迁移语义（本文件钉测覆盖）。
//
// 任务令静态豁免清单（db 包 10 个迁移/PRAGMA 测试文件）不经本 helper，零触碰。
const (
	// testMainDBFilename 主库文件名——db.Initialize 的落盘名（db 包未导出，
	// 按值钉住；改名时「既有库判定」失灵并显性红，不会静默错拷）。
	testMainDBFilename = "lazy-balancer.db"
	// testMainDBDSNParams 必须与 internal/db/db.go 的 sqliteWALDSNParams
	// 逐字一致（db 包未导出）。护栏双保险：①模板建立走真实 Initialize，
	// 生产口径由 applySQLiteRuntimePragmas 验证；②本 helper 每次直开后
	// 专用连接回读三参数（journal_mode/busy_timeout/synchronous），任一
	// 不符立即报错。
	testMainDBDSNParams = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)"
)

// testDBTemplate 进程级单例：模板目录 + 结构指纹。只缓存成功建立；
// 建立失败不缓存（下次调用重试，失败原因原样上抛给用例，fail-visible）。
var (
	testDBTemplateMu  sync.Mutex
	testDBTemplateDir string
	testDBTemplateFP  string
)

// ensureTestDBTemplate 返回（模板目录, 结构指纹）。模板经真实 db.Initialize
// 建立后关闭全部句柄：此后模板只读、零共享句柄。
func ensureTestDBTemplate() (string, string, error) {
	testDBTemplateMu.Lock()
	defer testDBTemplateMu.Unlock()
	if testDBTemplateDir != "" {
		return testDBTemplateDir, testDBTemplateFP, nil
	}
	templateDir, err := os.MkdirTemp("", "lb-handlers-testdb-template-*")
	if err != nil {
		return "", "", err
	}
	if err := db.Initialize(templateDir); err != nil {
		os.RemoveAll(templateDir)
		return "", "", fmt.Errorf("建立 handlers 测试库模板（真实全量 Initialize）: %w", err)
	}
	fingerprint, err := readMainDBSchemaFingerprint(db.DB)
	if err != nil {
		db.Close()
		os.RemoveAll(templateDir)
		return "", "", fmt.Errorf("记录模板 schema 指纹: %w", err)
	}
	// 关闭模板句柄：最后一次连接关闭即 checkpoint 收敛 WAL（实测模板目录
	// 仅余 3 个 .db 文件）。此后模板只读，任何用例不得持有模板句柄。
	if err := db.Close(); err != nil {
		os.RemoveAll(templateDir)
		return "", "", fmt.Errorf("关闭模板句柄: %w", err)
	}
	testDBTemplateDir = templateDir
	testDBTemplateFP = fingerprint
	return testDBTemplateDir, testDBTemplateFP, nil
}

// cleanupTestDBTemplate 移除进程级模板目录。模板生命周期超出任何单个用例
// （t.Cleanup 接不住），由 TestMain 在 m.Run() 之后调用。
func cleanupTestDBTemplate() {
	testDBTemplateMu.Lock()
	defer testDBTemplateMu.Unlock()
	if testDBTemplateDir != "" {
		os.RemoveAll(testDBTemplateDir)
		testDBTemplateDir = ""
		testDBTemplateFP = ""
	}
}

// copyTestDBTemplate 把模板目录整体拷入 dataDir：目录递归、文件内容与文件
// 位逐项保留（-wal/-shm 兄弟文件若存在则一并拷贝）。
func copyTestDBTemplate(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			return err
		}
		return dst.Close()
	})
}

// readMainDBSchemaFingerprint 计算 sqlite_master 结构指纹（type+name 排序
// 清单 sha256）——「schema 版本」的可观测单源：拷贝不全/模板损坏/迁移集
// 变化都会使指纹失配并显性红。
func readMainDBSchemaFingerprint(database *sql.DB) (string, error) {
	rows, err := database.Query("SELECT type, name FROM sqlite_master ORDER BY type, name")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	digest := sha256.New()
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return "", err
		}
		fmt.Fprintf(digest, "%s\x00%s\n", kind, name)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// verifyCopiedMainDBPragmas 在专用连接上回读三参数（镜像
// internal/db applySQLiteRuntimePragmas 的验证口径）：直开路径的 DSN 参数
// 若与生产 Initialize 漂移，此处立即红，不静默分叉。
func verifyCopiedMainDBPragmas(database *sql.DB) error {
	conn, err := database.Conn(testDBContext)
	if err != nil {
		return fmt.Errorf("checkout dedicated conn for pragma verify: %w", err)
	}
	defer conn.Close()
	expected := []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"busy_timeout", "30000"},
		{"synchronous", "1"}, // NORMAL=1
	}
	for _, e := range expected {
		var got string
		if err := conn.QueryRowContext(testDBContext, "PRAGMA "+e.pragma).Scan(&got); err != nil {
			return fmt.Errorf("verify pragma %q: %w", e.pragma, err)
		}
		if got != e.want {
			return fmt.Errorf("pragma %q = %q on fresh conn, want %q（测试直开 DSN 与 db.sqliteWALDSNParams 漂移？）", e.pragma, got, e.want)
		}
	}
	return nil
}

// testDBContext 直开/回读共用的上下文（用例装配为毫秒级，不复用用例级
// ctx 以保持与 db.Initialize 等价的装配语义）。
var testDBContext = context.Background()

// initTestDBFromTemplate 以模板库装配用例测试库（db.Initialize 的测试面
// 等价替身，语义对齐：成功后三库句柄就位 + SetDB 注册；失败关闭新句柄并
// 还原包级句柄，错误原样上抛）。
func initTestDBFromTemplate(t *testing.T, dataDir string) error {
	t.Helper()

	// 既有库语义保留：dataDir 已含主库文件（重启/再迁移模拟）不拷模板，
	// 走真实 db.Initialize（迁移按生产路径对既有库执行）。
	if _, statErr := os.Stat(filepath.Join(dataDir, testMainDBFilename)); statErr == nil {
		return db.Initialize(dataDir)
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}

	templateDir, fingerprint, err := ensureTestDBTemplate()
	if err != nil {
		return err
	}

	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	var database, metricsDB, auditDB *sql.DB
	// 镜像 db.Initialize 失败路径：关闭本轮新开句柄、还原包级三句柄。
	fail := func(err error) error {
		if auditDB != nil && auditDB != oldAuditDB {
			err = errors.Join(err, auditDB.Close())
		}
		if metricsDB != nil && metricsDB != oldMetricsDB {
			err = errors.Join(err, metricsDB.Close())
		}
		if database != nil {
			err = errors.Join(err, database.Close())
		}
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		return err
	}

	if err := copyTestDBTemplate(templateDir, dataDir); err != nil {
		return fmt.Errorf("拷贝 handlers 测试库模板: %w", err)
	}

	dbPath := filepath.Join(dataDir, testMainDBFilename)
	database, err = sql.Open("sqlite", dbPath+testMainDBDSNParams)
	if err != nil {
		return fail(fmt.Errorf("open copied main database: %w", err))
	}
	// 池参数与 db.Initialize 主库一致（10/5/30m，db.go 同源注释）。
	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	database.SetConnMaxLifetime(30 * time.Minute)
	if err := database.Ping(); err != nil {
		return fail(fmt.Errorf("ping copied main database: %w", err))
	}
	if _, err := database.ExecContext(testDBContext, "PRAGMA journal_mode=WAL"); err != nil {
		return fail(fmt.Errorf("apply pragma journal_mode=WAL: %w", err))
	}
	if err := verifyCopiedMainDBPragmas(database); err != nil {
		return fail(err)
	}
	gotFingerprint, err := readMainDBSchemaFingerprint(database)
	if err != nil {
		return fail(fmt.Errorf("read copied main database schema fingerprint: %w", err))
	}
	if gotFingerprint != fingerprint {
		return fail(fmt.Errorf("copied main database schema fingerprint mismatch (got %s, want %s)——拷贝不全或模板损坏", gotFingerprint, fingerprint))
	}
	// 数据存在性抽检（指纹只覆盖 schema；单例行 > 0 证明拷贝承载了迁移
	// 后数据面。抽检下限防过度钉死生产数据形态）。
	var configRows int
	if err := database.QueryRowContext(testDBContext, "SELECT COUNT(*) FROM global_config").Scan(&configRows); err != nil {
		return fail(fmt.Errorf("probe global_config on copied database: %w", err))
	}
	if configRows < 1 {
		return fail(fmt.Errorf("copied database global_config rows=%d, want >= 1（模板数据面缺失）", configRows))
	}
	// 权限收口对齐 db.Initialize 的 secureSQLiteArtifacts（直开后 -wal/-shm
	// 由驱动新建，文件位需显式收口）。
	for _, artifact := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(artifact, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(fmt.Errorf("chmod %s: %w", artifact, err))
		}
	}

	db.DB = database
	// 内置 system 名单播种重播（单源 db.SeedSystemIPLists，Initialize 迁移
	// 管线 db.go:2192 与导入提交后 config_backup.go:6794 同源）：模板建于
	// **默认注册表**，而旧流程每次 Initialize 按调用时注册表播种——用例在装配
	// 前扩展 db.ThreatSystemLists()（如 TestThreatLib_usesThreatSystemListRegistry
	// 的 future_source 场景）时，拷贝库缺扩展名单行，list link 必断。此处按
	// 当前注册表重播等价承接：收敛库零写（默认注册表仅数条只读 COUNT 探测），
	// 扩展注册表只补缺失行。
	if err := db.SeedSystemIPLists(database); err != nil {
		return fail(fmt.Errorf("seed system ip lists: %w", err))
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		return fail(fmt.Errorf("initialize metrics database: %w", err))
	}
	metricsDB = db.MetricsDB
	if err := db.InitializeAuditDB(dataDir); err != nil {
		return fail(fmt.Errorf("initialize audit database: %w", err))
	}
	auditDB = db.AuditDB
	db.SetDB(database)
	return nil
}

// TestInitTestDBFromTemplate_providesMigratedSchema 钉测：模板拷贝路径必须
// 交付与真实 Initialize 等价的「已迁移全 schema + 数据面」库（三库句柄就位、
// 代际可读、审计表可查、pragma 为生产口径）。
func TestInitTestDBFromTemplate_providesMigratedSchema(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := initTestDBFromTemplate(t, dir); err != nil {
		t.Fatalf("init from template: %v", err)
	}
	if db.DB == nil || db.MetricsDB == nil || db.AuditDB == nil {
		t.Fatalf("handles not installed: db=%v metrics=%v audit=%v", db.DB != nil, db.MetricsDB != nil, db.AuditDB != nil)
	}
	var configRows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM global_config").Scan(&configRows); err != nil {
		t.Fatalf("global_config: %v", err)
	}
	if configRows < 1 {
		t.Fatalf("global_config rows=%d, want >= 1", configRows)
	}
	if db.MetricsDBGeneration() == "" {
		t.Fatal("metrics generation must be bound after template init")
	}
	if _, err := db.AuditDB.Query("SELECT id FROM audit_log LIMIT 1"); err != nil {
		t.Fatalf("audit_log query: %v", err)
	}
	conn, err := db.DB.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var busyTimeout string
	if err := conn.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != "30000" {
		t.Fatalf("busy_timeout=%s, want 30000（生产口径）", busyTimeout)
	}
	// 迁移后形状抽检：newColumns 通道的透传列必须存在（与真实 Initialize
	// 同形状；列缺失=模板建于不完整迁移）。
	if _, err := db.DB.Exec("SELECT passthrough_upstream FROM lb_rules LIMIT 1"); err != nil {
		t.Fatalf("migrated column probe: %v", err)
	}
}

// TestInitTestDBFromTemplate_fallsBackToRealInitializeOnExistingDataDir 钉测：
// dataDir 已含主库文件（重启/再迁移模拟）时必须回退真实 db.Initialize——
// 模板拷贝不得覆盖既有库（迁移行为验证类用例依赖该语义）。
func TestInitTestDBFromTemplate_fallsBackToRealInitializeOnExistingDataDir(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := initTestDBFromTemplate(t, dir); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET caddy_config='{"marker":true}' WHERE id=1`); err != nil {
		t.Fatalf("seed marker row: %v", err)
	}
	// 第二次 Initialize（同目录）：必须走真实 Initialize 且不得覆盖种子行。
	supersededDB, supersededMetrics, supersededAudit := db.DB, db.MetricsDB, db.AuditDB
	if err := initTestDBFromTemplate(t, dir); err != nil {
		t.Fatalf("second init (existing data dir): %v", err)
	}
	closeSupersededTestDBHandles(supersededDB, supersededMetrics, supersededAudit)
	var marker string
	if err := db.DB.QueryRow(`SELECT caddy_config FROM global_config WHERE id=1`).Scan(&marker); err != nil {
		t.Fatalf("query marker row: %v", err)
	}
	if marker != `{"marker":true}` {
		t.Fatalf("marker row lost across re-initialize: caddy_config=%q（模板拷贝覆盖了既有库）", marker)
	}
}

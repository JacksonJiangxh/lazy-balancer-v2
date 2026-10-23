package db

import (
	"context"
	"database/sql"
	"errors"
)

// SetupAdminFallbackUserID 是「初始化创建的首个用户」的历史恒等值：旧库/旧
// 备份不带 is_setup_admin 标记时，保护判定回落到该 id（标记缺失即缺省）。
const SetupAdminFallbackUserID = 1

// setupAdminExecer 抽象 *sql.DB 与 *sql.Tx：迁移、导入事务与快照应用都要在
// 各自的事务内完成同一套标记归一。
type setupAdminExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// EnsureSetupAdminFlag 归一 break-glass 管理入口标记：
//   - 标记只允许落在「启用的管理员」行上，非管理员/禁用行的陈旧标记先清除；
//   - 多条启用管理员同时带标记（导入的备份、集群快照或带外改库的形态）收敛为
//     单条：只有最低 id 的启用管理员保留标记，其余清零。**仅在多标记时生效**——
//     单标记（哪怕落在非最低 id）是载荷/主端的显式事实，归一不得迁移；
//   - 若没有任何启用管理员带标记（旧库补列、旧备份/旧快照还原、表重建，
//     或标记行被带外改写），把最低 id 的启用管理员补标为入口。
//
// 幂等：稳态（恰有一个启用管理员带标记）零写入。空库或无启用管理员时零命中
// ——「至少一个启用管理员」由调用方各自的门负责（导入校验/启停保护）。
func EnsureSetupAdminFlag(ctx context.Context, ex setupAdminExecer) error {
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=0
		WHERE COALESCE(is_setup_admin,0)=1 AND NOT (role='admin' AND is_enabled=1)`); err != nil {
		return err
	}
	// 仅在**多标记并存**时收敛（先清非最低 id 的启用管理员标记，再交给下方补标）
	// ——单标记不迁移：集群快照/备份载荷显式把标记落在非最低 id 的管理员上时，
	// 该标记是主端事实，清零会违背「标记随载荷落库」的语义（随后补标又落到最低
	// id，等于篡改载荷）。多标记形态下两条相邻语句都不命中（补标分支要求「没有
	// 任何启用管理员带标记」），才会永久滞留、被 handlers 判为不可删/禁/降级。
	// 该 SQLite 子查询自引用 users 表在 UPDATE 中合法（同库既有迁移同款形态）。
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=0
		WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1
		  AND id <> (SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)
		  AND (SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1) > 1`); err != nil {
		return err
	}
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=1
		WHERE id=(SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)
		  AND NOT EXISTS (SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1)`); err != nil {
		return err
	}
	return nil
}

// setupAdminFlagWriteProbe 判定启动期标记归一是否可能改写任何行：三条 UPDATE
// 互为前置（前一条的结果影响后一条），无法逐条穷举，故一次只读探测取三条件
// 的并集——S1 陈旧标记（带标记但非启用管理员）、S2 多标记并存、S3 无标记需
// 补标。稳态（恰有一个启用管理员带标记）恒 false，收敛库启动零写。只读查询
// 不取写锁（_txlock=immediate 下写语句才是立即写事务）。
const setupAdminFlagWriteProbe = `SELECT EXISTS(
	SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND NOT (role='admin' AND is_enabled=1)
	UNION ALL
	SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1
	  AND id <> (SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)
	  AND (SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1) > 1
	UNION ALL
	SELECT 1 FROM users
	  WHERE id=(SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)
	  AND NOT EXISTS (SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1)
)`

// ensureSetupAdminFlagAtStartup 是启动迁移对 EnsureSetupAdminFlag 的入口：
// 先只读探测，命中才在一个写事务内完成三条归一（口径纳入
// startupMigrationWriteTx，二次启动收敛库零写）。
func ensureSetupAdminFlagAtStartup() error {
	var needed bool
	if err := DB.QueryRow(setupAdminFlagWriteProbe).Scan(&needed); err != nil {
		return err
	}
	if !needed {
		return nil
	}
	return withWriteTx("setup admin flag normalization", func(tx *sql.Tx) error {
		return EnsureSetupAdminFlag(context.Background(), tx)
	})
}

// IsSetupAdmin 判定用户是否为受保护的 break-glass 管理入口。
// 标记缺失（任何行都未标记——旧库尚未跑迁移/直连旧测试库）时回落到
// SetupAdminFallbackUserID，保持升级窗口内的保护面不塌陷。
func IsSetupAdmin(ctx context.Context, ex setupAdminExecer, userID int) (bool, error) {
	var flagged int
	err := ex.QueryRowContext(ctx, `SELECT COALESCE(is_setup_admin,0) FROM users WHERE id=?`, userID).Scan(&flagged)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if flagged == 1 {
		return true, nil
	}
	var marked int
	if err := ex.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&marked); err != nil {
		return false, err
	}
	if marked == 0 {
		return userID == SetupAdminFallbackUserID, nil
	}
	return false, nil
}

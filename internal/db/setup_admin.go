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
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=1
		WHERE id=(SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)
		  AND NOT EXISTS (SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1)`); err != nil {
		return err
	}
	return nil
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

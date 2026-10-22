package services

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

func AuthenticateClusterToken(ctx context.Context, database *sql.DB, token string) (int, error) {
	if token == "" {
		return 0, ErrInvalidClusterAuth
	}
	// 与注册密钥同口径：SQL 只筛选非秘密的 approved 状态，哈希比较全部在
	// Go 常量时间原语内完成；扫完候选集，不以数据库 memcmp 的提前退出泄露
	// 哈希前缀匹配长度。节点数远小于规则/事件表，且认证端点已有 IP 限流。
	rows, err := database.QueryContext(ctx, `SELECT id,COALESCE(cluster_token_hash,'') FROM nodes WHERE is_approved=1`)
	if err != nil {
		return 0, fmt.Errorf("校验集群令牌: %w", err)
	}
	providedHash := tokenHash(token)
	nodeID := 0
	for rows.Next() {
		var candidateID int
		var storedHash string
		if err := rows.Scan(&candidateID, &storedHash); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("校验集群令牌: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(storedHash), []byte(providedHash)) == 1 {
			nodeID = candidateID
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("校验集群令牌: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("校验集群令牌: %w", err)
	}
	if nodeID == 0 {
		return 0, ErrInvalidClusterAuth
	}
	return nodeID, nil
}

func AuthenticateRegistrationSecret(ctx context.Context, database *sql.DB, nodeID int, secret string) error {
	if secret == "" {
		return ErrInvalidClusterAuth
	}
	// 哈希比对改常量时间——镜像 RegistrationStatus 的
	// 形态(SQL 等值比对是提前退出的 memcmp,泄露哈希前缀匹配长度)。
	// 到期过滤依赖存储值与请求密钥无关,保留在 WHERE;仅密钥相关比较移出。
	var storedSecretHash string
	err := database.QueryRowContext(ctx, "SELECT COALESCE(registration_secret,'') FROM nodes WHERE id=? AND (registration_secret_expires_at IS NULL OR registration_secret_expires_at='' OR datetime(registration_secret_expires_at) > datetime('now'))", nodeID).Scan(&storedSecretHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidClusterAuth
	}
	if err != nil {
		return fmt.Errorf("校验注册凭证: %w", err)
	}
	if storedSecretHash == "" || subtle.ConstantTimeCompare([]byte(storedSecretHash), []byte(tokenHash(secret))) != 1 {
		return ErrInvalidClusterAuth
	}
	return nil
}

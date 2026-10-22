package handlers

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// systemTaskLogPathResolver 任务日志路径批量解析入口：普通注册任务直接按
// 任务 ID；cert-job 动态工作项一次全表预载 job_id→rule_id，供批量调用方
// （logstats 逐任务解析）复用避免 N+1。单条入口（GetSystemTaskLogs）走
// systemTaskLogPath 的单行查询，不经本 resolver。
type systemTaskLogPathResolver struct {
	certJobRuleIDs map[string]string
	certJobsLoaded bool
}

func (r *systemTaskLogPathResolver) resolve(taskID string) (string, error) {
	if !strings.HasPrefix(taskID, "cert-job:") {
		return taskengine.TaskLogPath(taskID), nil
	}
	if !r.certJobsLoaded {
		if db.DB == nil {
			r.certJobRuleIDs = map[string]string{}
			r.certJobsLoaded = true
		} else {
			rows, err := db.DB.Query(`SELECT id, rule_id FROM cert_jobs`)
			if err != nil {
				return "", err
			}
			loaded := make(map[string]string)
			for rows.Next() {
				var jobID int
				var ruleID string
				if scanErr := rows.Scan(&jobID, &ruleID); scanErr != nil {
					rows.Close()
					return "", scanErr
				}
				loaded[strconv.Itoa(jobID)] = ruleID
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return "", err
			}
			r.certJobRuleIDs = loaded
			r.certJobsLoaded = true
		}
	}
	ruleID := r.certJobRuleIDs[strings.TrimPrefix(taskID, "cert-job:")]
	if ruleID == "" {
		return "", nil
	}
	return services.CertJobLogPath(ruleID), nil
}

func systemTaskLogPath(taskID string) (string, error) {
	// 单条入口（日志弹框/MCP get_system_task_logs）：单行查询替代全表
	// 预载——cert_jobs 行数=规则×域名（无保留期清理，长期可达数千行），
	// 每次查看日志全表扫不可持续。批量调用方（logstats）仍走 resolver
	// 预载（一次全表扫供 N 次解析复用，N+1 防护不变）。
	if !strings.HasPrefix(taskID, "cert-job:") {
		return taskengine.TaskLogPath(taskID), nil
	}
	if db.DB == nil {
		return "", nil
	}
	jobID, err := strconv.Atoi(strings.TrimPrefix(taskID, "cert-job:"))
	if err != nil || jobID <= 0 {
		return "", nil
	}
	var ruleID string
	err = db.DB.QueryRow(`SELECT rule_id FROM cert_jobs WHERE id=?`, jobID).Scan(&ruleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if ruleID == "" {
		return "", nil
	}
	return services.CertJobLogPath(ruleID), nil
}

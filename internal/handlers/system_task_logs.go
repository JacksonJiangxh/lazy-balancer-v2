package handlers

import (
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// systemTaskLogPathResolver 是任务日志路径唯一解析入口。普通注册任务直接按
// 任务 ID；cert-job 动态工作项首批载入 job_id→rule_id，单条与批量调用共享
// 同一实现，批量调用方复用 resolver 避免 N+1。
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
	var resolver systemTaskLogPathResolver
	return resolver.resolve(taskID)
}

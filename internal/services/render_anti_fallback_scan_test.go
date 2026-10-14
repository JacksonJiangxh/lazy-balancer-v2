package services

// 库值唯一真相（批 1+2）机制级反兜底钉测：
// 扫描 caddy.go 渲染函数体，断言不存在「零值守卫 + 数字字面量赋值」的写死
// 兜底模式（`if x <= 0 { x = <N> }` / `if x == 0 { x = <N> }`）。规则→全局
// 变量回退（x = rule.GlobalY）与错误返回不属兜底（治理允许的分层缺省/fail-
// visible），不在扫描命中面。允许列表逐条携带 Ruling（类型②省略型/治理范围
// 外），双向精确匹配：扫描出清单外命中=有人往渲染层塞了写死兜底（FAIL）；
// 清单条目在源码中消失=该条目已退役、清单过期（FAIL）——防允许列表腐化。

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// antiFallbackScanTargets 渲染层函数清单（写死兜底禁区），按源文件分组。
// 批 3 起扫描面扩展到 security.go 渲染函数与 caddy.go 安全渲染消费函数。
var antiFallbackScanTargets = map[string][]string{
	"caddy.go": {
		"generateCaddyConfigWithCertSource",
		"buildCaddyLogging",
		"resolveRuleOverrides",
		"resolveProxyTimeouts",
		"formatFlushInterval",
		"GenerateSingleRuleCaddyConfig",
		"generateHTTPRouteObjects",
		"buildHTTPHandleChain",
		"buildTCPProxyRoute",
		"buildTCPServer",
		"buildRateLimitHandler",
		"buildBlockPageAttributionRoute",
		"buildBlockPageErrorRoute",
	},
	"security.go": {
		"BuildCorazaDirectives",
		"buildWafHandlerWithPolicy",
		"buildIPPrecheckDirectives",
		"emitBodyProcessorRules",
		"emitCustomRules",
		"emitCRSRuleGroupSelection",
		"emitScopedCRSExclusions",
	},
}

// antiFallbackAllowlist 允许列表：函数名 → 赋值形态 → Ruling。
// 类型②省略型/范围外字段的现行兜底，逐条披露于批 1+2/批 3 Ruling 报告。
var antiFallbackAllowlist = map[string]map[string]string{
	"generateCaddyConfigWithCertSource": {
		"weight = 1": "上游权重 weight<=0→1：upstreams.weight 非本批治理字段清单（范围外），原状保留；Caddy WRR 亦不接受零权重",
	},
	"buildHTTPHandleChain": {
		"weight = 1": "上游权重 weight<=0→1：同上（范围外，历史问题 分组层归一删除后链构建层唯一存留点）",
	},
	// 批 3 Ruling：block_status_code=类型②省略型（0=未设置，跟随默认 403）。
	// static_response 必须显式携带状态码，「省略」只能以默认值替换实现；写侧
	// 0 为合法值（枚举 400/401/403/404/503 仅约束非零），非兜底写死常量。
	"buildBlockPageAttributionRoute": {
		"statusCode = 403": "block_status_code=0→403：类型②省略型（0=未设置跟随默认 403），写侧 0 合法——批 3 Ruling 披露",
	},
	"buildBlockPageErrorRoute": {
		"statusCode = 403": "block_status_code=0→403：同 buildBlockPageAttributionRoute（类型②省略型）——批 3 Ruling 披露",
	},
	"buildIPPrecheckDirectives": {
		"denyStatus = 403": "阶段 1 预检 denyStatus=0→403：类型②省略型（0=规则未配阶段 1 拦截页，stage1BlockStatus 契约的未设置态；coraza deny 必须显式状态码，省略以默认 403 替换实现，保持 403 兜底归因边界）——批 3 Ruling 披露",
	},
}

func TestRenderLayer_hasNoHardcodedZeroFallbacks(t *testing.T) {
	fset := token.NewFileSet()

	scanned := map[string]bool{}
	violations := map[string]string{}
	for fileName, functions := range antiFallbackScanTargets {
		file, err := parser.ParseFile(fset, fileName, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", fileName, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, wanted := antiFallbackAllowlist[fn.Name.Name]; !wanted && !containsString(functions, fn.Name.Name) {
				continue
			}
			scanned[fn.Name.Name] = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifStmt, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				bin, ok := ifStmt.Cond.(*ast.BinaryExpr)
				if !ok || (bin.Op != token.EQL && bin.Op != token.LEQ) {
					return true
				}
				lit, ok := bin.Y.(*ast.BasicLit)
				if !ok || lit.Kind != token.INT || lit.Value != "0" {
					return true
				}
				ast.Inspect(ifStmt.Body, func(m ast.Node) bool {
					assign, ok := m.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, rhs := range assign.Rhs {
						if num, ok := rhs.(*ast.BasicLit); ok && num.Kind == token.INT {
							var buf bytes.Buffer
							_ = printer.Fprint(&buf, fset, assign)
							violations[fn.Name.Name+":"+buf.String()] = fset.Position(assign.Pos()).String()
							break
						}
					}
					return true
				})
				return true
			})
		}
	}

	// 双向核对：扫描面必须覆盖全部禁区函数（清单与源码同步）。
	for fileName, functions := range antiFallbackScanTargets {
		for _, name := range functions {
			if !scanned[name] {
				t.Errorf("scan list function %q not found in %s——清单与源码漂移，请更新 antiFallbackScanTargets", name, fileName)
			}
		}
	}

	// 方向一：清单外命中=新兜底混入渲染层。
	for key, pos := range violations {
		funcName, assign := splitScanKey(key)
		allowed, inAllowlist := antiFallbackAllowlist[funcName]
		reason, allowedAssign := allowed[assign]
		if !inAllowlist || !allowedAssign {
			t.Errorf("渲染函数 %s 出现清单外写死兜底 %q（%s）——库值唯一真相治理禁止在渲染层以数字字面量兜底无效库值；若为类型②省略型/范围外字段，请携 Ruling 加入 antiFallbackAllowlist", funcName, assign, pos)
			continue
		}
		_ = reason
	}

	// 方向二：清单条目必须仍存在于扫描命中（防允许列表腐化成死清单）。
	for funcName, entries := range antiFallbackAllowlist {
		for assign := range entries {
			if _, live := violations[funcName+":"+assign]; !live {
				t.Errorf("允许列表条目 %s:%q 在源码中已消失——兜底已退役，请同步删除该清单条目（防清单腐化）", funcName, assign)
			}
		}
	}
}

func splitScanKey(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

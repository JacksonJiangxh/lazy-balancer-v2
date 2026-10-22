package services

// 库值唯一真相（批 1+2）机制级反兜底钉测：
// 扫描 caddy.go 渲染函数体，断言不存在「零值守卫 + 字面量赋值」的写死
// 兜底模式（`if x <= 0 { x = <N> }` / `if x == 0 { x = <N> }`）。
// 形状扩展：字面量含 STRING（"5s"/"250ms" 类字符串兜底同在禁区）、命中面
// 扩到 else 链（`if x > 0 {…} else { x = "…" }` 的尾 else 兜底形态）、
// 赋值限定 plain `=`（:= 定义与 += 累加非兜底）。规则→全局变量回退
//（x = rule.GlobalY）与错误返回不属兜底（治理允许的分层缺省/fail-visible），
// 不在扫描命中面。允许列表逐条携带 Ruling（类型②省略型/治理范围外），
// 双向精确匹配：扫描出清单外命中=有人往渲染层塞了写死兜底（FAIL）；
// 清单条目在源码中消失=该条目已退役、清单过期（FAIL）——防允许列表腐化。
// 命中面扩展到 LSS(<0/<1)、NEQ(!=0)、GTR/GEQ 反向分支、
// switch/case 零值守卫与非 map 非空复合字面量默认值，并为每形态配夹具（
// TestFallbackScan_detectsEquivalentGuardShapes）——语义等价写法不得绕过机制。

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
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
		"buildStaticResponseHandler",
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
		"weight = 1": "上游权重 weight<=0→1：同上（范围外：分组层归一删除后链构建层唯一存留点）",
		// Ruling：HTTP 侧 try_duration==0 → 5s/250ms——存量 HTTP 行
		// 恒 0（列语义「0=默认重试窗口」，2026-09 渲染审计+方案 C 协议分叉已披露
		// UI/文档），行为不变的非治理形态；TCP 侧同列 0/-1 走显性报错/显式禁用，
		// 协议分叉为披露语义非写死兜底。td==-1 分支发射 retries=0 为「显式禁用
		// 重试」语义载体（cond 非零值守卫，不在扫描命中面）。
		`loadBalancing["try_duration"] = "5s"`:                    "HTTP 侧 try_duration==0→5s：存量 HTTP 行恒 0（0=默认重试窗口语义），方案 C 协议分叉+UI 已披露——G3 Ruling 披露",
		`loadBalancing["try_interval"] = "250ms"`:                 "HTTP 侧 try_interval==0→250ms：同上（与 5s 窗口成对发射）——G3 Ruling 披露",
		`serverName = "{lb.upstream_sni}"`:                        "逐上游回源域名在场时 SNI 改走占位符（逐连接展开实证）——host_header 缺省形态的发射形态切换（占位符 vs 静态值），非无效库值兜底；upstream-sni-host 方案披露——G3 Ruling 披露",
		`hostFallback = "{http.reverse_proxy.upstream.hostport}"`: "Host 回退 TLS 池形态：host_header 未配置时绑定上游 hostport 占位符（池形态分流），类型②省略型同族——G3 Ruling 披露",
		`hostFallback = "{http.request.hostport}"`:                "Host 回退常规池形态：host_header 未配置时绑定原始请求 hostport 占位符（现状复现）——G3 Ruling 披露",
		`sniFallback = "{http.reverse_proxy.upstream.host}"`:      "SNI 回退：host_header 未配置时绑定上游 host 占位符（stdlib 空 server_name 默认的同义载体）——G3 Ruling 披露",
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
	// 覆盖面扫描新发现：路径规则 static_response 的状态码
	// 缺省形态（写侧允许 0=未配置，声明默认 200；空字符串守卫不在扫描命中面）。
	"buildStaticResponseHandler": {
		"status = 200": "path rule ResponseStatus=0→200：类型②省略型（写侧允许 0=未配置并声明默认），非无效库值兜底——见该处 Ruling 披露",
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
			for assign, pos := range fallbackAssignmentsInFunction(fset, fn) {
				violations[fn.Name.Name+":"+assign] = pos
			}
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

	// 方向三：扫描包内全部非测试.go——渲染族命名函数若出现兜底
	// 形态却未登记 antiFallbackScanTargets，说明新增渲染文件/函数绕过了扫描面。
	listed := map[string]bool{}
	for fileName, functions := range antiFallbackScanTargets {
		for _, name := range functions {
			listed[fileName+"|"+name] = true
		}
	}
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	for _, path := range goFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !isRenderFamilyFunction(fn.Name.Name) {
				continue
			}
			if listed[path+"|"+fn.Name.Name] {
				continue
			}
			for assign, pos := range fallbackAssignmentsInFunction(fset, fn) {
				t.Errorf("渲染族函数 %s（%s）含兜底 %q（%s）但未登记 antiFallbackScanTargets——新增渲染函数必须纳入扫描面或携 Ruling 说明非渲染用途", fn.Name.Name, path, assign, pos)
			}
		}
	}
}

// fallbackAssignmentsInFunction 扫描函数体内的「零值守卫 + 字面量赋值」兜底
// 形态，返回赋值文本 → 位置。
// 形状：INT/STRING 字面量、plain `=`、else 链纳入。
// 扩展：LSS(<0/<1)、NEQ(!=0 的 else 链)、GEQ(>=1 的 else 链) 零值守卫、
// switch/case 的零值守卫分支、复合字面量默认值（`v = cfg{...}`）——原命中面
// 可被这些语义等价写法绕过，机制失效时无红灯。
func fallbackAssignmentsInFunction(fset *token.FileSet, fn *ast.FuncDecl) map[string]string {
	hits := map[string]string{}
	if fn.Body == nil {
		return hits
	}
	scanAssigns := func(branch ast.Node) {
		if branch == nil {
			return
		}
		ast.Inspect(branch, func(m ast.Node) bool {
			assign, ok := m.(*ast.AssignStmt)
			// 仅 plain `=`（= 定义与 += 累加非兜底赋值）。
			if !ok || assign.Tok != token.ASSIGN {
				return true
			}
			for _, rhs := range assign.Rhs {
				if isLiteralDefault(rhs) {
					var buf bytes.Buffer
					_ = printer.Fprint(&buf, fset, assign)
					hits[buf.String()] = fset.Position(assign.Pos()).String()
					break
				}
			}
			return true
		})
	}
	scanElseBlock := func(ifStmt *ast.IfStmt) {
		// 只扫终端 else 块；else-if 由链循环按各自守卫独立判定（直接 Inspect
		// else-if 节点会下钻其 body，把「非零值显式分支」误判为兜底）。
		if block, ok := ifStmt.Else.(*ast.BlockStmt); ok {
			scanAssigns(block)
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			// 逐级 else-if 链按各自守卫判定（外层守卫形态变化不改变
			// 内层判定的独立性）。
			matched := false
			for current := node; current != nil; {
				switch guardBranchOf(current.Cond) {
				case guardFallbackBody:
					scanAssigns(current.Body)
					matched = true
				case guardFallbackElse:
					scanElseBlock(current)
					matched = true
				case guardFallbackBoth:
					scanAssigns(current.Body)
					matched = true
				}
				next, ok := current.Else.(*ast.IfStmt)
				if !ok {
					break
				}
				current = next
			}
			if matched {
				// 守卫链的终端 else 块=链整体反向分支（旧实现同样纳入命中面：
				// `if td > 0 {…} else if td == -1 {…} else {5s}` 的兜底在此）。
				terminal := node
				for {
					next, ok := terminal.Else.(*ast.IfStmt)
					if !ok {
						break
					}
					terminal = next
				}
				if block, ok := terminal.Else.(*ast.BlockStmt); ok {
					scanAssigns(block)
				}
			}
		case *ast.SwitchStmt:
			// `switch { case x <= 0: x = 10 }` 与 `case x == 0:` 形态。
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					if guardBranchOf(expr) != guardNone {
						scanAssigns(&ast.BlockStmt{List: clause.Body})
						break
					}
				}
			}
		}
		return true
	})
	return hits
}

// guardBranch 枚举零值守卫的兜底分支位置。
type guardBranch int

const (
	guardNone guardBranch = iota
	guardFallbackBody
	guardFallbackElse
	guardFallbackBoth
)

// guardBranchOf 报告条件是否为零值/无效值守卫及其兜底赋值所在分支。整数域等价
// 形态：
//
//	x == 0 / x <= 0 / x < 0 / x < 1  → if 体
//	x != 0 / x >= 1                   → else 块
//	x > 0 → else 块 + if 体（命中面保留）
//
// GTR 保留 if 体扫描：`if len(x) > 0 { … }` 体内的字面量赋值由旧扫描器纳入，
// 收窄会让既有 allowlist 条目腐化——命中面只扩不收。
func guardBranchOf(cond ast.Expr) guardBranch {
	bin, isBinary := cond.(*ast.BinaryExpr)
	if !isBinary {
		return guardNone
	}
	lit, isInt := bin.Y.(*ast.BasicLit)
	if !isInt || lit.Kind != token.INT {
		return guardNone
	}
	switch bin.Op {
	case token.EQL, token.LEQ:
		if lit.Value == "0" {
			return guardFallbackBody
		}
	case token.LSS:
		if lit.Value == "0" || lit.Value == "1" {
			return guardFallbackBody
		}
	case token.NEQ:
		if lit.Value == "0" {
			return guardFallbackElse
		}
	case token.GTR:
		if lit.Value == "0" {
			return guardFallbackBoth
		}
	case token.GEQ:
		if lit.Value == "1" {
			return guardFallbackElse
		}
	}
	return guardNone
}

// isLiteralDefault 报告赋值右值是否为写死字面量默认值（INT/STRING 字面量、
// 非空命名/匿名结构的复合字面量或非空切片字面量）。排除：
//   - map 字面量（`m["k"] = map[string]interface{}{...}` 是结构装配，不是库值兜底）；
//   - 空复合字面量（`struct{}{}` 集合插入惯用法、`[]string{}` 非 nil 空切片 flag）。
func isLiteralDefault(rhs ast.Expr) bool {
	switch value := rhs.(type) {
	case *ast.BasicLit:
		return value.Kind == token.INT || value.Kind == token.STRING
	case *ast.CompositeLit:
		if _, isMap := value.Type.(*ast.MapType); isMap {
			return false
		}
		return len(value.Elts) > 0
	case *ast.UnaryExpr:
		// 负数字面量（-1）与一元取反同属字面量默认值。
		return value.Op == token.SUB && isLiteralDefault(value.X)
	}
	return false
}

// isRenderFamilyFunction 按命名识别渲染族函数
// build*/generate*/emit*/resolve*/format* 前缀，或 Handler/Directives/Route 后缀。
func isRenderFamilyFunction(name string) bool {
	for _, prefix := range []string{"build", "Build", "generate", "Generate", "emit", "Emit", "resolve", "Resolve", "format", "Format"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	for _, suffix := range []string{"Handler", "Directives", "Route"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
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

// 兜底扫描命中面必须覆盖语义等价写法——原实现只认
// `EQL/LEQ/GTR 对比 INT 0` 的 if 体，以下形态全部逃逸（机制失效时无红灯）：
//   - `x < 1`（LSS 对比 1，整数域等价 x<=0）；
//   - `x != 0 { … } else { x = 7 }`（NEQ 对比 0，兜底在 else 链）；
//   - `switch { case x <= 0: x = 10 }`（switch/case 零值守卫）；
//   - `if x == 0 { v = c{Timeout: 5} }`（复合字面量默认值）。
//
// 每个形态一个夹具：扫描器必须命中（否则「渲染层无写死兜底」第五链可被改写绕过）。
func TestFallbackScan_detectsEquivalentGuardShapes(t *testing.T) {
	fixtures := []struct {
		name   string
		source string
	}{
		{
			name:   "less-than-one",
			source: "package p\nfunc f(x int) int { if x < 1 { x = 5 }; return x }\n",
		},
		{
			name:   "not-equal-zero-else",
			source: "package p\nfunc f(x int) int { if x != 0 { x = x } else { x = 7 }; return x }\n",
		},
		{
			name:   "switch-case-zero-guard",
			source: "package p\nfunc f(x int) int { switch { case x <= 0: x = 10 }; return x }\n",
		},
		{
			name:   "composite-literal",
			source: "package p\ntype c struct{ Timeout int }\nfunc f(x int) c { var v c; if x == 0 { v = c{Timeout: 5} }; return v }\n",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, fixture.name+".go", fixture.source, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "f" {
					fn = candidate
					break
				}
			}
			if fn == nil {
				t.Fatal("fixture function f not found")
			}
			if hits := fallbackAssignmentsInFunction(fset, fn); len(hits) == 0 {
				t.Fatalf("等价兜底形态未被扫描命中——机制存在绕过路径: %s", fixture.source)
			}
		})
	}
}

// 反向形状：正常业务分支的数值赋值（非零值守卫）不得被误判为兜底。
func TestFallbackScan_ignoresNonZeroGuardBranches(t *testing.T) {
	source := "package p\nfunc f(x int) int { if x == 1 { x = 5 }; return x }\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "nonzero.go", source, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "f" {
			continue
		}
		if hits := fallbackAssignmentsInFunction(fset, fn); len(hits) != 0 {
			t.Fatalf("非零值守卫被误报为兜底: %v", hits)
		}
	}
}

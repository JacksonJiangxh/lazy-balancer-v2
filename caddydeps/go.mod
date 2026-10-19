module lazy-balancer-v2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，只声明镜像扫描要求的最低依赖版本（floor）。
// 实际约束机制分两层（E81-历史问题 口径修正）：
//  1. MVS floor：下方 require 是构建图的版本下限——其他依赖要求更低版本时
//     取高者；当前 Caddy v2.11.7 的传递图为 cel.dev/cel-go 0.32.0、grpc
//     1.83.2（与本 floor 等值），otel 1.46.0、x/net 0.60.0、x/crypto 0.57.0
//     （高于本 floor），因此 5/5 条 pin 今日均不产生抬升（2 等值 + 3 低于），
//     仅在未来传递图下移时才生效（PL历史问题 实测 caddygeoip/go.mod）。
//  2. 构建期断言：Dockerfile 的 `go version -m` 检查（阈值与下方 require 同值）
//     才是实际门禁——不达标直接失败。断言另含 github.com/corazawaf/coraza/v3
//     的区间 [v3.8.1, v3.9)：安全拦截判定依赖 coraza tx.ID 长度=16，该 pin 在
//     各 go.mod（根模块/caddygeoip/wafiplist），不是本模块的 floor。
// cel-go：Caddy v2.11.7 的 celmatcher 依赖 **cel.dev/cel-go v0.32.0**（模块
// 路径自上游切换后为 cel.dev/cel-go；github.com/google/cel-go 是另一个独立
// 模块路径——require 旧路径不参与本依赖图的 MVS，等于空转，历史 历史问题
// 修正）。调整下方 require 时同步 Dockerfile 断言阈值。
// go.sum 仅服务于本模块独立的 `go mod verify`（不参与 xcaddy 构建——替换模块
// 的依赖校验走构建主模块 go.sum），其版本代次与本模块图一致即可，无需跟
// caddygeoip/go.mod 同步。
require (
	cel.dev/cel-go v0.32.0
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0
	go.opentelemetry.io/otel/metric v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
	golang.org/x/crypto v0.56.0
	golang.org/x/net v0.58.0
	google.golang.org/grpc v1.83.2
)

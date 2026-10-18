module lazy-balancer-v2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，仅通过 MVS 抬升 Caddy 二进制的传递依赖版本，
// 满足镜像扫描的最低版本要求（见 Dockerfile xcaddy build 的 --with 引用）。
// cel-go：Caddy v2.11.7 的 celmatcher 依赖 **cel.dev/cel-go v0.32.0**（模块
// 路径自上游切换后为 cel.dev/cel-go；github.com/google/cel-go 是另一个独立
// 模块路径——require 旧路径不参与本依赖图的 MVS，等于空转，历史 历史问题
// 修正）。本钉版与上游同值，防传递解到更低偏移；调整时同步 Dockerfile 断言。
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

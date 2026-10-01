module lazy-balancer-v2/caddydeps

go 1.26.0

// 该模块不提供任何功能代码，仅通过 MVS 抬升 Caddy 二进制的传递依赖版本，
// 满足镜像扫描的最低版本要求（见 Dockerfile xcaddy build 的 --with 引用）。
// cel-go：Caddy v2.11.6 起自身要求 v0.29.2（celmatcher 已适配 v0.29 的
// interpreter API 变更）——本钉版随之从 v0.28.1 升至 v0.29.2 对齐上游，
// 防 MVS 解到 v0.28/v0.29 之外的偏移版本。调整时同步 Dockerfile 断言注释。
require (
	github.com/google/cel-go v0.29.2
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.45.0
	go.opentelemetry.io/otel/metric v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
	golang.org/x/crypto v0.56.0
	golang.org/x/net v0.58.0
	google.golang.org/grpc v1.83.2
)

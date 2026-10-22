#!/usr/bin/env bash
# 公网仓库守卫：审计过程记录、轮次测试与审计编号不得入库。
# 历史审计产物在私有审计仓；本脚本由 scripts/test-all.sh 与发布链调用。
#
# 三条独立通道，任一命中即失败：
#   1) 路径：审计报告目录与轮次测试文件名（Go/TS）——受控文件与未跟踪文件同扫，
#      仅跳过 .gitignore 已忽略者与构建/运行产物目录；
#   2) 内容：注释行与测试声明行里的审计编号/轮次元数据——覆盖 Go/TS/Vue/JS/CSS/
#      Markdown/Shell/YAML/SQL/go.mod/Dockerfile/docker-entrypoint.sh/
#      .dockerignore/Caddyfile。轮次引用按「审计动作共现」判定：裸轮次＋审计
#      动作（N 轮修复）、斜杠并列（第 N/N 轮审计）、无「第」的中文数字归属、
#      注释头被编辑截断的残骸（// N 轮）：…）都命中；循环轮次表述（每 N 轮
#      落行、连续 N 轮共识、第 N/N 轮打点）不按裸数字判罚；
#   3) 跨行拆字：“第”与“轮”之间被换行拆开书写同样命中（编号拆成两行不可绕过），
#      续行带注释前缀（“第”换行后接“// N 轮”）是同一形态的变体，一并命中。
#
# 误报收窄：白名单只锚定“审计编号形态”，不按裸数字判罚。百分位 P50/P95/P99、
# 版本串 v2.3.x、sha256/十六进制摘要、HTTP/3、TLS 1.3、PID1、X509、ED25519、
# HS256、LBF1 文件魔数等产品 token 不触发（见内嵌扫描器的 SHIELD 与纯十六进制
# 令牌过滤）。
#
# 用法：bash scripts/check-no-audit-artifacts.sh [--self-test]
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  exec bash "$script_dir/tests/guard-selftest.sh"
fi

cd "$script_dir/.."

# fail-closed：必须在 git 检出内运行——非 git 上下文无法枚举受控文件，拒绝静默通过。
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: 必须在 git 检出内运行本守卫（git rev-parse 失败，拒绝静默通过）" >&2
  exit 1
fi
if ! controlled=$(git ls-files --cached --others --exclude-standard); then
  echo "ERROR: git ls-files 失败——必须在 git 检出内运行本守卫" >&2
  exit 1
fi

# 构建产物/运行数据/本地工具目录一律不入扫描面（.gitignore 已覆盖大部分，
# 这里再显式声明一次：守卫不依赖 .gitignore 的完整性来避免扫描噪声）。
skip_re='^(\.git/|(.*/)?node_modules/|(.*/)?dist/|ui/|(.*/)?backup[^/]*/|(.*/)?data[^/]*/|(.*/)?logs[^/]*/|(.*/)?certs[^/]*/|(.*/)?waf[^/]*/|test-ui/|test-data/|(\.(omp|agent|superpowers|omo|sisyphus|opencode|worktrees|playwright-mcp))/)'

# ---------------------------------------------------------------------------
# 审计产物路径模式——单一事实源。
# 每条 = “<.gitignore 行><TAB><检测正则>”。.gitignore 的审计排除块必须与第一列
# 逐行一致（双向校验：多一行、少一行、改一行都失败），检测正则取第二列并集。
# 新增形态时两列同时加。
# ---------------------------------------------------------------------------
audit_path_rules=(
  $'docs/audit/\t^docs/audit/'
  $'**/audit[0-9]*_test.go\t(^|/)audit[0-9]+[^/]*_test\\.go$'
  $'**/*_audit[0-9]*_test.go\t(^|/)[^/]+_audit[0-9]+[^/]*_test\\.go$'
  $'**/audit_round[0-9]*_test.go\t(^|/)audit_round[0-9]+[^/]*_test\\.go$'
  $'**/r[0-9]*_test.go\t(^|/)r[0-9]+[^/]*_test\\.go$'
  $'**/round[0-9]*_test.go\t(^|/)round[0-9]+[^/]*_test\\.go$'
  $'**/*_r[0-9]*_test.go\t(^|/)[^/]+_r[0-9]+[^/]*_test\\.go$'
  $'**/*_round[0-9]*_test.go\t(^|/)[^/]+_round[0-9]+[^/]*_test\\.go$'
  $'**/*audit[0-9]*\t(^|/)[^/]*audit[0-9][^/]*'
  $'**/*round[0-9]*\t(^|/)[^/]*round[0-9][^/]*'
  $'**/*audit[0-9]*/\t(^|/)[^/]*audit[0-9][^/]*'
  $'**/*round[0-9]*/\t(^|/)[^/]*round[0-9][^/]*'
)

path_regex=""
ignore_expected=""
for rule in "${audit_path_rules[@]}"; do
  ignore_expected+="${rule%%$'\t'*}"$'\n'
  re="${rule#*$'\t'}"
  path_regex+="${path_regex:+|}(${re})"
done

# —— .gitignore 与模式表双向一致 ——
begin_marker='# >>> audit-artifact patterns'
end_marker='# <<< audit-artifact patterns'
if ! grep -qxF "$begin_marker" .gitignore || ! grep -qxF "$end_marker" .gitignore; then
  echo "ERROR: .gitignore 缺少审计排除块标记（${begin_marker} / ${end_marker}）" >&2
  exit 1
fi
if [[ "$(grep -cxF "$begin_marker" .gitignore)" != "1" || "$(grep -cxF "$end_marker" .gitignore)" != "1" ]]; then
  echo "ERROR: .gitignore 审计排除块标记重复" >&2
  exit 1
fi

actual_ignore="$(awk -v b="$begin_marker" -v e="$end_marker" '$0==b{f=1;next} $0==e{f=0} f' .gitignore | sed '/^[[:space:]]*$/d')"
expected_ignore="$(printf '%s' "$ignore_expected" | sed '/^[[:space:]]*$/d')"
if [[ "$(printf '%s\n' "$actual_ignore" | LC_ALL=C sort -u)" != "$(printf '%s\n' "$expected_ignore" | LC_ALL=C sort -u)" ]]; then
  echo "ERROR: .gitignore 审计排除块与本脚本模式表不一致（两侧模式集必须一一对应）：" >&2
  diff <(printf '%s\n' "$expected_ignore" | LC_ALL=C sort -u) \
       <(printf '%s\n' "$actual_ignore" | LC_ALL=C sort -u) | sed 's/^/  /' >&2 || true
  exit 1
fi

# —— 通道 1：路径 ——
bad_paths="$(printf '%s\n' "$controlled" | grep -v -E "$skip_re" | grep -E "$path_regex" || true)"
if [[ -n "$bad_paths" ]]; then
  echo "ERROR: 审计记录/轮次测试不得提交到公网仓库：" >&2
  echo "$bad_paths" >&2
  exit 1
fi

# —— 通道 2/3：内容与跨行拆字（内嵌扫描器）——
# 扫描面：受控 + 未跟踪（已按 .gitignore 与 skip_re 过滤）。
# 内容扫描豁免：仅限自检脚本（其内容即被测样本）。豁免面必须是显式单条——
# 数组长度断言防止它悄悄长成漏检通道。
content_exempt_paths=(scripts/tests/guard-selftest.sh)
if [[ ${#content_exempt_paths[@]} -ne 1 ]]; then
  echo "ERROR: 内容扫描豁免面必须恰好一条，实际：${content_exempt_paths[*]}" >&2
  exit 1
fi
content_exempt="^$(printf '%s' "${content_exempt_paths[0]}" | sed 's/[.]/\\./g')$"

scan_targets="$(printf '%s\n' "$controlled" \
  | grep -v -E "$skip_re" \
  | grep -v -E "$content_exempt" \
  | grep -E '\.(go|ts|vue|js|css|md|markdown|txt|sh|yml|yaml|sql|mod)$|(^|/)(Dockerfile[^/]*|docker-entrypoint\.sh|\.dockerignore|Caddyfile)$' \
  | while IFS= read -r f; do [[ -f "$f" ]] && printf '%s\n' "$f"; done || true)"

if [[ -n "$scan_targets" ]]; then
  # 内容/跨行扫描器用 perl 实现（跨行拆字需要整文件匹配；BSD grep 无 -P/-z
  # 等价能力）。缺 perl 时 fail-closed——不允许退化成只做行级扫描而静默通过。
  if ! command -v perl >/dev/null 2>&1; then
    echo "ERROR: 需要 perl 才能运行内容扫描（缺少 perl，拒绝静默通过）" >&2
    exit 1
  fi
  scan_prog="$(mktemp "${TMPDIR:-/tmp}/audit-guard-scan.XXXXXX.pl")"
  list_file="$(mktemp "${TMPDIR:-/tmp}/audit-guard-files.XXXXXX")"
  trap 'rm -f "$scan_prog" "$list_file"' EXIT

  cat >"$scan_prog" <<'PERL'
use strict;
use warnings;

# SHIELD：产品 token 先剥离，再匹配审计编号形态。剥离而非排除整行——同一行里
# 既有产品 token 又有审计编号时仍须命中。
my $shield = join '|',
  q{X-[A-Za-z][A-Za-z0-9-]*},            # X-LB-* 自定义头
  q{REQUEST-[0-9A-Z-]*}, q{RESPONSE-[0-9A-Z-]*},
  q{HTTP/[0-9.]+}, q{HTTP[0-9]},         # HTTP/3、HTTP2
  q{TLS[ ]?v?[0-9]+(\.[0-9]+)?}, q{QUIC[ ]?v?[0-9.]+},
  q{IPV[46]}, q{UTF-?8}, q{SHA-?[0-9]{3}}, q{HMAC-SHA256},
  q{(?:HS|RS|ES|PS|EdDSA)[0-9]{3}},      # JWT/PKI 算法名
  q{ED25519}, q{X25519}, q{X509}, q{P-256}, q{P256},
  q{AES-?[0-9]{3}(-GCM)?}, q{BASE64}, q{MD5},
  q{P[0-9]{2}(-P?[0-9]{2})?},            # P50/P95/P99 与 P50-P99 百分位
  q{v[0-9]+\.[0-9]+(?:\.[0-9x*]+)*(?:-[A-Za-z0-9.]+)?},  # 版本串 v2.3.x / v2.3.8-beta
  q{A-Za-z0-9}, q{YYYY-MM-DD}, q{NOT-NULL}, q{NULL-[a-z]+},
  q{BY-DESIGN}, q{TOP-LEVEL}, q{HTTP-only}, q{TCP-only}, q{HTTP-date},
  q{TLS-enabled}, q{TLS-only}, q{VERSION-only}, q{JSON-[A-Za-z]*},
  q{IP-control}, q{IP-level}, q{ACME-issued}, q{UPSERT-overwritten},
  q{AB-BA}, q{WEB-VIEWS-CORE}, q{UTC-[0-9]+}, q{MM-DD}, q{DOM-TOM},
  q{Apache-[0-9.]+}, q{CVE-[0-9]+(?:-[0-9]+)*}, q{RFC-?[0-9]+}, q{ISO-[0-9]+},
  q{HTTP-[0-9.]+}, q{TLS-[0-9.]+},
  q{CRS-active}, q{LBF1}, q{PID1}, q{DNS-01},
  q{MAX-[0-9]+}, q{MIN-[0-9]+},      # 容量边界常量（MAX-1 个自有键），非编号
  q{[A-F0-9]{16,}};                      # 长十六进制摘要（逐段哈希/指纹）

# 审计编号家族（历史出现过的全部形态）：
#   (a) 字母+数字开头，后接一段或多段短横线分段（序数-序号，或前缀-序数-序号）；
#   (b) 纯大写字母前缀 + 两段以上短横线分段（前缀-序数-序号）。
my $fam = q{[A-Z][A-Za-z]{0,7}[0-9][0-9A-Za-z]*(-[0-9A-Za-z]+)+}
        . q{|[A-Z]{2,8}(-[0-9A-Za-z]+){2,}}
        . q{|\b[A-Z][A-Za-z]{1,7}-[A-Z]{0,2}[0-9]{1,3}\b};

# —— 中文词条的 UTF-8 字节形态 ——
# 输入以 :raw 打开、不经 use utf8 解码（保持对任意字节形态的抗性），故中文字面
# 量必须写成字节转义；下列变量按字面含义命名，避免长正则不可读。
my $cn_di    = '\xe7\xac\xac';                                    # 第
my $cn_round = '\xe8\xbd\xae';                                    # 轮
my $cn_not_carousel = '(?!\xe6\x92\xad|\xe8\xaf\xa2)';           # 不吞「轮播/轮询」
  # 注：排除项必须写完整字符序列——写成字节字符类会误伤首字节相同的其它汉字
  # （「漏」与「播」同以 E6 起头），令「N 轮漏收敛」一类引用漏检。
# 审计动作词。轮次引用几乎总与它们共现；循环轮次表述（每 N 轮落行、连续 N 轮
# 共识、N 轮心跳、第 N/N 轮打点）不会——这是「裸数字不判罚」的收窄依据。
my $cn_audit_verbs = join '|',
  '\xe5\xae\xa1\xe8\xae\xa1',   # 审计
  '\xe4\xbf\xae\xe5\xa4\x8d',   # 修复
  '\xe8\xa3\x81\xe5\xae\x9a',   # 裁定
  '\xe5\x8f\x91\xe7\x8e\xb0',   # 发现
  '\xe6\x94\xb6\xe6\x95\x9b',   # 收敛
  '\xe5\x8a\xa0\xe5\x9b\xba',   # 加固
  '\xe5\xa4\x8d\xe6\xa0\xb8';   # 复核
# 并列轮次常以全角标点收尾（「第 N/N 轮，与写侧」）；循环轮次则接动作词或
# ASCII 逗号（「第 N/N 轮, iterations」）。
my $cn_stop_punct = '(?:\xef\xbc\x8c|\xe3\x80\x81|\xef\xbc\x9b|\xe3\x80\x82|\xef\xbc\x89)';
# 斜杠并列轮次：第 N/N 轮。
my $cn_slash_round = $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?'
  . '(?:/[ \t]*[0-9]+(?:\.[0-9]+)?)+[ \t]*' . $cn_round;

# 轮次/编号的其它书写形态：中文轮次（含裸轮次与并列轮次）、审计序数、
# round/audit 前缀、R 两位数、A 两位数、SYS/SEC/HP/CL 前缀，以及编号紧邻
# “裁定”的审计结论引用。
my $legacy = join '|',
  $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?[ \t]*' . $cn_round . $cn_not_carousel,
  # 裸轮次 + 审计动作（「N 轮修复前落库」）：裸数字单独出现不判罚。
  '[0-9]{1,3}(?:/[0-9]{1,3})?[ \t]*' . $cn_round . '[ \t]*(?:' . $cn_audit_verbs . ')',
  # 斜杠并列轮次 + 审计动作/全角标点收尾（「第 N/N 轮审计」「第 N/N 轮，」）。
  $cn_slash_round . '[ \t]*(?:(?:' . $cn_audit_verbs . ')|' . $cn_stop_punct . ')',
  # 注释头以裸轮次收尾于标点/审计动作（「// N 轮）：…」——被编辑截断的引用
  # 残骸；循环语义的注释头接动作词（「// N 轮渲染 → NR）」）故不在内）。
  '^[ \t]*(?://+|#|\*|/\*|--|;|<!--)[ \t]*[0-9]{1,3}[ \t]*' . $cn_round
    . '[ \t]*(?:(?:' . $cn_audit_verbs . ')|\xef\xbc\x89|\xef\xbc\x9a|\xef\xbc\x8c)',
  # 中文数字轮次 + 审计归属（审计动作词后接全角括号与中文数字轮次）。
  '\xe5\xae\xa1\xe8\xae\xa1[ \t]*\xef\xbc\x88' . $cn_di
    . '[^\n]{1,8}?' . $cn_round,
  '\xe5\xae\xa1\xe8\xae\xa1[ \t]*[0-9]{2,3}(?![0-9])',
  '(?i:\b(?:round|audit))[-_]?[0-9]{1,3}\b',
  '\b[Rr][0-9]{2}[a-z]?\b',
  '\bA[0-9]{2}[A-Za-z]?\b',
  '\b(?:SYS|SEC|HP|CL)[-_]?[0-9]{1,3}\b',
  '[A-Z][A-Za-z]{0,4}[0-9]{1,3}[A-Za-z]?[ \t]*\xe8\xa3\x81\xe5\xae\x9a';

# 连写形态（无短横线）：1-5 位大写字母 + 2-3 位数字 + 1-2 位大写字母收尾。
my $concat = q{\b[A-Z]{1,5}[0-9]{2,3}[A-Z]{1,2}\b};

# 下划线/小驼峰测试名形态：测试前缀 + 编号段 + 下划线接业务描述。
my $tname = q{\bTest[A-Za-z]{0,3}[0-9]+(?:_[0-9A-Za-z]+)+};

# 跨行拆字：“第”与“轮”被换行隔开的书写无法用行扫描发现，整文件再扫一遍。
# 续行带注释前缀（「第」换行后接「// N 轮」）是同一形态的常见变体——前缀必须
# 一并容忍，否则拆字仍可绕过。
my $cont_prefix = '(?:(?://+|#|\*|/\*)[ \t]*)?';
my $cross = join '|',
  $cn_di . '[ \t]*\r?\n[ \t]*' . $cont_prefix . '[0-9]+(?:\.[0-9]+)?[ \t]*'
    . '\r?\n?[ \t]*' . $cn_round . $cn_not_carousel,
  $cn_di . '[ \t]*[0-9]+(?:\.[0-9]+)?[ \t]*\r?\n[ \t]*' . $cont_prefix
    . $cn_round . $cn_not_carousel;

my $comment_re = qr{^[ \t]*(?://|///|\*|/\*|<!--|--|#|;)};
my $decl_re    = qr{^[ \t]*(?:func (?:Test|Benchmark|Fuzz)|describe\(|test\(|it\(|t\.Run\()};

my $hits = 0;
sub report {
  my ($file, $line, $text) = @_;
  my $where = $line ? "$file:$line" : "$file:cross-line";
  $text =~ s/\s+$//;
  print "$where: $text\n";
  $hits++;
}

my $list = shift or die "usage: scan <file-list>\n";
open(my $lf, '<', $list) or die "cannot read file list: $!\n";
while (my $f = <$lf>) {
  chomp $f;
  next if $f eq '';
  open(my $fh, '<:raw', $f) or do { warn "cannot read $f: $!\n"; $hits++; next };
  local $/;
  my $text = <$fh>;
  close $fh;
  next if $text =~ /\x00/;               # 二进制文件跳过
  my $is_doc = ($f =~ /\.(?:md|markdown|txt)$/i);

  $text =~ s/(?:$shield)//g;

  my @lines = split /\n/, $text, -1;
  for my $i (0 .. $#lines) {
    my $l = $lines[$i];
    next unless $is_doc || $l =~ $comment_re || $l =~ $decl_re;
    my $hit = ($l =~ /$fam/ || $l =~ /$legacy/ || $l =~ /$tname/);
    if (!$hit && $l =~ /$concat/) {
      # 纯十六进制字母数字连写不是编号；出现十六进制之外的字母才是编号形态。
      my @toks = ($l =~ /($concat)/g);
      $hit = grep { !/^[0-9A-F]+$/ } @toks;
    }
    report($f, $i + 1, $l) if $hit;
  }

  while ($text =~ /$cross/g) {
    my $snip = substr($text, $-[0], $+[0] - $-[0]);
    $snip =~ s/\s+/ /g;
    report($f, 0, $snip);
  }
}
close $lf;
exit($hits ? 1 : 0);
PERL

  printf '%s\n' "$scan_targets" >"$list_file"

  set +e
  scan_out="$(perl "$scan_prog" "$list_file")"
  scan_rc=$?
  set -e
  case "$scan_rc" in
    0) ;;
    1)
      echo "ERROR: 审计编号/轮次元数据不得提交到公网仓库：" >&2
      echo "$scan_out" >&2
      exit 1
      ;;
    *)
      echo "ERROR: 内容扫描器异常退出（rc=${scan_rc}）——拒绝静默通过" >&2
      echo "$scan_out" >&2
      exit 1
      ;;
  esac
fi

echo "no audit artifacts tracked"

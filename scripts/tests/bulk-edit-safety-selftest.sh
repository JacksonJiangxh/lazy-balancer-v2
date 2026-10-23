#!/usr/bin/env bash
# check-bulk-edit-safety 自测：事故形态必红、正常形态必绿、无 dry-run 脚本必红。
set -euo pipefail
src_script="$(cd "$(dirname "$0")/.." && pwd)/check-bulk-edit-safety.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/bulk-guard.XXXXXX")"
trap 'rm -rf "$work"' EXIT

mk_repo() {
  local d="$1"; mkdir -p "$d"; cd "$d"
  git init -q; git config user.email t@example.com; git config user.name t
  mkdir -p scripts
  cp "$src_script" scripts/check-bulk-edit-safety.sh
  chmod +x scripts/check-bulk-edit-safety.sh
}

# 1) 事故形态：一次删除大量 () -> 必须失败
mk_repo "$work/fail"
python3 - <<'PY'
lines = [f"func f{i}() {{ return g{i}() }}" for i in range(200)]
open('a.go','w').write("\n".join(lines)+"\n")
PY
git add -A && git commit -qm base
python3 - <<'PY'
s=open('a.go').read().replace('()','')
open('a.go','w').write(s)
PY
if bash scripts/check-bulk-edit-safety.sh >/tmp/bulk1.out 2>&1; then
  echo "SELFTEST FAIL: 事故形态未拦截"; cat /tmp/bulk1.out; exit 1
fi

# 2) 正常形态：少量新增/删除 -> 必须通过
mk_repo "$work/ok"
printf 'package x\nfunc A() {}\n' > a.go
git add -A && git commit -qm base
printf 'package x\nfunc A() {}\nfunc B() {}\n' > a.go
if ! bash scripts/check-bulk-edit-safety.sh >/tmp/bulk2.out 2>&1; then
  echo "SELFTEST FAIL: 正常形态被拦截"; cat /tmp/bulk2.out; exit 1
fi

# 3) 无 dry-run 的遍历写盘脚本 -> 必须失败
mk_repo "$work/script"
cat > scripts/rewrite.py <<'PY'
import os, re
for dp, _, fs in os.walk('.'):
    for f in fs:
        if f.endswith('.go'):
            p=os.path.join(dp,f)
            open(p,'w').write(re.sub(r'\\s+$','',open(p).read()))
PY
git add -A && git commit -qm base
if bash scripts/check-bulk-edit-safety.sh >/tmp/bulk3.out 2>&1; then
  echo "SELFTEST FAIL: 无 dry-run 脚本未拦截"; cat /tmp/bulk3.out; exit 1
fi

# 4) 写盘特征的非紧邻 -i 形态（sed -E -i / sed -e … -i / perl -pi -e /
#    python -c）带遍历但无 dry-run -> 必须失败。紧邻 sed -i 匹配漏掉这些形态，
#    而它们正是「全仓正则改写」事故的实际作业形态。
expect_write_shape_blocked() {
  local label="$1" body="$2"
  mk_repo "$work/$3"
  printf '%s\n' "$body" > scripts/rewrite.sh
  chmod +x scripts/rewrite.sh
  git add -A && git commit -qm base
  if bash scripts/check-bulk-edit-safety.sh >/tmp/bulk-shape.out 2>&1; then
    echo "SELFTEST FAIL: $label 形态未拦截"; cat /tmp/bulk-shape.out; exit 1
  fi
  if ! grep -q '缺少 --dry-run' /tmp/bulk-shape.out; then
    echo "SELFTEST FAIL: $label 形态命中原因错误（应为缺 dry-run 的批量改写脚本）"; cat /tmp/bulk-shape.out; exit 1
  fi
}

expect_write_shape_blocked 'sed -E -i' \
  "find . -name '*.go' | xargs sed -E -i 's/[[:space:]]+\$//'" sed-E-i
expect_write_shape_blocked 'sed -e … -i' \
  "find . -name '*.go' -exec sed -e 's/a/b/' -i {} +" sed-e-i
expect_write_shape_blocked 'perl -pi -e' \
  "for f in *.go; do perl -pi -e 's/a/b/' \"\$f\"; done" perl-pi

# python -c 直接批量写（无 dry-run）——匹配 python[0-9.]* -c
mk_repo "$work/python-c"
cat > scripts/rewrite.sh <<'SH'
for f in *.go; do python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().rstrip())' "$f"; done
SH
git add -A && git commit -qm base
if bash scripts/check-bulk-edit-safety.sh >/tmp/bulk-pyc.out 2>&1; then
  echo "SELFTEST FAIL: python -c 批量写形态未拦截"; cat /tmp/bulk-pyc.out; exit 1
fi

# 5) 同一批写盘形态但显式声明只读模式 -> 必须放行（收窄误报面）
mk_repo "$work/dryrun"
cat > scripts/rewrite.sh <<'SH'
#!/usr/bin/env bash
# 支持 --dry-run：只打印将改写的文件，不写盘
set -euo pipefail
for f in *.go; do
  if [[ "${1:-}" == "--dry-run" ]]; then echo "would rewrite $f"; continue; fi
  sed -E -i 's/a/b/' "$f"
done
SH
git add -A && git commit -qm base
if ! bash scripts/check-bulk-edit-safety.sh >/tmp/bulk-dry.out 2>&1; then
  echo "SELFTEST FAIL: 带 --dry-run 的批量脚本被误拦"; cat /tmp/bulk-dry.out; exit 1
fi

# 6) PATH 中无 python3：通道 B 必须 fail-closed（不得打印「变更形态正常」）。
# 事故形态已就绪（与用例 1 同形），守卫必须以非零退出并把「需要 python3」
# 作为原因——旧实现让 read 拿到空值、阈值按 0 处理，静默放行 RC=0。
mk_repo "$work/nopython"
for i in $(seq 1 200); do printf 'func f%s() { return g%s() }\n' "$i" "$i"; done > a.go
git add -A && git commit -qm base
sed -e 's/()//g' a.go > a.go.tmp && mv a.go.tmp a.go
bin="$work/bin-nopython"; mkdir -p "$bin"
for tool in bash sh git grep dirname cat sed awk uname mktemp; do
  p="$(type -P "$tool" || true)"
  [[ -n "$p" ]] && ln -sf "$p" "$bin/$tool"
done
if [[ -e "$bin/python3" ]]; then
  echo "SELFTEST FAIL: 夹具 PATH 仍含 python3"; exit 1
fi
set +e
env -i PATH="$bin" HOME="${HOME:-/tmp}" /bin/bash scripts/check-bulk-edit-safety.sh >/tmp/bulk-nopy.out 2>&1
rc=$?
set -e
if (( rc == 0 )); then
  echo "SELFTEST FAIL: 缺 python3 时通道 B 静默放行（RC=0）"; cat /tmp/bulk-nopy.out; exit 1
fi
if ! grep -q 'python3' /tmp/bulk-nopy.out; then
  echo "SELFTEST FAIL: 缺 python3 的失败原因未指明依赖"; cat /tmp/bulk-nopy.out; exit 1
fi
if grep -q '变更形态正常' /tmp/bulk-nopy.out; then
  echo "SELFTEST FAIL: 缺 python3 时仍宣告「变更形态正常」"; cat /tmp/bulk-nopy.out; exit 1
fi

# 7) 部分暂存：暂存区有正常改动时，未暂存的事故形态仍必须被检查。
# 旧实现按 staged > worktree 互斥取值，staged 非空即让未暂存改动完全跳过
# 通道 B——而第二段改动往往正是批量变换。
mk_repo "$work/partial"
printf 'package x\nfunc A() {}\n' > a.go
for i in $(seq 1 200); do printf 'func f%s() { return g%s() }\n' "$i" "$i"; done > b.go
git add -A && git commit -qm base
# 暂存区：a.go 的正常改动（不会触发通道 B）
printf 'package x\nfunc A() {}\nfunc B() {}\n' > a.go
git add a.go
# 未暂存：b.go 的一次性批量删括号（事故形态）
sed -e 's/()//g' b.go > b.go.tmp && mv b.go.tmp b.go
if bash scripts/check-bulk-edit-safety.sh >/tmp/bulk-partial.out 2>&1; then
  echo "SELFTEST FAIL: 部分暂存时未暂存事故形态未拦截"; cat /tmp/bulk-partial.out; exit 1
fi

echo "bulk-edit safety selftest: PASS"
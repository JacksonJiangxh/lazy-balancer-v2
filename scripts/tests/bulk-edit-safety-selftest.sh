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

echo "bulk-edit safety selftest: PASS"

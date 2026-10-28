#!/bin/sh
# `unsafe` lives in one file, and nowhere else can it be switched back on.
#
# The workspace denies `unsafe_code` (Cargo.toml) rather than forbidding it, because libgit2's global
# options are reached through two `unsafe` calls (crates/git/src/init.rs) and a forbidden lint cannot be
# allowed where it is needed. Deny can be lifted by any `#[allow(unsafe_code)]`, so this is what makes
# the deny a forbid everywhere else: an `unsafe` block, function, impl, trait, extern block or attribute,
# or an `allow`/`expect` of the lint, outside the allowed file fails. Comments and the word in text do
# not count — the pattern is the keyword followed by what makes it code.
#
# The allowed file is checked too: every `unsafe` there sits under a `// SAFETY:` comment (clippy's
# `undocumented_unsafe_blocks`, denied in Cargo.toml, checks the blocks; this checks it still exists).
set -eu
cd "$(dirname "$0")/.."

ALLOWED='crates/git/src/init.rs'
# The control plane's boundary tests carry the keyword as *text*: fixtures for their own `unsafe_code`
# rule, written into temporary crates to prove the rule catches every form. The grep below cannot tell a
# string from code; that crate's `syn`-based rule (crates/cp-arch-tests/src/unsafe_code.rs) reads tokens,
# so it can, and it reads these files too — only this textual pass skips them.
FIXTURES='crates/cp-arch-tests/tests/'
CODE='(^|[^[:alnum:]_])unsafe[[:space:]]*(\{|fn[[:space:]]|impl([[:space:]]|<)|trait[[:space:]]|extern[[:space:]]|\()'
LINT='(allow|expect|warn)[[:space:]]*\([^)]*unsafe_code'

files=$(find crates fuzz -name '*.rs' -not -path '*/target/*' 2>/dev/null | sort)
[ -n "$files" ] || { echo "no Rust source found: the check would have read nothing"; exit 1; }
count=$(echo "$files" | wc -l | tr -d ' ')

bad=0
for f in $files; do
  [ "$f" = "$ALLOWED" ] && continue
  case "$f" in "$FIXTURES"*) continue ;; esac
  if grep -nE "$CODE|$LINT" "$f" | grep -vE '^[0-9]+:[[:space:]]*//' ; then
    echo "  ^ $f: unsafe outside $ALLOWED"
    bad=1
  fi
done

[ -f "$ALLOWED" ] || { echo "$ALLOWED is gone: update this check with where libgit2 is initialised"; exit 1; }
blocks=$(grep -cE "$CODE" "$ALLOWED" || true)
safety=$(grep -c '// SAFETY:' "$ALLOWED" || true)
if [ "$safety" -lt "$blocks" ]; then
  echo "$ALLOWED: $blocks unsafe uses, $safety SAFETY comments"
  bad=1
fi

echo "$count Rust files read; unsafe in $ALLOWED only ($blocks uses, $safety SAFETY comments)"
exit "$bad"

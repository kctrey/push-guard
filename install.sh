#!/bin/sh
# push-guard installer (macOS / Linux). Safe to re-run: it updates the code and keeps your
# local lists (customer-terms.txt, allow.txt, reviewed.tsv, term-sources.txt).
#
#   ./install.sh                     guard every git repo on this machine (recommended)
#   ./install.sh ~/work ~/Projects   guard only repos inside these folders
set -eu

SRC="$(cd "$(dirname "$0")" && pwd -P)"
DEST="$HOME/.config/git/push-guard"
INCLUDE="$HOME/.config/git/push-guard.gitconfig"
HOOKS="applypatch-msg commit-msg post-applypatch post-checkout post-commit post-merge post-rewrite
pre-applypatch pre-auto-gc pre-commit pre-merge-commit pre-rebase prepare-commit-msg
push-to-checkout reference-transaction post-update pre-receive update proc-receive
sendemail-validate fsmonitor-watchman p4-changelist p4-prepare-changelist p4-post-changelist p4-pre-submit
post-index-change"

command -v python3 >/dev/null || { echo "push-guard needs python3 — install it first." >&2; exit 1; }

mkdir -p "$DEST/hooks"
cp "$SRC/push_guard.py" "$SRC/refresh_terms.py" "$DEST/"
cp "$SRC/hooks/_passthrough" "$DEST/hooks/"
chmod +x "$DEST/push_guard.py" "$DEST/refresh_terms.py" "$DEST/hooks/_passthrough"
ln -sf ../push_guard.py "$DEST/hooks/pre-push"
for h in $HOOKS; do ln -sf _passthrough "$DEST/hooks/$h"; done
[ -f "$DEST/allow.txt" ] || cp "$SRC/allow.txt" "$DEST/allow.txt"
[ -f "$DEST/term-sources.txt" ] || cp "$SRC/term-sources.txt" "$DEST/term-sources.txt"

printf '# Enables push-guard (customer-data review before every push).\n[core]\n\thooksPath = %s\n' \
  "$DEST/hooks" > "$INCLUDE"

if [ $# -eq 0 ]; then
  current="$(git config --global --get core.hooksPath || true)"
  if [ -n "$current" ] && [ "$current" != "$DEST/hooks" ]; then
    echo "Your global core.hooksPath is already set to: $current" >&2
    echo "Not overwriting it. Re-run with folder arguments instead, e.g.  ./install.sh ~/work" >&2
    exit 1
  fi
  git config --global core.hooksPath "$DEST/hooks"
  scope="every git repo on this machine"
else
  scope=""
  for d in "$@"; do
    dir="$(cd "$d" 2>/dev/null && pwd -P)" || { echo "Not a folder: $d" >&2; exit 1; }
    git config --global "includeIf.gitdir/i:$dir/.path" "$INCLUDE"
    scope="$scope $dir"
  done
fi

if [ -d "$HOME/.local/bin" ]; then
  ln -sf "$DEST/push_guard.py" "$HOME/.local/bin/push-guard"
  cmd="push-guard"
else
  cmd="$DEST/push_guard.py"
fi

cat <<EOF

push-guard installed for:$( [ $# -eq 0 ] && echo " $scope" || echo "$scope" )

  Review a blocked push:   $cmd --review     (run it yourself, in a terminal)
  Audit a branch:          $cmd --scan origin/main..HEAD
  Optional name list:      add folders with your customer spreadsheets to
                           $DEST/term-sources.txt  (needs: pip install openpyxl)
  Uninstall:               $SRC/uninstall.sh

Note: repos that set their own core.hooksPath (e.g. husky) override push-guard.
EOF

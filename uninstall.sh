#!/bin/sh
# Removes push-guard from git. Your local lists stay in ~/.config/git/push-guard unless you pass --purge.
set -eu
DEST="$HOME/.config/git/push-guard"
INCLUDE="$HOME/.config/git/push-guard.gitconfig"

if [ "$(git config --global --get core.hooksPath || true)" = "$DEST/hooks" ]; then
  git config --global --unset core.hooksPath
fi
git config --global --get-regexp '^includeif\..*\.path$' 2>/dev/null | while read -r key val; do
  [ "$val" = "$INCLUDE" ] && git config --global --unset "$key"
done
rm -f "$INCLUDE"
[ -L "$HOME/.local/bin/push-guard" ] && rm -f "$HOME/.local/bin/push-guard"

if [ "${1:-}" = "--purge" ]; then
  rm -rf "$DEST"
  echo "push-guard removed, including your local lists."
else
  echo "push-guard removed from git. Local lists kept in $DEST (delete with --purge)."
fi

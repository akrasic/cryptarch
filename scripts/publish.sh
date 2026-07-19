#!/usr/bin/env bash
# Export a CLEANED snapshot of the current tree onto the `public` branch —
# what GitHub sees. The local main (full history, CLAUDE.md, agent ops) never
# leaves this machine.
#
#   scripts/publish.sh ["commit message"]     # export snapshot
#   scripts/publish.sh --push [...]           # export, then push public->main
#
# Mechanics: a temporary git index takes HEAD's tree, drops the excluded
# files, and commit-tree writes it onto refs/heads/public. The first run has
# no parent — one orphan commit, the entire history squashed away. Later runs
# append exactly one sync commit each (skipped when nothing changed), so the
# public history stays a clean line of releases, not a mirror of the sausage
# factory.
#
# One-time GitHub setup (after creating the empty repo):
#   git remote add origin git@github.com:<you>/cryptarch.git
#   git config remote.origin.push refs/heads/public:refs/heads/main
# The refspec makes a bare `git push` ship ONLY the public branch as GitHub's
# main — an accidental `git push` can never leak the private history.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Files that exist for the humans+agents working here, not for the world.
EXCLUDE=(CLAUDE.md)

PUSH=0
if [ "${1:-}" = "--push" ]; then PUSH=1; shift; fi
MSG=${1:-"sync $(date +%Y-%m-%d)"}

tmp_index=$(mktemp)
trap 'rm -f "$tmp_index"' EXIT
export GIT_INDEX_FILE="$tmp_index"

git read-tree HEAD
for f in "${EXCLUDE[@]}"; do
  git rm --cached -q --ignore-unmatch "$f"
done
tree=$(git write-tree)
unset GIT_INDEX_FILE

parent=$(git rev-parse -q --verify refs/heads/public 2>/dev/null || true)
if [ -n "$parent" ] && [ "$(git rev-parse "$parent^{tree}")" = "$tree" ]; then
  echo "public branch already matches — nothing to publish"
  exit 0
fi

commit=$(git commit-tree "$tree" ${parent:+-p "$parent"} -m "$MSG")
git update-ref refs/heads/public "$commit"
echo "public -> $commit ($( [ -n "$parent" ] && echo "1 sync commit appended" || echo "orphan root — history squashed" ))"

if [ "$PUSH" = 1 ]; then
  git push origin refs/heads/public:refs/heads/main
  echo "pushed public -> origin/main"
fi

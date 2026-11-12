#!/usr/bin/env bash
# OBSERV AGENT · one-command update (adapted from FISHY's push.sh)
# Usage (Git Bash / UCRT64):
#   bash push.sh "pesan commit"          -> push ke branch dev  (Railway environment: dev)
#   bash push.sh "pesan commit" main     -> push ke branch main (Railway environment: production)
# What it does: take the newest observ*.zip in Downloads, unpack it over the observ repo
# (your .git history stays), show what changed, commit and push -> Railway redeploys that environment.
set -e
DL="/c/Users/Elbama_PC/Downloads"
REPO="$DL/observ"
REMOTE="https://github.com/tradepadrh/observagent.git"
MSG="${1:-Update OBSERV $(date '+%Y-%m-%d %H:%M')}"
BRANCH="${2:-dev}"

cd "$DL"
ZIP="$(ls -t observ*.zip 2>/dev/null | head -1)"
if [ -z "$ZIP" ]; then echo "X  Tidak ada observ*.zip di $DL"; exit 1; fi
echo ">> Zip    : $ZIP  (diunduh $(date -r "$ZIP" '+%d/%m %H:%M'))"
echo ">> Branch : $BRANCH"

TMP="$(mktemp -d)"
if command -v unzip >/dev/null 2>&1; then
  unzip -q -o "$ZIP" -d "$TMP"
else
  powershell.exe -NoProfile -Command "Expand-Archive -Path '$(cygpath -w "$DL/$ZIP")' -DestinationPath '$(cygpath -w "$TMP")' -Force"
fi
if [ ! -d "$TMP/observ" ]; then echo "X  Isi zip tidak berisi folder observ/"; rm -rf "$TMP"; exit 1; fi

mkdir -p "$REPO"
cd "$REPO"
if [ ! -d .git ]; then
  echo ">> Menyambungkan folder ke $REMOTE"
  git init -q && git branch -M main
  git remote add origin "$REMOTE"
  git fetch -q origin || true
fi
# work on the target branch (create it from main the first time)
git fetch -q origin || true
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then git checkout -q "$BRANCH"
elif git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then git checkout -q -b "$BRANCH" "origin/$BRANCH"
else git checkout -q -B "$BRANCH"; fi
git pull -q --ff-only origin "$BRANCH" 2>/dev/null || true

cp -rf "$TMP/observ/." "$REPO/"
rm -rf "$TMP"

git add -A
if git diff --cached --quiet; then
  echo "!  Tidak ada perubahan. Kemungkinan zip ini versi lama atau sudah pernah di-push."
  echo "   Commit terakhir: $(git log --oneline -1 2>/dev/null || echo '-')"
  exit 0
fi

echo ">> File yang berubah:"
git status --short | head -30
git commit -q -m "$MSG"
git push -u origin "$BRANCH"
echo "OK Selesai. Railway ($BRANCH) akan deploy: $(git log --oneline -1)"

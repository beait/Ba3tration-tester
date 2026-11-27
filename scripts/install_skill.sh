#!/usr/bin/env bash
# Installs the Ba3tration-tester skill (skills/ba3tration-tester) for the coding agents on this
# machine. It is one SKILL.md in the open agent-skills format: the same file for every agent.
# Usage: bash scripts/install_skill.sh [claude|codex|all]      (default: all)
#   claude -> ~/.claude/skills/ba3tration-tester
#   codex  -> ~/.agents/skills/ba3tration-tester   (another folder: CODEX_SKILLS_DIR=~/.codex/skills)
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)/skills/ba3tration-tester"
[ -f "$SRC/SKILL.md" ] || { echo "skill not found: $SRC" >&2; exit 1; }
install_to() {
  mkdir -p "$1/ba3tration-tester"
  cp "$SRC/SKILL.md" "$1/ba3tration-tester/SKILL.md"
  echo "Installed: $1/ba3tration-tester/SKILL.md"
}
case "${1:-all}" in
  claude) install_to "$HOME/.claude/skills" ;;
  codex) install_to "${CODEX_SKILLS_DIR:-$HOME/.agents/skills}" ;;
  all) install_to "$HOME/.claude/skills"; install_to "${CODEX_SKILLS_DIR:-$HOME/.agents/skills}" ;;
  *) echo "Usage: bash scripts/install_skill.sh [claude|codex|all]" >&2; exit 1 ;;
esac
echo "Start a new session of the agent, then ask it to set up or run Ba3tration-tester."

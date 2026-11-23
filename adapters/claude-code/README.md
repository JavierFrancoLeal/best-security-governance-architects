# Claude Code Adapter (`security-governance`)

Install into a workspace with:
```bash
bash adapters/install.sh --target claude --mode director-only --scope workspace --dest /path/to/repo
```
Installs `.claude/skills/security-director/` and non-destructively upserts the fenced governance block into `AGENTS.md` (and `CLAUDE.md` if regular file, or symlinks `CLAUDE.md -> AGENTS.md`).

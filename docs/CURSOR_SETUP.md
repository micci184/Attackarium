# Cursor setup and recommended provider Skills

This document describes **official third-party Skills to install locally** in
Cursor. An installation command is not evidence that a Skill is already present.
Run commands **from the root of this repository** on your own development
computer, then check Cursor's *Customize → Skills*.

## Initial Skills: install these three

| Skill | Official source | Usage |
| --- | --- | --- |
| `vercel-react-best-practices` | `vercel-labs/agent-skills` | Writing and reviewing React/Next.js dashboard code |
| `supabase` | `supabase/agent-skills` | Supabase APIs, Edge Functions, Storage, Cron, CLI and integration patterns |
| `supabase-postgres-best-practices` | `supabase/agent-skills` | PostgreSQL schema, indexes, RLS, migrations and SQL review |

Install into the **project** for **Cursor** (omit `--global`):

```bash
npx skills add vercel-labs/agent-skills --skill vercel-react-best-practices --agent cursor --yes
npx skills add supabase/agent-skills --skill supabase --agent cursor --yes
npx skills add supabase/agent-skills --skill supabase-postgres-best-practices --agent cursor --yes
npx skills list --agent cursor
```

The Skills CLI may put files in `.agents/skills/` and link them to the
agent-specific location. Cursor's official documentation recognizes both
`.agents/skills/` and `.cursor/skills/`. Verify the installed `SKILL.md` files,
their supporting resources and lock file before committing them to a **public**
repository. Avoid `--global` to ensure other projects are unaffected.

## Deployment later: use authenticated Vercel tooling

When the actual web application and a destination project exist, install the
**official Vercel Cursor plugin** by entering this in Cursor Agent chat:

```text
/add-plugin vercel
```

It combines Vercel-specific guidance with an authenticated Vercel MCP
connection. Confirm the correct Vercel team/project and have the user approve
the specific deployment before making changes.

Do **not** install `deploy-to-vercel` in this project by default. A public
security report describes a no-auth fallback that can upload unintended
local files without following `.gitignore`. For a security-research repository,
prefer explicit, authenticated, reviewed deployments. If choosing an alternative
Vercel deployment Skill later, review its files and all fallback scripts first.

## Supabase MCP: optional, not necessary to start

Skills provide **instructions**, not live project access. For Phase 1,
Supabase CLI with local migrations and test data is sufficient. When real
project administration is needed, add the official Supabase Cursor plugin/MCP
through its documented authentication flow and use least privilege. Do not
duplicate an existing MCP server connection or commit tokens to the repo.

## Safety checklist after installing/updating Skills

1. Review each `SKILL.md` and executable resources from the original repository.
2. Check that only the intended three Skills were installed, project scoped.
3. Do not let installation instructions trigger hosting, database writes,
   telemetry exports, code upload or external deployment without explicit consent.
4. In Cursor, verify that the Skills are visible; using Skills does not imply
   access to Vercel or Supabase accounts.
5. Run `npx skills update` only after reviewing upstream changes.

## Official references

- [Cursor AGENTS.md and rules](https://cursor.com/docs/rules)
- [Cursor Agent Skills](https://cursor.com/docs/skills)
- [Vercel's official Skills directory](https://vercel.com/docs/agent-resources/skills)
- [Supabase's official Skills directory](https://supabase.com/docs/guides/ai-tools/ai-skills)
- [Vercel Cursor plugin](https://vercel.com/i/cursor-plugins)
- [Reported deploy-to-vercel fallback behavior](https://github.com/vercel-labs/agent-skills/issues/335)

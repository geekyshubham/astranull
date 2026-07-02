---
name: grok-orchestrator
description: Use when the user invokes $grok-orchestrator, asks to use Grok CLI or Composer 2.5, wants Codex to delegate coding or repetitive implementation work to Grok, minimize Codex token usage, coordinate multiple Grok sessions or subagents, or loop until bugs and gaps are resolved.
---

# Grok Orchestrator

## Core Contract

Use Grok CLI as the implementation worker. Keep Codex responsible for task framing, prompt quality, parallelization strategy, code review, verification, and the final concise report.

Do not write application code directly while this skill is active unless Grok is unavailable after a retry, the user explicitly authorizes fallback coding, or the edit is limited to orchestration artifacts such as prompt files. Spend Codex tokens on judgment, not on producing code or long logs.

Default to a **parallel-first worker pool** for non-trivial work. Codex should actively look for independent slices and run multiple Grok sessions instead of a single long serial worker. Use one session only for tiny, inherently single-file, or architecturally inseparable changes, and briefly note why parallelization was unsafe or wasteful.

Default CLI path on this machine:

```bash
/Users/checkred_admin/.grok/bin/grok
```

If that path is unavailable, resolve with `command -v grok`. Run `grok --help` when the local interface appears different.

## Worker Model

Always run Grok workers with Composer 2.5:

```bash
--model grok-composer-2.5-fast
```

The local CLI may report this as the default, but still pass the model explicitly so the orchestration is stable if defaults change.

## Workflow

1. Triage the task.
   - Check `git status --short` before delegation and preserve user changes.
   - Inspect only the repo context needed to brief Grok: project layout, likely files, relevant tests, and local conventions.
   - Convert the user request into acceptance criteria and verification commands.
   - Ask the user only when ambiguity could cause the wrong product behavior or destructive action.
   - Capture expected file ownership before delegation. In dirty repos, explicitly separate task files from unrelated modified/untracked files.
   - Snapshot a small pre-run baseline such as `git diff --name-only`, `git ls-files --others --exclude-standard`, and targeted `rg` checks for the behavior being changed.

2. Choose a delegation shape.
   - Parallel-first rule: for any task with 2+ independent implementation, test, documentation, review, or verification slices, start multiple Grok sessions in the first dispatch wave.
   - Target at least 3 sessions for broad production-readiness work when safe: implementation, tests/QA, and docs/release-tracker cleanup. Scale to 10+ sessions when the ownership matrix is genuinely disjoint.
   - Use one Grok session only when the task cannot be split without shared-file conflicts, design ambiguity, or pointless overhead. Record that exception in the orchestration notes.
   - Prefer multiple Grok sessions for independent tasks with non-overlapping file ownership.
   - Assign every session one explicit ownership unit: file list, directory, module, test group, or read-only review scope.
   - Make exactly one session responsible for each writable file. Shared files such as `PROGRESS.md`, release checklists, root configs, migrations, and package manifests must be owned by one designated session or reserved for Codex integration.
   - Use read-only reviewer sessions freely, but state that they must not edit files.
   - Use `--best-of-n` when several alternative implementations can be judged by tests.
   - Use separate Grok worktrees for parallel writers, then review and merge patches intentionally.
   - Let Grok use its native subagents by default. Do not pass `--no-subagents` unless the user asks or subagents would create unsafe overlap.
   - When Grok subagent definitions are useful and the local CLI schema is known, pass focused roles with `--agents`; otherwise, spawn multiple CLI sessions with separate prompt files.
   - If two desirable slices need the same file, run them sequentially or split one into a read-only analysis prompt plus a later integration patch. Do not permit parallel writers on the same file.

3. Prompt Grok with a complete implementation contract.
   - Prefer `--prompt-file` for substantial tasks so the prompt is auditable.
   - Require Grok to edit files directly, run targeted verification, and return a terse status.
   - Tell Grok not to paste full files, long diffs, or noisy logs unless explicitly requested.
   - Include all relevant constraints from the user, repository instructions, and active skills.
   - Treat Grok as a literal execution worker, not a product thinker. Do not rely on it to infer missing context, resolve ambiguous requirements, or discover the intended design from vibes.
   - Front-load the prompt with enough implementation context to make the correct patch obvious: current behavior, target behavior, relevant data shapes, invariants, file ownership, known failure modes, and examples.
   - Give Grok the implementation approach when Codex already knows it. Prefer "change X function to do Y using Z pattern" over "make this better."
   - Include representative before/after examples, sample payloads, failing assertions, or SQL/JSON shapes when behavior depends on structured data.
   - For dirty worktrees or follow-up fixes, include an exact file allow-list and say "edit these files only." Add a no-commit/no-stage boundary unless the user explicitly asks Grok to own git operations.
   - Include negative acceptance criteria for known non-goals and false-positive risks, not just the happy path.
   - Include one or two concrete post-edit checks Grok can perform, such as "the file no longer contains X" and "the file contains Y." Codex must still verify independently.

4. Run Grok with bounded output.
   - In this local CLI, `acceptEdits` alone is insufficient: pass `--tools read_file,grep,search_replace` plus `--always-approve`, then review diffs before merging.
   - Prefer headless single-turn execution for delegated coding:

```bash
/Users/checkred_admin/.grok/bin/grok --model grok-composer-2.5-fast --prompt-file /path/to/prompt.md --cwd /absolute/repo --no-memory --no-plan --max-turns 80 --always-approve --tools read_file,grep,search_replace --permission-mode acceptEdits
```

   - For alternative attempts on the same scoped task:

```bash
/Users/checkred_admin/.grok/bin/grok --model grok-composer-2.5-fast --prompt-file /path/to/prompt.md --cwd /absolute/repo --no-memory --no-plan --max-turns 80 --always-approve --tools read_file,grep,search_replace --best-of-n 3 --permission-mode acceptEdits
```

   - For isolated parallel work:

```bash
/Users/checkred_admin/.grok/bin/grok --model grok-composer-2.5-fast --worktree grok-task-slug --prompt-file /path/to/prompt.md --cwd /absolute/repo --no-memory --no-plan --max-turns 80 --always-approve --tools read_file,grep,search_replace --permission-mode acceptEdits
```

   - When the execution tool supports output limits, set a small or medium cap and inspect files, diffs, or logs directly afterward.
   - Do not assume all flags compose. Known local quirks: `--no-subagents` cannot be combined with `--check`; subcommands such as `grok inspect` may not accept `--cwd`, so run them from the target directory instead.
   - If the allow-list reports "unmappable entries" or Grok keeps the full toolset, compensate with stricter prompt boundaries and post-run diff review.
   - Treat `bundle too large` as a warning only when Grok continues and produces a verifiable diff. If the run exits with no useful diff, rerun with a smaller `--cwd`, exact files, or an exact replacement prompt.
   - Prefer `--disable-web-search` for local code work unless the task explicitly requires web research.
   - Use `--permission-mode bypassPermissions` only as a last local retry for exact-file edits after safer modes failed to write changes and the user has authorized local editing. Review the resulting diff especially closely.

5. Review and verify.
   - Inspect `git status --short`, `git diff --stat`, and the relevant diffs yourself.
   - Run the verification commands yourself after Grok finishes.
   - Maintain a short issue ledger containing every bug, failing test, review concern, missing acceptance criterion, and user-visible gap.
   - If the ledger is not empty, send Grok narrow follow-up prompts with the failures, expected behavior, relevant file paths, and the remaining ledger items. Do not manually patch application code unless fallback is authorized.
   - Dispatch independent ledger items to multiple Grok sessions or Grok subagents when this can reduce turnaround without creating file conflicts.
   - Repeat the review-fix-verify loop until all known issues, bugs, and gaps are resolved and verification is clean, or until there is a genuine blocker that needs user input or an external state change.
   - Never trust Grok's success summary by itself. Confirm that files actually changed with `git diff --name-only`, targeted `rg`, or file reads. A worker that claims "tests passed" while leaving the old text intact is a failed run.
   - For untracked task files, `git diff` is empty by default. Inspect them with `git ls-files --others --exclude-standard`, `find`, `sed`, and targeted tests.
   - If a check cannot run because local dependencies are missing, do not install global tools by default. Try project-local tooling first; otherwise report the exact blocker and run the closest safe static or isolated sanity check.
   - When Grok misses a narrow issue twice, switch to an exact follow-up prompt: name one or two files, quote the stale text, quote the required replacement or invariant, and require Grok to read the file after editing before exiting.
   - For UI work, verify behavior with the project's actual test/rendering conventions. If tests render i18n keys, assert keys in tests while preserving human-readable translations in the app.

6. Report briefly.
   - Summarize what changed, which files matter, and which tests or checks ran.
   - Mention unresolved risks or failed checks plainly.
   - Avoid pasting large Grok output, code blocks, or full diffs unless the user asks.

## Prompt Template

Use this structure for Grok prompts and keep it concrete:

```markdown
You are the implementation worker. Codex is orchestrating this task and will review your diff.

Task:
- [User-facing goal]

Repository:
- CWD: [absolute path]
- Branch/status: [brief git status summary]
- Likely files: [paths]
- Local patterns to follow: [framework, test style, naming, commands]
- Worker model: grok-composer-2.5-fast

Current behavior / problem:
- [What happens now, with concrete error/output/UI/API behavior]
- [Known failing command, test, screenshot observation, or stale text]

Target behavior:
- [What should happen instead, phrased as product-visible behavior]
- [Data contract or state transition that must be true]

Implementation direction:
- [Specific function/component/query/config to change]
- [Preferred algorithm or local pattern to follow]
- [How to preserve backward compatibility or existing fields]

Examples / fixtures:
- Input: [sample payload/row/state]
- Expected output: [sample response/rendered text/row/state]
- Edge case: [counterexample that must not pass]

Acceptance criteria:
- [Observable behavior 1]
- [Observable behavior 2]
- [Edge case or non-goal]

Boundaries:
- Preserve existing user changes.
- Do not run destructive commands such as git reset --hard, git checkout --, rm -rf, database drops, force pushes, or secret exposure.
- Do not commit, push, install global tools, or change unrelated files unless explicitly requested.
- Keep output concise. Do not paste full files or long diffs.

Implementation expectations:
- Make the code changes directly.
- Use existing project patterns and minimal new abstraction.
- Follow the implementation direction above unless the repository proves it impossible; if so, report the blocker instead of inventing a broad redesign.
- Add or update focused tests when the change affects behavior.
- Run targeted verification commands.
- Continue fixing until all known issues, bugs, failing checks, and acceptance gaps are resolved.

Return only:
- Changed files
- Verification commands and pass/fail result
- Remaining unresolved issues, or `none`
```

## Exact Follow-Up Prompt Pattern

Use this when Grok reported success but Codex found no diff, stale text, or a single precise failure:

```markdown
You are the implementation worker. Codex will review the actual file diff. You must edit the file, not just describe the edit.

Task:
- [One concrete failing assertion/invariant]

Repository:
- CWD: [absolute path]
- Edit exactly these files only:
  - [path]

Current failure:
- Command: [verification command]
- Observed: [short failure or stale text]

Required edit:
- Replace/remove/add [specific text or invariant].
- Keep [important existing behavior].
- Do not touch [nearby tempting files/non-goals].

Acceptance checks before exit:
- `rg -n "[old text]" [file]` should [find/no matches].
- `rg -n "[new text]" [file]` should find the expected line.
- Run [targeted command] if available.

Return only:
- Changed files
- Verification result
- Remaining unresolved issues, or `none`
```

## Parallel Grok Sessions

Before starting parallel Grok work, split the task into independent ownership units. Give each session a unique prompt, branch or worktree name, file ownership, acceptance criteria, verification command, and `--model grok-composer-2.5-fast`.

Parallel sessions are the default for non-trivial work. Codex should build and keep a small ownership matrix before launching workers:

| Session | Purpose | Writable files / dirs | Read-only context | Verification |
|---|---|---|---|---|
| grok-a | Backend API | `src/services/foo.mjs`, `tests/unit/foo.test.mjs` | `docs/backend/foo.md` | `node --test tests/unit/foo.test.mjs` |
| grok-b | UI | `apps/web/app.js`, `tests/e2e/ui-smoke.test.mjs` | `docs/ux/foo.md` | `node --test tests/e2e/ui-smoke.test.mjs` |
| grok-c | Docs | `docs/api.md`, `PROGRESS.md` | implementation files | `rg` stale-text checks |

Session sizing guidance:
- 2 sessions: minimum for most medium tasks when one implementation slice and one test/docs/review slice can proceed independently.
- 3-5 sessions: default for broad feature work with backend, frontend, tests, docs, and security/review slices.
- 6-10+ sessions: allowed and encouraged for large production-hardening pushes when each worker has a disjoint write scope or is read-only.
- Stop adding sessions when the next worker would need files already owned by another worker, when architecture is not decided, or when integration overhead exceeds expected speedup.

Non-overlap rules:
- One writable owner per file per dispatch wave.
- One migration owner per dispatch wave.
- One package/config owner per dispatch wave.
- One release-tracker/docs owner for shared status files per dispatch wave.
- Read-only sessions must say "do not edit files" in the prompt.
- If Grok ignores boundaries and edits unowned files, reject or surgically discard those edits during Codex review.
- If a session needs a file owned by another session, stop it or convert it to read-only analysis.

Recommended large-task wave:
1. Backend implementation sessions by module or route family.
2. Frontend implementation sessions by page or component area.
3. Test sessions by test family, with write ownership limited to their test files.
4. Documentation/tracker session owning shared docs only.
5. Security/QA review sessions that are read-only and produce issue ledgers.

When using a shared worktree with parallel writers, prompts must include exact file allow-lists. For safer high-concurrency work, prefer separate Grok worktrees and merge patches intentionally after review.

Good parallel splits:
- Frontend component implementation vs backend API implementation when contracts are already clear.
- Test creation vs documentation cleanup.
- Competing implementations of the same small algorithm using `--best-of-n`.
- Independent issue-ledger fixes touching different modules.
- Production-hardening lanes such as auth, notifications, retention, agent packaging, and release evidence when each lane owns separate modules.
- Read-only audit sessions for security, docs drift, test coverage, and release checklist gaps.

Bad parallel splits:
- Multiple sessions editing the same file or migration.
- Tasks where architecture is still undecided.
- Production or data-changing operations.
- Multiple sessions updating `PROGRESS.md`, `package.json`, root configs, or the same docs in the same dispatch wave.
- A test worker and implementation worker both editing the same test file.

After parallel sessions complete, review each diff independently. Merge only the selected result, rerun verification in the final workspace, and discard unused worktrees or patches only when safe.

## Resolution Loop

Treat Grok as a reusable worker pool, not a one-shot code generator.

1. Gather evidence: Codex reviews the diff, runs tests, checks UI or runtime behavior when relevant, and records every issue in a concise ledger.
2. Route fixes: Send each independent ledger item to a Composer 2.5 Grok worker, using multiple sessions or Grok subagents where safe. Prefer another parallel dispatch wave over a serial queue whenever ledger items have disjoint ownership.
3. Reconcile: Codex reviews each returned patch, rejects unsafe or unrelated changes, and combines only clean work.
4. Verify again: Codex reruns targeted and relevant broader checks.
5. Continue: Repeat until the ledger is empty. Stop only when all known issues are resolved, the user stops the loop, or progress is blocked by missing information, unavailable tools, conflicting requirements, or an external dependency.

Do not mark work complete merely because Grok finished a run. Completion means Codex has no unresolved review findings and the selected verification commands pass or have a clearly explained, user-accepted exception.

## Git Handoff and Commit Gate

When the user asks for branches or commits, keep git under Codex control unless they explicitly delegate git to Grok.

- Create or switch branches only after understanding the current dirty state.
- Stage with explicit pathspecs, never broad `git add .`, in repos with unrelated work.
- Exclude generated caches, dependency folders, local config overrides, debug scripts, IDE files, and benchmark artifacts unless they are explicitly part of the requested deliverable.
- Before committing, show yourself `git diff --cached --name-only`, unstaged `git diff --name-only`, and untracked files. Commit only when the staged list matches the task boundary.
- After committing, confirm branch name, commit hash, and remaining unrelated dirty files.

## Safety Rules

- Never pass secrets, private tokens, customer data, or production credentials to Grok unless the user explicitly authorizes it for that task.
- Avoid `--always-approve`, `--permission-mode bypassPermissions`, and sandbox loosening. Use them only in disposable local worktrees after explicit user approval.
- Keep destructive operations, cloud changes, database writes, deploys, and force-pushes under Codex control and user confirmation.
- If Grok changes unrelated files, fails to preserve user work, or produces an unsafe patch, reject the result and re-prompt with tighter constraints.

## Token Discipline

- Keep Codex user updates short.
- Ask Grok for terse output and inspect artifacts directly.
- Do not quote Grok responses unless they contain a concise blocker.
- Prefer file paths, command names, and pass/fail status over explanations.
- Final answers should be high signal: outcome, verification, and next useful action.

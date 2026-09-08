# CodeLedger MCP — *panning for code*

A zero-dependency MCP server for Claude Code that remembers which code patterns
have been **verified** to work, which have **failed** (and why), and what
successfully replaced them. It learns from validated outcomes — never from the
model's opinion about whether code looks correct.

Repo: https://github.com/aibotjock/code-pan

## The loop

```
check memory → write/edit → validate → classify → remember
```

Paste this into your project's `CLAUDE.md`:

```markdown
### CodeLedger loop
- BEFORE writing non-trivial code: call `get_experience` (topic or candidate snippet).
  Heed quarantine warnings; prefer proven replacements over novel approaches.
- BEFORE committing to an approach: `check_code` the candidate snippet (read-only).
- AFTER validation passes (tests/build/lint/runtime): `record_success` with
  evidence [{type:"test", detail:"..."}]. Never claim evidence you didn't run.
- AFTER a failure: `record_failure` with reason + error signature + evidence.
  If you fixed it differently: pass replacement_code to link failure → fix.
- Never promote/quarantine on opinion alone; the server enforces this anyway.
```

## Install

```bash
git clone https://github.com/aibotjock/code-pan /data/codeledger
claude mcp add codeledger --scope user -- python3 /data/codeledger/server.py
```

No dependencies — Python 3.10+ stdlib only (sqlite3, including FTS5 with
automatic LIKE fallback). One SQLite database at `~/.codeledger/ledger.db`.

Env overrides: `CODELEDGER_DB`, `CODELEDGER_PROJECT` (defaults to
`<cwd-basename>-<hash>` of the directory Claude Code launches it from, so each
repo gets its own project scope automatically), `CODELEDGER_ACTOR`.

## Terminal: `codepan`

The same ledger from your shell (one-time install):

```bash
ln -sf /data/codeledger/codepan ~/.local/bin/codepan
```

```bash
codepan check src/foo.py                 # ⛔ BLOCK on known failure → exit 1
cat new_module.py | codepan check -      # pipe works too
codepan ok src/foo.py --evidence test='pytest: 42 passed'
codepan fail old.py --reason 'timeouts' --signature TimeoutError \
    --evidence test=regression --replacement new.py
codepan exp 'retry backoff'              # before coding: proven + known failures
codepan search 'fetch' --state quarantined
codepan explain 7 && codepan maintain --dry-run
```

Shares the database, project scoping, and audit trail with the MCP
(`--db/--project/--actor` or the same env vars). Exit codes: `0` ok, `1` BLOCK
(so `check` drops straight into hooks and CI), `2` usage/validation error.
From inside Claude Code, `! codepan check …` runs it in-session.

## Three states

| state | meaning | how you get there |
|---|---|---|
| **probation** | new or insufficiently verified | default for opinion-only records |
| **proven** | demonstrated success via objective evidence | `record_success` with test/build/lint/runtime/human_confirm evidence |
| **quarantined** | demonstrated failure or explicit rejection | `record_failure` with objective evidence, or `human_reject` |

Objective evidence types: `build`, `test`, `regression_test`, `lint`,
`typecheck`, `static_analysis`, `security_check`, `runtime`, `human_confirm`,
`human_reject`. `agent_opinion` is accepted but changes nothing on its own.

Hard rules enforced by the server:

- Opinion alone never promotes or quarantines.
- Quarantined entries are never deleted and never auto-un-quarantined —
  `reactivate` returns them to probation with a recorded reason and preserved
  history; fresh objective evidence is required to prove them again.
- Repository-specific failures stay project-scoped. Global promotion requires
  proven state + confidence ≥ 0.80 + ≥ 3 successful uses + a recorded reason.
- Every mutation appends an audit event (actor, reason, evidence,
  prev → new state/confidence). History is append-only.

## Tools (12)

| tool | when |
|---|---|
| `get_experience` | before coding: top proven patterns + known failures (with repairs) |
| `check_code` | before committing to an approach: BLOCK/WARN on quarantined similarity, reuse candidates |
| `search` | query the ledger by text and/or code similarity, filtered by state |
| `record_success` | after validation passes |
| `record_failure` | after a failure (optionally `replacement_code` to link the fix) |
| `promote` | probation→proven, or `to_global` for cross-repo patterns |
| `quarantine` | explicit quarantine (needs human_reject or prior objective failure evidence) |
| `reactivate` | quarantined→probation when deps/env changed; reason recorded |
| `link_replacement` | failure → successful replacement |
| `update_confidence` | manual nudge (≤0.5/call), audit-logged |
| `explain` | full classification history for an entry |
| `maintain` | decay, archive, merge duplicates, stats (`dry_run` supported) |

## Matching & context awareness

- Exact: SHA-256 of comment-stripped, whitespace-normalized code.
- Structural: token 3-shingle Jaccard similarity. ≥ 0.85 + quarantined +
  confidence ≥ 0.60 + no env conflict → **BLOCK**; 0.60–0.85 → warning only.
- Entries carry `env` (os, language version, deps…). Conflicting environments
  weaken quarantine warnings — a failure under macOS/Python 3.9 shouldn't block
  the same code on Linux/3.13. Conflicts are surfaced, never hidden.
- Project scope is always searched together with global scope.

## Confidence (simple, deterministic)

| event | change |
|---|---|
| objective success | +0.15 (human_confirm +0.20), cap 0.95 |
| opinion success | +0.10 |
| objective failure on proven/probation | quarantine (conf 0.70, or 0.85 human_reject) |
| opinion failure | −0.10 |
| failure on quarantined | +0.05 (reinforced) |
| conflicting success on quarantined | −0.25 + hint to reactivate |
| stale > 180 days (`maintain`) | −0.05 per 90 days; stale proven below 0.45 → probation |

## Security

Secrets are refused at the door: AWS/GitHub/OpenAI/Google/Slack tokens,
private keys, JWTs, and `password = "…"`-style assignments are detected before
persistence. The tool returns an error naming the *kind* (never the value);
`allow_redact=true` stores a `***REDACTED:kind***` copy. Redaction also applies
to titles, reasons, signatures, and evidence details.

## Maintenance

`maintain` (periodically, or via cron): confidence decay for stale entries,
archiving of low-value probation entries (>90 days old, never verified,
confidence < 0.25 — archived, never deleted), exact-duplicate merging with
link rewriting, near-duplicate reporting, and size stats. Quarantined
knowledge is permanent.

## Development

```bash
scripts/test.sh    # 80 tests, hermetic (temp DBs); pipefail-safe green check
```

`tests/test_protocol.py` drives the real server process over stdio JSON-RPC —
handshake, tool calls, secret refusal, hostile inputs (malformed initialize,
invalid UTF-8, oversized messages), clean shutdown. `tests/test_engine.py`
includes a two-process concurrent-writer suite.

## Robustness & limits

The stdio transport is hardened against hostile input: a bad message gets a
proper JSON-RPC error (`-32700`/`-32600`/`-32602`/`-32601`/`-32603`) and the
server keeps serving. Invalid UTF-8 bytes are replaced, not fatal. Messages
over 10 MiB are rejected with an explicit error — the session survives (the
official SDK default tears the session down silently at that size). Internal
errors never leak Python internals. Entry creation and its first audit event
are written in a single transaction.

Known limit: concurrent writers from multiple processes are safely serialized
by SQLite (no lost inserts), but read-modify-write sequences inside one tool
call (counters, confidence) can interleave under heavy multi-process load.
MCP launches one server process per client, so this only matters if you run
several `codepan` processes against one DB simultaneously.

## v1 non-goals

No embeddings, no vector DB, no ML scoring, no autonomous agents. The matching
above is deliberately simple; revisit only if real usage shows it's insufficient.

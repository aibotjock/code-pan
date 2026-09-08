"""Data layer: code normalization/fingerprints, secret hygiene, SQLite store.

Everything is stdlib. The database is a single SQLite file with three tables:
entries (current state), links (failure -> replacement), events (append-only
audit trail). Historical evidence is never rewritten.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

# --------------------------------------------------------------------- time


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def days_since(ts: str | None) -> float:
    """Days elapsed since an ISO timestamp; huge when unknown/future-safe."""
    if not ts:
        return 1e9
    then = datetime.fromisoformat(ts)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - then).total_seconds() / 86400.0)


def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def default_project() -> str:
    """Per-repo scope key: <dirname>-<hash> of the current working directory."""
    cwd = os.getcwd()
    tag = hashlib.sha1(cwd.encode()).hexdigest()[:8]
    return f"{os.path.basename(cwd) or 'root'}-{tag}"


def truncate(text: str, limit: int, label: str = "output") -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[…truncated {len(text) - limit} chars of {label}]"


# ------------------------------------------------------------- normalization

_HASH_LINE = {
    "python", "py", "shell", "sh", "bash", "zsh", "yaml", "yml", "toml", "ini",
    "dockerfile", "makefile", "r", "ruby", "rb", "perl", "powershell",
}
_DASH_LINE = {"sql", "sqlite", "postgres", "postgresql", "mysql", "lua", "haskell"}
_NO_COMMENT = {"text", "txt", "md", "markdown", "json", "csv", "log"}


def _comment_styles(language: str | None) -> tuple[tuple[str, ...], tuple[str, str] | None]:
    lang = (language or "").lower()
    if lang in _NO_COMMENT:
        return (), None
    if lang in _HASH_LINE:
        return ("#",), None
    if lang in _DASH_LINE:
        return ("--",), ("/*", "*/")
    if not lang:
        return ("#", "//"), ("/*", "*/")  # unknown language: common superset
    return ("//",), ("/*", "*/")  # c-family default: js, ts, go, java, rust, php…


def strip_comments(code: str, language: str | None = None) -> str:
    """Remove comments while respecting string literals (fingerprinting-grade)."""
    line_tok, block = _comment_styles(language)
    out: list[str] = []
    i, n = 0, len(code)
    while i < n:
        ch = code[i]
        if ch in ('"', "'"):
            if code.startswith(ch * 3, i):  # triple-quoted string
                end = code.find(ch * 3, i + 3)
                end = n if end == -1 else end + 3
                out.append(code[i:end])
                i = end
                continue
            j = i + 1
            while j < n and code[j] != ch:
                j += 2 if code[j] == "\\" else 1
            out.append(code[i:min(j + 1, n)])
            i = j + 1
            continue
        if block and code.startswith(block[0], i):
            end = code.find(block[1], i + 2)
            i = n if end == -1 else end + len(block[1])
            out.append("\n")  # a block comment ends the logical line
            continue
        if any(code.startswith(tok, i) for tok in line_tok):
            nl = code.find("\n", i)
            i = n if nl == -1 else nl  # keep the newline
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def normalize(code: str, language: str | None = None) -> str:
    """Comments stripped, lines trimmed, blank lines dropped."""
    lines = (ln.rstrip() for ln in strip_comments(code, language).splitlines())
    return "\n".join(ln for ln in lines if ln.strip())


def fingerprint(code: str, language: str | None = None) -> str:
    return hashlib.sha256(normalize(code, language).encode("utf-8", "replace")).hexdigest()[:32]


_TOKEN_RE = re.compile(
    r"""[A-Za-z_][A-Za-z0-9_]*|\d[\d._]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|==|!=|<=|>=|->|=>|&&|\|\||\S"""
)


def tokens(code: str) -> list[str]:
    return _TOKEN_RE.findall(normalize(code))


def _stable_hash(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest(), "big")


def shingles(code: str, n: int = 3) -> set[int]:
    toks = _TOKEN_RE.findall(normalize(code))
    if not toks:
        return set()
    if len(toks) < n:
        return {_stable_hash(" ".join(toks))}
    return {_stable_hash(" ".join(toks[i:i + n])) for i in range(len(toks) - n + 1)}


def similarity(a: set[int], b: set[int]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------- security

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("openai_or_anthropic_key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b")),
]

_GENERIC_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token|"
    r"client_?secret|private_?token|token)\b\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']"
)
_PLACEHOLDER = re.compile(
    r"(?i)(xxx|yyy|placeholder|your[_-]|example|<[^>]*>|\$\{|%s|\{[a-z_]+\}|changeme|change-me|\.\.\.|…)"
)
_NON_SECRET_VALUES = {
    "password", "secret", "token", "true", "false", "null", "none", "undefined",
    "os.environ", "input()", "redacted",
}


def redact(text: str) -> tuple[str, list[str]]:
    """Return (sanitized_text, kinds_found). Secret values are never echoed."""
    kinds: list[str] = []
    new = text
    for kind, pat in _SECRET_PATTERNS:

        def _repl(m: re.Match, kind: str = kind) -> str:
            kinds.append(kind)
            return f"***REDACTED:{kind}***"

        new = pat.sub(_repl, new)

    def _generic(m: re.Match) -> str:
        value = m.group(2)
        if _PLACEHOLDER.search(value) or value.strip().lower() in _NON_SECRET_VALUES:
            return m.group(0)
        kinds.append("credential_assignment")
        start = m.start(2) - m.start(0)
        return m.group(0)[:start] + "***REDACTED:credential_assignment***" + m.group(0)[start + len(value):]

    new = _GENERIC_SECRET.sub(_generic, new)
    return new, kinds


# ------------------------------------------------------------------- store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  state TEXT NOT NULL DEFAULT 'probation' CHECK(state IN ('probation','proven','quarantined')),
  scope TEXT NOT NULL DEFAULT 'project' CHECK(scope IN ('project','global')),
  project TEXT,
  title TEXT NOT NULL,
  code TEXT NOT NULL,
  language TEXT,
  framework TEXT,
  purpose TEXT,
  env TEXT,
  norm_hash TEXT NOT NULL,
  failure_reason TEXT,
  failure_signature TEXT,
  evidence TEXT NOT NULL DEFAULT '[]',
  confidence REAL NOT NULL DEFAULT 0.3,
  success_count INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0,
  limitations TEXT,
  provenance TEXT,
  superseded_by INTEGER,
  archived INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_verified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_norm ON entries(norm_hash);
CREATE INDEX IF NOT EXISTS idx_entries_state ON entries(state, archived);
CREATE TABLE IF NOT EXISTS links(
  failure_id INTEGER NOT NULL,
  replacement_id INTEGER NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(failure_id, replacement_id)
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  entry_id INTEGER,
  action TEXT NOT NULL,
  actor TEXT,
  reason TEXT,
  evidence TEXT,
  prev_state TEXT,
  new_state TEXT,
  prev_confidence REAL,
  new_confidence REAL,
  detail TEXT
);
"""

_FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS entries_fts_ai AFTER INSERT ON entries BEGIN
  INSERT INTO entries_fts(rowid, title, code, purpose, failure_reason, failure_signature)
  VALUES (new.id, new.title, new.code, new.purpose, new.failure_reason, new.failure_signature);
END;
CREATE TRIGGER IF NOT EXISTS entries_fts_ad AFTER DELETE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, title, code, purpose, failure_reason, failure_signature)
  VALUES ('delete', old.id, old.title, old.code, old.purpose, old.failure_reason, old.failure_signature);
END;
CREATE TRIGGER IF NOT EXISTS entries_fts_au AFTER UPDATE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, title, code, purpose, failure_reason, failure_signature)
  VALUES ('delete', old.id, old.title, old.code, old.purpose, old.failure_reason, old.failure_signature);
  INSERT INTO entries_fts(rowid, title, code, purpose, failure_reason, failure_signature)
  VALUES (new.id, new.title, new.code, new.purpose, new.failure_reason, new.failure_signature);
END;
"""

_ENTRY_COLS = {
    "state", "scope", "project", "title", "code", "language", "framework",
    "purpose", "env", "norm_hash", "failure_reason", "failure_signature",
    "evidence", "confidence", "success_count", "failure_count", "limitations",
    "provenance", "superseded_by", "archived", "last_verified_at",
}


class Store:
    """SQLite-backed ledger. Mutations append an event; nothing is deleted."""

    def __init__(self, db_path: str, use_fts: bool = True):
        d = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(d, exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.executescript(_SCHEMA)
        self.fts = False
        if use_fts:
            try:
                self.conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5("
                    "title, code, purpose, failure_reason, failure_signature, "
                    "content='entries', content_rowid='id')"
                )
                self.conn.executescript(_FTS_TRIGGERS)
                n_entries = self.conn.execute("SELECT count(*) FROM entries").fetchone()[0]
                n_fts = self.conn.execute("SELECT count(*) FROM entries_fts").fetchone()[0]
                if n_entries != n_fts:
                    self.conn.execute("INSERT INTO entries_fts(entries_fts) VALUES('rebuild')")
                self.fts = True
            except sqlite3.OperationalError:
                self.fts = False
        self.conn.commit()

    @contextmanager
    def _tx(self):
        with self.conn:
            yield

    # -- entries ------------------------------------------------------------

    def insert(self, **fields) -> int:
        cols = [c for c in fields if c in _ENTRY_COLS]
        now = now_iso()
        values = {c: fields[c] for c in cols}
        values.setdefault("state", "probation")
        values.setdefault("scope", "project")
        values.setdefault("confidence", 0.3)
        values.setdefault("success_count", 0)
        values.setdefault("failure_count", 0)
        values.setdefault("archived", 0)
        values["created_at"] = now
        values["updated_at"] = now
        keys = list(values)
        with self._tx():
            cur = self.conn.execute(
                f"INSERT INTO entries ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                [values[k] for k in keys],
            )
            return int(cur.lastrowid)

    def update(self, entry_id: int, **fields) -> None:
        cols = {k: v for k, v in fields.items() if k in _ENTRY_COLS}
        if not cols:
            return
        cols["updated_at"] = now_iso()
        keys = list(cols)
        with self._tx():
            self.conn.execute(
                f"UPDATE entries SET {', '.join(f'{k} = ?' for k in keys)} WHERE id = ?",
                [cols[k] for k in keys] + [entry_id],
            )

    def get(self, entry_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return dict(row) if row else None

    def all(self, limit: int = 5000) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM entries ORDER BY id LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def candidates(
        self,
        state: str | None = None,
        language: str | None = None,
        project: str | None = None,
        include_archived: bool = False,
        limit: int = 2000,
    ) -> list[dict]:
        q = "SELECT * FROM entries WHERE 1=1"
        params: list = []
        if not include_archived:
            q += " AND archived = 0"
        if state and state != "all":
            q += " AND state = ?"
            params.append(state)
        if language:
            q += " AND (language = ? OR language IS NULL)"
            params.append(language)
        if project:
            q += " AND (scope = 'global' OR project = ?)"
            params.append(project)
        q += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def find_by_hash(self, norm_hash: str, project: str | None) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM entries WHERE norm_hash = ? AND archived = 0 "
            "AND (scope = 'global' OR project = ?) "
            "ORDER BY CASE WHEN scope = 'project' THEN 0 ELSE 1 END LIMIT 1",
            (norm_hash, project),
        ).fetchone()
        return dict(row) if row else None

    # -- events -------------------------------------------------------------

    def add_event(
        self,
        entry_id: int | None,
        action: str,
        actor: str | None = None,
        reason: str | None = None,
        evidence: list | None = None,
        prev_state: str | None = None,
        new_state: str | None = None,
        prev_confidence: float | None = None,
        new_confidence: float | None = None,
        detail: dict | None = None,
    ) -> None:
        import json as _json
        with self._tx():
            self.conn.execute(
                "INSERT INTO events (ts, entry_id, action, actor, reason, evidence, "
                "prev_state, new_state, prev_confidence, new_confidence, detail) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    now_iso(), entry_id, action, actor, reason,
                    _json.dumps(evidence) if evidence else None,
                    prev_state, new_state, prev_confidence, new_confidence,
                    _json.dumps(detail) if detail else None,
                ),
            )

    def events(self, entry_id: int, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE entry_id = ? ORDER BY id DESC LIMIT ?", (entry_id, limit)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # -- links --------------------------------------------------------------

    def link(self, failure_id: int, replacement_id: int, note: str | None = None) -> None:
        with self._tx():
            self.conn.execute(
                "INSERT INTO links (failure_id, replacement_id, note, created_at) VALUES (?,?,?,?) "
                "ON CONFLICT(failure_id, replacement_id) "
                "DO UPDATE SET note = COALESCE(excluded.note, links.note)",
                (failure_id, replacement_id, note, now_iso()),
            )

    def links_from(self, failure_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM links WHERE failure_id = ?", (failure_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def links_to(self, replacement_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM links WHERE replacement_id = ?", (replacement_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def rewrite_links(self, old_id: int, new_id: int) -> None:
        """Point all links at `new_id` (used when merging duplicates)."""
        with self._tx():
            for f, r, note in self.conn.execute(
                "SELECT failure_id, replacement_id, note FROM links "
                "WHERE failure_id = ? OR replacement_id = ?", (old_id, old_id)
            ).fetchall():
                nf, nr = (new_id if f == old_id else f, new_id if r == old_id else r)
                if nf == nr:
                    continue
                self.conn.execute(
                    "INSERT INTO links (failure_id, replacement_id, note, created_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(failure_id, replacement_id) DO NOTHING",
                    (nf, nr, note, now_iso()),
                )
            self.conn.execute(
                "DELETE FROM links WHERE failure_id = ? OR replacement_id = ?", (old_id, old_id)
            )

    # -- search / stats -----------------------------------------------------

    def text_search(self, terms: list[str], limit: int = 100) -> dict[int, float]:
        """Full-text scores {entry_id: 0..1}. FTS5 when available, LIKE otherwise."""
        terms = [t for t in terms if t]
        if not terms:
            return {}
        if self.fts:
            match = " OR ".join('"' + t.replace('"', " ").strip() + '"' for t in terms if t.replace('"', " ").strip())
            if match:
                try:
                    rows = self.conn.execute(
                        "SELECT rowid, rank FROM entries_fts WHERE entries_fts MATCH ? "
                        "ORDER BY rank LIMIT ?",
                        (match, limit),
                    ).fetchall()
                    return {r[0]: (min(1.0, abs(r[1]) / 6.0) if r[1] is not None else 0.5) for r in rows}
                except sqlite3.OperationalError:
                    pass
        scores: dict[int, float] = {}
        for t in terms:
            pat = "%" + t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conds = " OR ".join(
                f"{c} LIKE ? ESCAPE '\\'" for c in ("title", "code", "purpose", "failure_reason", "failure_signature")
            )
            rows = self.conn.execute(f"SELECT id FROM entries WHERE {conds}", (pat,) * 5).fetchall()
            for r in rows:
                scores[r[0]] = min(1.0, scores.get(r[0], 0.0) + 0.4)
        top = sorted(scores.items(), key=lambda kv: -kv[1])[:limit]
        return dict(top)

    def stats(self) -> dict:
        out: dict = {"by_state": {}, "by_scope": {}, "archived": 0, "total": 0,
                     "events": 0, "links": 0}
        for state, n in self.conn.execute("SELECT state, count(*) FROM entries GROUP BY state"):
            out["by_state"][state] = n
        for scope, n in self.conn.execute("SELECT scope, count(*) FROM entries GROUP BY scope"):
            out["by_scope"][scope] = n
        out["archived"] = self.conn.execute("SELECT count(*) FROM entries WHERE archived = 1").fetchone()[0]
        out["total"] = self.conn.execute("SELECT count(*) FROM entries").fetchone()[0]
        out["events"] = self.conn.execute("SELECT count(*) FROM events").fetchone()[0]
        out["links"] = self.conn.execute("SELECT count(*) FROM links").fetchone()[0]
        return out

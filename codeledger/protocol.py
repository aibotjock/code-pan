"""MCP stdio transport: newline-delimited JSON-RPC 2.0.

Speaks the Model Context Protocol tools surface over stdin/stdout with zero
dependencies. stdout carries only protocol messages; logs go to stderr.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

from . import __version__, engine
from .ledger import Store, default_project, now_iso

SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}

_EVIDENCE = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": sorted(engine.VALID_EVIDENCE)},
            "detail": {"type": "string"},
        },
        "required": ["type"],
    },
}

_TOOL_SPECS = [
    (
        "get_experience",
        "Retrieve relevant experience BEFORE writing or editing non-trivial code. "
        "Returns top proven patterns to reuse and known failures to avoid (with linked "
        "repair replacements). Pass 'query' (topic terms) and/or 'code' (candidate "
        "snippet); optionally 'language' and 'env' (e.g. {\"python\":\"3.12\",\"os\":\"linux\"}) "
        "for context-aware ranking. Project + global scopes are always both searched.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "code": {"type": "string"},
                "language": {"type": "string"},
                "env": {"type": "object"},
            },
        },
    ),
    (
        "check_code",
        "Check a candidate snippet BEFORE committing to an approach (read-only). "
        "Flags strong similarity to quarantined failures (BLOCK, or a weaker warning "
        "when the environment differs) and proven patterns worth reusing. Never stores anything.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "language": {"type": "string"},
                "env": {"type": "object"},
            },
            "required": ["code"],
        },
    ),
    (
        "search",
        "Search the ledger: proven solutions, quarantined failures, or probation entries. "
        "'state' filters (default all). 'query' matches text; 'code' adds structural similarity. "
        "Returns compact one-line summaries only.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "code": {"type": "string"},
                "state": {"type": "string", "enum": ["all", "proven", "probation", "quarantined"]},
                "language": {"type": "string"},
                "env": {"type": "object"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                "include_archived": {"type": "boolean"},
            },
        },
    ),
    (
        "record_success",
        "AFTER validation passes (tests, build, lint, runtime, human confirmation), record "
        "the code/pattern as working. Objective evidence promotes probation entries to PROVEN; "
        "agent_opinion evidence alone keeps them in probation. Updates counts and confidence "
        "when the same fingerprint already exists (project scope first, then global).",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "entry_id": {"type": "integer"},
                "title": {"type": "string"},
                "purpose": {"type": "string"},
                "language": {"type": "string"},
                "framework": {"type": "string"},
                "env": {"type": "object"},
                "evidence": _EVIDENCE,
                "limitations": {"type": "string"},
                "provenance": {"type": "string"},
                "allow_redact": {"type": "boolean"},
                "project": {"type": "string"},
                "actor": {"type": "string"},
            },
        },
    ),
    (
        "record_failure",
        "AFTER a failure is observed, record the code/pattern, why it failed, and the error "
        "signature. Objective evidence (test/regression/runtime/human_reject) quarantines it; "
        "opinion-only keeps it in probation with lowered confidence. Optionally pass "
        "'replacement_code' to record the working fix and link failure → replacement in one call.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "entry_id": {"type": "integer"},
                "title": {"type": "string"},
                "reason": {"type": "string"},
                "signature": {"type": "string"},
                "language": {"type": "string"},
                "framework": {"type": "string"},
                "env": {"type": "object"},
                "evidence": _EVIDENCE,
                "replacement_code": {"type": "string"},
                "replacement_title": {"type": "string"},
                "replacement_evidence": _EVIDENCE,
                "allow_redact": {"type": "boolean"},
                "project": {"type": "string"},
                "actor": {"type": "string"},
            },
            "required": ["reason"],
        },
    ),
    (
        "promote",
        "promote: probation → proven (requires objective success evidence on the entry), "
        "or with to_global=true: proven project entry → GLOBAL scope (requires confidence "
        ">= 0.80, >= 3 successful uses, objective evidence). Reason is audit-logged.",
        {
            "type": "object",
            "properties": {
                "entry_id": {"type": "integer"},
                "reason": {"type": "string"},
                "to_global": {"type": "boolean"},
            },
            "required": ["entry_id", "reason"],
        },
    ),
    (
        "quarantine",
        "Move an entry to QUARANTINED. Requires objective grounds: either the entry already "
        "has objective failure evidence, or pass evidence [{\"type\":\"human_reject\",...}] "
        "for explicit human rejection. Reason is audit-logged.",
        {
            "type": "object",
            "properties": {
                "entry_id": {"type": "integer"},
                "reason": {"type": "string"},
                "signature": {"type": "string"},
                "evidence": _EVIDENCE,
            },
            "required": ["entry_id", "reason"],
        },
    ),
    (
        "reactivate",
        "Return a QUARANTINED entry to probation when circumstances change (dependency "
        "upgraded, bug fixed, environment changed, misclassification). Reason is required "
        "and audit-logged; the failure history is preserved; fresh objective evidence is "
        "required before it can become proven again.",
        {
            "type": "object",
            "properties": {
                "entry_id": {"type": "integer"},
                "reason": {"type": "string"},
            },
            "required": ["entry_id", "reason"],
        },
    ),
    (
        "link_replacement",
        "Link a failed approach to its successful replacement: failure #id → replacement "
        "(existing entry id, or new code that is recorded now). Powers 'what to use instead'.",
        {
            "type": "object",
            "properties": {
                "failure_id": {"type": "integer"},
                "replacement_id": {"type": "integer"},
                "replacement_code": {"type": "string"},
                "replacement_title": {"type": "string"},
                "replacement_evidence": _EVIDENCE,
                "note": {"type": "string"},
            },
            "required": ["failure_id"],
        },
    ),
    (
        "update_confidence",
        "Manually adjust an entry's confidence (delta <= 0.5 per call, or an absolute value "
        "in [0,1]). Reason is audit-logged. Prefer record_success/record_failure — they move "
        "confidence from evidence.",
        {
            "type": "object",
            "properties": {
                "entry_id": {"type": "integer"},
                "delta": {"type": "number"},
                "value": {"type": "number", "minimum": 0, "maximum": 1},
                "reason": {"type": "string"},
            },
            "required": ["entry_id", "reason"],
        },
    ),
    (
        "explain",
        "Explain an entry's classification: current state, confidence, environment context, "
        "evidence, failure → replacement links, and the full append-only history of how it "
        "got here.",
        {
            "type": "object",
            "properties": {"entry_id": {"type": "integer"}},
            "required": ["entry_id"],
        },
    ),
    (
        "maintain",
        "Lightweight maintenance: confidence decay for stale entries, archive low-value "
        "probation entries, merge exact duplicates, report near-duplicates, size stats. "
        "Nothing is ever deleted — quarantined knowledge is permanent. dry_run=true reports only.",
        {
            "type": "object",
            "properties": {
                "dry_run": {"type": "boolean"},
                "merge_duplicates": {"type": "boolean"},
            },
        },
    ),
]

TOOLS = [
    {"name": name, "description": desc, "inputSchema": schema}
    for name, desc, schema in _TOOL_SPECS
]

_DISPATCH = {
    "get_experience": engine.get_experience,
    "check_code": engine.check_code,
    "search": engine.search,
    "record_success": engine.record_success,
    "record_failure": engine.record_failure,
    "promote": engine.promote,
    "quarantine": engine.quarantine,
    "reactivate": engine.reactivate,
    "link_replacement": engine.link_replacement,
    "update_confidence": engine.update_confidence,
    "explain": engine.explain,
    "maintain": engine.maintain,
}


def _default_project() -> str:
    return default_project()


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _log(msg: str) -> None:
    sys.stderr.write(json.dumps({"ts": now_iso(), "msg": msg}) + "\n")
    sys.stderr.flush()


def _tool_result(text: str, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return result


def _call_tool(store: Store, default_project: str, default_actor: str | None,
               client: str, params: dict) -> dict:
    name = params.get("name")
    fn = _DISPATCH.get(name)
    if fn is None:
        return _tool_result(f"unknown tool '{name}'", is_error=True)
    args = dict(params.get("arguments") or {})
    ctx = {
        "store": store,
        "actor": args.pop("actor", None) or default_actor or f"client:{client}",
        "project": args.pop("project", None) or default_project,
        "db_path": store.db_path,
    }
    try:
        return _tool_result(fn(ctx, args))
    except engine.ToolError as exc:
        _log(f"tool error ({name}): {exc}")
        return _tool_result(str(exc), is_error=True)


def serve(db_path: str | None = None) -> None:
    db_path = db_path or os.environ.get("CODELEDGER_DB") or os.path.expanduser(
        "~/.codeledger/ledger.db")
    store = Store(db_path)
    default_project = os.environ.get("CODELEDGER_PROJECT") or _default_project()
    default_actor = os.environ.get("CODELEDGER_ACTOR")
    client = "unknown-client"
    _log(f"codeledger {__version__} serving db={db_path} project={default_project}")
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                _send({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32700, "message": "Parse error"}})
                continue
            if not isinstance(msg, dict):
                _send({"jsonrpc": "2.0", "id": None,
                       "error": {"code": -32600, "message": "Invalid Request"}})
                continue
            method = msg.get("method")
            msg_id = msg.get("id")
            if method == "initialize":
                params = msg.get("params") or {}
                client = (params.get("clientInfo") or {}).get("name", client)
                version = params.get("protocolVersion")
                if version not in SUPPORTED_PROTOCOL_VERSIONS:
                    version = "2025-06-18"
                _send({
                    "jsonrpc": "2.0", "id": msg_id, "result": {
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "codeledger", "version": __version__},
                    }
                })
                continue
            if "id" not in msg:
                continue  # notification (notifications/initialized, cancelled, …)
            try:
                if method == "ping":
                    _send({"jsonrpc": "2.0", "id": msg_id, "result": {}})
                elif method == "tools/list":
                    _send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
                elif method == "tools/call":
                    _send({"jsonrpc": "2.0", "id": msg_id, "result": _call_tool(
                        store, default_project, default_actor, client, msg.get("params") or {})})
                else:
                    _send({"jsonrpc": "2.0", "id": msg_id,
                           "error": {"code": -32601, "message": f"Method not found: {method}"}})
            except Exception as exc:  # transport must never die on a handler bug
                _log(f"error handling {method}: {exc}\n{traceback.format_exc()}")
                _send({"jsonrpc": "2.0", "id": msg_id,
                       "error": {"code": -32603, "message": f"Internal error: {exc}"}})
    except KeyboardInterrupt:
        pass
    finally:
        store.conn.close()


if __name__ == "__main__":
    serve()

"""codepan — terminal front-end to the CodeLedger.

Same engine and same SQLite database as the MCP server, so terminal and
Claude Code share one memory. Exit codes: 0 ok, 1 `check` hit a BLOCK,
2 usage/validation error.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import engine
from .engine import ToolError
from .ledger import Store, default_project


def _parse_evidence(items: list[str] | None) -> list[dict] | None:
    if not items:
        return None
    out = []
    for it in items:
        typ, _, detail = it.partition("=")
        out.append({"type": typ.strip(), "detail": detail.strip()})
    return out


def _parse_env(items: list[str] | None) -> dict | None:
    if not items:
        return None
    env = {}
    for it in items:
        k, sep, v = it.partition("=")
        if not sep or not k:
            raise ToolError(f"--env expects KEY=VALUE, got {it!r}")
        env[k.strip()] = v
    return env


def _read_code(args: argparse.Namespace) -> str:
    if getattr(args, "code", None):
        return args.code
    src = getattr(args, "file", "-") or "-"
    if src == "-":
        if sys.stdin.isatty():
            raise ToolError("no input: pass a file, a code snippet, or pipe via -")
        code = sys.stdin.read()
        if not code.strip():
            raise ToolError("no input: stdin was empty; pass a file, a snippet, or pipe code via -")
        return code
    if os.path.exists(src):
        with open(src, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return src  # small literal snippet instead of a path


def _code_args(args: argparse.Namespace) -> dict:
    d = {"code": _read_code(args), "language": args.lang}
    if getattr(args, "title", None):
        d["title"] = args.title
    env = _parse_env(getattr(args, "env", None))
    if env:
        d["env"] = env
    return d


# ----------------------------------------------------------------- handlers


def _h_check(ctx, args):
    out = engine.check_code(ctx, {"code": _read_code(args), "language": args.lang,
                                  "env": _parse_env(args.env)})
    return out, (1 if "⛔ BLOCK" in out else 0)


def _h_ok(ctx, args):
    d = _code_args(args)
    d["evidence"] = _parse_evidence(args.evidence) or [{"type": "agent_opinion"}]
    for k in ("purpose", "framework", "limitations", "entry_id"):
        if getattr(args, k, None) is not None:
            d[k] = getattr(args, k)
    if args.allow_redact:
        d["allow_redact"] = True
    return engine.record_success(ctx, d), 0


def _h_fail(ctx, args):
    d = _code_args(args)
    d.update(reason=args.reason, signature=args.signature,
             evidence=_parse_evidence(args.evidence))
    if args.replacement:
        with open(args.replacement, encoding="utf-8", errors="replace") as fh:
            d["replacement_code"] = fh.read()
        d["replacement_title"] = args.replacement_title
        d["replacement_evidence"] = _parse_evidence(args.replacement_evidence)
    if args.allow_redact:
        d["allow_redact"] = True
    if args.entry_id is not None:
        d["entry_id"] = args.entry_id
    return engine.record_failure(ctx, d), 0


def _h_exp(ctx, args):
    return engine.get_experience(ctx, {"query": " ".join(args.query), "language": args.lang,
                                       "env": _parse_env(args.env)}), 0


def _h_search(ctx, args):
    d = {"query": " ".join(args.query), "state": args.state, "language": args.lang,
         "limit": args.limit, "env": _parse_env(args.env)}
    if args.code_file:
        with open(args.code_file, encoding="utf-8", errors="replace") as fh:
            d["code"] = fh.read()
    return engine.search(ctx, d), 0


def _h_explain(ctx, args):
    return engine.explain(ctx, {"entry_id": args.id}), 0


def _h_promote(ctx, args):
    return engine.promote(ctx, {"entry_id": args.id, "reason": args.reason,
                                "to_global": args.to_global}), 0


def _h_quarantine(ctx, args):
    d = {"entry_id": args.id, "reason": args.reason, "signature": args.signature}
    if args.rejected:
        d["evidence"] = [{"type": "human_reject", "detail": args.reason}]
    return engine.quarantine(ctx, d), 0


def _h_reactivate(ctx, args):
    return engine.reactivate(ctx, {"entry_id": args.id, "reason": args.reason}), 0


def _h_link(ctx, args):
    d = {"failure_id": args.failure_id, "note": args.note,
         "replacement_id": args.replacement_id, "replacement_title": args.replacement_title,
         "replacement_evidence": _parse_evidence(args.evidence)}
    if args.replacement:
        with open(args.replacement, encoding="utf-8", errors="replace") as fh:
            d["replacement_code"] = fh.read()
    return engine.link_replacement(ctx, d), 0


def _h_conf(ctx, args):
    d = {"entry_id": args.id, "reason": args.reason}
    if args.delta is not None:
        d["delta"] = args.delta
    if args.value is not None:
        d["value"] = args.value
    return engine.update_confidence(ctx, d), 0


def _h_maintain(ctx, args):
    return engine.maintain(ctx, {"dry_run": args.dry_run,
                                  "merge_duplicates": not args.no_merge}), 0


# ------------------------------------------------------------------ parser


def _add_code_input(sp, with_title=False):
    sp.add_argument("file", nargs="?", default="-",
                    help="file containing the code, '-' for stdin, or a literal snippet")
    sp.add_argument("--code", help="inline code string (overrides the positional)")
    sp.add_argument("--lang", help="language (python, js, sql, …)")
    sp.add_argument("--env", action="append", metavar="K=V",
                    help="environment context, repeatable (os=linux python=3.12)")
    if with_title:
        sp.add_argument("--title")


def _add_evidence(sp, label="--evidence", dest="evidence"):
    sp.add_argument(label, dest=dest, action="append", metavar="TYPE=DETAIL",
                    help=f"objective evidence, repeatable ({label} test='pytest: 42 passed')")
    sp.add_argument("--allow-redact", action="store_true",
                    help="store a redacted copy when secrets are detected")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codepan",
        description="CodeLedger terminal client — same memory as the codeledger MCP.",
    )
    p.add_argument("--db", default=os.environ.get("CODELEDGER_DB")
                   or os.path.expanduser("~/.codeledger/ledger.db"))
    p.add_argument("--project", default=os.environ.get("CODELEDGER_PROJECT"),
                   help="project scope (default: <dirname>-<hash> of the cwd)")
    p.add_argument("--actor", default=os.environ.get("CODELEDGER_ACTOR")
                   or f"cli:{getpass.getuser()}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("check", help="check code against known failures (exit 1 on BLOCK)")
    _add_code_input(sp)
    sp.set_defaults(func=_h_check)

    sp = sub.add_parser("ok", help="record a success (after validation passes)")
    _add_code_input(sp, with_title=True)
    sp.add_argument("--purpose")
    sp.add_argument("--framework")
    sp.add_argument("--limitations")
    sp.add_argument("--id", type=int, dest="entry_id")
    _add_evidence(sp)
    sp.set_defaults(func=_h_ok)

    sp = sub.add_parser("fail", help="record a failure (why + signature + evidence)")
    _add_code_input(sp, with_title=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--signature", default="")
    sp.add_argument("--id", type=int, dest="entry_id")
    sp.add_argument("--framework")
    _add_evidence(sp)
    sp.add_argument("--replacement", metavar="FILE",
                    help="code of the working fix — records and links it")
    sp.add_argument("--replacement-title")
    sp.add_argument("--replacement-evidence", action="append", metavar="TYPE=DETAIL")
    sp.set_defaults(func=_h_fail)

    sp = sub.add_parser("exp", help="relevant experience before coding (proven + failures)")
    sp.add_argument("query", nargs="*", help="topic terms")
    _add_code_input(sp)
    sp.set_defaults(func=_h_exp)

    sp = sub.add_parser("search", help="search the ledger")
    sp.add_argument("query", nargs="*")
    sp.add_argument("--state", default="all",
                    choices=["all", "proven", "probation", "quarantined"])
    sp.add_argument("--lang")
    sp.add_argument("--limit", type=int, default=5)
    sp.add_argument("--code-file", help="also match by similarity against this file")
    sp.add_argument("--env", action="append", metavar="K=V")
    sp.set_defaults(func=_h_search)

    sp = sub.add_parser("explain", help="full classification history of an entry")
    sp.add_argument("id", type=int)
    sp.set_defaults(func=_h_explain)

    sp = sub.add_parser("promote", help="probation→proven, or --global for project→global")
    sp.add_argument("id", type=int)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--global", dest="to_global", action="store_true")
    sp.set_defaults(func=_h_promote)

    sp = sub.add_parser("quarantine", help="quarantine an entry (--rejected for human reject)")
    sp.add_argument("id", type=int)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--signature", default="")
    sp.add_argument("--rejected", action="store_true",
                    help="explicit human rejection (counts as objective evidence)")
    sp.set_defaults(func=_h_quarantine)

    sp = sub.add_parser("reactivate", help="quarantined→probation (reason recorded)")
    sp.add_argument("id", type=int)
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=_h_reactivate)

    sp = sub.add_parser("link", help="link a failure to its replacement")
    sp.add_argument("failure_id", type=int)
    sp.add_argument("--replacement-id", type=int)
    sp.add_argument("--replacement", metavar="FILE", help="code of the replacement")
    sp.add_argument("--replacement-title")
    sp.add_argument("--note")
    _add_evidence(sp)
    sp.set_defaults(func=_h_link)

    sp = sub.add_parser("conf", help="manually adjust confidence")
    sp.add_argument("id", type=int)
    sp.add_argument("--delta", type=float)
    sp.add_argument("--value", type=float)
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=_h_conf)

    sp = sub.add_parser("maintain", help="decay, archive, merge duplicates, stats")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--no-merge", action="store_true")
    sp.set_defaults(func=_h_maintain)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    ctx = {"store": store, "actor": args.actor,
           "project": args.project or default_project(), "db_path": store.db_path}
    try:
        text, code = args.func(ctx, args)
        if text:
            print(text)
        return code
    except ToolError as exc:
        print(f"codepan: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"codepan: {exc}", file=sys.stderr)
        return 2
    finally:
        store.conn.close()


if __name__ == "__main__":
    sys.exit(main())

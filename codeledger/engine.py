"""Engine: three-state lifecycle, evidence rules, and the CodeLedger tools.

States: probation (unverified), proven (objective success evidence),
quarantined (objective failure evidence or explicit human rejection).
Every state change writes an audit event; history is never rewritten.

Golden rule: opinion alone changes nothing. Only objective evidence
(tests, builds, runtime, human confirmation/rejection) moves code between
proven and quarantined.
"""
from __future__ import annotations

import json
import re

from .ledger import (
    Store, days_since, clamp, fingerprint, now_iso, redact, shingles,
    similarity, truncate,
)

MAX_CODE_CHARS = 64_000
MAX_OUTPUT_CHARS = 6_000
STRONG_SIM = 0.85
MEDIUM_SIM = 0.60

VALID_EVIDENCE = {
    "build", "test", "regression_test", "lint", "typecheck", "static_analysis",
    "security_check", "runtime", "human_confirm", "human_reject", "agent_opinion",
}
OBJECTIVE = VALID_EVIDENCE - {"agent_opinion"}

_SUCCESS_WEIGHT = {"agent_opinion": 0.10, "human_confirm": 0.20}  # default objective: 0.15


class ToolError(Exception):
    """User-facing error; surfaced as an MCP tool error, never a crash."""


# ------------------------------------------------------------------ helpers


def _evidence(items: list | None, polarity: str) -> list[dict]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ToolError("'evidence' must be a list of {type, detail} objects")
    if polarity == "success":
        banned = {"human_reject"}
    else:
        banned = {"human_confirm"}
    out = []
    for it in items:
        if not isinstance(it, dict) or it.get("type") not in VALID_EVIDENCE:
            raise ToolError(
                f"evidence type must be one of {sorted(VALID_EVIDENCE)}; got {it!r}"
            )
        if it.get("type") in banned:
            raise ToolError(f"evidence '{it['type']}' contradicts a {polarity} record")
        clean, _ = redact(str(it.get("detail", ""))[:500])
        out.append({"type": it["type"], "detail": clean, "ts": now_iso(), "polarity": polarity})
    return out


def _has_objective(entry: dict, polarity: str) -> bool:
    ev = json.loads(entry.get("evidence") or "[]")
    return any(
        e.get("polarity") == polarity and e.get("type") in OBJECTIVE for e in ev
    )


def _weight(evidence: list[dict]) -> float:
    return max(_SUCCESS_WEIGHT.get(e["type"], 0.15) for e in evidence) if evidence else 0.0


def _sanitize_fields(args: dict, keys: tuple[str, ...]) -> tuple[dict, list[str]]:
    """Redact the given string fields; report kinds found so caller can refuse."""
    cleaned, kinds = {}, []
    for k in keys:
        v = args.get(k)
        if v is None:
            continue
        cleaned[k], found = redact(str(v))
        kinds += found
    return cleaned, kinds


def _check_secrets(kinds: list[str], args: dict) -> None:
    if kinds and not args.get("allow_redact"):
        raise ToolError(
            "refusing to persist: possible secrets detected ("
            + ", ".join(sorted(set(kinds)))
            + "). Remove them and retry, or pass allow_redact=true to store a redacted copy."
        )


def _default_title(code: str) -> str:
    for ln in code.splitlines():
        if ln.strip():
            return ln.strip()[:80]
    return "(empty)"


def _env_conflicts(entry_env: dict | None, query_env: dict | None) -> list[str]:
    if not entry_env or not query_env:
        return []
    out = []
    for k, v in query_env.items():
        if k in entry_env:
            a, b = str(entry_env[k]), str(v)
            if a != b and not a.startswith(b) and not b.startswith(a):
                out.append(f"{k}: entry={a} vs current={b}")
    return out


def _entry_env(entry: dict) -> dict | None:
    try:
        return json.loads(entry.get("env") or "null")
    except ValueError:
        return None


def _brief(entry: dict) -> str:
    tag = f"#{entry['id']} [{entry['state'].upper()}·{entry['scope']}"
    if entry.get("language"):
        tag += f"·{entry['language']}"
    tag += f"] conf {entry['confidence']:.2f} · {entry['success_count']}✓/{entry['failure_count']}✗"
    line = f"{tag} · {entry['title']}"
    if entry["state"] == "quarantined" and entry.get("failure_reason"):
        line += f"\n    why: {entry['failure_reason']}"
        if entry.get("failure_signature"):
            line += f"\n    signature: {entry['failure_signature']}"
    if entry.get("limitations"):
        line += f"\n    limits: {entry['limitations']}"
    return line


def _merged_evidence(entry: dict, new_items: list[dict]) -> str:
    ev = json.loads(entry.get("evidence") or "[]") + new_items
    return json.dumps(ev[-20:])  # keep the most recent 20 items


def _parse_evidence_list(entry: dict) -> list[dict]:
    return json.loads(entry.get("evidence") or "[]")


# ------------------------------------------------------------------ record


def record_success(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    evidence = _evidence(args.get("evidence"), "success")
    objective = any(e["type"] in OBJECTIVE for e in evidence)
    entry_id = args.get("entry_id")

    if entry_id is not None:
        entry = store.get(int(entry_id))
        if not entry:
            raise ToolError(f"entry {entry_id} not found")
    else:
        code = args.get("code")
        if not code or not str(code).strip():
            raise ToolError("provide 'code' or 'entry_id'")
        code = str(code)
        if len(code) > MAX_CODE_CHARS:
            raise ToolError(f"code exceeds {MAX_CODE_CHARS} chars; store a normalized snippet instead")
        clean, kinds = _sanitize_fields(args, ("title", "purpose", "limitations", "provenance"))
        clean_code, ck = redact(code)
        _check_secrets(kinds + ck, args)
        language = args.get("language")
        entry = store.find_by_hash(fingerprint(clean_code, language), ctx["project"])
        if entry is None:
            title = clean.get("title") or _default_title(clean_code)
            env = args.get("env") if isinstance(args.get("env"), dict) else None
            entry_id = store.insert(
                state="proven" if objective else "probation",
                scope="project", project=ctx["project"],
                title=title, code=clean_code, language=language,
                framework=args.get("framework"), purpose=clean.get("purpose"),
                env=json.dumps(env) if env else None,
                norm_hash=fingerprint(clean_code, language),
                evidence=json.dumps(evidence),
                confidence=0.65 if objective else 0.30,
                success_count=1, failure_count=0,
                limitations=clean.get("limitations"), provenance=clean.get("provenance"),
                last_verified_at=now_iso() if objective else None,
            )
            store.add_event(entry_id, "created", ctx["actor"], reason="success recorded",
                            evidence=evidence, new_state="proven" if objective else "probation",
                            new_confidence=0.65 if objective else 0.30)
            return (f"created #{entry_id} [{'PROVEN' if objective else 'PROBATION'}·{ctx['project']}] "
                    f"confidence {'0.65' if objective else '0.30'}"
                    + ("" if objective else " — opinion only; objective evidence (test/build/runtime/human) will promote it"))

    # --- update path ---
    entry_id = entry["id"]
    prev_state, prev_conf = entry["state"], entry["confidence"]
    new_conf = clamp(prev_conf + (_weight(evidence) if evidence else 0.10), hi=0.95)
    updates = {
        "evidence": _merged_evidence(entry, evidence),
        "success_count": entry["success_count"] + 1,
        "confidence": new_conf,
    }
    if objective:
        updates["last_verified_at"] = now_iso()
    action, note = "evidence_added", f"success recorded on #{entry_id} ({entry['state']})"
    if entry["state"] == "probation" and objective:
        updates["state"] = "proven"
        updates["confidence"] = max(new_conf, 0.65)
        action, note = "promoted", note + " → PROVEN (objective evidence)"
        new_conf = updates["confidence"]
    elif entry["state"] == "quarantined" and objective:
        updates["confidence"] = clamp(new_conf - 0.25, lo=0.05)  # conflicting result
        new_conf = updates["confidence"]
        note += (f" — conflicting success evidence; confidence lowered to {new_conf:.2f}. "
                 f"If circumstances changed (deps/env), call reactivate.")
    store.update(entry_id, **updates)
    store.add_event(entry_id, action, ctx["actor"], reason="success recorded",
                    evidence=evidence, prev_state=prev_state,
                    new_state=updates.get("state", prev_state),
                    prev_confidence=prev_conf, new_confidence=new_conf)
    entry = store.get(entry_id)
    return f"{note}; confidence {entry['confidence']:.2f}, {entry['success_count']}✓/{entry['failure_count']}✗"


def record_failure(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    if not args.get("reason", "").strip():
        raise ToolError("'reason' is required: what failed and why")
    evidence = _evidence(args.get("evidence"), "fail")
    objective = any(e["type"] in OBJECTIVE for e in evidence)  # human_reject counts
    clean_reason, rk = redact(args["reason"])
    clean_sig, sk = redact(str(args.get("signature") or ""))
    entry_id = args.get("entry_id")

    if entry_id is not None:
        entry = store.get(int(entry_id))
        if not entry:
            raise ToolError(f"entry {entry_id} not found")
    else:
        code = args.get("code")
        if not code or not str(code).strip():
            raise ToolError("provide 'code' or 'entry_id'")
        code = str(code)
        if len(code) > MAX_CODE_CHARS:
            raise ToolError(f"code exceeds {MAX_CODE_CHARS} chars; store a normalized snippet instead")
        clean, kinds = _sanitize_fields(args, ("title", "purpose"))
        clean_code, ck = redact(code)
        _check_secrets(kinds + ck + rk + sk, args)
        language = args.get("language")
        entry = store.find_by_hash(fingerprint(clean_code, language), ctx["project"])
        if entry is None:
            quarantined = objective
            conf = (0.85 if any(e["type"] == "human_reject" for e in evidence)
                    else 0.70 if quarantined else 0.30)
            env = args.get("env") if isinstance(args.get("env"), dict) else None
            entry_id = store.insert(
                state="quarantined" if quarantined else "probation",
                scope="project", project=ctx["project"],
                title=clean.get("title") or _default_title(clean_code),
                code=clean_code, language=language, framework=args.get("framework"),
                purpose=clean.get("purpose"),
                env=json.dumps(env) if env else None,
                norm_hash=fingerprint(clean_code, language),
                failure_reason=clean_reason[:2000],
                failure_signature=(clean_sig[:500] or None),
                evidence=json.dumps(evidence),
                confidence=conf, success_count=0, failure_count=1,
            )
            store.add_event(entry_id, "created", ctx["actor"], reason=clean_reason,
                            evidence=evidence,
                            new_state="quarantined" if quarantined else "probation",
                            new_confidence=conf)
            note = (f"created #{entry_id} [QUARANTINED·{ctx['project']}] confidence {conf:.2f}"
                    if quarantined else
                    f"created #{entry_id} [PROBATION·{ctx['project']}] confidence 0.30 "
                    f"— opinion-only failure; needs objective evidence to quarantine")
            if args.get("replacement_code"):
                note += "\n" + _link_replacement_impl(ctx, entry_id, args)
            return note

    # --- update path ---
    entry_id = entry["id"]
    prev_state, prev_conf = entry["state"], entry["confidence"]
    updates = {
        "evidence": _merged_evidence(entry, evidence),
        "failure_count": entry["failure_count"] + 1,
        "failure_reason": clean_reason[:2000],
    }
    if clean_sig:
        updates["failure_signature"] = clean_sig[:500]
    action = "evidence_added"
    if prev_state == "quarantined":
        updates["confidence"] = clamp(prev_conf + 0.05, hi=0.95)  # failure reinforced
    elif objective:
        updates["state"] = "quarantined"
        updates["confidence"] = (0.85 if any(e["type"] == "human_reject" for e in evidence) else 0.70)
        action = "auto_quarantined"
    else:
        updates["confidence"] = clamp(prev_conf - 0.10, lo=0.05)
    store.update(entry_id, **updates)
    store.add_event(entry_id, action, ctx["actor"], reason=clean_reason, evidence=evidence,
                    prev_state=prev_state, new_state=updates.get("state", prev_state),
                    prev_confidence=prev_conf, new_confidence=updates["confidence"])
    note = (f"failure recorded on #{entry_id} [{updates.get('state', prev_state).upper()}] "
            f"confidence {updates['confidence']:.2f}")
    if args.get("replacement_code"):
        note += "\n" + _link_replacement_impl(ctx, entry_id, args)
    return note


# ------------------------------------------------------- state transitions


def promote(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    entry = store.get(int(args.get("entry_id", 0)))
    if not entry:
        raise ToolError("entry not found")
    reason = (args.get("reason") or "").strip()
    if not reason:
        raise ToolError("'reason' is required (recorded in the audit trail)")
    if args.get("to_global"):
        if entry["scope"] != "project":
            raise ToolError("entry is already global")
        if entry["state"] != "proven":
            raise ToolError("only PROVEN entries can be promoted to global scope")
        if not (_has_objective(entry, "success") and entry["success_count"] >= 3
                and entry["confidence"] >= 0.80):
            raise ToolError(
                "global promotion needs strong evidence: objective success evidence, "
                f">=3 successful uses (has {entry['success_count']}), confidence >= 0.80 "
                f"(has {entry['confidence']:.2f})"
            )
        store.update(entry["id"], scope="global", project=None)
        store.add_event(entry["id"], "promote_global", ctx["actor"], reason=reason,
                        prev_state="proven", new_state="proven",
                        prev_confidence=entry["confidence"], new_confidence=entry["confidence"])
        return f"#{entry['id']} promoted to GLOBAL scope (repository failures never auto-escalate)"
    if entry["state"] == "quarantined":
        raise ToolError("entry is quarantined; use reactivate (returns it to probation)")
    if entry["state"] == "proven":
        return f"#{entry['id']} is already proven"
    if not _has_objective(entry, "success"):
        raise ToolError(
            "cannot promote on opinion alone: record_success with objective evidence "
            "(test/build/lint/runtime/human_confirm) first"
        )
    new_conf = max(entry["confidence"], 0.65)
    store.update(entry["id"], state="proven", confidence=new_conf, last_verified_at=now_iso())
    store.add_event(entry["id"], "promoted", ctx["actor"], reason=reason,
                    prev_state="probation", new_state="proven",
                    prev_confidence=entry["confidence"], new_confidence=new_conf)
    return f"#{entry['id']} PROBATION → PROVEN, confidence {new_conf:.2f}"


def quarantine(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    entry = store.get(int(args.get("entry_id", 0)))
    if not entry:
        raise ToolError("entry not found")
    reason = (args.get("reason") or "").strip()
    if not reason:
        raise ToolError("'reason' is required")
    reason, _ = redact(reason)
    if entry["state"] == "quarantined":
        return f"#{entry['id']} is already quarantined"
    ev = _evidence(args.get("evidence"), "fail")
    has_reject = any(e["type"] == "human_reject" for e in ev) or _has_objective(entry, "fail")
    if not has_reject:
        raise ToolError(
            "cannot quarantine on opinion alone: pass evidence [{type:'human_reject',...}] "
            "for explicit rejection, or use record_failure with objective evidence"
        )
    new_conf = 0.85 if any(e["type"] == "human_reject" for e in ev) else 0.70
    updates = {"state": "quarantined", "confidence": new_conf, "failure_reason": reason[:2000]}
    if args.get("signature"):
        updates["failure_signature"] = str(args["signature"])[:500]
    if ev:
        updates["evidence"] = _merged_evidence(entry, ev)
        updates["failure_count"] = entry["failure_count"] + 1
    store.update(entry["id"], **updates)
    store.add_event(entry["id"], "quarantined", ctx["actor"], reason=reason, evidence=ev,
                    prev_state=entry["state"], new_state="quarantined",
                    prev_confidence=entry["confidence"], new_confidence=new_conf)
    return f"#{entry['id']} → QUARANTINED, confidence {new_conf:.2f}. Record a replacement and link it when you have one."


def reactivate(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    entry = store.get(int(args.get("entry_id", 0)))
    if not entry:
        raise ToolError("entry not found")
    reason = (args.get("reason") or "").strip()
    if not reason:
        raise ToolError("'reason' is required (e.g. 'dependency X upgraded to 2.1, bug fixed upstream')")
    if entry["state"] != "quarantined":
        return f"#{entry['id']} is {entry['state']}, not quarantined — nothing to reactivate"
    store.update(entry["id"], state="probation", confidence=0.30, last_verified_at=None)
    store.add_event(entry["id"], "reactivated", ctx["actor"], reason=reason,
                    prev_state="quarantined", new_state="probation",
                    prev_confidence=entry["confidence"], new_confidence=0.30,
                    detail={"note": "failure history preserved; fresh validation required"})
    return (f"#{entry['id']} QUARANTINED → PROBATION (history preserved). "
            f"It needs fresh objective evidence via record_success before it can be proven again.")


def _link_replacement_impl(ctx: dict, failure_id: int, args: dict) -> str:
    store: Store = ctx["store"]
    failure = store.get(failure_id)
    if not failure:
        raise ToolError(f"failure entry {failure_id} not found")
    replacement_id = args.get("replacement_id")
    if replacement_id is None and not args.get("replacement_code"):
        raise ToolError("provide 'replacement_id' or 'replacement_code'")
    if replacement_id is None:
        sub = {k: v for k, v in args.items() if not k.startswith("replacement_")}
        sub["code"] = args.get("replacement_code")
        sub["title"] = args.get("replacement_title") or f"replacement for #{failure_id}"
        sub["evidence"] = args.get("replacement_evidence")
        created = record_success(ctx, sub)
        replacement_id = int(re.search(r"#(\d+)", created).group(1))
        created_note = created.splitlines()[0] + " "
    else:
        replacement_id = int(replacement_id)
        created_note = ""
    if replacement_id == failure_id:
        raise ToolError("an entry cannot replace itself")
    replacement = store.get(replacement_id)
    if not replacement:
        raise ToolError(f"replacement entry {replacement_id} not found")
    store.link(failure_id, replacement_id, args.get("note"))
    store.add_event(failure_id, "link_replacement", ctx["actor"],
                    reason=args.get("note") or "replacement linked",
                    prev_state=failure["state"], new_state=failure["state"],
                    detail={"replacement_id": replacement_id})
    store.add_event(replacement_id, "linked_as_replacement", ctx["actor"],
                    reason=args.get("note") or "replaces a quarantined approach",
                    detail={"failure_id": failure_id})
    return (f"{created_note}linked: failure #{failure_id} → replacement #{replacement_id} "
            f"[{replacement['state'].upper()}]")


def link_replacement(ctx: dict, args: dict) -> str:
    if args.get("failure_id") is None:
        raise ToolError("'failure_id' is required")
    return _link_replacement_impl(ctx, int(args["failure_id"]), args)


def update_confidence(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    entry = store.get(int(args.get("entry_id", 0)))
    if not entry:
        raise ToolError("entry not found")
    reason = (args.get("reason") or "").strip()
    if not reason:
        raise ToolError("'reason' is required")
    if args.get("value") is not None:
        new_conf = clamp(float(args["value"]))
    elif args.get("delta") is not None:
        delta = float(args["delta"])
        if abs(delta) > 0.5:
            raise ToolError("|delta| must be <= 0.5 per adjustment")
        new_conf = clamp(entry["confidence"] + delta)
    else:
        raise ToolError("provide 'delta' or 'value'")
    store.update(entry["id"], confidence=new_conf)
    store.add_event(entry["id"], "manual_confidence", ctx["actor"], reason=reason,
                    prev_state=entry["state"], new_state=entry["state"],
                    prev_confidence=entry["confidence"], new_confidence=new_conf)
    return f"#{entry['id']} confidence {entry['confidence']:.2f} → {new_conf:.2f}"


# ------------------------------------------------------------------- query


def _search_internal(ctx: dict, args: dict, state: str, limit: int) -> list[tuple[dict, float, list[str]]]:
    store: Store = ctx["store"]
    query = args.get("query") or ""
    code = args.get("code")
    terms = [w for w in re.sub(r"[^A-Za-z0-9_.\- ]+", " ", query).split() if len(w) >= 2]
    text_scores = store.text_search(terms) if terms else {}
    candidates = store.candidates(
        state=state, language=args.get("language"), project=ctx["project"],
        include_archived=bool(args.get("include_archived")),
    )
    code_shingles = shingles(code) if code else None
    want_fp = fingerprint(code, args.get("language")) if code else None
    q_env = args.get("env") if isinstance(args.get("env"), dict) else None
    scored = []
    for e in candidates:
        text = text_scores.get(e["id"], 0.0)
        sim = similarity(code_shingles, shingles(e["code"])) if code_shingles else 0.0
        if terms or code:  # a query was given: require some signal beyond confidence
            relevant = (terms and text > 0) or (
                code and (sim >= 0.15 or e["norm_hash"] == want_fp))
            if not relevant:
                continue
        score = 0.45 * text + 0.35 * sim + 0.20 * e["confidence"]
        if want_fp and e["norm_hash"] == want_fp:
            score += 0.15
        conflicts = _env_conflicts(_entry_env(e), q_env)
        if conflicts:
            score *= 0.75
        scored.append((e, score, conflicts))
    scored.sort(key=lambda t: -t[1])
    return scored[:limit]


def search(ctx: dict, args: dict) -> str:
    state = args.get("state") or "all"
    limit = min(int(args.get("limit", 5)), 20)
    results = _search_internal(ctx, args, state, limit)
    if not results:
        return f"no matches (state={state}, project={ctx['project']})"
    lines = [f"{len(results)} match(es) [state={state}·project={ctx['project']}·+global]"]
    for e, score, conflicts in results:
        lines.append(_brief(e))
        if conflicts:
            lines.append("    ⚠ env mismatch: " + "; ".join(conflicts[:3]))
    return truncate("\n".join(lines), MAX_OUTPUT_CHARS)


def check_code(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    code = args.get("code")
    if not code or not str(code).strip():
        raise ToolError("'code' is required")
    code = str(code)
    language = args.get("language")
    fp = fingerprint(code, language)
    target = shingles(code)
    q_env = args.get("env") if isinstance(args.get("env"), dict) else None
    candidates = store.candidates(language=language, project=ctx["project"])
    verdicts: list[tuple[float, dict, str, list[str]]] = []
    for e in candidates:
        sim = 1.0 if e["norm_hash"] == fp else similarity(target, shingles(e["code"]))
        if sim < MEDIUM_SIM:
            continue
        conflicts = _env_conflicts(_entry_env(e), q_env)
        if e["state"] == "quarantined":
            if sim >= STRONG_SIM and e["confidence"] >= 0.60 and not conflicts:
                level = "BLOCK"
            elif conflicts:
                level = "WARN-ENV"
            else:
                level = "WARN"
        elif e["state"] == "proven":
            level = "REUSE" if sim >= STRONG_SIM else "INFO"
        else:
            level = "INFO"
        verdicts.append((sim, e, level, conflicts))
    verdicts.sort(key=lambda t: (-{"BLOCK": 0, "WARN": 1, "WARN-ENV": 2, "REUSE": 3, "INFO": 4}[t[2]], -t[0]))
    verdicts = verdicts[:6]
    if not verdicts:
        return f"no significant matches ({len(candidates)} entries scanned) [fingerprint {fp[:12]}]"
    lines = [f"CodeLedger check [fingerprint {fp[:12]}·{len(candidates)} entries scanned]"]
    for sim, e, level, conflicts in verdicts:
        if level == "BLOCK":
            lines.append(f"⛔ BLOCK — {sim:.2f} similar to known failure {_brief(e)}")
        elif level in ("WARN", "WARN-ENV"):
            tag = "⚠ warning" if level == "WARN" else "⚠ warning (env differs — weaker)"
            lines.append(f"{tag} — {sim:.2f} resembles known failure {_brief(e)}")
        elif level == "REUSE":
            lines.append(f"✓ reuse candidate — {sim:.2f} match with proven pattern {_brief(e)}")
        else:
            lines.append(f"· {sim:.2f} similar to {e['state']} entry {_brief(e)}")
        for c in conflicts[:2]:
            lines.append(f"    env: {c}")
        if e["state"] == "quarantined":
            for l in store.links_from(e["id"]):
                r = store.get(l["replacement_id"])
                if r:
                    lines.append(f"    → use instead: {_brief(r)}")
    return truncate("\n".join(lines), MAX_OUTPUT_CHARS)


def get_experience(ctx: dict, args: dict) -> str:
    proven = _search_internal(ctx, args, "proven", 3)
    quarantined = _search_internal(ctx, args, "quarantined", 3)
    store: Store = ctx["store"]
    lines = []
    if proven:
        lines.append("Proven patterns to reuse:")
        lines += [f"  {_brief(e)}" + ("\n    ⚠ env: " + "; ".join(c[:2]) if c else "")
                  for e, _, c in proven]
    if quarantined:
        lines.append("Known failures to avoid:")
        for e, _, c in quarantined:
            lines.append(f"  {_brief(e)}")
            for l in store.links_from(e["id"]):
                r = store.get(l["replacement_id"])
                if r:
                    lines.append(f"    → repaired by: {_brief(r)}")
    if not lines:
        return f"no relevant experience for this query [project={ctx['project']}]"
    return truncate("\n".join(lines), MAX_OUTPUT_CHARS)


def explain(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    entry = store.get(int(args.get("entry_id", 0)))
    if not entry:
        raise ToolError("entry not found")
    lines = [_brief(entry)]
    for k in ("purpose", "framework", "provenance", "limitations"):
        if entry.get(k):
            lines.append(f"{k}: {entry[k]}")
    if entry.get("env"):
        lines.append(f"env: {entry['env']}")
    if entry.get("superseded_by"):
        lines.append(f"superseded by: #{entry['superseded_by']}")
    lines.append(f"created: {entry['created_at']}  last verified: {entry.get('last_verified_at') or 'never'}")
    ev = _parse_evidence_list(entry)
    if ev:
        lines.append("evidence:")
        lines += [f"  [{e['polarity']}] {e['type']}: {e.get('detail', '')[:200]}" for e in ev[-8:]]
    for l in store.links_from(entry["id"]):
        lines.append(f"replaced by: #{l['replacement_id']}" + (f" ({l['note']})" if l.get("note") else ""))
    for l in store.links_to(entry["id"]):
        lines.append(f"repairs failure: #{l['failure_id']}" + (f" ({l['note']})" if l.get("note") else ""))
    lines.append("history:")
    for ev_row in store.events(entry["id"], 30):
        transition = f" {ev_row['prev_state']}→{ev_row['new_state']}" if ev_row.get("new_state") else ""
        if ev_row.get("prev_confidence") is not None and ev_row.get("new_confidence") is not None:
            conf = f" conf {ev_row['prev_confidence']:.2f}→{ev_row['new_confidence']:.2f}"
        elif ev_row.get("new_confidence") is not None:
            conf = f" conf →{ev_row['new_confidence']:.2f}"
        else:
            conf = ""
        reason = f" — {ev_row['reason'][:160]}" if ev_row.get("reason") else ""
        lines.append(f"  {ev_row['ts']} {ev_row['action']}{transition}{conf} by {ev_row.get('actor') or '?'}{reason}")
    return truncate("\n".join(lines), MAX_OUTPUT_CHARS)


# -------------------------------------------------------------- maintenance


def maintain(ctx: dict, args: dict) -> str:
    store: Store = ctx["store"]
    dry = bool(args.get("dry_run"))
    actions: list[str] = []

    def apply(entry_id: int, **fields):
        if not dry:
            store.update(entry_id, **fields)

    # 1. confidence decay for stale entries
    for e in store.all():
        if e["archived"]:
            continue
        age = days_since(e.get("last_verified_at") or e["created_at"])
        if age <= 180:
            continue
        loss = min(0.30, 0.05 * (int((age - 180) // 90) + 1))
        new_conf = clamp(e["confidence"] - loss, lo=0.05)
        fields = {"confidence": new_conf}
        note = f"decay #{e['id']}: {e['confidence']:.2f} → {new_conf:.2f} (unverified for {int(age)}d)"
        if e["state"] == "proven" and new_conf < 0.45:
            fields["state"] = "probation"
            note += ", PROVEN → PROBATION (stale)"
        apply(e["id"], **fields)
        if not dry:
            store.add_event(e["id"], "decay", "maintenance",
                            reason=f"unverified for {int(age)} days",
                            prev_state=e["state"], new_state=fields.get("state", e["state"]),
                            prev_confidence=e["confidence"], new_confidence=new_conf)
        actions.append(("[dry-run] " if dry else "") + note)

    # 2. archive low-value, never-verified probation entries
    for e in store.all():
        if (e["state"] == "probation" and not e["archived"] and not e["superseded_by"]
                and e["success_count"] == 0 and days_since(e["created_at"]) > 90
                and e["confidence"] < 0.25):
            apply(e["id"], archived=1)
            if not dry:
                store.add_event(e["id"], "archived", "maintenance",
                                reason="low-value probation: never verified, stale",
                                prev_state="probation", new_state="probation")
            actions.append(("[dry-run] " if dry else "") + f"archive #{e['id']} (stale probation)")

    # 3. merge exact duplicates (same fingerprint + scope + project)
    if args.get("merge_duplicates", True):
        groups: dict[tuple, list[dict]] = {}
        for e in store.all():
            if e["archived"]:
                continue
            groups.setdefault((e["norm_hash"], e["scope"], e["project"] or ""), []).append(e)
        for _, group in groups.items():
            if len(group) < 2:
                continue
            group.sort(key=lambda e: e["id"])
            keep = group[0]
            for dup in group[1:]:
                if not dry:
                    store.rewrite_links(dup["id"], keep["id"])
                    merged_ev = (_parse_evidence_list(keep) + _parse_evidence_list(dup))[-20:]
                    store.update(
                        dup["id"], archived=1, superseded_by=keep["id"],
                    )
                    store.update(
                        keep["id"],
                        evidence=json.dumps(merged_ev),
                        success_count=keep["success_count"] + dup["success_count"],
                        failure_count=keep["failure_count"] + dup["failure_count"],
                        confidence=max(keep["confidence"], dup["confidence"]),
                    )
                    store.add_event(dup["id"], "merged", "maintenance",
                                    reason="exact duplicate", detail={"kept": keep["id"]})
                actions.append(f"[dry-run] " if dry else "" +
                               f"merge #{dup['id']} into #{keep['id']} (same fingerprint)")

    # 4. near-duplicate report (structural similarity)
    live = [e for e in store.all() if not e["archived"]]
    if len(live) <= 500:
        reported = 0
        for i in range(len(live)):
            if reported >= 10:
                actions.append("near-dup report capped at 10 pairs")
                break
            for j in range(i + 1, len(live)):
                a, b = live[i], live[j]
                if a["norm_hash"] == b["norm_hash"] or (
                        a.get("language") and b.get("language") and a["language"] != b["language"]):
                    continue
                if similarity(shingles(a["code"]), shingles(b["code"])) > 0.90:
                    actions.append(f"near-dup: #{a['id']} vs #{b['id']} (>0.90 similarity) — consider linking/merging")
                    reported += 1
                    break
    else:
        actions.append(f"near-dup scan skipped ({len(live)} entries > 500 cap)")

    st = store.stats()
    try:
        import os
        size = os.path.getsize(ctx["db_path"])
    except OSError:
        size = 0
    lines = actions or ["no maintenance actions needed"]
    lines.append(
        f"stats: {st['total']} entries "
        + " ".join(f"{k}={v}" for k, v in st["by_state"].items())
        + f" | global={st['by_scope'].get('global', 0)}"
        + f" | archived={st['archived']} | events={st['events']} | links={st['links']}"
        + f" | db {size / 1024:.0f} KiB"
    )
    return truncate("\n".join(lines), MAX_OUTPUT_CHARS)

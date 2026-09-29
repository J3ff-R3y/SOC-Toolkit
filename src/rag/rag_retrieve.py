#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import unicodedata

RETRIEVER_VERSION = "domain-aware-retriever-v1"
KNOWLEDGE_DOMAIN_SCOPES = {
    "general": ("soc", "iso", "shared"),
    "soc": ("soc", "shared"),
    "iso": ("iso", "shared"),
}
DOMAIN_VALUES = ("soc", "iso", "shared")
DEFAULT_CONFIG = "/etc/jeffrey-rag/rag.json"
DOC_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/\\-]{0,63}", re.UNICODE)

class RetrievalError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

def emit(obj, stream=sys.stdout):
    json.dump(obj, stream, ensure_ascii=False, sort_keys=True)
    stream.write("\n")
    stream.flush()

def fail(code, message, details=None, rc=2):
    emit({
        "valid": False,
        "error": {"code": code, "message": message, "details": details},
        "retriever_version": RETRIEVER_VERSION,
    }, sys.stderr)
    raise SystemExit(rc)

def config_path():
    return Path(os.environ.get("JEFFREY_RAG_CONFIG", DEFAULT_CONFIG))

def load_config():
    try:
        cfg = json.loads(config_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RetrievalError("config_missing", f"RAG config missing: {config_path()}")
    except Exception as exc:
        raise RetrievalError("config_invalid", f"cannot parse RAG config: {exc}")

    required = {
        "index_path", "retrieval_default_top_k", "retrieval_max_top_k",
        "retrieval_candidate_multiplier", "retrieval_min_term_coverage",
        "retrieval_max_context_chars", "retrieval_max_query_chars",
    }
    missing = sorted(required - set(cfg))
    if missing:
        raise RetrievalError("config_invalid", "retrieval config keys missing", missing)

    for key in (
        "retrieval_default_top_k", "retrieval_max_top_k",
        "retrieval_candidate_multiplier", "retrieval_max_context_chars",
        "retrieval_max_query_chars",
    ):
        if not isinstance(cfg[key], int) or isinstance(cfg[key], bool) or cfg[key] <= 0:
            raise RetrievalError("config_invalid", f"{key} must be a positive integer")

    cov = cfg["retrieval_min_term_coverage"]
    if not isinstance(cov, (int, float)) or isinstance(cov, bool) or not (0 <= float(cov) <= 1):
        raise RetrievalError("config_invalid", "retrieval_min_term_coverage must be between 0 and 1")
    if cfg["retrieval_default_top_k"] > cfg["retrieval_max_top_k"]:
        raise RetrievalError("config_invalid", "default top_k exceeds maximum")
    return cfg

def connect(cfg):
    db = Path(cfg["index_path"])
    if not db.is_file():
        raise RetrievalError("store_not_initialized", f"RAG index missing: {db}")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA busy_timeout=5000")
    return con

def normalize(value):
    return unicodedata.normalize("NFKC", value).casefold()

def query_tokens(query):
    tokens, seen = [], set()
    for token in TOKEN_RE.findall(normalize(query)):
        token = token.strip("._:/\\-")
        if token and token not in seen:
            seen.add(token)
            tokens.append(token)
        if len(tokens) >= 24:
            break
    return tokens

def fts_query(tokens):
    return " OR ".join('"' + t.replace('"', '""') + '"' for t in tokens)

def validate_ids(values):
    if values is None:
        return []
    if not isinstance(values, list):
        raise RetrievalError("invalid_document_ids", "document_ids must be an array")
    if len(values) > 100:
        raise RetrievalError("too_many_document_ids", "at most 100 document IDs may be selected")
    out, seen = [], set()
    for value in values:
        if not isinstance(value, str) or not DOC_ID_RE.fullmatch(value):
            raise RetrievalError(
                "invalid_document_id",
                "document IDs must be 32 lowercase hex characters",
                {"value": value},
            )
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out

def validate_knowledge_domain(value):
    if value is None:
        value = "general"
    if not isinstance(value, str):
        raise RetrievalError(
            "invalid_knowledge_domain",
            "knowledge_domain must be a string",
        )
    value = value.strip().lower()
    if value not in KNOWLEDGE_DOMAIN_SCOPES:
        raise RetrievalError(
            "invalid_knowledge_domain",
            "knowledge_domain must be one of: general, soc, iso",
            {"allowed": sorted(KNOWLEDGE_DOMAIN_SCOPES)},
        )
    return value

def ensure_domain_extension(con):
    cols = {
        row["name"]
        for row in con.execute("PRAGMA table_info(documents)").fetchall()
    }
    if "domain" not in cols:
        raise RetrievalError(
            "domain_extension_missing",
            "documents.domain is required for domain-aware retrieval",
        )
    invalid = con.execute(
        "SELECT COUNT(*) AS c FROM documents "
        "WHERE domain NOT IN ('soc','iso','shared') OR domain IS NULL"
    ).fetchone()["c"]
    if int(invalid) != 0:
        raise RetrievalError(
            "invalid_domain_state",
            "knowledge store contains invalid document domains",
            {"count": int(invalid)},
        )

def ensure_selected_exist(con, ids):
    if not ids:
        raise RetrievalError(
            "selected_documents_required",
            "selected_documents mode requires at least one document ID",
        )
    marks = ",".join("?" for _ in ids)
    rows = con.execute(
        f"SELECT document_id FROM documents WHERE active=1 AND document_id IN ({marks})",
        ids,
    ).fetchall()
    found = {r["document_id"] for r in rows}
    missing = [x for x in ids if x not in found]
    if missing:
        raise RetrievalError(
            "selected_document_not_found",
            "one or more selected documents do not exist or are inactive",
            {"document_ids": missing},
        )

def search(con, tokens, ids, limit, allowed_domains=None):
    params = [fts_query(tokens)]
    clauses = []

    if ids is not None:
        marks = ",".join("?" for _ in ids)
        clauses.append(f"d.document_id IN ({marks})")
        params.extend(ids)

    if allowed_domains is not None:
        domains = list(allowed_domains)
        if not domains:
            return []
        marks = ",".join("?" for _ in domains)
        clauses.append(f"d.domain IN ({marks})")
        params.extend(domains)

    extra = ""
    if clauses:
        extra = " AND " + " AND ".join(clauses)

    params.append(limit)

    return con.execute(f"""
        SELECT
            c.id AS chunk_rowid,
            c.document_id,
            c.chunk_no,
            c.char_start,
            c.char_end,
            c.content,
            d.filename,
            d.extension,
            d.sha256,
            d.domain,
            bm25(chunks_fts) AS bm25_score
        FROM chunks_fts
        JOIN chunks AS c ON c.id=chunks_fts.rowid
        JOIN documents AS d ON d.document_id=c.document_id
        WHERE chunks_fts MATCH ?
          AND d.active=1
          {extra}
        ORDER BY bm25_score ASC, c.document_id ASC, c.chunk_no ASC
        LIMIT ?
    """, params).fetchall()

def matched_terms(content, terms):
    hay = normalize(content)
    return [t for t in terms if t in hay]

def rank(rows, terms, min_cov, top_k, max_chars):
    denom = max(1, len(terms))
    candidates = []
    for row in rows:
        matched = matched_terms(row["content"], terms)
        coverage = len(matched) / denom
        if coverage + 1e-12 < min_cov:
            continue
        candidates.append({
            "row": row,
            "matched_terms": matched,
            "coverage": round(coverage, 6),
            "bm25": float(row["bm25_score"]),
        })

    candidates.sort(key=lambda x: (
        -x["coverage"], x["bm25"],
        x["row"]["document_id"], int(x["row"]["chunk_no"])
    ))

    selected, used = [], 0
    for item in candidates:
        if len(selected) >= top_k:
            break
        content = item["row"]["content"]
        if used + len(content) > max_chars:
            continue
        selected.append(item)
        used += len(content)
    return selected, used

def sources_from(selected):
    out = []
    for i, item in enumerate(selected, 1):
        r = item["row"]
        out.append({
            "source_id": f"K{i}",
            "document_id": r["document_id"],
            "filename": r["filename"],
            "extension": r["extension"],
            "sha256": r["sha256"],
            "domain": r["domain"],
            "chunk_no": int(r["chunk_no"]),
            "char_start": int(r["char_start"]),
            "char_end": int(r["char_end"]),
            "matched_terms": item["matched_terms"],
            "term_coverage": item["coverage"],
            "bm25_score": item["bm25"],
            "content": r["content"],
        })
    return out

def context_from(sources):
    parts = []
    for s in sources:
        parts.append(
            f"[{s['source_id']}] {s['filename']} "
            f"(document_id={s['document_id']}, chunk={s['chunk_no']})\n{s['content']}"
        )
    return "\n\n".join(parts)

def retrieve(query, mode, ids, top_k, knowledge_domain="general"):
    cfg = load_config()
    if mode not in {"off", "automatic", "selected_documents"}:
        raise RetrievalError("invalid_mode", "invalid knowledge mode")
    knowledge_domain = validate_knowledge_domain(knowledge_domain)

    if not isinstance(query, str):
        raise RetrievalError("invalid_query", "query must be a string")
    query = query.strip()
    if not query:
        raise RetrievalError("invalid_query", "query may not be empty")
    if len(query) > cfg["retrieval_max_query_chars"]:
        raise RetrievalError("query_too_large", "query exceeds configured limit")

    ids = validate_ids(ids)
    if top_k is None:
        top_k = cfg["retrieval_default_top_k"]
    if not isinstance(top_k, int) or isinstance(top_k, bool):
        raise RetrievalError("invalid_top_k", "top_k must be an integer")
    if not 1 <= top_k <= cfg["retrieval_max_top_k"]:
        raise RetrievalError(
            "invalid_top_k", "top_k outside configured range",
            {"max_top_k": cfg["retrieval_max_top_k"]},
        )

    if mode == "off":
        if ids:
            raise RetrievalError(
                "document_filter_not_allowed",
                "document IDs are not allowed when knowledge mode is off",
            )
        return {
            "valid": True, "operation": "retrieve", "mode": "off",
            "knowledge_domain": knowledge_domain,
            "allowed_domains": [],
            "domain_filter_applied": False,
            "retrieval_used": False, "matched": False,
            "reason": "knowledge_mode_off", "query_terms": [],
            "document_filter": [], "sources": [], "context": "",
            "context_chars": 0, "retriever_version": RETRIEVER_VERSION,
            "network_access": False, "model_used": False,
        }

    terms = query_tokens(query)
    if not terms:
        return {
            "valid": True, "operation": "retrieve", "mode": mode,
            "knowledge_domain": knowledge_domain,
            "allowed_domains": list(KNOWLEDGE_DOMAIN_SCOPES[knowledge_domain])
                if mode == "automatic" else [],
            "domain_filter_applied": mode == "automatic",
            "retrieval_used": True, "matched": False,
            "reason": "no_indexable_query_terms", "query_terms": [],
            "document_filter": ids if mode == "selected_documents" else [],
            "sources": [], "context": "", "context_chars": 0,
            "retriever_version": RETRIEVER_VERSION,
            "network_access": False, "model_used": False,
        }

    con = connect(cfg)
    try:
        ensure_domain_extension(con)

        doc_filter = None
        domain_filter = None

        if mode == "selected_documents":
            # Explicit document selection is authoritative. It intentionally
            # overrides automatic SOC/ISO domain filtering.
            ensure_selected_exist(con, ids)
            doc_filter = ids
        elif ids:
            raise RetrievalError(
                "document_filter_not_allowed",
                "document IDs are only allowed in selected_documents mode",
            )
        else:
            domain_filter = KNOWLEDGE_DOMAIN_SCOPES[knowledge_domain]

        candidate_limit = min(
            200,
            max(top_k, top_k * cfg["retrieval_candidate_multiplier"]),
        )
        rows = search(
            con, terms, doc_filter, candidate_limit,
            allowed_domains=domain_filter,
        )
        selected, used = rank(
            rows, terms, float(cfg["retrieval_min_term_coverage"]),
            top_k, cfg["retrieval_max_context_chars"],
        )
    finally:
        con.close()

    sources = sources_from(selected)
    return {
        "valid": True,
        "operation": "retrieve",
        "mode": mode,
        "knowledge_domain": knowledge_domain,
        "allowed_domains": list(domain_filter or []),
        "domain_filter_applied": mode == "automatic",
        "retrieval_used": True,
        "matched": bool(sources),
        "reason": "matched" if sources else "below_threshold_or_no_match",
        "query_terms": terms,
        "document_filter": ids if mode == "selected_documents" else [],
        "top_k": top_k,
        "min_term_coverage": float(cfg["retrieval_min_term_coverage"]),
        "candidate_count": len(rows),
        "source_count": len(sources),
        "sources": sources,
        "context": context_from(sources),
        "context_chars": used,
        "retriever_version": RETRIEVER_VERSION,
        "network_access": False,
        "model_used": False,
    }

def list_documents():
    cfg = load_config()
    con = connect(cfg)
    try:
        rows = con.execute("""
            SELECT document_id,filename,extension,sha256,size_bytes,
                   extracted_chars,chunk_count,active,created_at,updated_at,domain
            FROM documents
            WHERE active=1
            ORDER BY created_at ASC, document_id ASC
        """).fetchall()
    finally:
        con.close()
    docs = [dict(r) for r in rows]
    for d in docs:
        d["active"] = bool(d["active"])
    return {
        "valid": True, "operation": "list-documents",
        "documents": docs, "count": len(docs),
        "retriever_version": RETRIEVER_VERSION,
    }

def self_check():
    cfg = load_config()
    con = connect(cfg)
    try:
        schema = con.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        docs = con.execute("SELECT COUNT(*) AS c FROM documents").fetchone()["c"]
        chunks = con.execute("SELECT COUNT(*) AS c FROM chunks").fetchone()["c"]
        fts = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='chunks_fts'"
        ).fetchone()
        query_only = con.execute("PRAGMA query_only").fetchone()[0]
        cols = {
            r["name"] for r in con.execute("PRAGMA table_info(documents)").fetchall()
        }
        extension = con.execute(
            "SELECT value FROM schema_meta WHERE key='domain_extension_version'"
        ).fetchone()
        invalid_domains = (
            con.execute(
                "SELECT COUNT(*) AS c FROM documents "
                "WHERE domain NOT IN ('soc','iso','shared') OR domain IS NULL"
            ).fetchone()["c"]
            if "domain" in cols else -1
        )
    finally:
        con.close()
    valid = (
        schema is not None and schema["value"] == "1"
        and fts is not None and int(query_only) == 1
        and "domain" in cols
        and extension is not None
        and extension["value"] == "domain-aware-v1"
        and int(invalid_domains) == 0
    )
    return {
        "valid": valid, "operation": "self-check",
        "checks": {
            "schema_version": schema["value"] if schema else None,
            "fts5_table": bool(fts), "query_only": bool(query_only),
            "documents": int(docs), "chunks": int(chunks),
            "domain_column": "domain" in cols,
            "domain_extension_version": extension["value"] if extension else None,
            "invalid_domain_rows": int(invalid_domains),
            "knowledge_domain_scopes": {
                k: list(v) for k, v in KNOWLEDGE_DOMAIN_SCOPES.items()
            },
        },
        "retriever_version": RETRIEVER_VERSION,
        "network_access": False, "model_used": False,
    }

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("self-check")
    sub.add_parser("list-documents")
    r = sub.add_parser("retrieve")
    r.add_argument("--query", required=True)
    r.add_argument("--mode", default="automatic",
                   choices=("off", "automatic", "selected_documents"))
    r.add_argument("--document-id", action="append", default=[])
    r.add_argument("--top-k", type=int)
    r.add_argument(
        "--knowledge-domain",
        default="general",
        choices=("general", "soc", "iso"),
    )
    args = p.parse_args()

    try:
        if args.command == "self-check":
            result = self_check()
        elif args.command == "list-documents":
            result = list_documents()
        else:
            result = retrieve(
                args.query, args.mode, args.document_id, args.top_k,
                args.knowledge_domain,
            )
        emit(result)
    except RetrievalError as exc:
        fail(exc.code, exc.message, exc.details, 2)
    except sqlite3.OperationalError as exc:
        fail("sqlite_query_failed", f"SQLite query failed: {exc}", None, 2)
    except Exception as exc:
        fail("internal_error", f"{type(exc).__name__}: {exc}", None, 1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Jeffrey persistent local RAG knowledge store.

Scope:
- local/offline only
- persistent documents + metadata + chunks
- SQLite FTS5 lexical index
- explicit ingest/list/delete/reindex
- no model calls
- no network access
- no arbitrary shell execution

The retrieval layer adds deterministic ranking/filtering on top of this store.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import uuid

try:
    import yaml
except Exception:
    yaml = None

STORE_VERSION = "rag-store-v1"
SCHEMA_VERSION = "1"
DEFAULT_CONFIG = "/etc/jeffrey-rag/rag.json"
DOC_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SAFE_DISPLAY_RE = re.compile(r"[\x00-\x1f\x7f]")
DOMAIN_VALUES = ("soc", "iso", "shared")
DOMAIN_EXTENSION_VERSION = "domain-aware-v1"

class RagError(Exception):
    def __init__(self, code: str, message: str, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def emit(obj, *, stream=sys.stdout):
    json.dump(obj, stream, ensure_ascii=False, sort_keys=True)
    stream.write("\n")
    stream.flush()

def fail(code: str, message: str, details=None, rc: int = 2):
    emit({
        "valid": False,
        "error": {
            "code": code,
            "message": message,
            "details": details,
        },
        "store_version": STORE_VERSION,
    }, stream=sys.stderr)
    raise SystemExit(rc)

def config_path() -> Path:
    return Path(os.environ.get("JEFFREY_RAG_CONFIG", DEFAULT_CONFIG))

def load_config() -> dict:
    path = config_path()
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RagError("config_missing", f"RAG config missing: {path}")
    except Exception as exc:
        raise RagError("config_invalid", f"cannot parse RAG config: {exc}")

    required = {
        "data_root", "documents_root", "index_path", "state_root",
        "allowed_extensions", "max_document_bytes", "max_total_bytes",
        "max_documents", "max_extracted_chars", "chunk_target_chars",
        "chunk_overlap_chars", "max_chunks_per_document",
    }
    missing = sorted(required - set(cfg))
    if missing:
        raise RagError("config_invalid", "required config keys missing", missing)

    if not isinstance(cfg["allowed_extensions"], list) or not cfg["allowed_extensions"]:
        raise RagError("config_invalid", "allowed_extensions must be a non-empty list")

    for key in (
        "max_document_bytes", "max_total_bytes", "max_documents",
        "max_extracted_chars", "chunk_target_chars",
        "chunk_overlap_chars", "max_chunks_per_document",
    ):
        if not isinstance(cfg[key], int) or cfg[key] <= 0:
            raise RagError("config_invalid", f"{key} must be a positive integer")

    if cfg["chunk_overlap_chars"] >= cfg["chunk_target_chars"]:
        raise RagError("config_invalid", "chunk overlap must be smaller than chunk target")

    return cfg

def paths(cfg: dict):
    return (
        Path(cfg["data_root"]),
        Path(cfg["documents_root"]),
        Path(cfg["index_path"]),
        Path(cfg["state_root"]),
    )

def ensure_existing_store_paths(cfg: dict):
    data_root, docs_root, index_path, state_root = paths(cfg)
    for p in (data_root, docs_root, index_path.parent, state_root):
        if not p.is_dir():
            raise RagError("store_not_initialized", f"required directory missing: {p}")

def connect(cfg: dict) -> sqlite3.Connection:
    ensure_existing_store_paths(cfg)
    db = Path(cfg["index_path"])
    con = sqlite3.connect(str(db), timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=5000")
    con.execute("PRAGMA synchronous=FULL")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_schema(con: sqlite3.Connection):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS documents (
        document_id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        extension TEXT NOT NULL,
        media_type TEXT NOT NULL,
        parser TEXT NOT NULL,
        sha256 TEXT NOT NULL UNIQUE,
        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
        extracted_chars INTEGER NOT NULL CHECK(extracted_chars >= 0),
        chunk_count INTEGER NOT NULL CHECK(chunk_count > 0),
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS chunks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
        chunk_no INTEGER NOT NULL CHECK(chunk_no >= 0),
        char_start INTEGER NOT NULL CHECK(char_start >= 0),
        char_end INTEGER NOT NULL CHECK(char_end >= char_start),
        content TEXT NOT NULL,
        UNIQUE(document_id, chunk_no)
    );

    CREATE INDEX IF NOT EXISTS idx_chunks_document_id
      ON chunks(document_id);

    CREATE INDEX IF NOT EXISTS idx_documents_active
      ON documents(active);

    CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        action TEXT NOT NULL,
        document_id TEXT,
        details_json TEXT NOT NULL
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
        content,
        content='chunks',
        content_rowid='id',
        tokenize='unicode61 remove_diacritics 2'
    );

    CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
      INSERT INTO chunks_fts(rowid, content) VALUES (new.id, new.content);
    END;

    CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
      INSERT INTO chunks_fts(chunks_fts, rowid, content)
      VALUES('delete', old.id, old.content);
    END;

    CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
      INSERT INTO chunks_fts(chunks_fts, rowid, content)
      VALUES('delete', old.id, old.content);
      INSERT INTO chunks_fts(rowid, content) VALUES (new.id, new.content);
    END;
    """)

    existing = con.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    if existing and existing["value"] != SCHEMA_VERSION:
        raise RagError(
            "schema_version_mismatch",
            f"expected schema version {SCHEMA_VERSION}, found {existing['value']}",
        )

    con.execute(
        "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('schema_version',?)",
        (SCHEMA_VERSION,),
    )
    con.execute(
        "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('store_version',?)",
        (STORE_VERSION,),
    )
    ensure_domain_schema(con)
    con.execute(
        "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('domain_extension_version',?)",
        (DOMAIN_EXTENSION_VERSION,),
    )
    con.commit()

def validate_domain(value: str) -> str:
    if not isinstance(value, str):
        raise RagError("invalid_domain", "domain must be a string")
    value = value.strip().lower()
    if value not in DOMAIN_VALUES:
        raise RagError(
            "invalid_domain",
            "domain must be one of: soc, iso, shared",
            {"allowed_domains": list(DOMAIN_VALUES)},
        )
    return value

def ensure_domain_schema(con: sqlite3.Connection):
    cols = {
        row["name"]
        for row in con.execute("PRAGMA table_info(documents)").fetchall()
    }
    if "domain" not in cols:
        con.execute(
            "ALTER TABLE documents "
            "ADD COLUMN domain TEXT NOT NULL DEFAULT 'shared' "
            "CHECK(domain IN ('soc','iso','shared'))"
        )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_documents_domain_active "
        "ON documents(domain, active)"
    )
    bad = con.execute(
        "SELECT COUNT(*) AS c FROM documents "
        "WHERE domain NOT IN ('soc','iso','shared') OR domain IS NULL"
    ).fetchone()["c"]
    if int(bad) != 0:
        raise RagError(
            "invalid_domain_state",
            "one or more stored documents have an invalid knowledge domain",
            {"count": int(bad)},
        )

def media_type_for(ext: str) -> str:
    return {
        ".txt": "text/plain",
        ".md": "text/markdown",
        ".json": "application/json",
        ".csv": "text/csv",
        ".yaml": "application/yaml",
        ".yml": "application/yaml",
    }[ext]

def safe_display_filename(value: str) -> str:
    name = Path(value).name.strip()
    name = SAFE_DISPLAY_RE.sub("_", name)
    if not name:
        raise RagError("invalid_filename", "filename is empty after sanitization")
    if len(name) > 255:
        raise RagError("invalid_filename", "filename exceeds 255 characters")
    return name

def extension_for(filename: str, cfg: dict) -> str:
    ext = Path(filename).suffix.lower()
    allowed = {str(x).lower() for x in cfg["allowed_extensions"]}
    if ext not in allowed:
        raise RagError(
            "unsupported_document_type",
            f"unsupported document extension: {ext or '<none>'}",
            {"allowed_extensions": sorted(allowed)},
        )
    return ext

def read_regular_file_no_follow(source: Path, max_bytes: int) -> bytes:
    try:
        st_l = os.lstat(source)
    except FileNotFoundError:
        raise RagError("source_missing", "source file does not exist")

    if stat.S_ISLNK(st_l.st_mode):
        raise RagError("symlink_rejected", "symlink source is forbidden")
    if not stat.S_ISREG(st_l.st_mode):
        raise RagError("special_file_rejected", "source must be a regular file")
    if st_l.st_size <= 0:
        raise RagError("empty_document", "empty document rejected")
    if st_l.st_size > max_bytes:
        raise RagError(
            "document_too_large",
            "document exceeds maximum allowed size",
            {"size_bytes": st_l.st_size, "max_document_bytes": max_bytes},
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise RagError("source_open_failed", f"cannot safely open source: {exc}")

    try:
        st_f = os.fstat(fd)
        if not stat.S_ISREG(st_f.st_mode):
            raise RagError("special_file_rejected", "opened source is not a regular file")
        if (st_f.st_dev, st_f.st_ino) != (st_l.st_dev, st_l.st_ino):
            raise RagError("source_changed", "source changed during validation")
        if st_f.st_size > max_bytes:
            raise RagError("document_too_large", "document exceeds maximum allowed size")
        parts = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        data = b"".join(parts)
        if len(data) > max_bytes:
            raise RagError("document_too_large", "document exceeds maximum allowed size")
        return data
    finally:
        os.close(fd)

def decode_utf8(data: bytes) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RagError(
            "invalid_utf8",
            "document must be UTF-8 for the current parser set",
            {"offset": exc.start},
        )
    if "\x00" in text:
        raise RagError("binary_content_rejected", "NUL byte detected in text document")
    return text.replace("\r\n", "\n").replace("\r", "\n")

def extract_text(ext: str, data: bytes, cfg: dict) -> tuple[str, str]:
    text = decode_utf8(data)
    parser = ""

    if ext in (".txt", ".md"):
        parser = "utf8_text_v1"
        extracted = text

    elif ext == ".json":
        parser = "json_stdlib_v1"
        try:
            obj = json.loads(text)
        except Exception as exc:
            raise RagError("invalid_json", f"JSON parse failed: {exc}")
        extracted = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)

    elif ext == ".csv":
        parser = "csv_stdlib_v1"
        try:
            rows = list(csv.reader(io.StringIO(text)))
        except Exception as exc:
            raise RagError("invalid_csv", f"CSV parse failed: {exc}")
        if not rows:
            raise RagError("empty_document", "CSV contains no rows")
        # Preserve cell boundaries deterministically without executing formulas.
        extracted = "\n".join("\t".join(cell for cell in row) for row in rows)

    elif ext in (".yaml", ".yml"):
        parser = "pyyaml_safe_v1"
        if yaml is None:
            raise RagError("parser_unavailable", "PyYAML is not available")
        try:
            obj = yaml.safe_load(text)
        except Exception as exc:
            raise RagError("invalid_yaml", f"YAML parse failed: {exc}")
        if obj is None:
            raise RagError("empty_document", "YAML has no content")
        extracted = yaml.safe_dump(
            obj,
            allow_unicode=True,
            sort_keys=True,
            default_flow_style=False,
        )

    else:
        raise RagError("unsupported_document_type", f"unsupported extension: {ext}")

    extracted = extracted.strip()
    if not extracted:
        raise RagError("empty_document", "no extractable text found")
    if len(extracted) > cfg["max_extracted_chars"]:
        raise RagError(
            "extracted_text_too_large",
            "extracted text exceeds configured limit",
            {
                "extracted_chars": len(extracted),
                "max_extracted_chars": cfg["max_extracted_chars"],
            },
        )
    return extracted, parser

def chunk_text(text: str, cfg: dict) -> list[dict]:
    target = cfg["chunk_target_chars"]
    overlap = cfg["chunk_overlap_chars"]
    n = len(text)
    chunks = []
    start = 0
    chunk_no = 0

    while start < n:
        hard_end = min(start + target, n)
        end = hard_end

        if hard_end < n:
            floor = start + max(1, int(target * 0.60))
            candidate = text.rfind("\n\n", floor, hard_end)
            if candidate == -1:
                candidate = text.rfind("\n", floor, hard_end)
            if candidate == -1:
                candidate = text.rfind(" ", floor, hard_end)
            if candidate > start:
                end = candidate

        raw = text[start:end]
        leading = len(raw) - len(raw.lstrip())
        trailing = len(raw.rstrip())
        actual_start = start + leading
        actual_end = start + trailing

        if actual_end > actual_start:
            content = text[actual_start:actual_end]
            chunks.append({
                "chunk_no": chunk_no,
                "char_start": actual_start,
                "char_end": actual_end,
                "content": content,
            })
            chunk_no += 1

        if end >= n:
            break

        next_start = max(end - overlap, start + 1)
        while next_start < n and text[next_start].isspace():
            next_start += 1
        start = next_start

        if len(chunks) > cfg["max_chunks_per_document"]:
            raise RagError(
                "too_many_chunks",
                "document exceeds maximum chunk count",
                {"max_chunks_per_document": cfg["max_chunks_per_document"]},
            )

    if not chunks:
        raise RagError("empty_document", "chunker produced no content")
    if len(chunks) > cfg["max_chunks_per_document"]:
        raise RagError(
            "too_many_chunks",
            "document exceeds maximum chunk count",
            {"max_chunks_per_document": cfg["max_chunks_per_document"]},
        )
    return chunks

def audit(con: sqlite3.Connection, action: str, document_id: str | None, details: dict):
    con.execute(
        "INSERT INTO audit_events(ts,action,document_id,details_json) VALUES(?,?,?,?)",
        (now_utc(), action, document_id, json.dumps(details, sort_keys=True)),
    )

def total_usage(con: sqlite3.Connection) -> tuple[int, int]:
    row = con.execute(
        "SELECT COUNT(*) AS c, COALESCE(SUM(size_bytes),0) AS b FROM documents"
    ).fetchone()
    return int(row["c"]), int(row["b"])

def write_json_atomic(path: Path, obj: dict, mode=0o660):
    tmp = path.with_name(path.name + ".tmp")
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def write_chunks_jsonl(path: Path, document_id: str, filename: str, chunks: list[dict]):
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for ch in chunks:
            row = {
                "schema_version": SCHEMA_VERSION,
                "document_id": document_id,
                "filename": filename,
                **ch,
            }
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)

def ingest(source: Path, display_filename: str | None, domain: str = "shared") -> dict:
    cfg = load_config()
    domain = validate_domain(domain)
    ensure_existing_store_paths(cfg)

    display = safe_display_filename(display_filename or source.name)
    ext = extension_for(display, cfg)
    data = read_regular_file_no_follow(source, cfg["max_document_bytes"])
    digest = hashlib.sha256(data).hexdigest()
    extracted, parser = extract_text(ext, data, cfg)
    chunks = chunk_text(extracted, cfg)

    con = connect(cfg)
    init_schema(con)

    duplicate = con.execute(
        "SELECT document_id, filename FROM documents WHERE sha256=?",
        (digest,),
    ).fetchone()
    if duplicate:
        con.close()
        raise RagError(
            "duplicate_document",
            "document with identical SHA256 already exists",
            {
                "document_id": duplicate["document_id"],
                "filename": duplicate["filename"],
            },
        )

    doc_count, total_bytes = total_usage(con)
    if doc_count >= cfg["max_documents"]:
        con.close()
        raise RagError("document_limit_reached", "maximum document count reached")
    if total_bytes + len(data) > cfg["max_total_bytes"]:
        con.close()
        raise RagError("knowledge_store_full", "knowledge-store byte limit reached")

    document_id = uuid.uuid4().hex
    docs_root = Path(cfg["documents_root"])
    final_dir = docs_root / document_id
    temp_dir = docs_root / f".tmp-{document_id}"

    if final_dir.exists() or temp_dir.exists():
        con.close()
        raise RagError("document_id_collision", "unexpected document ID collision")

    temp_dir.mkdir(mode=0o770)
    renamed = False
    try:
        original = temp_dir / "original"
        with open(original, "xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(original, 0o660)

        metadata = {
            "schema_version": SCHEMA_VERSION,
            "store_version": STORE_VERSION,
            "document_id": document_id,
            "filename": display,
            "extension": ext,
            "media_type": media_type_for(ext),
            "parser": parser,
            "sha256": digest,
            "size_bytes": len(data),
            "extracted_chars": len(extracted),
            "chunk_count": len(chunks),
            "created_at": now_utc(),
            "active": True,
        }
        write_json_atomic(temp_dir / "metadata.json", metadata)
        write_chunks_jsonl(temp_dir / "chunks.jsonl", document_id, display, chunks)

        con.execute("BEGIN IMMEDIATE")
        con.execute(
            """
            INSERT INTO documents(
                document_id, filename, extension, media_type, parser, sha256,
                size_bytes, extracted_chars, chunk_count, active,
                created_at, updated_at, domain
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                document_id,
                display,
                ext,
                metadata["media_type"],
                parser,
                digest,
                len(data),
                len(extracted),
                len(chunks),
                1,
                metadata["created_at"],
                metadata["created_at"],
                domain,
            ),
        )
        con.executemany(
            """
            INSERT INTO chunks(document_id,chunk_no,char_start,char_end,content)
            VALUES(?,?,?,?,?)
            """,
            [
                (
                    document_id,
                    ch["chunk_no"],
                    ch["char_start"],
                    ch["char_end"],
                    ch["content"],
                )
                for ch in chunks
            ],
        )
        audit(
            con,
            "ingest",
            document_id,
            {
                "filename": display,
                "sha256": digest,
                "size_bytes": len(data),
                "chunk_count": len(chunks),
                "domain": domain,
            },
        )

        os.rename(temp_dir, final_dir)
        renamed = True
        con.commit()
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        if renamed and final_dir.exists():
            shutil.rmtree(final_dir, ignore_errors=True)
        elif temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        con.close()
        raise

    con.close()
    return {
        "valid": True,
        "operation": "ingest",
        "document": {**metadata, "domain": domain},
        "persistent": True,
        "reupload_required_for_future_chats": False,
        "store_version": STORE_VERSION,
    }

def list_documents(active_only=True) -> dict:
    cfg = load_config()
    con = connect(cfg)
    init_schema(con)
    sql = """
      SELECT document_id,filename,extension,media_type,parser,sha256,size_bytes,
             extracted_chars,chunk_count,active,created_at,updated_at,domain
        FROM documents
    """
    params=()
    if active_only:
        sql += " WHERE active=1"
    sql += " ORDER BY created_at ASC, document_id ASC"
    rows=[dict(r) for r in con.execute(sql,params).fetchall()]
    con.close()
    for r in rows:
        r["active"] = bool(r["active"])
    return {
        "valid": True,
        "operation": "list",
        "documents": rows,
        "count": len(rows),
        "store_version": STORE_VERSION,
    }

def validate_document_id(document_id: str):
    if not DOC_ID_RE.fullmatch(document_id or ""):
        raise RagError("invalid_document_id", "document_id must be 32 lowercase hex characters")

def set_document_domain(document_id: str, domain: str) -> dict:
    validate_document_id(document_id)
    domain = validate_domain(domain)
    cfg = load_config()
    con = connect(cfg)
    init_schema(con)

    row = con.execute(
        "SELECT document_id,filename,domain FROM documents WHERE document_id=?",
        (document_id,),
    ).fetchone()
    if not row:
        con.close()
        raise RagError("document_not_found", "document does not exist")

    old_domain = row["domain"]
    if old_domain == domain:
        con.close()
        return {
            "valid": True,
            "operation": "set-domain",
            "document_id": document_id,
            "filename": row["filename"],
            "old_domain": old_domain,
            "domain": domain,
            "changed": False,
            "domain_extension_version": DOMAIN_EXTENSION_VERSION,
            "store_version": STORE_VERSION,
        }

    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute(
            "UPDATE documents SET domain=?, updated_at=? WHERE document_id=?",
            (domain, now_utc(), document_id),
        )
        audit(
            con,
            "set_domain",
            document_id,
            {"old_domain": old_domain, "domain": domain},
        )
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()

    return {
        "valid": True,
        "operation": "set-domain",
        "document_id": document_id,
        "filename": row["filename"],
        "old_domain": old_domain,
        "domain": domain,
        "changed": True,
        "domain_extension_version": DOMAIN_EXTENSION_VERSION,
        "store_version": STORE_VERSION,
    }

def delete_document(document_id: str) -> dict:
    validate_document_id(document_id)
    cfg = load_config()
    con = connect(cfg)
    init_schema(con)

    row=con.execute(
        "SELECT document_id,filename FROM documents WHERE document_id=?",
        (document_id,),
    ).fetchone()
    if not row:
        con.close()
        raise RagError("document_not_found", "document does not exist")

    docs_root=Path(cfg["documents_root"])
    final_dir=docs_root/document_id
    tomb=docs_root/f".delete-{document_id}-{uuid.uuid4().hex[:8]}"

    if not final_dir.is_dir():
        con.close()
        raise RagError("document_storage_missing", "document directory is missing")

    os.rename(final_dir,tomb)
    committed=False
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM chunks WHERE document_id=?", (document_id,))
        con.execute("DELETE FROM documents WHERE document_id=?", (document_id,))
        audit(con,"delete",document_id,{"filename":row["filename"]})
        con.commit()
        committed=True
    except Exception:
        con.rollback()
        os.rename(tomb,final_dir)
        con.close()
        raise

    con.close()
    if committed:
        shutil.rmtree(tomb)
    return {
        "valid": True,
        "operation": "delete",
        "document_id": document_id,
        "filename": row["filename"],
        "store_version": STORE_VERSION,
    }

def reindex_document(document_id: str) -> dict:
    validate_document_id(document_id)
    cfg = load_config()
    con = connect(cfg)
    init_schema(con)

    row=con.execute(
        "SELECT * FROM documents WHERE document_id=?",
        (document_id,),
    ).fetchone()
    if not row:
        con.close()
        raise RagError("document_not_found", "document does not exist")

    doc_dir=Path(cfg["documents_root"])/document_id
    source=doc_dir/"original"
    data=read_regular_file_no_follow(source,cfg["max_document_bytes"])
    digest=hashlib.sha256(data).hexdigest()
    if digest != row["sha256"]:
        con.close()
        raise RagError(
            "stored_document_hash_mismatch",
            "stored original no longer matches recorded SHA256",
        )

    extracted,parser=extract_text(row["extension"],data,cfg)
    chunks=chunk_text(extracted,cfg)
    updated_at=now_utc()

    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute("DELETE FROM chunks WHERE document_id=?", (document_id,))
        con.executemany(
            """
            INSERT INTO chunks(document_id,chunk_no,char_start,char_end,content)
            VALUES(?,?,?,?,?)
            """,
            [
                (
                    document_id,
                    ch["chunk_no"],
                    ch["char_start"],
                    ch["char_end"],
                    ch["content"],
                )
                for ch in chunks
            ],
        )
        con.execute(
            """
            UPDATE documents
               SET parser=?, extracted_chars=?, chunk_count=?, updated_at=?
             WHERE document_id=?
            """,
            (parser,len(extracted),len(chunks),updated_at,document_id),
        )
        audit(
            con,
            "reindex",
            document_id,
            {"chunk_count":len(chunks),"sha256":digest},
        )
        con.commit()
    except Exception:
        con.rollback()
        con.close()
        raise
    con.close()

    metadata=json.loads((doc_dir/"metadata.json").read_text(encoding="utf-8"))
    metadata.update({
        "parser":parser,
        "extracted_chars":len(extracted),
        "chunk_count":len(chunks),
        "updated_at":updated_at,
    })
    write_json_atomic(doc_dir/"metadata.json",metadata)
    write_chunks_jsonl(doc_dir/"chunks.jsonl",document_id,row["filename"],chunks)

    return {
        "valid": True,
        "operation": "reindex",
        "document_id": document_id,
        "chunk_count": len(chunks),
        "store_version": STORE_VERSION,
    }

def stats() -> dict:
    cfg=load_config()
    con=connect(cfg)
    init_schema(con)
    row=con.execute("""
      SELECT COUNT(*) AS documents,
             COALESCE(SUM(size_bytes),0) AS total_bytes,
             COALESCE(SUM(chunk_count),0) AS chunks
      FROM documents
    """).fetchone()
    audits=con.execute("SELECT COUNT(*) AS c FROM audit_events").fetchone()["c"]
    domain_rows = con.execute(
        "SELECT domain,COUNT(*) AS c FROM documents GROUP BY domain ORDER BY domain"
    ).fetchall()
    domains = {r["domain"]: int(r["c"]) for r in domain_rows}
    for name in DOMAIN_VALUES:
        domains.setdefault(name, 0)
    con.close()
    return {
        "valid": True,
        "operation": "stats",
        "documents": int(row["documents"]),
        "total_bytes": int(row["total_bytes"]),
        "chunks": int(row["chunks"]),
        "audit_events": int(audits),
        "domains": domains,
        "domain_extension_version": DOMAIN_EXTENSION_VERSION,
        "limits": {
            "max_documents": cfg["max_documents"],
            "max_total_bytes": cfg["max_total_bytes"],
            "max_document_bytes": cfg["max_document_bytes"],
        },
        "store_version": STORE_VERSION,
    }

def self_check() -> dict:
    cfg=load_config()
    data_root,docs_root,index_path,state_root=paths(cfg)
    ensure_existing_store_paths(cfg)

    # Verify FTS5 independently and schema integrity.
    con=connect(cfg)
    init_schema(con)
    con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS temp.rag_selfcheck USING fts5(content)")
    con.execute("INSERT INTO rag_selfcheck(content) VALUES(?)",("powershell encoded command",))
    found=con.execute(
        "SELECT rowid FROM rag_selfcheck WHERE rag_selfcheck MATCH ?",
        ("powershell",),
    ).fetchone()
    schema=con.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()["value"]
    integrity=con.execute("PRAGMA integrity_check").fetchone()[0]
    cols = {
        r["name"] for r in con.execute("PRAGMA table_info(documents)").fetchall()
    }
    bad_domains = con.execute(
        "SELECT COUNT(*) AS c FROM documents "
        "WHERE domain NOT IN ('soc','iso','shared') OR domain IS NULL"
    ).fetchone()["c"] if "domain" in cols else -1
    domain_counts = {}
    if "domain" in cols:
        for r in con.execute(
            "SELECT domain,COUNT(*) AS c FROM documents GROUP BY domain ORDER BY domain"
        ).fetchall():
            domain_counts[r["domain"]] = int(r["c"])
    con.close()

    checks={
        "config_path":str(config_path()),
        "data_root":str(data_root),
        "documents_root":str(docs_root),
        "index_path":str(index_path),
        "state_root":str(state_root),
        "fts5":bool(found),
        "schema_version":schema,
        "integrity_check":integrity,
        "allowed_extensions":cfg["allowed_extensions"],
        "domain_column": "domain" in cols,
        "invalid_domain_rows": int(bad_domains),
        "domain_counts": domain_counts,
        "domain_extension_version": DOMAIN_EXTENSION_VERSION,
    }
    valid=(
        bool(found)
        and schema==SCHEMA_VERSION
        and integrity=="ok"
        and "domain" in cols
        and int(bad_domains)==0
    )
    return {
        "valid":valid,
        "operation":"self-check",
        "checks":checks,
        "store_version":STORE_VERSION,
        "network_access":False,
        "model_used":False,
    }

def init_command() -> dict:
    cfg=load_config()
    ensure_existing_store_paths(cfg)
    con=connect(cfg)
    init_schema(con)
    con.close()
    return {
        "valid":True,
        "operation":"init",
        "store_version":STORE_VERSION,
        "schema_version":SCHEMA_VERSION,
    }

def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest="command",required=True)

    sub.add_parser("init")
    sub.add_parser("self-check")
    sub.add_parser("stats")

    p_list=sub.add_parser("list")
    p_list.add_argument("--all",action="store_true")

    p_ingest=sub.add_parser("ingest")
    p_ingest.add_argument("--source",required=True)
    p_ingest.add_argument("--filename")
    p_ingest.add_argument("--domain",default="shared",choices=DOMAIN_VALUES)

    p_domain=sub.add_parser("set-domain")
    p_domain.add_argument("--document-id",required=True)
    p_domain.add_argument("--domain",required=True,choices=DOMAIN_VALUES)

    p_delete=sub.add_parser("delete")
    p_delete.add_argument("--document-id",required=True)

    p_reindex=sub.add_parser("reindex")
    p_reindex.add_argument("--document-id",required=True)

    args=parser.parse_args()

    try:
        if args.command=="init":
            result=init_command()
        elif args.command=="self-check":
            result=self_check()
        elif args.command=="stats":
            result=stats()
        elif args.command=="list":
            result=list_documents(active_only=not args.all)
        elif args.command=="ingest":
            result=ingest(Path(args.source),args.filename,args.domain)
        elif args.command=="set-domain":
            result=set_document_domain(args.document_id,args.domain)
        elif args.command=="delete":
            result=delete_document(args.document_id)
        elif args.command=="reindex":
            result=reindex_document(args.document_id)
        else:
            raise RagError("unknown_command","unknown command")
        emit(result)
    except RagError as exc:
        fail(exc.code,exc.message,exc.details,2)
    except Exception as exc:
        fail("internal_error",f"{type(exc).__name__}: {exc}",None,1)

if __name__=="__main__":
    main()

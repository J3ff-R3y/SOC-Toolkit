# Installation

This repository is intentionally environment-agnostic. The examples assume Enterprise Linux-style paths, Apache and systemd, but the core design is portable.

## Prerequisites

- Python 3.12+
- `llama.cpp` `llama-server`
- Apache httpd with proxy modules
- Python packages used by the current validators (`jsonschema`, YAML support where enabled)
- SQLite with FTS5 support
- `htpasswd` for the included session-auth helper

## Recommended filesystem layout

```text
/opt/jeffrey-gateway/
/etc/jeffrey-gateway/
/opt/jeffrey-rag/
/etc/jeffrey-rag/
/var/lib/jeffrey-rag/
/opt/jeffrey-update/
/var/lib/jeffrey-updates/
/opt/jeffrey-benchmark/
/srv/jeffrey/frontend/
```

Copy the matching files from `src/`, `schemas/`, `frontend/` and `config/`. Keep code/config root-owned and grant only the service access needed for runtime data.

## Service order

1. Start `llama-server` on loopback.
2. Start `jeffrey-gateway` on loopback.
3. Initialize the RAG store.
4. Start `jeffrey-rag-gateway` on loopback.
5. Validate Apache syntax and route clients only to the two gateway services.

## Initialize RAG

```bash
sudo -u jeffrey-gateway \
  env JEFFREY_RAG_CONFIG=/etc/jeffrey-rag/rag.json \
  /opt/jeffrey-rag/bin/rag_store.py init
```

## Validate before exposure

Run:

```bash
python3 -m py_compile /opt/jeffrey-gateway/*.py /opt/jeffrey-rag/bin/*.py
apachectl configtest
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8082/health
curl http://127.0.0.1:8083/health
```

Then confirm ports 8081/8082/8083 are bound only to loopback and unauthenticated application routes return 401.

See `config/` for sanitized examples.

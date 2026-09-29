# Operations

## Health

```bash
systemctl status llama-server jeffrey-gateway jeffrey-rag-gateway httpd
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8082/health
curl http://127.0.0.1:8083/health
```

## RAG self-checks

```bash
sudo -u jeffrey-gateway env JEFFREY_RAG_CONFIG=/etc/jeffrey-rag/rag.json \
  /opt/jeffrey-rag/bin/rag_store.py self-check

sudo -u jeffrey-gateway env JEFFREY_RAG_CONFIG=/etc/jeffrey-rag/rag.json \
  /opt/jeffrey-rag/bin/rag_retrieve.py self-check
```

## Knowledge lifecycle

- Upload documents explicitly.
- Assign `SOC`, `ISO` or `Shared` at upload.
- Reindex only through the explicit store operation.
- Delete documents explicitly; the RAG layer never turns chat messages into persistent knowledge.

## Model policy

Use a single approved/tested model unless a second model has completed the same benchmark, quality and resource checks. Do not treat a file merely present in the model directory as approved.

## Change control

Before gateway, RAG, model or route changes:

1. capture hashes/config/service state;
2. create a rollback copy;
3. change one narrow component;
4. compile/config-test;
5. perform authenticated and unauthenticated regressions;
6. preserve evidence separately from the public repository.

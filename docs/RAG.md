# Persistent local RAG

Jeffrey Toolkit uses a deliberately simple offline-first RAG design: original files + SQLite FTS5 lexical retrieval. It does not require an embedding service or vector database.

## Persistence

Documents are uploaded once. Original bytes are stored under a generated opaque document ID; metadata/chunks/search state are persisted in SQLite. They remain available to future chats until explicitly deleted.

## Supported baseline formats

- TXT
- Markdown
- JSON
- CSV
- YAML/YML

Additional formats should only be enabled when an approved local parser is available and tested.

## Knowledge modes

### Off
No retrieval; ordinary chat behavior is used.

### Automatic
The active tool chooses an automatic domain scope. If nothing relevant passes the threshold, generation continues without RAG context.

### Selected documents
Only explicitly selected opaque document IDs are searched. This selection is authoritative, even when a selected document belongs to another domain.

## Domains

```text
soc     operational SOC/detection material
iso     policy, risk and compliance material
shared  material useful to both
```

The browser asks the user to assign one of these labels at upload. The label is stored persistently in SQLite; it is not inferred from a filename.

## Tool-aware retrieval

The browser separates the compact retrieval query from the full model-generation prompt. Long formatting instructions therefore do not dominate document search.

ISO mappings include policy generation, risk analysis, advice notes and compliance Q&A. SOC mappings include detection trigger testing, SOAR playbooks, Sigma analysis, network detection and forensic triage.

## Source attribution

Retrieved chunks receive source labels (`K1`, `K2`, ...) with document name and domain metadata.

## No conversational memory

RAG persistence applies to documents, not chat history. This layer does not implement long-term user/conversation memory.

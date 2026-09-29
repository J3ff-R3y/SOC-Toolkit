# Jeffrey Toolkit

Jeffrey Toolkit is an offline-first SOC and information-security assistant built around a local `llama.cpp` runtime. It combines chat, structured detection engineering, deterministic utilities, static forensics, persistent local document retrieval, offline update controls, and reproducible model benchmarking behind localhost-only backend services.

The repository describes the project as one integrated platform. Historical implementation phases and environment-specific evidence are intentionally not part of the public layout.

## Capabilities

- Local OpenAI-compatible chat through a hardened gateway
- Session-protected browser/API access
- Structured Sigma, YARA, Suricata and Zeek generation with deterministic validation
- Deterministic IOC/text encoding utilities that do not call the model
- Static-only file triage helpers
- Persistent offline RAG using SQLite FTS5
- Knowledge modes: Off, Automatic, Selected documents
- Persistent knowledge domains: `soc`, `iso`, `shared`
- Automatic tool-aware retrieval:
  - SOC tools -> `soc + shared`
  - ISO tools -> `iso + shared`
  - normal chat -> `soc + iso + shared`
- Source attribution for retrieved chunks
- Offline update verification/import/activation with rollback-oriented versioned releases
- Reproducible benchmark corpus and quality evaluation tooling
- Explicit single-model-by-default operating policy

## Architecture

```text
Browser / VDI
      |
      v
Apache / reverse proxy
      |
      +-- /api/chat, structured APIs, deterministic utility
      |        |
      |        v
      |   Jeffrey Gateway :8082 (localhost)
      |        |
      |        v
      |   llama-server :8081 (localhost)
      |
      `-- /api/rag/*
               |
               v
          RAG Gateway :8083 (localhost)
               |
               +-- SQLite FTS5 knowledge store
               +-- document files
               +-- domain-aware retrieval
               `-- Jeffrey Gateway :8082 -> llama-server
```

Only the reverse proxy should be externally reachable. The model server and both Python gateways are designed to remain loopback-only.

## Repository layout

```text
frontend/            browser UI and local static assets
src/gateway/         core gateway, auth, structured tools, validators, utilities
src/rag/             persistent store, retriever and RAG sidecar
src/update/          offline bundle verification/import/activation
src/benchmark/       benchmark runner, corpus and quality analysis
schemas/             JSON schemas for structured outputs and control planes
config/              sanitized example configs and service definitions
docs/                architecture, installation, operations and security docs
scripts/             local validation helpers
```

## Important security boundaries

- Backend ports bind to loopback.
- Retrieved document text is untrusted reference context, never executable instruction.
- Chat history is not persisted as long-term user memory by the RAG layer.
- Selected-document mode is an explicit hard document-ID filter.
- Offline bundles are verified before import and cannot supply arbitrary shell commands.
- Static forensics is intentionally non-executing.
- Baseline YARA/Suricata/Zeek validators are conservative checks, not claims of full engine/compiler equivalence.

See [Architecture](docs/ARCHITECTURE.md), [Installation](docs/INSTALLATION.md), [Security](docs/SECURITY.md), and [RAG](docs/RAG.md).

## Scope

The public repository is deployment-agnostic. It contains no organization-specific IP addresses, hostnames, credentials, session tokens, internal evidence bundles, or environment-specific network policy. Adapt the example paths, service users and firewall policy to your own managed environment.

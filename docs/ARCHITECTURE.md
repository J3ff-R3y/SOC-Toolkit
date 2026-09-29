# Architecture

Jeffrey Toolkit separates public HTTP handling, policy enforcement, model generation and document retrieval.

## Components

### Apache / reverse proxy
Provides the browser entry point and routes APIs to localhost services. It must not proxy clients directly to `llama-server`.

### Jeffrey Gateway
The main local middleware on `127.0.0.1:8082`. Responsibilities include request limits, model parameter policy, session validation, request IDs, structured SOC routes, deterministic utilities and chat streaming passthrough.

### llama-server
A local `llama.cpp` OpenAI-compatible server on `127.0.0.1:8081`. Model choice is deployment-specific.

### RAG Gateway
A local sidecar on `127.0.0.1:8083`. It reuses the main gateway session boundary, retrieves local knowledge and injects bounded untrusted reference context before forwarding generation to the Jeffrey Gateway.

### Knowledge store
Original document bytes live outside SQLite. Metadata, chunks and FTS5 search state live in an embedded SQLite database. Documents are uploaded once and remain reusable until explicitly deleted.

## Knowledge routing

```text
General chat -> soc + iso + shared
SOC tools    -> soc + shared
ISO tools    -> iso + shared
```

Explicit `selected_documents` mode overrides automatic domain filtering and searches only the chosen opaque document IDs.

## Structured tooling

Sigma, YARA, Suricata and Zeek generation use dedicated response schemas and deterministic baseline validators. The model produces a candidate; the gateway validates the candidate before returning success.

## Deterministic tooling

The deterministic route is deliberately model-free and designed without shell, filesystem-path or outbound-network primitives for supported operations.

## Offline maintenance

The update control plane is local and not web-exposed. Approved bundles are transferred into the isolated environment, verified, imported into versioned releases, then activated using explicit source-specific policies.

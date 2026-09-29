# Security model

## Network boundary

The model server and both Python gateways are designed for loopback-only binding. Apache is the client-facing component. Environment-specific firewall, TLS and enterprise authentication decisions are intentionally outside this repository's generic examples.

## Sessions

The included browser compatibility layer issues random in-memory session tokens after validating credentials against a local `htpasswd` file. Tokens are not written to repository files. For internet-facing or higher-assurance deployments, integrate with an approved enterprise authentication/TLS design.

## Prompt/document trust

Retrieved knowledge is marked and treated as untrusted reference context. Documents must not be allowed to redefine system/tool instructions or trigger command execution.

## Structured generation

Model output is schema-checked and then passed to deterministic baseline validators. These validators intentionally do not claim compiler/engine equivalence unless a real approved engine is integrated.

## Deterministic utilities

The deterministic utility path is separate from model generation. Supported operations are allowlisted and do not accept arbitrary shell commands, filesystem paths or outbound network targets.

## Static forensics

Static file triage inspects bytes/metadata only. Do not execute uploaded samples.

## Offline updates

Bundle manifests declare each payload path, size and SHA256. Verification rejects traversal, absolute paths, symlinks, hardlinks, FIFO/device/special entries and undeclared files. Bundle metadata cannot contain arbitrary activation commands.

## Public-repository hygiene

Do not commit:

- real hostnames/IP ranges;
- credentials or password databases;
- session tokens;
- private keys/certificates;
- investigation uploads;
- production evidence bundles;
- model binaries.

# Jeffrey Toolkit — Security Hardening Guide

This document contains generic hardening guidance. It is **not** a drop-in configuration: every host, network and operating system must be checked before applying a control.

## 1. Trust boundaries

A typical deployment should look like:

```
User/client
   │
   ▼
Reverse proxy + authentication
   │
   ▼
Jeffrey application
   │
   ▼
Local model API
   │
   ▼
Model files
```

The model API should normally not be exposed directly to users.

For an isolated deployment:

```
Client network ──► Jeffrey host
                       │
                       ├── local model API
                       └── model/data storage
                              X
                           Internet
```

The exact network controls depend on the environment.

## 2. Dedicated service account

Run llama.cpp as a dedicated unprivileged account.

Example:

```bash
sudo useradd --system --home-dir /var/lib/jeffrey --create-home \
  --shell /sbin/nologin jeffrey-llama
```

The service account should have only the permissions required to:

- execute the llama-server binary
- read the required model files
- write only required runtime/log/cache locations

Do not give the service account sudo access.

## 3. File permissions

Recommended principle:

```
Application binaries  → root-owned, not writable by service
Model files           → root-owned, readable by service
Web content           → not writable by web-server process
Secrets               → restricted to the process that needs them
Logs                  → writable only where required
```

Do not recursively make an application directory owned by the web-server account merely to make deployment convenient.

## 4. Model API binding

Prefer:

```
127.0.0.1:<model-port>
```

rather than:

```
0.0.0.0:<model-port>
```

when the reverse proxy is on the same host.

If remote access is genuinely required, use explicit firewall rules and authentication rather than relying on obscurity.

## 5. systemd hardening

A suitable starting point may include:

```ini
[Service]
User=jeffrey-llama
Group=jeffrey-llama

NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

RestrictSUIDSGID=true
LockPersonality=true
```

Test incrementally. Do not blindly enable the strictest possible sandbox settings because llama.cpp, model loading, logging or a future runtime feature may need a specific filesystem path.

Move from `ProtectSystem=full` to stricter settings only after testing.

## 6. Reverse proxy

The reverse proxy should:

- provide authentication
- restrict methods where appropriate
- enforce reasonable request/body limits
- proxy only the endpoints that are needed
- avoid exposing internal administrative endpoints
- preserve streaming/SSE behaviour where required
- log security-relevant errors without logging sensitive prompt content unnecessarily

Disable directory indexing unless explicitly required.

## 7. Health endpoints

Health endpoints should expose the minimum information needed.

Prefer a local/internal health check.

Do not expose detailed system information, model paths, environment variables or credentials through health endpoints.

## 8. Network segmentation

Document separately:

- user/client source networks
- management source networks
- monitoring source networks
- server VLAN/subnet
- allowed destination ports
- expected egress behaviour

Use source-restricted firewall rules.

Never remove the existing management rule before the replacement management path has been tested.

## 9. Egress

For an offline deployment, verify rather than assume that egress is blocked.

Document:

- default route
- DNS behaviour
- proxy configuration
- firewall egress policy
- package/update mechanism
- approved exceptions

The toolkit itself should not require internet connectivity during normal operation.

## 10. Secrets

Never commit:

- passwords
- API keys
- private certificates
- private SSH keys
- internal hostnames if they are sensitive
- internal IP ranges if the public repository should not disclose them
- production usernames
- tokens

Use examples/placeholders in this repository.

## 11. Browser/client considerations

The frontend must treat all model output as untrusted text.

Avoid inserting model-generated content into `innerHTML` unless it has been deliberately sanitized.

Where possible:

- use text nodes for untrusted content
- sanitize rendered Markdown/HTML
- validate uploaded file types
- limit file sizes
- limit the number of attachments
- avoid storing sensitive conversations in browser persistent storage unless explicitly required

Stateless client environments are compatible with this design.

## 12. Upload handling

For every supported file type:

- enforce size limits
- validate MIME/type where practical
- parse with the appropriate library
- fail closed on malformed files
- avoid executing uploaded content
- avoid server-side temporary files unless required
- clean up temporary resources

For PDFs and office documents, parsing should remain a data-extraction operation rather than an execution path.

## 13. LLM-specific security

Treat the model as an untrusted component.

Do not assume that:

- system prompts are secrets
- the model will obey every instruction
- uploaded documents are trustworthy
- generated commands are safe
- generated detection rules are syntactically valid
- generated CVE details are correct

Use deterministic validation and explicit tool allow-lists.

## 14. Rollback

Every infrastructure change should have:

1. a backup of the current configuration
2. a documented restore path
3. a health check
4. a functional regression test
5. a clear point at which rollback is preferred over further debugging

Keep the known-good deployment available until the replacement has been validated.

## 15. Security change checklist

Before merging/deploying:

- [ ] No secrets added
- [ ] Service account permissions reviewed
- [ ] Model API not unintentionally exposed
- [ ] Reverse proxy authentication tested
- [ ] Firewall allow rules tested
- [ ] Firewall deny behaviour tested
- [ ] Egress behaviour documented
- [ ] Upload limits reviewed
- [ ] Logs reviewed for sensitive data
- [ ] Rollback tested
- [ ] Existing toolkit functions regression-tested

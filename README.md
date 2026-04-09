# Jeffrey Toolkit v1.0

**SOC Intelligence Suite** — AI-powered assistant for Security Operations Centers, running fully offline on-premise.

## What is Jeffrey?

Jeffrey is a self-hosted AI toolkit for SOC analysts, running on llama.cpp with Qwen 3.5 35B-A3B (Mixture-of-Experts + Vision). It generates SIEM queries, SOAR playbooks, detection rules, complete security onboarding packages, and can analyze screenshots — all from a single HTML interface behind Apache Basic Auth.

## Features

- **SIEM Query Builder** — Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL/Lucene) with use case dropdowns, time range, MITRE ATT&CK mapping
- **SOAR Playbooks** — Sentinel Logic Apps and Splunk SOAR with incident type, severity, and automation action selection
- **Sigma Rules** — Convert Sigma YAML to platform-specific detection with field mapping and false positive analysis
- **Network Detection** — Suricata IDS/IPS rules and Zeek scripts with threat type and protocol focus
- **SOC Kickstart** — Complete onboarding package: STRIDE threat model, MITRE ATT&CK mapping, log requirements, detection rules, monitoring queries, security hardening checklist
- **Forensische Triage** — First-pass analysis of suspicious binaries (strings extraction, IOC detection, magic bytes, entropy, YARA rule suggestions)
- **Screenshot Analysis** — Paste or upload screenshots (SIEM alerts, dashboards, network diagrams) for visual analysis
- **Streaming Output** — Live token-by-token responses with timer and stop button
- **File Upload (RAG)** — Upload TXT/CSV/JSON/LOG context for analysis
- **Chat History** — Persistent conversations stored locally per user
- **Export** — Download conversations as Markdown, Text, or JSON
- **Custom Login** — Username/password authentication via Apache Basic Auth
- **Jeffrey Identity** — System prompt ensures consistent assistant behavior

## Architecture

```
Browser  →  Apache (:8080)  →  llama.cpp server (:8081)
            Basic Auth          Qwen 3.5 35B-A3B MoE
            Reverse Proxy       + Vision projector
            SSE Streaming       CPU inference
```

## Requirements

| Component | Spec |
|-----------|------|
| OS | RHEL 10 (or compatible) |
| RAM | 64 GB minimum |
| Disk | 100 GB on /data |
| Network | Offline (no internet required) |
| GPU | Not required (CPU-only inference) |

## Quick Start

### 1. Download (on a PC with internet)

| File | Source | Size |
|------|--------|------|
| `llama.cpp-master.zip` | [GitHub](https://github.com/ggml-org/llama.cpp) → Code → Download ZIP | ~50 MB |
| `Qwen3.5-35B-A3B-MXFP4_MOE.gguf` | [unsloth/Qwen3.5-35B-A3B-GGUF](https://huggingface.co/unsloth/Qwen3.5-35B-A3B-GGUF) | ~20 GB |
| `mmproj-F16.gguf` | Same repo (for vision support) | ~900 MB |

### 2. Upload to server

```bash
scp llama.cpp-master.zip user@SERVER:/data/toolkit/
scp Qwen3.5-35B-A3B-MXFP4_MOE.gguf user@SERVER:/data/toolkit/
scp mmproj-F16.gguf user@SERVER:/data/toolkit/
scp deploy-jeffrey-v1.0.sh user@SERVER:/data/toolkit/
scp jeffrey-v1.0.html user@SERVER:/data/toolkit/
```

### 3. Deploy

```bash
sudo bash /data/toolkit/deploy-jeffrey-v1.0.sh
```

The script handles everything: cleanup of old installations, compiling llama.cpp from source (CMake), model + vision projector setup, Apache reverse proxy with Basic Auth, SELinux, firewall, and systemd service creation.

## File Structure (after deployment)

```
/data/
├── toolkit/
│   ├── index.html                         # Active HTML (served by Apache)
│   ├── deploy-jeffrey-v1.0.sh              # Deploy script
│   └── jeffrey-v1.0.html                   # HTML source
├── models/
│   ├── Qwen3.5-35B-A3B-MXFP4_MOE.gguf    # Main model (~20 GB)
│   └── mmproj-F16.gguf                    # Vision projector (~900 MB)
/opt/llama-server/
│   └── llama-server                        # Compiled binary
/etc/httpd/conf.d/jeffrey.conf              # Apache config
/etc/systemd/system/llama-server.service
/etc/systemd/system/llama-server.service.d/override.conf
```

## Management

```bash
# Services
systemctl status llama-server
journalctl -u llama-server -f

# Users
htpasswd /etc/httpd/.htpasswd <username>         # Add
htpasswd -D /etc/httpd/.htpasswd <username>       # Remove

# Restart after config change
sudo systemctl restart llama-server
```

## Current Model

| Property | Value |
|----------|-------|
| Model | Qwen 3.5 35B-A3B Instruct |
| Architecture | Mixture-of-Experts (3B active of 35B total) |
| Quantization | MXFP4_MOE (Unsloth) |
| Vision | Yes (via mmproj-F16) |
| Size (main) | ~20 GB |
| Size (mmproj) | ~900 MB |
| RAM usage | ~24 GB |
| Context window | 16384 tokens |
| License | Apache 2.0 |

## Performance (CPU-only, 64GB RAM)

| Query type | Expected time |
|------------|---------------|
| Simple question | 5-15 sec |
| SIEM query | 15-30 sec |
| SOAR / Sigma / Network | 30-90 sec |
| SOC Kickstart package | 2-5 min |
| Screenshot analysis | 30-90 sec |

## Migration from Qwen 3.5 27B

If you're upgrading from the original Qwen 3.5 27B dense model, use the migration script which handles everything including backup and rollback:

```bash
sudo /data/toolkit/migrate-to-qwen35-moe.sh
```

The script:
- Backs up your current systemd override with timestamp
- Installs the new model + vision projector
- Updates the systemd configuration
- Preserves the old model for easy rollback
- Verifies the new setup works before declaring success

## Repository Contents

| File | Purpose |
|------|---------|
| `jeffrey-v1.0.html` | Web interface (with vision support) |
| `deploy-jeffrey-v1.0.sh` | Fresh deployment script |
| `migrate-to-qwen35-moe.sh` | Migration from Qwen 3.5 27B to 35B-A3B |
| `upgrade-llamacpp.sh` | In-place llama.cpp recompilation |
| `README.md` | This document |
| `.gitignore` | Excludes GGUF models, builds, credentials |

## License

This toolkit is provided as-is for internal SOC use. The Qwen 3.5 model is licensed under Apache 2.0.

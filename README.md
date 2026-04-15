# Jeffrey Toolkit v1.0

**SOC & ISO Intelligence Suite** — AI-powered assistant for Security Operations Centers and Information Security Officers, running fully offline on-premise.

## What is Jeffrey?

Jeffrey is a self-hosted AI toolkit running on llama.cpp with Qwen 3.5 35B-A3B (Mixture-of-Experts + Vision). It provides SOC analysts with query builders, playbooks, detection rules, incident enrichment, and forensics tooling. It provides ISOs with policy generation, risk analysis, advisory notes, and compliance Q&A. All behind Apache Basic Auth in a single HTML interface.

## Features

### SOC Tools
- **SIEM Query Builder** — Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL/Lucene) with use case dropdowns, time range, MITRE ATT&CK mapping
- **SOAR Playbooks** — Sentinel Logic Apps and Splunk SOAR with incident type, severity, and automation action selection
- **Sigma Rules** — Convert Sigma YAML to platform-specific detection with field mapping and false positive analysis
- **Network Detection** — Suricata IDS/IPS rules and Zeek scripts with threat type and protocol focus
- **SOC Kickstart** — Complete onboarding package: STRIDE threat model, MITRE ATT&CK mapping, log requirements, detection rules, monitoring queries, security hardening checklist
- **Forensische Triage** — First-pass analysis of suspicious binaries (strings extraction, IOC detection, magic bytes, entropy, YARA rule suggestions)
- **Incident Enrichment** — Structured investigation plan where the model determines relevant SIEM platforms and data sources based on alert content
- **Sentinel Pipeline** — BICEP templates and CI/CD pipelines for Sentinel content deployment with conflict prevention for co-existing MSSP pipelines

### ISO Tools
- **Beleid Generator** — Generates policy documents in standard Dutch government structure (versiebeheer, verspreiding, verwijzingen, acceptatie, inleiding, maatregelen, mapping, rollen, bijlage)
- **Risicoanalyse** — Supports risk analyses with criticality levels (Laag/Midden/Hoog/Kritiek), STRIDE modeling, and BIO2/ISO 27005 mapping
- **Adviesnotitie** — Structured advisory notes with summary, analysis, considerations, recommendation, conditions, and alternatives
- **Compliance Q&A** — Answers on framework interpretation, practical application, mapping between frameworks, and compliance evidence

**Supported frameworks:** BIO2, ISO 27001/27002/27005, NIS2, AVG/GDPR, NEN 7510, Cyberbeveiligingswet, ABRO, VIR-BI 2025.

### Platform Features
- **Screenshot Analysis** — Paste or upload screenshots (SIEM alerts, dashboards, network diagrams) for visual analysis
- **Streaming Output** — Live token-by-token responses with timer and stop button
- **Context-Aware Follow-ups** — Chat history maintained across follow-up questions
- **File Upload (RAG)** — Upload TXT/CSV/JSON/LOG context for analysis, or images for vision
- **Chat History** — Persistent conversations stored locally per user
- **Export** — Download conversations as Markdown, Text, or JSON
- **Collapsible Sidebar** — Full collapse mode with icon-only view, or collapse individual sections (SOC/ISO/Chats)
- **Custom Login** — Username/password authentication via Apache Basic Auth

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
| Policy document (ISO) | 1-3 min |
| Risk analysis (ISO) | 1-2 min |
| Sentinel Pipeline | 2-5 min |

## Repository Contents

| File | Purpose |
|------|---------|
| `jeffrey-v1.0.html` | Web interface (SOC + ISO tools, vision support) |
| `deploy-jeffrey-v1.0.sh` | Fresh deployment script |
| `upgrade-llamacpp.sh` | In-place llama.cpp recompilation for updates |
| `README.md` | This document |
| `.gitignore` | Excludes GGUF models, builds, credentials |

## Disclaimers

Jeffrey is a personal/test project. It is not an officially supported production service. Generated content (policies, risk analyses, advisory notes, detection rules) should always be reviewed before use. AI assistance is not a replacement for professional judgment.

## License

This toolkit is provided as-is for internal SOC/ISO use. The Qwen 3.5 model is licensed under Apache 2.0.

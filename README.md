# Jeffrey Toolkit v1.0

**SOC Intelligence Suite** — AI-powered assistant for Security Operations Centers, running fully offline on-premise.

## What is Jeffrey?

Jeffrey is a self-hosted AI toolkit for SOC analysts, running on llama.cpp with Qwen 3.5 27B. It generates SIEM queries, SOAR playbooks, detection rules, and complete security onboarding packages — all from a single HTML interface behind Apache Basic Auth.

## Features

- **SIEM Query Builder** — Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL/Lucene) with use case dropdowns, time range, MITRE ATT&CK mapping
- **SOAR Playbooks** — Sentinel Logic Apps and Splunk SOAR with incident type, severity, and automation action selection
- **Sigma Rules** — Convert Sigma YAML to platform-specific detection with field mapping and false positive analysis
- **Network Detection** — Suricata IDS/IPS rules and Zeek scripts with threat type and protocol focus
- **SOC Kickstart** — Complete onboarding package: STRIDE threat model, MITRE ATT&CK mapping, log requirements, detection rules, monitoring queries, security hardening checklist
- **Streaming Output** — Live token-by-token responses with timer and stop button
- **File Upload (RAG)** — Upload TXT/CSV/JSON/LOG context for analysis
- **Chat History** — Persistent conversations stored locally per user
- **Custom Login** — Username/password authentication via Apache Basic Auth
- **Jeffrey Identity** — System prompt ensures consistent assistant behavior

## Architecture

```
Browser  →  Apache (:8080)  →  llama.cpp server (:8081)
            Basic Auth          Qwen 3.5 27B Q8
            Reverse Proxy       CPU inference
            SSE Streaming
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
| `Qwen3.5-27B-Q8_0.gguf` | [unsloth/Qwen3.5-27B-GGUF](https://huggingface.co/unsloth/Qwen3.5-27B-GGUF) | 28.6 GB |

### 2. Upload to server

```bash
scp llama.cpp-master.zip user@SERVER:/data/toolkit/
scp Qwen3.5-27B-Q8_0.gguf user@SERVER:/data/toolkit/
scp deploy-jeffrey-v1.0.sh user@SERVER:/data/toolkit/
scp jeffrey-v1.0.html user@SERVER:/data/toolkit/
```

### 3. Deploy

```bash
sudo bash /data/toolkit/deploy-jeffrey-v1.0.sh
```

The script handles everything: cleanup of old installations, compiling llama.cpp from source (CMake), model setup, Apache reverse proxy with Basic Auth, SELinux, firewall, and systemd service creation.

## File Structure (after deployment)

```
/data/
├── toolkit/
│   ├── index.html                  # Active HTML (served by Apache)
│   ├── deploy-jeffrey-v1.0.sh      # Deploy script
│   └── jeffrey-v1.0.html           # HTML source
├── models/
│   └── Qwen3.5-27B-Q8_0.gguf      # 28.6 GB model
/opt/llama-server/
│   └── llama-server                # Compiled binary
/etc/httpd/conf.d/jeffrey.conf      # Apache config
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
| Model | Qwen 3.5 27B Instruct (dense) |
| Quantization | Q8_0 (Unsloth) |
| Size | 28.6 GB |
| RAM usage | ~32 GB |
| Quality loss | <0.1% vs full precision |
| Context window | 16384 tokens |
| License | Apache 2.0 |

## Performance (CPU-only, 64GB RAM)

| Query type | Expected time |
|------------|---------------|
| Simple question | 30 sec - 2 min |
| SIEM query | 30 sec - 2 min |
| SOAR / Sigma / Network | 2-5 min |
| SOC Kickstart package | 5-15 min |

## Future: Gemma 4 Migration

Google released **Gemma 4 26B-A4B** (Mixture-of-Experts) in early April 2026 under Apache 2.0. It promises significant speed improvements over Qwen 3.5 on CPU hardware:

| Metric | Qwen 3.5 27B (current) | Gemma 4 26B-A4B (future) |
|---|---|---|
| Architecture | Dense (27B active) | MoE (3.8B active of 26B) |
| Token generation | ~3 tok/s | ~8-10 tok/s |
| RAM usage | ~32 GB | ~18-20 GB |
| SOC Kickstart | 5-15 min | 2-5 min (estimated) |

### Why we're waiting

Gemma 4 was released only days before our migration attempt. During testing we encountered known upstream issues:

- **llama.cpp Jinja parser bug** — chat template fails on tool-call/multimodal data parsing
- **GGUF metadata issues** — current Unsloth Gemma 4 GGUFs have incomplete `eog_token_ids`, causing the model to generate `<|tool_call|>` and `[multimodal]` tokens instead of normal text
- **Dag-1 release maturity** — three new things at once (model architecture, MXFP4 quantization format, llama.cpp implementation) creates many edge cases

The community is actively fixing these issues. We expect stability within 2-4 weeks of the release.

### Migration when ready

When Gemma 4 stabilizes:

1. Download the latest Unsloth GGUF (recommend Q8_0 for stability over MXFP4_MOE):
   `https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF`
2. Download the latest `llama.cpp-master.zip` from GitHub
3. Upload both to `/data/toolkit/` on the server
4. Run the upgrade and migration scripts:
   ```bash
   sudo /data/toolkit/upgrade-llamacpp.sh   # Recompile llama.cpp with latest source
   sudo /data/toolkit/migrate-to-gemma4.sh  # Switch model from Qwen to Gemma 4
   ```

Both scripts include automatic rollback to Qwen 3.5 if anything fails. The Qwen model file is preserved during migration.

## Repository Contents

| File | Purpose |
|------|---------|
| `jeffrey-v1.0.html` | Web interface (model-agnostic) |
| `deploy-jeffrey-v1.0.sh` | Fresh deployment script (ships with Qwen 3.5) |
| `migrate-to-gemma4.sh` | Future migration script (Qwen → Gemma 4) |
| `upgrade-llamacpp.sh` | In-place llama.cpp recompilation |
| `README.md` | This document |
| `.gitignore` | Excludes GGUF models, builds, credentials |

## License

This toolkit is provided as-is for internal SOC use. The Qwen 3.5 and Gemma 4 models are licensed under Apache 2.0.

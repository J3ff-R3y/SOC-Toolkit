# Jeffrey Toolkit v1.0

**SOC Intelligence Suite** — AI-powered assistant for Security Operations Centers, running fully offline on-premise.

## What is Jeffrey?

Jeffrey is a self-hosted AI toolkit for SOC analysts, running on llama.cpp with Qwen 3.5 27B. It generates SIEM queries, SOAR playbooks, detection rules, and complete security onboarding packages — all from a single HTML interface behind Apache Basic Auth.

## Features

- **SIEM Query Generation** — Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL/Lucene)
- **SOAR Playbooks** — Incident response automation workflows
- **Cribl Pipelines** — Stream pipeline configuration builder
- **Sigma Rules** — Convert Sigma YAML to platform-specific detection
- **Network Detection** — Suricata IDS/IPS rules, Zeek scripts
- **SOC Kickstart** — Complete onboarding: STRIDE threat model, log requirements, detection rules, monitoring queries, security checklist
- **Chat History** — Persistent conversations with localStorage
- **Jeffrey Identity** — Custom system prompt ensures consistent assistant behavior

## Architecture

```
Browser  →  Apache (:8080)  →  llama.cpp server (:8081)
            Basic Auth          Qwen 3.5 27B Q8
            Reverse Proxy       CPU inference
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
# Also copy deploy script and HTML from this repo
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
│   └── jeffrey-v1.0-qwen35.html    # HTML source
├── models/
│   └── Qwen3.5-27B-Q8_0.gguf      # 28.6 GB model
/opt/llama-server/
│   └── llama-server                # Compiled binary
/etc/httpd/conf.d/jeffrey.conf      # Apache config
/etc/systemd/system/llama-server.service
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

## Model Info

| Property | Value |
|----------|-------|
| Model | Qwen 3.5 27B (dense) |
| Quantization | Q8_0 (Unsloth Dynamic 2.0) |
| Size | 28.6 GB |
| Quality loss | <0.1% vs full precision |
| Context window | 4096 tokens (configurable) |
| Thinking mode | Disabled (faster responses) |
| License | Apache 2.0 |

## Performance (CPU-only, 64GB RAM)

| Query type | Expected time |
|------------|---------------|
| Simple question | 15-30 sec |
| SIEM query | 20-45 sec |
| SOAR playbook | 30-60 sec |
| SOC Kickstart package | 60-120 sec |

## License

This toolkit is provided as-is for internal SOC use. The Qwen 3.5 model is licensed under Apache 2.0.

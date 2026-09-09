# Jeffrey Toolkit v1.0

**SOC & ISO Intelligence Suite** — AI-powered assistant for Security Operations Centers and Information Security Officers, running fully offline on-premise.

## What is Jeffrey?

Jeffrey is a self-hosted AI toolkit running on llama.cpp with Qwen 3.6 35B-A3B (Mixture-of-Experts + Vision). It provides SOC analysts with playbooks, detection rules, network/forensics tooling, a detection trigger tester, and a living-off-the-land binaries reference. It provides ISOs with policy generation, risk analysis, advisory notes, and compliance Q&A. All behind Apache Basic Auth in a single HTML interface.

## Features

### SOC Tools

- **SOAR Playbooks** — Sentinel Logic Apps and Splunk SOAR with incident type, severity, and automation action selection
- **Sigma Rules** — Convert Sigma YAML to platform-specific detection with field mapping and false positive analysis
- **Network Detection** — Suricata IDS/IPS rules and Zeek scripts with threat type and protocol focus
- **Forensische Triage** — First-pass analysis of suspicious binaries (strings extraction, IOC detection, magic bytes, entropy, YARA rule suggestions)
- **Detectie Trigger Tester** — Paste a detection rule as delivered by a SIEM/vendor (Sentinel JSON, Splunk SPL, or Elastic TOML) and get a plan to verify the alert actually fires: rule logic explained, target OS inferred from the rule content, a ready-to-run PowerShell/bash trigger script where safe to automate, or an explicit risk explanation plus a manual step-by-step plan where it isn't — always followed by what to check in the SIEM afterwards
- **Living Off The Land Naslag** — Local, offline-searchable reference of the [LOLBAS project](https://lolbas-project.github.io/) (living-off-the-land binaries/scripts): search by binary name, command fragment, or MITRE ID and get direct links to matching Sigma/Elastic/Splunk detection rules. Pure client-side lookup against a bundled JSON snapshot — no AI interpretation, no hallucination risk

### ISO Tools

- **Beleid Generator** — Generates policy documents in standard Dutch government structure (versiebeheer, verspreiding, verwijzingen, acceptatie, inleiding, maatregelen, mapping, rollen, bijlage)
- **Risicoanalyse** — Supports risk analyses with criticality levels (Laag/Midden/Hoog/Kritiek), STRIDE modeling, and BIO2/ISO 27005 mapping
- **Adviesnotitie** — Structured advisory notes with summary, analysis, considerations, recommendation, conditions, and alternatives
- **Compliance Q&A** — Answers on framework interpretation, practical application, mapping between frameworks, and compliance evidence

**Supported frameworks:** BIO2, ISO 27001/27002/27005, NIS2, AVG/GDPR, NEN 7510, Cyberbeveiligingswet, ABRO, VIR-BI 2025.

### Platform Features

- **Multi-file Upload** — Up to 5 files at once, mixed types: text (TXT/CSV/JSON/MD/XML/YAML/CONF), Excel (XLSX/XLS), **PDF** (client-side text extraction via PDF.js), and up to 3 images together (PNG/JPG/GIF/WEBP for vision)
- **Paste-to-attachment** — Pasting long text (>500 characters) into the input field automatically becomes an attachment instead of cluttering the input box, same pattern as Claude/ChatGPT
- **Screenshot Analysis** — Paste or upload screenshots (SIEM alerts, dashboards, network diagrams) for visual analysis
- **Streaming Output** — Live token-by-token responses with timer and stop button, with scroll behavior that respects manual scrolling during generation
- **Context-Aware Follow-ups** — In-session chat history maintained across follow-up questions, with a token budget that scales down as the conversation grows (prevents responses being cut off mid-generation in long conversations)
- **Collapsible Sidebar** — Full collapse mode with icon-only view, or collapse individual sections (SOC/ISO)
- **Custom Login** — Username/password authentication via Apache Basic Auth

**No persistent chat history.** This toolkit is typically accessed from a stateless Citrix environment, where the browser profile (and anything in `localStorage`) is reset on every session. Persistent chat storage was removed rather than left in a broken state — conversations exist only within the current session, same as the follow-up context above.

## Architecture

```
Browser  →  Apache (:8080)  →  llama.cpp server (:8081)
            Basic Auth          Qwen 3.6 35B-A3B MoE
            Reverse Proxy       + Vision projector
            SSE Streaming       CPU inference
```

## Requirements

| Component | Spec                              |
| --------- | ---------------------------------- |
| OS        | RHEL 10 (or compatible)           |
| RAM       | 64 GB minimum                     |
| Disk      | 100 GB on /data                   |
| Network   | Offline (no internet required)    |
| GPU       | Not required (CPU-only inference) |

## Quick Start

### 1. Download (on a PC with internet)

| File                              | Source                                                                                | Size    |
| ---------------------------------- | -------------------------------------------------------------------------------------- | ------- |
| `llama.cpp` source                 | [GitHub](https://github.com/ggml-org/llama.cpp) → tagged release → Download ZIP        | ~50 MB  |
| `Qwen3.6-35B-A3B-MXFP4_MOE.gguf`   | [unsloth/Qwen3.6-35B-A3B-GGUF](https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF)   | ~21 GB  |
| `mmproj-F16.gguf`                  | Same repo (for vision support) — must match the model version, not interchangeable    | ~900 MB |
| `pdf.min.mjs` + `pdf.worker.min.mjs`   | Included in `frontend/` (PDF.js 4.0.379) — only re-download from [PDF.js releases](https://github.com/mozilla/pdf.js/releases) if you want a newer build | ~1.4 MB |
| `lolbas.json`                      | Included in `frontend/` (snapshot for the Living Off The Land Naslag tab) — re-download from [lolbas-project.github.io/api/lolbas.json](https://lolbas-project.github.io/api/lolbas.json) for a fresher snapshot | ~430 KB |

### 2. Upload to server

```
scp llama.cpp-source.zip user@SERVER:/data/toolkit/
scp Qwen3.6-35B-A3B-MXFP4_MOE.gguf user@SERVER:/data/toolkit/
scp mmproj-F16.gguf user@SERVER:/data/toolkit/
scp deploy-jeffrey-v1.0.sh user@SERVER:/data/toolkit/
scp jeffrey-v1.0.html user@SERVER:/data/toolkit/
scp xlsx.full.min.js user@SERVER:/data/toolkit/
scp pdf.min.mjs pdf.worker.min.mjs user@SERVER:/data/toolkit/
scp lolbas.json user@SERVER:/data/toolkit/
```

### 3. Deploy

```
sudo bash /data/toolkit/deploy-jeffrey-v1.0.sh
```

The script handles everything: cleanup of old installations, compiling llama.cpp from source (CMake), model + vision projector setup, Apache reverse proxy with Basic Auth, SELinux, firewall, and systemd service creation.

> **Note:** this script (in `archief/`) was written for the original 16384-context, PDF-less setup. It still works for a fresh install, but after deploying, apply the current production settings manually: increase `--ctx-size` to 32768 and add `--batch-size 1024 --ubatch-size 2048` to the systemd override (see `docs/NASLAG.md`), and copy `pdf.min.mjs` / `pdf.worker.min.mjs` / `lolbas.json` from `frontend/` alongside the HTML for PDF support and the Living Off The Land Naslag tab (the script does not copy these).

## File Structure (after deployment)

```
/data/
├── toolkit/
│   ├── index.html                          # Active HTML (served by Apache)
│   ├── jeffrey-v1.0.html                   # HTML source / staging copy
│   ├── xlsx.full.min.js                    # Excel parsing (SheetJS)
│   ├── pdf.min.mjs                         # PDF text extraction (PDF.js)
│   ├── pdf.worker.min.mjs                  # PDF.js worker
│   ├── lolbas.json                         # LOLBAS data snapshot (Living Off The Land Naslag tab)
│   └── deploy-jeffrey-v1.0.sh               # Deploy script
├── models/
│   ├── Qwen3.6-35B-A3B-MXFP4_MOE.gguf     # Main model (~21 GB)
│   └── mmproj-F16.gguf                     # Vision projector (~900 MB)
├── scripts/
│   ├── update-model.sh                     # Reusable model-update script
│   └── README.md                           # Update instructions
/opt/llama-server/
│   └── llama-server                         # Compiled binary
/etc/httpd/conf.d/jeffrey.conf               # Apache config
/etc/systemd/system/llama-server.service
/etc/systemd/system/llama-server.service.d/override.conf
```

## Management

```
# Services
systemctl status llama-server
journalctl -u llama-server -f          # note: this service logs to /var/log/llama-server.log, not journald
tail -f /var/log/llama-server.log      # actual runtime logs, including per-request timing

# Users
htpasswd /etc/httpd/.htpasswd <username>          # Add
htpasswd -D /etc/httpd/.htpasswd <username>        # Remove

# Restart after config change
sudo systemctl restart llama-server
```

### Updating the model

A reusable, tested update script lives in `/data/scripts/` on the server (configuration block at the top, run with `sudo bash update-model.sh`). See `docs/NASLAG.md` for background and the full procedure.

## Current Model

| Property       | Value                                        |
| -------------- | --------------------------------------------- |
| Model          | Qwen 3.6 35B-A3B Instruct                    |
| Architecture   | Mixture-of-Experts (~3B active of 35B total) |
| Quantization   | MXFP4\_MOE (Unsloth)                         |
| Vision         | Yes (via mmproj-F16, version-matched)        |
| Size (main)    | ~21 GB                                       |
| Size (mmproj)  | ~900 MB                                      |
| RAM usage      | ~12–16 GB (varies; MoE + mmap keeps this lower than the full weight size) |
| Context window | 32768 tokens                                 |
| Batch size     | 1024 (`--batch-size`)                        |
| Micro-batch    | 2048 (`--ubatch-size`, the flag that actually affects prompt-processing speed on CPU) |
| License        | Apache 2.0                                   |

Context window was doubled from the original 16384 after confirming (via community reports and this MoE architecture's low KV-cache growth) that the RAM cost of a larger context is minimal — a few hundred MB, not gigabytes.

## Performance (CPU-only, 64GB RAM)

| Query type                          | Expected time |
| ------------------------------------ | ------------- |
| Simple question                      | 5-15 sec      |
| SIEM query                           | 15-30 sec     |
| SOAR / Sigma / Network               | 30-90 sec     |
| Single screenshot analysis           | 30-90 sec     |
| Multiple images + document together  | Several minutes — most of the time is spent in vision-encoder prompt processing, not answer generation. This is CPU-only cost, not a bug; a GPU would reduce this substantially. |
| Policy document (ISO)                | 1-3 min       |
| Risk analysis (ISO)                  | 1-2 min       |

## Known behavior

- **The model can hallucinate on specific facts** — most notably CVE details (wrong vendor/product for a given CVE number). This is inherent to how language models work, not something a configuration change fixes. For anything requiring verified accuracy (CVE details, CVSS scores), treat the model as a starting point and confirm against an authoritative source (e.g. nvd.nist.gov).
- **No knowledge of events after the model's training cutoff** — recent CVEs or advisories won't be known to the model, and it won't always say so explicitly.
- **Vision processing is CPU-bound and slow relative to text** — expect multi-minute waits for multiple images combined with documents. See Performance table above.

## Repository Contents

```
├── README.md                    # This document
├── jeffrey-v1.0.html            # (root copy, also under frontend/)
frontend/
├── index.html                   # (server copy, kept for reference — not auto-deployed from here)
├── jeffrey-v1.0.html            # HTML source
├── xlsx.full.min.js             # SheetJS library (Apache 2.0)
├── pdf.min.mjs                  # PDF.js 4.0.379 (Apache 2.0)
├── pdf.worker.min.mjs           # PDF.js worker
└── lolbas.json                  # LOLBAS project data snapshot (used by the Living Off The Land Naslag tab)
docs/
└── NASLAG.md                    # Background: architecture, file layout, terminology, model-update procedure
archief/
├── deploy-jeffrey-v1.0.sh       # Fresh-install deployment script
└── upgrade-llamacpp.sh          # In-place llama.cpp recompilation for updates
.gitignore                       # Excludes GGUF models, builds, credentials
```

Note: `pdf.min.mjs` and `pdf.worker.min.mjs` (PDF.js 4.0.379, ~1.4 MB combined) are included in `frontend/`. This is an older but confirmed-working build; a newer PDF.js release can be substituted if tested against the real browser environment first (headless Node.js testing proved unreliable for verifying newer builds due to missing browser-only APIs).

Note: `lolbas.json` (~430 KB, 242 entries) is a snapshot of the [LOLBAS project](https://lolbas-project.github.io/) data, used entirely client-side by the Living Off The Land Naslag tab — no backend, no AI interpretation. It's a reference snapshot rather than a live feed; re-download periodically from the source above if you want the latest entries.

## Disclaimers

Jeffrey is a personal/test project. It is not an officially supported production service. Generated content (policies, risk analyses, advisory notes, detection rules) should always be reviewed before use. AI assistance is not a replacement for professional judgment.

## License

This toolkit is provided as-is for internal SOC/ISO use. The Qwen 3.6 model is licensed under Apache 2.0.

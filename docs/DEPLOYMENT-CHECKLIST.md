# Jeffrey Toolkit — Deployment Checklist

Use this checklist for a new deployment or a major upgrade. It is intentionally generic.

## Before installation

- [ ] Target OS/version documented
- [ ] CPU/RAM/GPU documented
- [ ] Storage capacity documented
- [ ] Model and quantization selected
- [ ] Model license verified
- [ ] llama.cpp version/build documented
- [ ] Vision projector requirement verified
- [ ] Network path documented
- [ ] Client source network documented
- [ ] Management source network documented
- [ ] Monitoring source network documented
- [ ] Egress policy documented
- [ ] Backup location available

## Runtime

- [ ] Dedicated service account exists
- [ ] Model files are readable by the service
- [ ] Model files are not writable by the service
- [ ] Model API binds to localhost where possible
- [ ] systemd hardening tested
- [ ] Logs configured
- [ ] Health endpoint works
- [ ] Reverse proxy configuration validates
- [ ] Authentication works
- [ ] Directory listing disabled
- [ ] Firewall rules applied
- [ ] Direct model API access from client network blocked

## Functional regression

- [ ] Login
- [ ] Simple chat
- [ ] Follow-up context
- [ ] Streaming
- [ ] Stop generation
- [ ] Text attachments
- [ ] JSON/YAML
- [ ] Excel
- [ ] PDF
- [ ] Images/vision
- [ ] SOAR
- [ ] Sigma
- [ ] Network detection
- [ ] Forensics
- [ ] Trigger tester
- [ ] LOLBAS
- [ ] ISO tools

Only mark an item complete after testing it in the target browser/network environment.

## Rollback

- [ ] Current configuration backed up
- [ ] Previous model retained until validation completes
- [ ] Previous service configuration retained
- [ ] Previous reverse-proxy configuration retained
- [ ] Firewall rollback documented
- [ ] Rollback executed successfully in a test

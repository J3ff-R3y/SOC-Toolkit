#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m py_compile \
  "$ROOT"/src/gateway/*.py \
  "$ROOT"/src/gateway/utilities/*.py \
  "$ROOT"/src/gateway/validators/*.py \
  "$ROOT"/src/gateway/forensics/*.py \
  "$ROOT"/src/rag/*.py \
  "$ROOT"/src/update/*.py \
  "$ROOT"/src/benchmark/*.py
python3 - <<'PY' "$ROOT"
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for p in list((root/'schemas').glob('*.json')) + list((root/'config').glob('*.json')):
    json.loads(p.read_text(encoding='utf-8'))
print('JSON parse: OK')
PY
echo 'Python compile: OK'

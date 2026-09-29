# Model benchmarking

The benchmark tooling establishes a reproducible baseline before model/routing decisions.

The included corpus covers short chat, SOC reasoning and structured Sigma/YARA/Suricata/Zeek generation. Raw run evidence should be retained alongside summaries.

Measure at least:

- wall-clock latency;
- streaming first-data latency where available;
- success/failure HTTP status;
- structured validator acceptance;
- repeatability across repeated runs;
- semantic SOC reasoning quality through a documented review rubric.

A second model should not become routable merely because it exists on disk. It should pass the same benchmark/quality checks and a separate capacity/fallback regression first.

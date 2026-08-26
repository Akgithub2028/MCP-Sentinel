# External Benchmark Datasets & Community Test Corpus

This directory houses external, third-party, and community-contributed MCP security benchmark datasets.

## Ground-Truth Provenance & Labeling Methodology

All benchmark cases in this repository are curated with strict binary ground-truth labels (`is_vulnerable: true | false`):

1. **Vulnerable Test Cases (`is_vulnerable: true`)**:
   - Explicit prompt injection payloads (direct or indirect) embedded in tool descriptions
   - Toxic parameter instructions targeting exfiltration endpoints (`https://...`)
   - Unicode homoglyph collisions mimicking standard system utilities
   - Confused deputy directives harvesting environment variables (`$HOME/.ssh`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `CANARY_KEY`)
   - Unconstrained schemas enabling arbitrary command injection or code execution
   - Annotation mismatches (claiming `readOnly: true` while executing write/delete operations)

2. **Clean / Safe Baselines (`is_vulnerable: false`)**:
   - Standard production tool descriptions without instruction overrides
   - Mathematical, formatting, encoding, and conversion utilities
   - Edge cases containing security terminology without malicious instructions (e.g. token format validators)

## Sample Benchmark Dataset

See [`sample_community_benchmark.json`](./sample_community_benchmark.json) for a reference dataset containing both vulnerable attack patterns and benign baselines.

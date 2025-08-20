# False Positive Testing Suite (v0.1.3)

Purpose:
- Maintain a <2% false positive rate on benign prompts using smart matching
- Provide a reproducible benchmark with zero external dependencies
- Enable community-driven reporting of false positives

Definition (strict):
- A false positive occurs when the scanner’s risk_level != "SAFE" for a benign sample.

Dataset:
- Curated: [datasets/false_positives/curated.jsonl](datasets/false_positives/curated.jsonl)
- Community: [datasets/false_positives/community.jsonl](datasets/false_positives/community.jsonl)
- Format: JSONL (one JSON object per line). Comments allowed only in community.jsonl lines starting with '#'.
- Schema: [docs/false_positive_schema.json](docs/false_positive_schema.json)

Run the benchmark:
- Curated only:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl

- Curated + Community:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --include-community

- JSON output (for automation):
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --json

- Adjust threshold:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --threshold 0.01

- Quick run (limit samples):
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --limit 5

Expected output:
- Human-readable:
  === False Positive Benchmark ===
  Dataset: datasets/false_positives/curated.jsonl
  Total benign samples: 15
  False positives:      X
  False Positive Rate:  Y.YY%  — PASS (target ≤ 2.0%)
  Top categories contributing to FPs:
    - prompt_injection: 2
    - jailbreak: 1
  Top patterns associated with FPs:
    - ignore previous instructions: 2

- JSON:
  {"total":15,"false_positives":X,"false_positive_rate":0.YY,"threshold":0.02,"pass":true,"top_categories":[["prompt_injection",2]],"top_patterns":[["ignore previous instructions",2]]}

Troubleshooting:
- ImportError for AIThreatScanner: Run from repo root so [examples/false_positive_benchmark.py](examples/false_positive_benchmark.py) can import [src/scanner.py](src/scanner.py).
- JSON decode errors: Check for trailing commas, ensure one JSON object per line. Comments are only allowed in [datasets/false_positives/community.jsonl](datasets/false_positives/community.jsonl) and must start with '#'.
- High FP rate: Inspect “Top categories/patterns” and open an issue or PR with minimal reproducer.

Contributing false positives:
- Preferred: Open a PR adding entries to [datasets/false_positives/community.jsonl](datasets/false_positives/community.jsonl)
- Alternative: Open an issue with a single-line JSON object following [docs/false_positive_schema.json](docs/false_positive_schema.json)
- Submissions must be benign, reproducible, and non-sensitive. By contributing, you assert rights to share under the repo’s LICENSE.

Manual schema checks (stdlib-only):
- Quick parse:
  python3 -c "import sys,json; [json.loads(l) for l in sys.stdin if l.strip() and not l.lstrip().startswith('#')]; print('OK')" < datasets/false_positives/curated.jsonl
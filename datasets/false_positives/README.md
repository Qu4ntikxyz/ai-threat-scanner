# AI Threat Scanner — False Positives Dataset

This directory hosts benign prompts and texts that are commonly misclassified as threats by naive pattern matchers. It enables a reproducible false positive (FP) benchmark with the goal of maintaining <2% FP rate in smart-matching mode.

Files:
- curated.jsonl — Maintainer-curated, high-quality benign examples
- community.jsonl — Community-submitted benign examples (triaged gradually)

Format:
- JSON Lines (JSONL): one JSON object per line
- Required fields:
  - id: string (e.g., "fp-edu-001")
  - text: string (benign content; expected NOT to be flagged)
  - context_type: one of ["user_input","llm_response","educational","research","code_block","documentation"]
  - source: one of ["curated","community","dataset","reddit","paper","internal"]
  - tags: array of strings (e.g., ["meta_discussion","prompt_injection_talk"])
  - expected: object, minimally {"safe": true}
- Optional:
  - notes: string (why this is benign / context explanation)

False Positive Definition:
- A false positive occurs when the scanner’s risk_level != "SAFE" for a dataset record when run with smart_matching=True.

Schema and Contribution:
- See the JSON Schema: [docs/false_positive_schema.json](docs/false_positive_schema.json)
- Contribution process: [CONTRIBUTING.md](CONTRIBUTING.md) (“False Positive Submissions” section)
- Please ensure examples are benign, reproducible, and non-sensitive. By contributing, you assert you have the right to share the text under the repository’s license.

Validation (manual, stdlib only):
- Quick parse check:
  python3 -c "import sys,json; [json.loads(l) for l in sys.stdin if l.strip() and not l.lstrip().startswith('#')]; print('OK')" < datasets/false_positives/curated.jsonl

License:
- Contributions are provided under the repository’s LICENSE unless otherwise specified in the submission.
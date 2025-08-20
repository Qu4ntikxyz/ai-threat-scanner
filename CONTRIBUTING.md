
## False Positive Submissions

We welcome community contributions to improve our false positive (FP) rate. A false positive is any benign prompt that the scanner classifies with a risk_level other than "SAFE" in smart matching mode.

Two ways to contribute:
1. Open a PR adding entries to [datasets/false_positives/community.jsonl](datasets/false_positives/community.jsonl)
2. Open a GitHub Issue with a single-line JSON object payload following [docs/false_positive_schema.json](docs/false_positive_schema.json)

Guidelines:
- Only submit benign, reproducible, and non-sensitive text.
- One JSON object per line (JSONL). No trailing commas.
- In community.jsonl, lines starting with '#' are treated as comments and ignored by parsers.
- Use fields: id, text, context_type, source, tags, expected. Optional: notes.
- Context types: "user_input","llm_response","educational","research","code_block","documentation"
- Example (remove the leading '#'):
  # {"id":"fp-comm-042","text":"Explain why \"DAN mode\" is unsafe in production without demonstrating it.","context_type":"educational","source":"community","tags":["meta_discussion","jailbreak_history"],"notes":"Benign explanatory content.","expected":{"safe":true}}

Manual validation (stdlib only):
- Quick parse:
  python3 -c "import sys,json; [json.loads(l) for l in sys.stdin if l.strip() and not l.lstrip().startswith('#')]; print('OK')" &lt; datasets/false_positives/community.jsonl

Benchmarking:
- Run FP benchmark on curated set:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl
- Include community samples:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --include-community

License:
- By contributing, you affirm you have rights to the text and license it under the repository’s LICENSE.
#!/usr/bin/env python3
"""
False Positive Benchmark for AI Threat Scanner (v0.1.3)

Purpose:
- Benchmark the scanner against a curated set of benign prompts
- Compute strict false positive rate (FP = risk_level != "SAFE")
- Target: FP rate < 2% by default (configurable with --threshold)

Usage:
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --include-community
  python3 examples/false_positive_benchmark.py --dataset datasets/false_positives/curated.jsonl --json

Notes:
- Zero external dependencies; JSONL parsing is via stdlib only.
- Commented lines starting with '#' are ignored to support community.jsonl comments.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple, Any

# Ensure repository root (containing 'src/') is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# Prefer direct module access per project architecture
try:
    from src.scanner import AIThreatScanner  # type: ignore
except Exception as e:
    sys.stderr.write(
        "ImportError: Unable to import AIThreatScanner from src.scanner. "
        "Ensure you're running from the repository root.\n"
        f"Details: {e}\n"
    )
    sys.exit(1)


def load_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.lstrip().startswith("#"):
                continue
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError as je:
                sys.stderr.write(f"JSON decode error in {path}: {je}\n")
                continue


def build_context_hint(context_type: str, record: Dict[str, Any]) -> str:
    # Lightweight hint passed to scanner context parameter without changing core logic
    tags = record.get("tags", [])
    tag_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
    return f"context_type={context_type}; tags=[{tag_str}]"


def get_risk_level(result: Any) -> str:
    # Accommodate different possible shapes of the scanner result
    if isinstance(result, dict):
        rl = (
            result.get("risk_level")
            or result.get("riskLevel")
            or (result.get("risk") or {}).get("level")
        )
        if rl:
            return str(rl).upper()
    # Fallback: attempt attribute access
    rl = getattr(result, "risk_level", None)
    if rl:
        return str(rl).upper()
    # Final fallback: consider SAFE if unknown
    return "UNKNOWN"


def iter_threats(result: Any) -> Iterator[Dict[str, Any]]:
    # Attempt to yield threat items for aggregation if present
    candidates = None
    if isinstance(result, dict):
        candidates = (
            result.get("threats")
            or result.get("details")
            or (result.get("result") or {}).get("threats")
        )
    if candidates and isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict):
                yield item


def aggregate_errors(results: List[Tuple[Dict[str, Any], Any]]) -> Tuple[Counter, Counter]:
    cat_counter: Counter = Counter()
    pattern_counter: Counter = Counter()
    for rec, res in results:
        for item in iter_threats(res):
            cat = item.get("category") or item.get("type") or "unknown"
            cat_counter[cat] += 1
            pat = item.get("pattern") or item.get("pattern_text") or item.get("keyword")
            if pat:
                pattern_counter[str(pat)] += 1
    return cat_counter, pattern_counter


def run_benchmark(
    curated_path: Path,
    include_community: bool = False,
    threshold: float = 0.02,
    output_json: bool = False,
    limit: int = 0,
) -> int:
    community_path = curated_path.parent / "community.jsonl"
    records: List[Dict[str, Any]] = list(load_jsonl(curated_path))
    if include_community:
        records += list(load_jsonl(community_path))

    if not records:
        sys.stderr.write("No dataset records found. Aborting.\n")
        return 2

    if limit and limit > 0:
        records = records[:limit]

    scanner = AIThreatScanner(verbose=False, smart_matching=True)  # type: ignore

    total = 0
    fp = 0
    erroneous: List[Tuple[Dict[str, Any], Any]] = []

    for rec in records:
        total += 1
        text = rec.get("text", "")
        ctx_type = rec.get("context_type", "user_input")
        context_hint = build_context_hint(ctx_type, rec)

        try:
            result = scanner.scan_prompt(str(text), str(context_hint))  # type: ignore
        except Exception as e:
            sys.stderr.write(f"Error scanning record id={rec.get('id')}: {e}\n")
            fp += 1  # conservative: count as FP since expected SAFE
            erroneous.append((rec, {"error": str(e)}))
            continue

        risk_level = get_risk_level(result)
        is_fp = (risk_level != "SAFE")
        if is_fp:
            fp += 1
            erroneous.append((rec, result))

    rate = (fp / total) if total else 0.0
    passed = rate <= threshold  # inclusive pass on exact threshold

    cats, pats = aggregate_errors(erroneous)

    summary = {
        "total": total,
        "false_positives": fp,
        "false_positive_rate": rate,
        "threshold": threshold,
        "pass": passed,
        "top_categories": cats.most_common(5),
        "top_patterns": pats.most_common(5),
    }

    if output_json:
        print(json.dumps(summary, ensure_ascii=False))
    else:
        print("=== False Positive Benchmark ===")
        print(f"Dataset: {curated_path}")
        if include_community:
            print(f"+ Community: {community_path}")
        print(f"Total benign samples: {total}")
        print(f"False positives:      {fp}")
        print(f"False Positive Rate:  {rate*100:.2f}%  — {'PASS' if passed else 'FAIL'} (target ≤ {threshold*100:.1f}%)")
        if erroneous:
            print("\nTop categories contributing to FPs:")
            for cat, c in summary["top_categories"]:
                print(f"  - {cat}: {c}")
            if summary["top_patterns"]:
                print("Top patterns associated with FPs:")
                for pat, c in summary["top_patterns"]:
                    print(f"  - {pat}: {c}")

    # Exit code: 0 on pass, 2 on fail (non-zero for CI integration)
    return 0 if passed else 2


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="False Positive Benchmark for AI Threat Scanner")
    p.add_argument(
        "--dataset",
        required=True,
        help="Path to curated JSONL dataset (e.g., datasets/false_positives/curated.jsonl)",
    )
    p.add_argument(
        "--include-community",
        action="store_true",
        help="Also include community.jsonl from the same directory as the curated dataset",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary instead of human-readable text",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.02,
        help="False positive threshold (default 0.02 = 2%)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of samples processed (0 = no limit)",
    )
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    curated_path = Path(args.dataset)
    return run_benchmark(
        curated_path=curated_path,
        include_community=args.include_community,
        threshold=args.threshold,
        output_json=args.json,
        limit=args.limit,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
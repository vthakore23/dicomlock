"""CLI for the benchmark engine.

  python -m bench               run the full corpus, print the report, write bench/results.json
  python -m bench --json-only   just write the JSON artifact
"""

import argparse
import json
import os
import tempfile

from bench import corpus, evaluate, report

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(prog="bench", description="DicomLock CDR efficacy benchmark")
    ap.add_argument("--out", default=os.path.join(HERE, "results.json"),
                    help="where to write the JSON artifact")
    ap.add_argument("--json-only", action="store_true", help="suppress the markdown report")
    ap.add_argument("--skip-scale", action="store_true",
                    help="skip the large real-CT (data/tcia_ct) scan-only false-positive pass")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="dicomlock-bench-") as tmp:
        entries = corpus.load_all() + corpus.load_generated()
        gen_n = len(corpus.load_generated())
        if gen_n:
            print(f"including {gen_n} adversarial generated files (samples/generated/)...")
        results = evaluate.evaluate_all(tmp, entries)

    if not args.skip_scale:
        real_cts = corpus.load_real_cts()
        if real_cts:
            print(f"scaling false-positive check over {len(real_cts)} real CTs (scan-only)...")
            results += evaluate.scan_only(real_cts)

    summary = report.summarize(results)

    if not args.json_only:
        print(report.render_markdown(summary))

    with open(args.out, "w") as f:
        json.dump({"summary": summary, "results": results}, f, indent=2)
    print(f"artifact: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

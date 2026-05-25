"""Aggregate per-file results into the study's metrics and render them."""

from collections import defaultdict


def summarize(results):
    tampered = [r for r in results if not r["benign"]]
    benign = [r for r in results if r["benign"]]
    danger = [r for r in tampered if r["intrinsic_danger"]]
    real_ct = [r for r in benign if r["attack_class"] == "real_ct"]

    detected = sum(r["detected"] for r in tampered)
    fps = sum(r["false_positive"] for r in benign)
    neut = sum(1 for r in danger if r["neutralized"])
    blocked_tampered = [r for r in tampered if r["dl_verdict"] == "block"]
    accepted_by_all = sum(1 for r in blocked_tampered if r["toolkits_accept"])

    fid_applicable = [r for r in results if r["fidelity"] in ("bit-exact", "CHANGED")]
    fid_exact = sum(1 for r in fid_applicable if r["fidelity"] == "bit-exact")

    # --- falsification: the failures we are hunting ---
    scanner_misses = [{"name": r["name"], "class": r["attack_class"],
                       "expected": r["expected_verdict"], "got": r["dl_verdict"]}
                      for r in tampered if not r["detected"]]
    cdr_escapes = [{"name": r["name"], "class": r["attack_class"], "cdr": r["cdr_action"]}
                   for r in tampered if r["intrinsic_danger"] and r["neutralized"] is False]
    fidelity_breaks = [{"name": r["name"], "class": r["attack_class"]}
                       for r in results if r["fidelity"] == "CHANGED"]
    fp_files = [{"name": r["name"], "class": r["attack_class"]}
                for r in benign if r["false_positive"]]

    by_class = defaultdict(lambda: {"n": 0, "detected": 0, "neut": 0, "neut_n": 0})
    for r in tampered:
        c = by_class[r["attack_class"]]
        c["n"] += 1
        c["detected"] += int(r["detected"])
        if r["intrinsic_danger"]:
            c["neut_n"] += 1
            c["neut"] += int(bool(r["neutralized"]))

    return {
        "targets": _targets(),
        "n_benign": len(benign),
        "n_tampered": len(tampered),
        "benign_breakdown": {"curated_samples": len(benign) - len(real_ct),
                             "real_ct_scan_only": len(real_ct)},
        "detection": [detected, len(tampered)],
        "false_positives": [fps, len(benign)],
        "neutralization": [neut, len(danger)],
        "fidelity_bit_exact": [fid_exact, len(fid_applicable)],
        "differentiation_accepted_by_all_targets": [accepted_by_all, len(blocked_tampered)],
        "by_class": {k: dict(v) for k, v in sorted(by_class.items())},
        "failures": {
            "scanner_misses": scanner_misses,
            "cdr_escapes": cdr_escapes,
            "fidelity_breaks": fidelity_breaks,
            "false_positives": fp_files,
        },
    }


def _targets():
    from bench import targets
    return targets.TARGET_NAMES


def _pct(pair):
    n, d = pair
    return f"{n}/{d}" + (f" ({100*n//d}%)" if d else "")


def render_markdown(summary):
    L = []
    L.append("# DicomLock benchmark results\n")
    bb = summary.get("benign_breakdown", {})
    benign_note = (f"{summary['n_benign']} "
                   f"({bb.get('curated_samples', summary['n_benign'])} curated"
                   + (f" + {bb['real_ct_scan_only']} real CTs, scan-only"
                      if bb.get('real_ct_scan_only') else "") + ")")
    L.append(f"Targets: {', '.join(summary['targets'])}  |  "
             f"benign: {benign_note}  |  tampered: {summary['n_tampered']}\n")
    L.append("| Metric | Result |")
    L.append("|--------|--------|")
    L.append(f"| Detection (tampered flagged as expected) | {_pct(summary['detection'])} |")
    L.append(f"| False positives (benign blocked) | {_pct(summary['false_positives'])} |")
    L.append(f"| Neutralization (dangerous inputs made safe by CDR) | {_pct(summary['neutralization'])} |")
    L.append(f"| Fidelity (disarmed pixels bit-exact) | {_pct(summary['fidelity_bit_exact'])} |")
    L.append(f"| Differentiation (DicomLock-flagged files the other toolkits accept) | "
             f"{_pct(summary['differentiation_accepted_by_all_targets'])} |")
    L.append("\n## By attack class\n")
    L.append("| Attack class | n | Detected | Neutralized |")
    L.append("|--------------|---|----------|-------------|")
    for cls, c in summary["by_class"].items():
        neut = f"{c['neut']}/{c['neut_n']}" if c["neut_n"] else "n/a"
        L.append(f"| {cls} | {c['n']} | {c['detected']}/{c['n']} | {neut} |")

    f = summary.get("failures", {})
    L.append("\n## Failures hunted (the falsification result)\n")
    any_fail = False
    for label, items, sev in [
        ("CDR escapes (dangerous, NOT neutralized)", f.get("cdr_escapes", []), "CRITICAL"),
        ("False positives (benign blocked)", f.get("false_positives", []), "high"),
        ("Fidelity breaks (CDR altered pixels)", f.get("fidelity_breaks", []), "high"),
        ("Scanner misses (expected-flag not raised)", f.get("scanner_misses", []), "review"),
    ]:
        if items:
            any_fail = True
            L.append(f"- **{label}: {len(items)}** [{sev}]")
            for it in items[:20]:
                extra = it.get("got", "") and f" (expected {it.get('expected')}, got {it.get('got')})"
                L.append(f"    - `{it['name']}` [{it.get('class','')}]" + (extra or ""))
        else:
            L.append(f"- {label}: 0")
    if not any_fail:
        L.append("\nNo failures found on this corpus. That is a result to distrust until the corpus is "
                 "hard enough — scale it and add the pinned vulnerable codec before believing it.")
    return "\n".join(L) + "\n"

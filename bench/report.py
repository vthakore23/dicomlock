"""Aggregate per-file results into the study's metrics and render them."""

import math
from collections import defaultdict


def _wilson(k, n, z=1.96):
    """Wilson score 95% confidence interval for a proportion. Returns (point, low, high).

    Better than the normal approximation at the extremes (k=n or k=0), which is exactly where a
    detection/neutralization study lives. Dependency-free."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (p, max(0.0, center - half), min(1.0, center + half))


def _rule_of_three_upper(n, conf=0.95):
    """One-sided upper bound on a rate when zero events were observed in n trials.

    The 'rule of three' (≈3/n at 95%): if 0/n failed, the true rate is below this with `conf`
    confidence. The honest way to report a 0/N false-positive or 0/N escape result."""
    if n == 0:
        return 1.0
    return min(1.0, -math.log(1 - conf) / n)


def _mcnemar(b, c):
    """Continuity-corrected McNemar test (1 dof) for two paired binary classifiers on the same
    files. b, c are the discordant counts. Returns (chi2, p). p uses erfc (no scipy)."""
    if b + c == 0:
        return (0.0, 1.0)
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    return (chi2, math.erfc(math.sqrt(chi2 / 2)))


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

    # --- paired comparison: DicomLock vs the parser matrix (McNemar) ---
    # Restrict to tampered files the parsers actually executed: exclude DoS bombs we pre-identified
    # and never ran raw (there the parser "outcome" is our protection, not the parser's own verdict).
    ran = [r for r in tampered if r.get("raw_outcomes")
           and not all(str(v).startswith("dos") for v in r["raw_outcomes"].values())]
    # "positive" = the system flagged the file as problematic. For DicomLock that is any non-clean
    # verdict (block OR warn — a warn is still a raised flag); for the parsers it is "not every
    # present parser accepted it cleanly". Crediting a DicomLock warn to the parser (e.g. a J2K file
    # a parser simply cannot decode) would overcount the parsers, so we count it for DicomLock.
    mc_b = sum(1 for r in ran if r["dl_verdict"] != "clean" and r["toolkits_accept"])
    mc_c = sum(1 for r in ran if r["dl_verdict"] == "clean" and not r["toolkits_accept"])
    mc_chi2, mc_p = _mcnemar(mc_b, mc_c)

    stats = {
        "detection_ci": _wilson(detected, len(tampered)),
        "neutralization_ci": _wilson(neut, len(danger)),
        "fidelity_ci": _wilson(fid_exact, len(fid_applicable)),
        "false_positive_ci": _wilson(fps, len(benign)),
        "false_positive_upper95": _rule_of_three_upper(len(benign)) if fps == 0 else None,
        "mcnemar": {"n": len(ran), "b_dicomlock_only": mc_b, "c_parsers_only": mc_c,
                    "chi2": mc_chi2, "p": mc_p},
    }

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
        "stats": stats,
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


def _ci(triple):
    """Format a (point, low, high) proportion triple as a 95% CI string."""
    _, lo, hi = triple
    return f"{100*lo:.1f}–{100*hi:.1f}%"


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
    st = summary.get("stats", {})
    L.append("| Metric | Result | 95% CI (Wilson) |")
    L.append("|--------|--------|-----------------|")
    L.append(f"| Detection (tampered flagged as expected) | {_pct(summary['detection'])} | "
             f"{_ci(st['detection_ci']) if st else ''} |")
    fp_ci = (f"≤ {100*st['false_positive_upper95']:.2f}% (rule of three)"
             if st and st.get("false_positive_upper95") is not None else (_ci(st['false_positive_ci']) if st else ""))
    L.append(f"| False positives (benign blocked) | {_pct(summary['false_positives'])} | {fp_ci} |")
    L.append(f"| Neutralization (dangerous inputs made safe by CDR) | "
             f"{_pct(summary['neutralization'])} | {_ci(st['neutralization_ci']) if st else ''} |")
    L.append(f"| Fidelity (disarmed pixels bit-exact) | {_pct(summary['fidelity_bit_exact'])} | "
             f"{_ci(st['fidelity_ci']) if st else ''} |")
    L.append(f"| Differentiation (DicomLock-flagged files the other toolkits accept) | "
             f"{_pct(summary['differentiation_accepted_by_all_targets'])} | |")

    if st and st.get("mcnemar"):
        m = st["mcnemar"]
        L.append("\n## Statistical confidence\n")
        L.append("Confidence intervals are Wilson score (95%); a 0-event rate is reported as a "
                 "one-sided 95% upper bound (rule of three). The parser comparison is McNemar's "
                 "paired test.\n")
        p_str = "< 1e-6" if m["p"] < 1e-6 else f"{m['p']:.2g}"
        L.append(f"**DicomLock vs the parser matrix** ({', '.join(summary['targets'])}), on the "
                 f"{m['n']} tampered files the parsers actually executed (a flag = a non-clean "
                 f"DicomLock verdict, or a parser not accepting the file cleanly): DicomLock "
                 f"flagged {m['b_dicomlock_only']} files every parser accepted as valid; "
                 f"{m['c_parsers_only']} files DicomLock passed as clean were not accepted by some "
                 f"parser. McNemar χ² = {m['chi2']:.1f}, p = {p_str}.")

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

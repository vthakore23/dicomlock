"""Labeled corpus for the benchmark.

Each entry carries an attack class and the verdict DicomLock is expected to reach, so the
evaluator can score detection per class. Labels are derived from filename, so adding a new
fixture to samples/tampered/ (via make_tampered_corpus.py) is picked up automatically as long
as its name matches a rule below.

expected_verdict:
  block  DicomLock should raise a blocking finding (fail/critical)
  warn   DicomLock should flag exposure (codec-CVE / preamble entropy) without blocking
  clean  benign file, should pass
"""

import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
TAMPERED_DIR = os.path.join(PROJECT, "samples", "tampered")
BENIGN_DIR = os.path.join(PROJECT, "samples")
GENERATED_DIR = os.path.join(PROJECT, "samples", "generated")
# Large real-world benign set: 575 TCIA clinical CTs. Lives under data/ (gitignored), so it is
# present locally but absent on a fresh clone — load_real_cts() degrades to [] in that case.
REAL_CT_DIR = os.path.join(PROJECT, "data", "tcia_ct")

# (filename substring, (attack_class, expected_verdict)) — first match wins.
_RULES = [
    ("bad_magic",        ("malformed_header", "block")),
    ("deep_nesting",     ("nesting_bomb", "block")),
    ("length_bomb",      ("length_bomb", "block")),
    ("pixel_decompress", ("decompression_bomb", "block")),
    ("pixel_dimension",  ("dimension_bomb", "block")),
    ("polyglot",         ("polyglot", "block")),
    ("private_payload",  ("private_payload", "block")),
    ("high_entropy",     ("preamble_anomaly", "warn")),
    ("deflated",         ("codec_exposure", "warn")),
    ("htj2k",            ("codec_exposure", "warn")),
    ("jpip",             ("codec_exposure", "warn")),
    ("video_",           ("codec_exposure", "warn")),
]


class Entry:
    def __init__(self, path, attack_class, expected_verdict, benign):
        self.path = path
        self.name = os.path.basename(path)
        self.attack_class = attack_class
        self.expected_verdict = expected_verdict
        self.benign = benign
        # intrinsic_danger = a CDR target (block-class is dangerous; warn-class still routes
        # through a vulnerable codec / carries a preamble anomaly that CDR removes).
        self.intrinsic_danger = expected_verdict in ("block", "warn")

    def __repr__(self):
        return f"<Entry {self.name} {self.attack_class}/{self.expected_verdict}>"


def _classify(name):
    for sub, label in _RULES:
        if sub in name:
            return label
    return ("unknown", "block")  # unrecognized tampered file -> assume it should block, surfaces for review


def load_tampered():
    return [Entry(fp, *_classify(os.path.basename(fp)), benign=False)
            for fp in sorted(glob.glob(os.path.join(TAMPERED_DIR, "*.dcm")))]


def load_benign():
    return [Entry(fp, "benign", "clean", benign=True)
            for fp in sorted(glob.glob(os.path.join(BENIGN_DIR, "*.dcm")))]


def load_real_cts():
    """575 real TCIA CTs for the scaled false-positive metric. Empty if data/ is absent."""
    return [Entry(fp, "real_ct", "clean", benign=True)
            for fp in sorted(glob.glob(os.path.join(REAL_CT_DIR, "*.dcm")))]


def load_generated(directory=GENERATED_DIR):
    """Adversarial generated corpus, labeled by its manifest.json. Empty if not generated yet.

    A `benign_edge` class is treated as benign (expected clean) so it scores into the false-positive
    and fidelity metrics, not detection.
    """
    manifest_path = os.path.join(directory, "manifest.json")
    if not os.path.exists(manifest_path):
        return []
    out = []
    for m in json.load(open(manifest_path)):
        fp = os.path.join(directory, m["name"])
        if not os.path.exists(fp):
            continue
        benign = m["expected_verdict"] == "clean"
        e = Entry(fp, m["attack_class"], m["expected_verdict"], benign=benign)
        e.note = m.get("note", "")
        out.append(e)
    return out


def load_all():
    return load_benign() + load_tampered()

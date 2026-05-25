#!/usr/bin/env bash
# Coverage-guided fuzz of the pinned OpenJPEG until the first crash, then triage it through the
# DicomLock CDR Aim-3 pipeline (RAW vs CDR vs POST + fidelity).
set -u

OPJ_DEC=$(find /src/openjpeg/build -name opj_decompress | head -1)
OPJ_ENC=$(find /src/openjpeg/build -name opj_compress | head -1)
echo "target: $OPJ_DEC"
mkdir -p /tmp/in /tmp/out

# Rich seed corpus: varied J2K *and* JP2 features (tiles, resolutions, RGB, progression, JP2 boxes)
# so AFL reaches the deep decode + box-parser paths where OpenJPEG's memory bugs actually live. A
# single trivial 64x64 grayscale seed gives almost no coverage and finds nothing.
python3 - "$OPJ_ENC" <<'PY'
import sys, subprocess, os, numpy as np
enc = sys.argv[1]
os.makedirs('/tmp/in', exist_ok=True)
def gray(w, h):
    a = (np.add.outer(np.arange(h), np.arange(w)) % 256).astype(np.uint8)
    open('/tmp/g.pgm', 'wb').write(b'P5\n%d %d\n255\n' % (w, h) + a.tobytes()); return '/tmp/g.pgm'
def rgb(w, h):
    a = np.dstack([(np.add.outer(np.arange(h), np.arange(w)) % 256),
                   (np.add.outer(np.arange(h), np.zeros(w, int)) % 256),
                   (np.add.outer(np.zeros(h, int), np.arange(w)) % 256)]).astype(np.uint8)
    open('/tmp/c.ppm', 'wb').write(b'P6\n%d %d\n255\n' % (w, h) + a.tobytes()); return '/tmp/c.ppm'
g, c = gray(64, 64), rgb(48, 40)
def E(args): subprocess.run([enc] + args, check=False, capture_output=True)
E(['-i', g, '-o', '/tmp/in/a.j2k'])
E(['-i', g, '-o', '/tmp/in/b.j2k', '-t', '32,32'])     # tiled
E(['-i', g, '-o', '/tmp/in/c.j2k', '-n', '5'])         # 5 resolution levels
E(['-i', c, '-o', '/tmp/in/d.j2k', '-p', 'RLCP'])      # RGB + progression order
E(['-i', g, '-o', '/tmp/in/e.jp2'])                    # JP2 wrapper (box + color parser)
E(['-i', c, '-o', '/tmp/in/f.jp2', '-t', '16,16'])     # JP2 tiled RGB
print('seeds:', sorted(os.listdir('/tmp/in')))
PY

# Add REAL medical-JPEG2000 seeds if mounted at /seeds (extracted from sample DICOMs). These reach
# the deep multi-component/tile/JP2-box decode paths where OpenJPEG's memory bugs live; synthetic
# gradients top out around ~38% coverage.
if [ -d /seeds ]; then
    for s in /seeds/*.j2k /seeds/*.jp2; do [ -e "$s" ] && cp "$s" /tmp/in/; done
    echo "real seeds added: $(ls /tmp/in | grep -E '\.(j2k|jp2)$' | tr '\n' ' ')"
fi

# Large benign conformance corpus baked into the image (OpenJPEG open test data) — the key to
# breaking past the ~38% coverage plateau and reaching the vulnerable decode paths.
if [ -d /seedcorpus ]; then
    cp /seedcorpus/* /tmp/in/ 2>/dev/null || true
fi
echo "total seed corpus: $(ls /tmp/in | wc -l) files"

# J2K marker + JP2 box dictionary so mutations keep enough structure to reach the decoders.
cat > /tmp/j2k.dict <<'DICT'
soc="\xff\x4f"
siz="\xff\x51"
cod="\xff\x52"
coc="\xff\x53"
rgn="\xff\x5e"
qcd="\xff\x5c"
qcc="\xff\x5d"
poc="\xff\x5f"
tlm="\xff\x55"
plm="\xff\x57"
plt="\xff\x58"
ppm="\xff\x60"
ppt="\xff\x61"
sot="\xff\x90"
sop="\xff\x91"
eph="\xff\x92"
sod="\xff\x93"
eoc="\xff\xd9"
b_ftyp="ftyp"
b_jp2h="jp2h"
b_ihdr="ihdr"
b_colr="colr"
b_pclr="pclr"
b_cmap="cmap"
b_cdef="cdef"
b_jp2c="jp2c"
DICT

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1
# AFL requires symbolize=0 during fuzzing; the triage step (run_aim3.py) sets its own ASAN_OPTIONS
# with symbolization back on so we still get readable stack frames for the chosen crash.
export ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:max_allocation_size_mb=1024:hard_rss_limit_mb=2048

NJOBS="${NJOBS:-8}"   # one structured-format core finds little; run independent instances in parallel
echo "=== afl-fuzz x${NJOBS} (independent dirs, <= ${FUZZ_SECONDS}s each) ==="
SCHEDULES="explore fast coe lin quad exploit rare seek"
i=0
for sched in $(echo $SCHEDULES | tr ' ' '\n' | head -n "$NJOBS"); do
    # NOTE: output MUST use a recognized extension (.pgm/.raw). opj_decompress rejects an unknown
    # output format BEFORE decoding, which pins coverage at ~0.35% (only arg-parse edges) and finds
    # nothing. With .pgm it actually runs the decoder, where the memory bugs live.
    ( timeout "${FUZZ_SECONDS}s" afl-fuzz -i /tmp/in -o "/tmp/out$i" -m none -t 2000+ \
        -x /tmp/j2k.dict -p "$sched" -- "$OPJ_DEC" -i @@ -o "/tmp/dec$i.pgm" \
        > "/out/afl_$i.log" 2>&1 ) &
    i=$((i + 1))
done

# A plain stop-on-first-crash returns the EASY allocation/OOM bomb (OpenJPEG aborts on a giant
# alloc within seconds). We want a true MEMORY-CORRUPTION (heap/stack/global overflow or UAF), so
# keep fuzzing past OOM/alloc crashes and stop only when one of these signatures actually appears.
MEMSIG='heap-buffer-overflow|heap-use-after-free|use-after-free|stack-buffer-overflow|global-buffer-overflow|dynamic-stack-buffer-overflow|negative-size-param'
PROBED=/tmp/probed.txt; : > "$PROBED"
have_memcorruption() {
    for c in /tmp/out*/default/crashes/id*; do
        [ -e "$c" ] || continue
        grep -qxF "$c" "$PROBED" 2>/dev/null && continue   # probe each crash once
        echo "$c" >> "$PROBED"
        out=$(ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:max_allocation_size_mb=1024:hard_rss_limit_mb=2048 \
              "$OPJ_DEC" -i "$c" -o /tmp/probe.pgm 2>&1)
        if echo "$out" | grep -qE "$MEMSIG"; then
            echo "  memory-corruption confirmed: $(basename "$c")"
            return 0
        fi
    done
    return 1
}

start=$(date +%s)
deadline=$(( start + FUZZ_SECONDS ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 30
    ncr=$(ls /tmp/out*/default/crashes/id* 2>/dev/null | wc -l)
    echo "  [$(( $(date +%s) - start ))s] saved crashes so far: $ncr"
    if [ "$ncr" -gt 0 ] && have_memcorruption; then
        echo "memory-corruption found after $(( $(date +%s) - start ))s — stopping for triage"
        break
    fi
    pgrep -x afl-fuzz >/dev/null 2>&1 || { echo "all afl instances exited (budget reached)"; break; }
done
pkill -x afl-fuzz 2>/dev/null || true
sleep 2
echo "=== crashes (all instances) ==="
mkdir -p /tmp/allcrashes
n=0
for d in /tmp/out*/default/crashes; do
    for c in "$d"/id*; do
        [ -e "$c" ] || continue
        cp "$c" "/tmp/allcrashes/$(echo "$d" | tr / _)__$(basename "$c")"
        n=$((n + 1))
    done
done
echo "total crashes across instances: $n"
grep -hoE "PROGRAM ABORT[^\"]*|saved crashes : [0-9]+" /out/afl_*.log 2>/dev/null | sort -u | head
if [ "$n" -eq 0 ]; then
    echo "AFL found no crash within ${FUZZ_SECONDS}s x ${NJOBS} jobs"
    exit 3
fi
cp /tmp/allcrashes/* /out/ 2>/dev/null || true
echo ""
echo "=== triage the AFL crashes through DicomLock CDR (prefer memory-corruption) ==="
exec python3 run_aim3.py --crash-dir /tmp/allcrashes

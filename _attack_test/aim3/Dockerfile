# Aim 3 harness (STUDY_DESIGN.md): a PINNED-VULNERABLE codec (the target) + DicomLock CDR (the
# defense) in one image, so the paired raw-vs-CDR experiment runs hermetically and reproducibly.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates libasan8 \
    && rm -rf /var/lib/apt/lists/*

# Build OpenJPEG v2.3.0 with AddressSanitizer. The pin makes the CVE-era memory bugs present; ASan
# makes a heap over-read/-write abort and be observable rather than silently tolerated. This binary
# is the vulnerable TARGET (a stand-in for the codec a slow-to-patch PACS/viewer runs). We build
# with gcc (its libasan ships in the toolchain) and relax gcc-14's newer C errors so the 2018 code
# still compiles.
RUN git clone --depth 1 --branch v2.3.0 https://github.com/uclouvain/openjpeg.git /src/openjpeg
WORKDIR /src/openjpeg/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=gcc \
        -DCMAKE_C_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer -Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion" \
    && make -j"$(nproc)"

# DicomLock CDR side: a MODERN, patched OpenJPEG bundled inside pylibjpeg-openjpeg (statically
# linked in its own extension, independent of the system 2.3.0 above), plus pydicom/numpy/gdcm.
RUN pip install --no-cache-dir pydicom numpy pillow pylibjpeg pylibjpeg-openjpeg python-gdcm

COPY scanner /dicomlock/scanner
COPY run_aim3.py /dicomlock/run_aim3.py
WORKDIR /dicomlock
ENV PYTHONPATH=/dicomlock \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:exitcode=134 \
    FUZZ_SECONDS=180
CMD ["python3", "run_aim3.py"]

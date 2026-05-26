# syntax=docker/dockerfile:1.7
#
# DicomLock, container image
#
# Default command launches the REST API and web UI on port 8899. Override the
# entrypoint to use the CLI:
#
#   docker build -t dicomlock .
#   docker run --rm -p 8899:8899 dicomlock                          # API + web at http://localhost:8899
#   docker run --rm -v "$PWD/data:/data" --entrypoint dicomlock \
#       dicomlock /data --disarm                                    # CLI on a host directory
#
# Single-stage build kept on python:3.12-slim. The package's pixel-decoding
# backends (python-gdcm, pylibjpeg-libjpeg, pylibjpeg-openjpeg) ship as
# manylinux wheels, so no apt-level codec libraries are needed.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/dicomlock

# Install the dicomlock package with the [server] extra. This pulls only what
# scanning, disarm, and the API need: pydicom + numpy + python-gdcm + pylibjpeg
# backends + fastapi + uvicorn + python-multipart. The legacy pixel-forensics
# modules (which would pull scipy, scikit-image, PyWavelets) are not in the
# default scan path and are deliberately not installed here.
COPY pyproject.toml README.md LICENSE ./
COPY scanner/ ./scanner/
RUN pip install --no-cache-dir ".[server]"

# Layer 3: the server, CLI script, web UI, and a handful of bundled samples so
# the image is self-demoing. The full samples/ tree and data/ tree are
# excluded via .dockerignore to keep the image small.
COPY server.py scan.py ./
COPY web/ ./web/
COPY samples/ct_sample.dcm samples/mr_sample.dcm samples/JPEG2000.dcm ./samples/

# Run as a non-root user. The server only reads uploads in a per-request temp
# directory and deletes them right after the scan, so PHI is never persisted
# inside the container.
RUN groupadd --system dicomlock \
    && useradd --system --gid dicomlock --home /opt/dicomlock --shell /usr/sbin/nologin dicomlock \
    && chown -R dicomlock:dicomlock /opt/dicomlock
USER dicomlock

EXPOSE 8899

# Default command: launch the API and web UI. Override --entrypoint to use the
# CLI instead, e.g. docker run --entrypoint dicomlock dicomlock samples/.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8899"]

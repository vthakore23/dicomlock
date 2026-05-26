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

# Install the dicomlock package with the [server] extra. The wheel ships
# scanner/, scanner/server.py, and scanner/web/ (the static UI), and registers
# two console scripts: `dicomlock` (CLI) and `dicomlock-server` (API + UI). The
# legacy pixel-forensics modules (which would pull scipy, scikit-image,
# PyWavelets) are not in the default scan path and are deliberately not
# installed here.
COPY pyproject.toml README.md LICENSE ./
COPY scanner/ ./scanner/
RUN pip install --no-cache-dir ".[server]"

# A handful of bundled samples so `docker run --entrypoint dicomlock dicomlock
# samples/ct_sample.dcm` works as a self-demo from WORKDIR. The full samples/
# tree and data/ tree are excluded via .dockerignore.
COPY samples/ct_sample.dcm samples/mr_sample.dcm samples/JPEG2000.dcm ./samples/

# Run as a non-root user. The server only reads uploads in a per-request temp
# directory and deletes them right after the scan, so PHI is never persisted
# inside the container.
RUN groupadd --system dicomlock \
    && useradd --system --gid dicomlock --home /opt/dicomlock --shell /usr/sbin/nologin dicomlock \
    && chown -R dicomlock:dicomlock /opt/dicomlock
USER dicomlock

EXPOSE 8899

# Default command: the API and web UI via the wheel's console-script entry
# point. Override --entrypoint dicomlock to use the CLI instead. Host and port
# can be overridden via DICOMLOCK_HOST and DICOMLOCK_PORT environment variables.
CMD ["dicomlock-server"]

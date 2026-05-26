#!/usr/bin/env python3
"""
Top-level shim. The real FastAPI app lives in `scanner.server` and ships in
the wheel under `pip install dicomlock[server]`. This file is kept so that
running from a git checkout continues to work:

    python server.py    # http://localhost:8899 with --reload for dev

After `pip install dicomlock[server]`, prefer the console script:

    dicomlock-server
"""

from scanner.server import app  # noqa: F401  (re-export for uvicorn)


if __name__ == "__main__":
    import uvicorn

    # The dev path keeps --reload so editing scanner/* triggers a restart.
    uvicorn.run("scanner.server:app", host="0.0.0.0", port=8899, reload=True)

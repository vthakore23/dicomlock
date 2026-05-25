#!/usr/bin/env python3
"""
DicomLock — Web Server

FastAPI backend: scan a DICOM upload, and optionally disarm it (or quarantine if it
cannot be made safe). Uploaded files are never persisted (PHI safety).

Usage:
    python server.py   ->  http://localhost:8899
"""

import os
import sys
import tempfile

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.pipeline import (
    run_security_scan,
    disarm_or_quarantine,
    is_dangerous,
    SCANNER_VERSION,
)

app = FastAPI(title="DicomLock", description="DICOM Security Scanner API", version="0.7.0")

# CORS — allow the local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB


async def _save_upload(file: UploadFile) -> str:
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 500MB)")
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")
    suffix = os.path.splitext(file.filename or "upload.dcm")[1] or ".dcm"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(contents)
        return tmp.name


@app.post("/api/scan")
async def scan_upload(file: UploadFile = File(...), deid: bool = False):
    """Upload a DICOM file and receive a security report."""
    tmp_path = await _save_upload(file)
    try:
        report = run_security_scan(tmp_path, run_deid=deid)
        report["filename"] = file.filename or "upload.dcm"
        return report
    finally:
        os.unlink(tmp_path)  # never persist PHI


@app.post("/api/disarm")
async def disarm_upload(file: UploadFile = File(...)):
    """Scan, then return a clean DISARMED file — or a QUARANTINE verdict (JSON) if the
    file cannot be made safe (e.g. a length bomb, or an attack disarm can't neutralize)."""
    tmp_path = await _save_upload(file)
    orig_name = file.filename or "upload.dcm"
    report = run_security_scan(tmp_path)

    if not is_dangerous(report):
        os.unlink(tmp_path)
        return JSONResponse({"action": "clean", "filename": orig_name,
                             "summary": report["summary"]})

    action = disarm_or_quarantine(tmp_path, out_path=tmp_path + ".disarmed.dcm")

    if action["action"] == "disarmed":
        clean_name = os.path.splitext(orig_name)[0] + ".disarmed.dcm"

        def _cleanup():
            for p in (tmp_path, action["output"]):
                try:
                    os.unlink(p)
                except OSError:
                    pass

        return FileResponse(
            action["output"],
            media_type="application/dicom",
            filename=clean_name,
            headers={
                "X-DicomLock-Action": "disarmed",
                "X-DicomLock-Changes": "; ".join(action.get("changes", [])),
            },
            background=BackgroundTask(_cleanup),
        )

    # quarantined
    os.unlink(tmp_path)
    return JSONResponse({"action": "quarantined", "filename": orig_name,
                         "reason": action.get("reason", ""),
                         "summary": report["summary"]})


@app.get("/api/health")
async def health():
    return {"status": "ok", "scanner": SCANNER_VERSION}


# Serve frontend — must be last so API routes take priority
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8899, reload=True)

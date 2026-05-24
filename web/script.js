// DicomLock — Web UI

const API = "/api/scan";

const $ = (sel) => document.querySelector(sel);
const uploadZone = $("#upload-zone");
const fileInput = $("#file-input");
const scanningEl = $("#scanning");
const reportEl = $("#report");

let lastReport = null;
let lastFile = null;

// --- Upload Handling ---

uploadZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", (e) => {
  if (e.target.files.length) handleFile(e.target.files[0]);
});

// Drag & drop
uploadZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadZone.classList.add("drag-over");
});

uploadZone.addEventListener("dragleave", () => {
  uploadZone.classList.remove("drag-over");
});

uploadZone.addEventListener("drop", (e) => {
  e.preventDefault();
  uploadZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});

// --- Scan ---

async function handleFile(file) {
  lastFile = file;
  // Show scanning state
  uploadZone.classList.add("hidden");
  reportEl.classList.add("hidden");
  scanningEl.classList.remove("hidden");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(API, { method: "POST", body: formData });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Server error" }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const report = await res.json();
    lastReport = report;
    renderReport(report);
  } catch (err) {
    showError(err.message);
    resetToUpload();
  }
}

// --- Render Report ---

function renderReport(report) {
  scanningEl.classList.add("hidden");
  reportEl.classList.remove("hidden");

  // File info
  $("#report-filename").textContent = report.filename;
  $("#report-size").textContent = formatBytes(report.file_size);
  $("#report-time").textContent = formatTime(report.scan_time);
  $("#report-hash").textContent = `SHA-256: ${report.sha256}`;

  // Trust score
  const summary = report.summary;
  const trustPct = Math.round(summary.trust_score * 100);
  const level = summary.overall.toLowerCase();

  const trustBar = $("#trust-bar");
  trustBar.className = `trust-bar ${level}`;
  // Trigger animation
  requestAnimationFrame(() => {
    trustBar.style.width = `${trustPct}%`;
  });

  const badge = $("#trust-badge");
  badge.className = `trust-badge ${level}`;
  badge.textContent = `${summary.overall} (${trustPct}%)`;

  // Findings
  const findingsList = $("#findings-list");
  findingsList.innerHTML = "";
  $("#findings-count").textContent = `${summary.total_checks} checks`;

  for (const f of report.findings) {
    const el = document.createElement("div");
    el.className = "finding";
    el.innerHTML = `
      <span class="finding-badge ${f.severity}">${f.severity}</span>
      <div class="finding-content">
        <div class="finding-message">${escapeHtml(f.message)}</div>
        ${f.details ? `<div class="finding-details">${escapeHtml(f.details)}</div>` : ""}
      </div>
    `;
    findingsList.appendChild(el);
  }

  // Summary counts
  const counts = summary.counts;
  const countsEl = $("#summary-counts");
  countsEl.innerHTML = "";
  for (const [sev, count] of Object.entries(counts)) {
    const label = sev === "pass" ? "passed" : sev === "warn" ? "warnings" : sev === "fail" ? "failures" : sev;
    countsEl.innerHTML += `
      <div class="count-item">
        <span class="count-dot ${sev}"></span>
        <span>${count} ${label}</span>
      </div>
    `;
  }
}

// --- Actions ---

$("#scan-another").addEventListener("click", resetToUpload);

$("#download-json").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${lastReport.filename.replace(/\.[^.]+$/, "")}_report.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// Disarm & download a clean file (or surface the quarantine / clean verdict)
$("#disarm-btn").addEventListener("click", async () => {
  if (!lastFile) return;
  const btn = $("#disarm-btn");
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Disarming…";
  try {
    const fd = new FormData();
    fd.append("file", lastFile);
    const res = await fetch("/api/disarm", { method: "POST", body: fd });
    const ct = res.headers.get("Content-Type") || "";

    if (res.ok && ct.includes("application/dicom")) {
      // A clean, rebuilt DICOM came back — download it.
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = lastFile.name.replace(/\.[^.]+$/, "") + ".disarmed.dcm";
      a.click();
      URL.revokeObjectURL(url);
      const changes = res.headers.get("X-DicomLock-Changes");
      showToast("Disarmed — clean file downloaded" + (changes ? `: ${changes}` : ""), "ok");
    } else {
      const j = await res.json().catch(() => ({}));
      if (j.action === "clean") showToast("Already clean — no disarm needed.", "ok");
      else if (j.action === "quarantined") showToast("QUARANTINED — " + (j.reason || "cannot be made safe"), "bad");
      else showToast(j.detail || "Disarm failed", "bad");
    }
  } catch (err) {
    showToast(err.message, "bad");
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

function resetToUpload() {
  reportEl.classList.add("hidden");
  scanningEl.classList.add("hidden");
  uploadZone.classList.remove("hidden");
  fileInput.value = "";
  // Reset trust bar for next animation
  $("#trust-bar").style.width = "0%";
}

// --- Utilities ---

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString();
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function showToast(msg, kind = "bad") {
  const toast = document.createElement("div");
  toast.className = "error-toast";
  if (kind === "ok") toast.style.background = "#0a7d3f";
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 6000);
}

function showError(msg) {
  showToast(msg, "bad");
}

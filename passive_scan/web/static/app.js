const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const RING_CIRCUMFERENCE = 2 * Math.PI * 52;

let pollTimer = null;
let latestReportId = null;
let selectedReportId = null;
let cachedTargets = [];
let modeDescriptions = {};
let lockedScanMode = null;
let lockedTargetIds = [];

function formatApiError(payload, fallback) {
  if (!payload) return fallback || "Request failed";
  const detail = payload.detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
  }
  if (typeof detail === "string") return detail;
  return fallback || "Request failed";
}

async function api(path, options = {}) {
  const res = await fetch(path, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const message =
      formatApiError(err, null) ||
      (res.status === 500 ? "Internal server error — try refreshing the page." : res.statusText);
    throw new Error(message);
  }
  return res.json();
}

function showView(name) {
  $$(".view").forEach((v) => v.classList.remove("active"));
  $$(".nav-item").forEach((n) => n.classList.remove("active"));
  $(`#view-${name}`)?.classList.add("active");
  $(`.nav-item[data-view="${name}"]`)?.classList.add("active");
}

function getSelectedScanMode() {
  const checked = $('input[name="scan-mode"]:checked');
  return checked ? checked.value : "passive";
}

function getSelectedTargetIds() {
  return [...$$("#scan-target-checkboxes input[type=checkbox]:checked")].map((el) => el.value);
}

function computePercent(progress) {
  if (typeof progress.percent === "number") {
    return Math.min(100, Math.max(0, progress.percent));
  }
  const total = progress.total || 1;
  const index = progress.index || 0;
  if (progress.phase === "starting") return 5;
  if (progress.phase === "writing") return 92;
  if (progress.phase === "done") return 100;
  if (
    progress.phase === "target" ||
    progress.phase === "well_known" ||
    progress.phase === "cve" ||
    progress.phase === "tls" ||
    progress.phase === "subdomains" ||
    progress.phase === "file" ||
    progress.phase === "ports" ||
    progress.phase === "paths"
  ) {
    return Math.round(10 + (index / total) * 80);
  }
  return 15;
}

function setProgressRing(percent, isActive) {
  const ring = $("#progress-ring-fill");
  const label = $("#progress-pct");
  if (!ring || !label) return;
  ring.classList.toggle("active-mode", !!isActive);
  const offset = RING_CIRCUMFERENCE * (1 - percent / 100);
  ring.style.strokeDashoffset = String(offset);
  label.textContent = `${Math.round(percent)}%`;
}

function setScanLock(locked, statusData = {}) {
  const fieldset = $("#scan-setup-fieldset");
  const card = $("#scan-setup-card");
  const notice = $("#scan-locked-notice");
  const selectAll = $("#targets-select-all");
  const selectNone = $("#targets-select-none");

  if (locked) {
    lockedScanMode = statusData.scan_mode || getSelectedScanMode();
    lockedTargetIds = statusData.target_ids || getSelectedTargetIds();
    if (fieldset) fieldset.disabled = true;
    card?.classList.add("is-locked");
    if (selectAll) selectAll.disabled = true;
    if (selectNone) selectNone.disabled = true;
    const modeLabel = lockedScanMode === "active" ? "Active" : "Passive";
    const count = lockedTargetIds.length;
    if (notice) {
      notice.textContent = `Scan locked — ${modeLabel} mode, ${count} target(s). Settings cannot be changed until this run finishes.`;
      notice.classList.remove("hidden");
    }
    const radio = $(`input[name="scan-mode"][value="${lockedScanMode}"]`);
    if (radio) radio.checked = true;
    $$("#scan-target-checkboxes input").forEach((input) => {
      input.checked = lockedTargetIds.includes(input.value);
      input.disabled = true;
    });
    $("#stat-mode").textContent = lockedScanMode;
  } else {
    lockedScanMode = null;
    lockedTargetIds = [];
    if (fieldset) fieldset.disabled = false;
    card?.classList.remove("is-locked");
    if (selectAll) selectAll.disabled = false;
    if (selectNone) selectNone.disabled = false;
    notice?.classList.add("hidden");
    $$("#scan-target-checkboxes input").forEach((input) => {
      input.disabled = false;
    });
    $("#stat-mode").textContent = getSelectedScanMode();
  }
}

function showScanError(message) {
  const banner = $("#scan-error-banner");
  if (!banner) return;
  banner.innerHTML = `<strong>Scan aborted</strong> ${escapeHtml(message)}`;
  banner.classList.remove("hidden");
}

function hideScanError() {
  $("#scan-error-banner")?.classList.add("hidden");
}

function setScanUI(status, progress = {}, error = null, statusData = {}) {
  const pill = $("#status-pill");
  const msg = $("#status-message");
  const wrap = $("#progress-wrap");
  const detail = $("#progress-detail");
  const subdetail = $("#progress-subdetail");
  const runBtn = $("#run-scan-btn");
  const results = $("#result-actions");
  const mode =
    progress.scan_mode || statusData.scan_mode || lockedScanMode || getSelectedScanMode();

  setScanLock(status === "running", statusData);

  pill.className = `status-pill ${status}`;
  pill.textContent =
    status === "running"
      ? "Scanning"
      : status === "completed"
        ? "Complete"
        : status === "failed"
          ? "Failed"
          : "Ready";

  if (status === "running") {
    runBtn.disabled = true;
    wrap.classList.remove("hidden");
    results.classList.add("hidden");
    const pct = computePercent(progress);
    setProgressRing(pct, mode === "active");
    detail.textContent = progress.message || "Working…";
    const total = progress.total || 0;
    const index = progress.index || 0;
    const modeLabel = mode === "active" ? "Active" : "Passive";
    if (progress.label && total) {
      subdetail.textContent = `${modeLabel} — ${progress.label} (${index}/${total})`;
    } else {
      subdetail.textContent = total ? `${modeLabel} — step ${index} of ${total}` : modeLabel;
    }
    msg.textContent = `${modeLabel} scan in progress`;
  } else {
    runBtn.disabled = false;
    wrap.classList.add("hidden");
    setProgressRing(0, false);
    if (status === "completed") {
      hideScanError();
      msg.textContent = "Scan finished. Report saved to your reports folder.";
      results.classList.remove("hidden");
    } else if (status === "failed") {
      const errText = error || "Scan failed.";
      msg.textContent = errText;
      showScanError(errText);
      results.classList.add("hidden");
    } else {
      hideScanError();
      msg.textContent = "No scan in progress.";
      results.classList.add("hidden");
    }
    if (subdetail) subdetail.textContent = "";
  }
  if (status !== "running") {
    $("#stat-mode").textContent = getSelectedScanMode();
  }
}

function targetLocator(t) {
  return t.address || t.url || "";
}

function targetTypeLabel(t) {
  const labels = {
    url: "Web URL",
    host: "Host",
    ip: "IP",
    file: "File",
    path: "Path",
  };
  if (t.type && labels[t.type]) return labels[t.type];
  const loc = targetLocator(t);
  if (/^https?:\/\//i.test(loc)) return "Web URL";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(loc)) return "IP";
  if (loc.startsWith("/") || loc.startsWith("~/") || loc.startsWith("./")) return "File";
  return "Auto";
}

function renderScanTargetCheckboxes(targets) {
  const box = $("#scan-target-checkboxes");
  if (!box) return;
  box.innerHTML = "";
  if (!targets.length) {
    box.innerHTML = '<p class="muted small">Add targets on the Targets tab first.</p>';
    return;
  }
  targets.forEach((t) => {
    const label = document.createElement("label");
    label.className = "target-check";
    label.innerHTML = `
      <input type="checkbox" value="${escapeHtml(t.id)}" checked />
      <span class="target-check-text">
        <strong>${escapeHtml(t.label || t.id)}</strong>
        <span class="surface-type-pill">${escapeHtml(targetTypeLabel(t))}</span>
        <code>${escapeHtml(targetLocator(t))}</code>
      </span>
    `;
    box.appendChild(label);
  });
}

function updateModeHint() {
  const mode = getSelectedScanMode();
  const hint = $("#mode-hint");
  if (hint && modeDescriptions[mode]) {
    hint.textContent = modeDescriptions[mode];
  }
  $("#stat-mode").textContent = mode;
}

async function loadOverview() {
  const data = await api("/api/overview");
  $("#program-subtitle").textContent = data.program_name;
  $("#stat-targets").textContent = data.target_count;
  modeDescriptions = data.modes || {};
  updateModeHint();
  $("#paths-hint").textContent = `Reports: ${data.reports_path}`;
}

async function loadTargets() {
  const data = await api("/api/targets");
  cachedTargets = data.targets || [];
  const list = $("#targets-list");
  list.innerHTML = "";
  if (!cachedTargets.length) {
    list.innerHTML = '<p class="muted">No targets yet. Add one above.</p>';
  } else {
    cachedTargets.forEach((t) => {
      const el = document.createElement("div");
      el.className = "target-row";
      el.innerHTML = `
        <strong>${escapeHtml(t.label || t.id)}</strong>
        <span>${escapeHtml(t.category || "")}</span>
        <span class="surface-type-pill">${escapeHtml(targetTypeLabel(t))}</span>
        <code>${escapeHtml(targetLocator(t))}</code>
      `;
      list.appendChild(el);
    });
  }
  $("#stat-targets").textContent = cachedTargets.length;
  renderScanTargetCheckboxes(cachedTargets);
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function showTargetFeedback(message, isError) {
  const el = $("#add-target-feedback");
  el.textContent = message;
  el.classList.remove("hidden", "success", "error");
  el.classList.add(isError ? "error" : "success");
}

function updatePathFieldsVisibility() {
  const type = $("#target-type")?.value;
  const show = type === "path";
  $$(".path-only").forEach((el) => el.classList.toggle("hidden", !show));
}

async function submitTarget(event) {
  event.preventDefault();
  const label = $("#target-label").value.trim();
  const address = $("#target-address").value.trim();
  const type = $("#target-type").value.trim() || null;
  const base_url = $("#target-base-url")?.value.trim() || null;
  const path = $("#target-path")?.value.trim() || null;
  const btn = $("#add-target-btn");
  btn.disabled = true;
  try {
    await api("/api/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, address, type, base_url, path }),
    });
    $("#add-target-form").reset();
    showTargetFeedback(`Added “${label}” to your scan list.`, false);
    await loadTargets();
    await loadOverview();
  } catch (e) {
    showTargetFeedback(e.message, true);
  } finally {
    btn.disabled = false;
  }
}

function formatReportLabel(id) {
  return id
    .replace(/^ig88-(passive|active)-scan-/, "$1 · ")
    .replace(/^(passive|active)-walkthrough-/, "$1 · ");
}

async function loadReports() {
  const data = await api("/api/reports");
  $("#stat-reports").textContent = data.runs.length;
  const container = $("#reports-by-date");
  container.innerHTML = "";

  if (!data.runs.length) {
    container.innerHTML = '<p class="muted">No reports yet. Run a scan from the Dashboard.</p>';
    return;
  }

  const dates = Object.keys(data.by_date).sort().reverse();
  dates.forEach((date) => {
    const group = document.createElement("div");
    group.className = "date-group";
    const title =
      date.match(/^\d{4}-\d{2}-\d{2}$/) ?
        new Date(date + "T12:00:00").toLocaleDateString(undefined, {
          weekday: "short",
          year: "numeric",
          month: "short",
          day: "numeric",
        })
      : date;
    group.innerHTML = `<h3>${escapeHtml(title)}</h3>`;
    data.by_date[date].forEach((run) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "report-item" + (run.id === selectedReportId ? " active" : "");
      const time = new Date(run.modified_at).toLocaleTimeString();
      const modeTag = run.scan_mode === "active" ? "[active] " : "";
      btn.textContent = `${modeTag}${time} — ${formatReportLabel(run.id)}`;
      btn.addEventListener("click", () => selectReport(run.id));
      group.appendChild(btn);
    });
    container.appendChild(group);
  });

  if (data.runs[0]) {
    latestReportId = data.runs[0].id;
  }
}

function renderReportActions(json) {
  const panel = $("#report-actions-panel");
  if (!panel || !json) {
    panel?.classList.add("hidden");
    return;
  }
  const steps = json.summary_next_steps || [];
  const inApp = steps.filter((s) => typeof s === "object" && s.category === "in_app");
  if (!inApp.length) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  panel.innerHTML = "<h3>Actions you can run from this app</h3><div class=\"report-action-list\"></div>";
  const list = panel.querySelector(".report-action-list");
  inApp.forEach((step) => {
    const row = document.createElement("div");
    row.className = "report-action-item";
    const tagClass =
      step.category === "in_app" ? "tag-in-app" : step.category === "governance" ? "tag-governance" : "tag-engineering";
    row.innerHTML = `
      <div>
        <span class="tag ${tagClass}">${escapeHtml(step.category)}</span>
        <span>${escapeHtml(step.text)}</span>
      </div>
    `;
    if (step.action) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn secondary small";
      btn.textContent =
        step.action === "active_rescan" ? "Run active scan" : "Run passive scan";
      btn.addEventListener("click", () => {
        showView("dashboard");
        if (step.action === "active_rescan") {
          $('input[name="scan-mode"][value="active"]').checked = true;
        } else {
          $('input[name="scan-mode"][value="passive"]').checked = true;
        }
        updateModeHint();
        if (step.target_ids?.length) {
          $$("#scan-target-checkboxes input").forEach((input) => {
            input.checked = step.target_ids.includes(input.value);
          });
        }
        startScan();
      });
      row.appendChild(btn);
    }
    list.appendChild(row);
  });
}

let currentReportJson = null;

async function selectReport(id) {
  selectedReportId = id;
  const data = await api(`/api/reports/${encodeURIComponent(id)}`);
  currentReportJson = data.json;
  $("#report-placeholder").classList.add("hidden");
  renderReportActions(data.json);

  const dashEl = $("#report-dashboard");
  if (data.json && window.IG88ReportViewer) {
    IG88ReportViewer.renderReportDashboard(data.json, dashEl);
  } else {
    dashEl?.classList.add("hidden");
    if (dashEl) dashEl.innerHTML = "";
  }

  const article = $("#report-content");
  article.classList.remove("hidden");
  article.innerHTML = marked.parse(data.markdown || "");
  if (window.IG88ReportViewer) {
    IG88ReportViewer.enhanceReportArticle(article, data.json);
  }

  $("#report-toolbar").classList.remove("hidden");
  $("#download-md").href = `/api/reports/${encodeURIComponent(id)}/download/md`;
  $("#download-html").href = `/api/reports/${encodeURIComponent(id)}/export/html`;
  $("#download-json").href = data.json
    ? `/api/reports/${encodeURIComponent(id)}/download/json`
    : "#";
  await loadReports();
}

async function startScan() {
  if (lockedScanMode) {
    return;
  }
  const targetIds = getSelectedTargetIds();
  if (!targetIds.length) {
    alert("Select at least one target to scan.");
    return;
  }
  const mode = getSelectedScanMode();
  if (mode === "active") {
    const ok = confirm(
      "Active scan will run TCP port checks and probe common paths on the selected targets. " +
        "No exploit payloads will be sent. Continue?"
    );
    if (!ok) return;
  }

  const runBtn = $("#run-scan-btn");
  runBtn.disabled = true;
  hideScanError();

  try {
    const result = await api("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode, target_ids: targetIds }),
    });
    const statusData = {
      scan_mode: result.mode || mode,
      target_ids: result.target_ids || targetIds,
      locked: true,
    };
    setScanUI(
      "running",
      {
        message: "Starting scan…",
        percent: 2,
        scan_mode: statusData.scan_mode,
        total: targetIds.length,
        index: 0,
      },
      null,
      statusData
    );
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollScanStatus, 800);
    pollScanStatus();
  } catch (e) {
    runBtn.disabled = false;
    setScanLock(false);
    showScanError(e.message);
    alert(e.message);
  }
}

async function pollScanStatus() {
  const data = await api("/api/scan/status");
  setScanUI(data.status, data.progress, data.error, data);
  if (data.status === "completed" || data.status === "failed") {
    clearInterval(pollTimer);
    pollTimer = null;
    await loadReports();
    if (data.status === "completed") {
      const runs = await api("/api/reports");
      if (runs.runs[0]) {
        latestReportId = runs.runs[0].id;
      }
    }
  }
}

function initNav() {
  $$(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      showView(btn.dataset.view);
      if (btn.dataset.view === "reports") loadReports();
      if (btn.dataset.view === "targets") loadTargets();
      if (btn.dataset.view === "dashboard") renderScanTargetCheckboxes(cachedTargets);
    });
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  initNav();
  $$('input[name="scan-mode"]').forEach((r) =>
    r.addEventListener("change", () => {
      if (lockedScanMode) return;
      updateModeHint();
    })
  );
  $("#targets-select-all")?.addEventListener("click", () => {
    $$("#scan-target-checkboxes input").forEach((i) => (i.checked = true));
  });
  $("#targets-select-none")?.addEventListener("click", () => {
    $$("#scan-target-checkboxes input").forEach((i) => (i.checked = false));
  });
  $("#run-scan-btn").addEventListener("click", startScan);
  $("#add-target-form")?.addEventListener("submit", submitTarget);
  $("#target-type")?.addEventListener("change", updatePathFieldsVisibility);
  updatePathFieldsVisibility();
  $("#refresh-reports-btn").addEventListener("click", loadReports);
  $("#open-folder-btn").addEventListener("click", async () => {
    try {
      await api("/api/reports/open-folder", { method: "POST" });
    } catch (e) {
      alert(e.message);
    }
  });
  $("#export-gdocs-btn")?.addEventListener("click", () => {
    if (!selectedReportId || !currentReportJson) {
      alert("Select a report first.");
      return;
    }
    const article = $("#report-content");
    if (window.IG88ReportViewer) {
      IG88ReportViewer.downloadExportHtml(
        currentReportJson,
        article?.innerHTML || "",
        selectedReportId
      );
      alert(
        "HTML downloaded. In Google Drive: New → File upload → choose the .html file → right-click → Open with → Google Docs."
      );
    }
  });

  $("#view-latest-btn").addEventListener("click", async () => {
    showView("reports");
    await loadReports();
    if (latestReportId) await selectReport(latestReportId);
  });

  try {
    await loadOverview();
    await loadTargets();
    await loadReports();
    const status = await api("/api/scan/status");
    setScanUI(status.status, status.progress, status.error, status);
    if (status.status === "running") {
      pollTimer = setInterval(pollScanStatus, 800);
    }
  } catch (e) {
    $("#program-subtitle").textContent = "Could not connect to app server.";
    console.error(e);
  }
});

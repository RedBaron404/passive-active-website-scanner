/**
 * IG-88 report presentation: dashboard, severity badges, collapsible blocks.
 */

const SEVERITY_META = {
  critical: { label: "Critical", icon: "⬤", class: "critical" },
  high: { label: "High", icon: "▲", class: "high" },
  medium: { label: "Medium", icon: "◆", class: "medium" },
  low: { label: "Low", icon: "▽", class: "low" },
  info: { label: "Info", icon: "○", class: "info" },
};

function severityBadge(severity) {
  const key = (severity || "info").toLowerCase();
  const meta = SEVERITY_META[key] || SEVERITY_META.info;
  return `<span class="sev-badge sev-badge-${meta.class}" title="${meta.label}">${meta.icon} ${meta.label}</span>`;
}

function buildDashboardFromJson(json) {
  if (json?.dashboard) return json.dashboard;

  const actionable = [];
  let reachable = 0;
  (json?.targets || []).forEach((t) => {
    (t.actionable_findings || []).forEach((f) => actionable.push(f));
    const err = t.fetch?.error;
    const st = t.fetch?.status_code;
    if (!err) {
      if (t.surface_type === "file") {
        if (!t.file_review?.error) reachable += 1;
      } else if (st != null && st >= 200 && st < 400) reachable += 1;
    }
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  actionable.forEach((f) => {
    const s = (f.severity || "info").toLowerCase();
    if (counts[s] !== undefined) counts[s] += 1;
  });

  const generated = json?.generated_at || "";
  let generatedDisplay = generated;
  try {
    generatedDisplay = new Date(generated).toLocaleString(undefined, {
      dateStyle: "full",
      timeStyle: "short",
    });
  } catch (_) {
    /* keep raw */
  }

  return {
    generated_at: generated,
    generated_display: generatedDisplay,
    scan_mode: json?.mode || "passive",
    program_name: json?.program_name || "IG-88 Corporate Scanner",
    target_count: (json?.targets || []).length,
    targets_reachable: reachable,
    targets_need_review: (json?.targets || []).length - reachable,
    actionable_total: actionable.length,
    severity: counts,
    by_target: (json?.targets || []).map((t) => ({
      id: t.id,
      label: t.label,
      finding_count: (t.actionable_findings || []).length,
      reachable: !t.fetch?.error,
    })),
  };
}

function renderReportDashboard(json, container) {
  if (!container || !json) return;
  const d = buildDashboardFromJson(json);
  const sev = d.severity || {};
  const mode = (d.scan_mode || "passive").toUpperCase();

  container.innerHTML = `
    <div class="report-dashboard">
      <div class="report-dashboard-header">
        <h2>Report dashboard</h2>
        <p class="report-dashboard-date">${escapeHtml(d.generated_display || d.generated_at || "")}</p>
      </div>
      <div class="report-dashboard-stats">
        <div class="dash-stat">
          <span class="dash-stat-value">${d.target_count}</span>
          <span class="dash-stat-label">Surfaces</span>
        </div>
        <div class="dash-stat dash-stat-ok">
          <span class="dash-stat-value">${d.targets_reachable}</span>
          <span class="dash-stat-label">Reachable</span>
        </div>
        <div class="dash-stat dash-stat-warn">
          <span class="dash-stat-value">${d.targets_need_review}</span>
          <span class="dash-stat-label">Need review</span>
        </div>
        <div class="dash-stat">
          <span class="dash-stat-value">${d.actionable_total}</span>
          <span class="dash-stat-label">Findings</span>
        </div>
        <div class="dash-stat dash-stat-mode">
          <span class="dash-stat-value">${escapeHtml(mode)}</span>
          <span class="dash-stat-label">Scan mode</span>
        </div>
      </div>
      <div class="report-severity-row">
        ${["critical", "high", "medium", "low", "info"]
          .map(
            (name) => `
          <div class="report-sev-tile sev-tile-${name}">
            ${severityBadge(name)}
            <span class="report-sev-count">${sev[name] || 0}</span>
          </div>`
          )
          .join("")}
      </div>
    </div>
  `;
  container.classList.remove("hidden");
}

function wrapCollapsibleBlocks(root) {
  if (!root) return;

  root.querySelectorAll("pre").forEach((pre) => {
    const text = pre.textContent || "";
    const lines = text.split("\n").length;
    if (text.length < 180 && lines < 6) return;

    const details = document.createElement("details");
    details.className = "report-collapsible";
    const summary = document.createElement("summary");
    summary.innerHTML = `<span class="collapse-caret">▸</span> Code / output (${lines} lines, ${text.length.toLocaleString()} chars)`;
    pre.parentNode.insertBefore(details, pre);
    details.appendChild(summary);
    details.appendChild(pre);
    details.addEventListener("toggle", () => {
      const caret = summary.querySelector(".collapse-caret");
      if (caret) caret.textContent = details.open ? "▾" : "▸";
    });
  });

  root.querySelectorAll("ul").forEach((ul) => {
    if (ul.closest("details.report-collapsible")) return;
    const items = ul.querySelectorAll(":scope > li");
    if (items.length < 10) return;
    const parent = ul.parentNode;
    const details = document.createElement("details");
    details.className = "report-collapsible report-collapsible-list";
    const summary = document.createElement("summary");
    summary.innerHTML = `<span class="collapse-caret">▸</span> ${items.length} items (click to expand)`;
    parent.insertBefore(details, ul);
    details.appendChild(summary);
    details.appendChild(ul);
    details.addEventListener("toggle", () => {
      const caret = summary.querySelector(".collapse-caret");
      if (caret) caret.textContent = details.open ? "▾" : "▸";
    });
  });

  root.querySelectorAll("table").forEach((table) => {
    if (table.rows.length < 8) return;
    const wrapper = document.createElement("details");
    wrapper.className = "report-collapsible report-collapsible-table";
    wrapper.open = true;
    const summary = document.createElement("summary");
    summary.innerHTML = `<span class="collapse-caret">▾</span> Table (${table.rows.length} rows)`;
    table.parentNode.insertBefore(wrapper, table);
    wrapper.appendChild(summary);
    wrapper.appendChild(table);
  });
}

function decorateSeverityMarkers(root) {
  if (!root) return;

  root.querySelectorAll("table tbody tr").forEach((row) => {
    const cell = row.cells[0];
    if (!cell) return;
    const text = cell.textContent.trim().toLowerCase();
    if (SEVERITY_META[text]) {
      cell.innerHTML = severityBadge(text);
    }
  });

  root.querySelectorAll("h3, h4").forEach((heading) => {
    heading.innerHTML = heading.innerHTML.replace(
      /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/gi,
      (_, sev) => severityBadge(sev.toLowerCase())
    );
  });

  root.querySelectorAll("p, li").forEach((el) => {
    if (el.closest(".report-dashboard")) return;
    const html = el.innerHTML;
    if (!/\*\*(Critical|High|Medium|Low)\*\*/i.test(html) && !/\bCRITICAL\b/.test(html)) return;
    el.innerHTML = html.replace(
      /\*\*(Critical|High|Medium|Low|Info)\*\*/gi,
      (_, s) => severityBadge(s.toLowerCase())
    );
  });
}

function enhanceReportArticle(article, json) {
  if (!article) return;
  decorateSeverityMarkers(article);
  wrapCollapsibleBlocks(article);
}

function buildExportHtmlDocument(json, articleHtml) {
  const d = buildDashboardFromJson(json);
  const sev = d.severity || {};
  const dashCards = ["critical", "high", "medium", "low", "info"]
    .map(
      (name) =>
        `<div class="sev-card sev-${name}"><strong>${sev[name] || 0}</strong>${name}</div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>${escapeHtml(d.program_name)} — Report</title>
<style>
body{font-family:"Segoe UI",Arial,sans-serif;margin:2rem;color:#0f172a;line-height:1.55;max-width:960px}
.dashboard{background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:1.25rem;margin-bottom:2rem}
.sev-grid{display:flex;flex-wrap:wrap;gap:.5rem}.sev-card{flex:1;min-width:80px;padding:.5rem;border-radius:8px;text-align:center}
.sev-critical{background:#fef2f2;color:#991b1b}.sev-high{background:#fff7ed;color:#9a3412}
.sev-medium{background:#fffbeb;color:#92400e}.sev-low{background:#f0fdf4;color:#166534}.sev-info{background:#f1f5f9}
.sev-badge{display:inline-block;padding:.15rem .45rem;border-radius:999px;font-size:.7rem;font-weight:700;color:#fff}
.sev-badge-critical{background:#dc2626}.sev-badge-high{background:#ea580c}.sev-badge-medium{background:#d97706}
.sev-badge-low{background:#059669}.sev-badge-info{background:#64748b}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #e2e8f0;padding:.4rem}
pre{background:#f1f5f9;padding:.75rem;font-size:.85rem}
</style></head><body>
<h1>${escapeHtml(d.program_name)}</h1>
<p><em>Upload to Google Drive → Open with Google Docs</em></p>
<section class="dashboard"><h2>Report dashboard</h2>
<p><strong>Date:</strong> ${escapeHtml(d.generated_display || "")} · <strong>Mode:</strong> ${escapeHtml(
    (d.scan_mode || "").toUpperCase()
  )}</p>
<p>${d.actionable_total} actionable finding(s) · ${d.target_count} surfaces</p>
<div class="sev-grid">${dashCards}</div></section>
<div class="report-body">${articleHtml || ""}</div>
</body></html>`;
}

function downloadExportHtml(json, articleHtml, reportId) {
  const doc = buildExportHtmlDocument(json, articleHtml);
  const blob = new Blob([doc], { type: "text/html;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${reportId || "ig88-report"}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

window.IG88ReportViewer = {
  severityBadge,
  buildDashboardFromJson,
  renderReportDashboard,
  enhanceReportArticle,
  buildExportHtmlDocument,
  downloadExportHtml,
};

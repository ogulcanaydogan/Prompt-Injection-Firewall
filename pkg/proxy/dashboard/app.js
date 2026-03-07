const apiPrefix = window.PIF_DASHBOARD_API_PREFIX || "/api/dashboard";
const refreshSeconds = Number(window.PIF_DASHBOARD_REFRESH_SECONDS || "5");

const historyState = {
  requests: [],
  detections: [],
  maxPoints: 60,
};

const statusPill = document.getElementById("status-pill");
const refreshPill = document.getElementById("refresh-pill");

const fields = {
  totalRequests: document.getElementById("total-requests"),
  totalInjections: document.getElementById("total-injections"),
  totalRateLimit: document.getElementById("total-ratelimit"),
  scanP95: document.getElementById("scan-p95"),
  lastRefresh: document.getElementById("last-refresh"),
};

refreshPill.textContent = `Refresh: ${refreshSeconds}s`;

async function fetchJSON(path) {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function addHistoryPoint(series, value) {
  series.push(Number(value || 0));
  if (series.length > historyState.maxPoints) {
    series.shift();
  }
}

function drawLineChart(canvasId, points, color) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(26,45,43,0.18)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, height - 16);
  ctx.lineTo(width, height - 16);
  ctx.stroke();

  if (points.length === 0) {
    return;
  }

  const max = Math.max(...points, 1);
  const step = points.length > 1 ? width / (points.length - 1) : width;

  ctx.beginPath();
  ctx.lineWidth = 2;
  ctx.strokeStyle = color;
  points.forEach((value, index) => {
    const x = step * index;
    const normalized = value / max;
    const y = (height - 24) - normalized * (height - 36);
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();
}

function renderRules(ruleSets) {
  const tbody = document.getElementById("rules-body");
  if (!tbody) return;

  if (!Array.isArray(ruleSets) || ruleSets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3">No rule set metadata available.</td></tr>`;
    return;
  }

  tbody.innerHTML = ruleSets
    .map((rs) => {
      const version = rs.version || "-";
      return `<tr>
        <td>${escapeHtml(rs.name || "-")}</td>
        <td>${escapeHtml(version)}</td>
        <td>${Number(rs.rule_count || 0)}</td>
      </tr>`;
    })
    .join("");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setHealthyStatus(text) {
  statusPill.textContent = text;
  statusPill.classList.remove("error");
}

function setErrorStatus(text) {
  statusPill.textContent = text;
  statusPill.classList.add("error");
}

async function refreshDashboard() {
  try {
    const [summary, metrics, rules] = await Promise.all([
      fetchJSON(`${apiPrefix}/summary`),
      fetchJSON(`${apiPrefix}/metrics`),
      fetchJSON(`${apiPrefix}/rules`),
    ]);

    fields.totalRequests.textContent = Number(summary?.totals?.requests || 0).toLocaleString();
    fields.totalInjections.textContent = Number(summary?.totals?.injections || 0).toLocaleString();
    fields.totalRateLimit.textContent = Number(summary?.totals?.rate_limit_events || 0).toLocaleString();
    fields.scanP95.textContent = Number(summary?.p95_scan_duration_seconds || 0).toFixed(4);

    const generatedAt = metrics?.generated_at || new Date().toISOString();
    fields.lastRefresh.textContent = new Date(generatedAt).toLocaleTimeString();

    addHistoryPoint(historyState.requests, metrics?.total_requests || 0);
    addHistoryPoint(historyState.detections, metrics?.total_injection_detections || 0);
    drawLineChart("requests-chart", historyState.requests, "#007c6f");
    drawLineChart("detections-chart", historyState.detections, "#cc5300");
    renderRules(rules?.rule_sets || []);

    setHealthyStatus(`Live - uptime ${Math.max(0, Number(summary?.uptime_seconds || 0))}s`);
  } catch (error) {
    setErrorStatus(`Degraded: ${error.message}`);
  }
}

refreshDashboard();
window.setInterval(refreshDashboard, Math.max(1, refreshSeconds) * 1000);

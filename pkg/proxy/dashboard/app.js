const apiPrefix = window.PIF_DASHBOARD_API_PREFIX || "/api/dashboard";
const refreshSeconds = Number(window.PIF_DASHBOARD_REFRESH_SECONDS || "5");

const historyState = {
  requests: [],
  detections: [],
  maxPoints: 60,
};

const appState = {
  editingRuleID: "",
  latestRules: [],
  ruleManagement: {
    enabled: false,
    writable: false,
    managedPath: "",
  },
};

const statusPill = document.getElementById("status-pill");
const refreshPill = document.getElementById("refresh-pill");
const writePill = document.getElementById("write-pill");

const fields = {
  totalRequests: document.getElementById("total-requests"),
  totalInjections: document.getElementById("total-injections"),
  totalRateLimit: document.getElementById("total-ratelimit"),
  scanP95: document.getElementById("scan-p95"),
  lastRefresh: document.getElementById("last-refresh"),
};

const ruleForm = document.getElementById("rule-form");
const managedRulesBody = document.getElementById("managed-rules-body");
const managedPathText = document.getElementById("managed-path");
const ruleWriteNote = document.getElementById("rule-write-note");
const ruleSaveBtn = document.getElementById("rule-save-btn");
const ruleClearBtn = document.getElementById("rule-clear-btn");

refreshPill.textContent = `Refresh: ${refreshSeconds}s`;

async function fetchJSON(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `${response.status} ${response.statusText}`);
  }

  if (response.status === 204) {
    return null;
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

function renderManagedRules(rules) {
  if (!managedRulesBody) return;

  if (!Array.isArray(rules) || rules.length === 0) {
    managedRulesBody.innerHTML = `<tr><td colspan="5">No managed custom rules.</td></tr>`;
    return;
  }

  managedRulesBody.innerHTML = rules
    .map((rule) => {
      const safeID = escapeHtml(rule.id || "-");
      return `<tr>
        <td>${safeID}</td>
        <td>${escapeHtml(rule.category || "-")}</td>
        <td>${Number(rule.severity || 0)}</td>
        <td>${rule.enabled ? "yes" : "no"}</td>
        <td>
          <button type="button" data-action="edit" data-id="${safeID}">Edit</button>
          <button type="button" class="danger" data-action="delete" data-id="${safeID}">Delete</button>
        </td>
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

function updateRuleManagementStatus(ruleResponse) {
  const status = ruleResponse?.rule_management || {};
  appState.ruleManagement = {
    enabled: Boolean(status.enabled),
    writable: Boolean(status.writable),
    managedPath: status.managed_path || "-",
  };
  appState.latestRules = Array.isArray(ruleResponse?.managed_rules) ? ruleResponse.managed_rules : [];

  const { enabled, writable, managedPath } = appState.ruleManagement;
  managedPathText.textContent = `Path: ${managedPath}`;

  if (!enabled) {
    writePill.textContent = "Rule write: disabled";
    ruleWriteNote.textContent = "Rule management feature is disabled in config.";
  } else if (!writable) {
    writePill.textContent = "Rule write: forbidden";
    ruleWriteNote.textContent = "Rule management requires dashboard auth (enabled + valid Basic Auth).";
  } else {
    writePill.textContent = "Rule write: enabled";
    ruleWriteNote.textContent = "Custom rules are writable. Changes apply immediately after save.";
  }

  const canWrite = enabled && writable;
  for (const element of ruleForm.elements) {
    element.disabled = !canWrite;
  }
}

function setFormMode(id) {
  appState.editingRuleID = id || "";
  ruleSaveBtn.textContent = appState.editingRuleID ? "Update Rule" : "Create Rule";
}

function resetRuleForm() {
  ruleForm.reset();
  document.getElementById("rule-severity").value = "2";
  document.getElementById("rule-enabled").checked = true;
  setFormMode("");
}

function fillRuleForm(rule) {
  document.getElementById("rule-id").value = rule.id || "";
  document.getElementById("rule-name").value = rule.name || "";
  document.getElementById("rule-category").value = rule.category || "";
  document.getElementById("rule-severity").value = String(Number(rule.severity || 0));
  document.getElementById("rule-pattern").value = rule.pattern || "";
  document.getElementById("rule-description").value = rule.description || "";
  document.getElementById("rule-enabled").checked = Boolean(rule.enabled);
  setFormMode(rule.id || "");
}

function buildRuleFromForm() {
  return {
    id: document.getElementById("rule-id").value.trim(),
    name: document.getElementById("rule-name").value.trim(),
    category: document.getElementById("rule-category").value.trim(),
    severity: Number(document.getElementById("rule-severity").value),
    pattern: document.getElementById("rule-pattern").value,
    description: document.getElementById("rule-description").value.trim(),
    enabled: Boolean(document.getElementById("rule-enabled").checked),
    case_sensitive: false,
    tags: [],
    metadata: {},
  };
}

async function submitRuleForm(event) {
  event.preventDefault();
  if (!appState.ruleManagement.enabled || !appState.ruleManagement.writable) {
    setErrorStatus("Rule write is not allowed in current dashboard configuration");
    return;
  }

  try {
    const rule = buildRuleFromForm();
    if (!rule.id) {
      throw new Error("rule id is required");
    }

    if (appState.editingRuleID) {
      await fetchJSON(`${apiPrefix}/rules/${encodeURIComponent(appState.editingRuleID)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule }),
      });
    } else {
      await fetchJSON(`${apiPrefix}/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule }),
      });
    }

    resetRuleForm();
    await refreshDashboard();
  } catch (error) {
    setErrorStatus(`Degraded: ${error.message}`);
  }
}

async function onManagedRuleAction(event) {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) {
    return;
  }

  const action = target.dataset.action;
  const id = target.dataset.id;
  if (!action || !id) {
    return;
  }

  const selected = appState.latestRules.find((r) => r.id === id);
  if (!selected) {
    return;
  }

  if (action === "edit") {
    fillRuleForm(selected);
    return;
  }

  if (action === "delete") {
    if (!appState.ruleManagement.enabled || !appState.ruleManagement.writable) {
      setErrorStatus("Rule delete is not allowed in current dashboard configuration");
      return;
    }

    try {
      await fetchJSON(`${apiPrefix}/rules/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (appState.editingRuleID === id) {
        resetRuleForm();
      }
      await refreshDashboard();
    } catch (error) {
      setErrorStatus(`Degraded: ${error.message}`);
    }
  }
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
    updateRuleManagementStatus(rules || {});
    renderManagedRules(rules?.managed_rules || []);

    setHealthyStatus(`Live - uptime ${Math.max(0, Number(summary?.uptime_seconds || 0))}s`);
  } catch (error) {
    setErrorStatus(`Degraded: ${error.message}`);
  }
}

ruleForm.addEventListener("submit", submitRuleForm);
ruleClearBtn.addEventListener("click", () => resetRuleForm());
managedRulesBody.addEventListener("click", onManagedRuleAction);

resetRuleForm();
refreshDashboard();
window.setInterval(refreshDashboard, Math.max(1, refreshSeconds) * 1000);

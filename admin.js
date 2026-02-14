const loginSection = document.getElementById("loginSection");
const panelSection = document.getElementById("panelSection");
const loginForm = document.getElementById("loginForm");
const loginStatus = document.getElementById("loginStatus");
const panelStatus = document.getElementById("panelStatus");
const adminTableBody = document.getElementById("adminTableBody");
const auditTableBody = document.getElementById("auditTableBody");
const signatureViewerSection = document.getElementById("signatureViewerSection");
const closeSignatureViewer = document.getElementById("closeSignatureViewer");
const signatureMeta = document.getElementById("signatureMeta");
const signaturePreview = document.getElementById("signaturePreview");
const signatureDownloadLink = document.getElementById("signatureDownloadLink");

const logoutButton = document.getElementById("logoutButton");
const refreshButton = document.getElementById("refreshButton");
const exportButton = document.getElementById("exportButton");
const showTableButton = document.getElementById("showTableButton");
const showBoardButton = document.getElementById("showBoardButton");
const tableView = document.getElementById("tableView");
const boardView = document.getElementById("boardView");

const filterDateFrom = document.getElementById("filterDateFrom");
const filterDateTo = document.getElementById("filterDateTo");
const filterRequester = document.getElementById("filterRequester");
const filterAssignee = document.getElementById("filterAssignee");
const filterState = document.getElementById("filterState");
const filterPriority = document.getElementById("filterPriority");
const filterMinOpenHours = document.getElementById("filterMinOpenHours");
const applyFiltersButton = document.getElementById("applyFiltersButton");
const clearFiltersButton = document.getElementById("clearFiltersButton");

const sumTotal = document.getElementById("sumTotal");
const sumOpen = document.getElementById("sumOpen");
const sumWip = document.getElementById("sumWip");
const sumPending = document.getElementById("sumPending");
const sumAwaiting = document.getElementById("sumAwaiting");
const sumResolved = document.getElementById("sumResolved");
const sumClosed = document.getElementById("sumClosed");
const sumAssign = document.getElementById("sumAssign");
const sumResolution = document.getElementById("sumResolution");

const colOpen = document.getElementById("colOpen");
const colWip = document.getElementById("colWip");
const colPending = document.getElementById("colPending");
const colAwaiting = document.getElementById("colAwaiting");
const colResolved = document.getElementById("colResolved");
const colClosed = document.getElementById("colClosed");

let departments = {};
let requestsCache = [];
let auditLogsCache = [];
let activeView = "table";

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function asArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value && Array.isArray(value.rows)) {
    return value.rows;
  }
  if (value && Array.isArray(value.requests)) {
    return value.requests;
  }
  if (value && Array.isArray(value.items)) {
    return value.items;
  }
  return [];
}

function isResolvedState(status) {
  return status === "Resolved" || status === "Closed";
}

function durationMs(request) {
  const start = new Date(request.createdAt).getTime();
  const end = isResolvedState(request.status)
    ? new Date(request.resolvedAt || request.updatedAt || request.createdAt).getTime()
    : Date.now();
  return Math.max(0, end - start);
}

function unresolvedHours(request) {
  if (isResolvedState(request.status)) {
    return 0;
  }
  return durationMs(request) / (1000 * 60 * 60);
}

function formatDuration(request) {
  const totalMinutes = Math.floor(durationMs(request) / (1000 * 60));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;
  const prefix = isResolvedState(request.status) ? "Resolved in" : "Open for";
  return `${prefix} ${days}d ${hours}h ${minutes}m`;
}

function formatTrackedMinutes(totalMinutesValue) {
  const totalMinutes = Number.parseInt(String(totalMinutesValue || 0), 10);
  if (!Number.isInteger(totalMinutes) || totalMinutes <= 0) {
    return "0m";
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) {
    return `${minutes}m`;
  }
  return `${hours}h ${minutes}m`;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function hasRequesterSignoff(request) {
  if (Object.prototype.hasOwnProperty.call(request, "hasSignature")) {
    return request.hasSignature === true || request.hasSignature === 1 || request.hasSignature === "1";
  }

  return (
    request.requesterSignedOff === true
    || request.requesterSignedOff === 1
    || request.requesterSignedOff === "1"
    || Boolean(request.requesterSignedOffAt)
    || Boolean(request.requesterSignedOffName)
  );
}

function slaClass(request) {
  const hours = unresolvedHours(request);
  if (isResolvedState(request.status)) {
    return "sla-ok";
  }
  if (hours >= 48) {
    return "sla-critical";
  }
  if (hours >= 24) {
    return "sla-warning";
  }
  return "sla-ok";
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || "Request failed.");
  }
  return body;
}

async function checkSession() {
  const session = await fetchJson("/api/admin/session");
  return session.authenticated;
}

async function login(password) {
  await fetchJson("/api/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

async function logout() {
  const response = await fetch("/api/admin/logout", { method: "POST" });
  if (!response.ok) {
    throw new Error("Failed to logout.");
  }
}

async function loadDepartments() {
  const data = await fetchJson("/api/admin/departments");
  if (data && typeof data === "object" && !Array.isArray(data)) {
    return data;
  }
  return {};
}

async function loadAuditLogs() {
  const data = await fetchJson("/api/admin/audit-logs?limit=120");
  return asArray(data);
}

async function loadRequests() {
  const data = await fetchJson("/api/admin/requests");
  return asArray(data);
}

async function loadMetrics() {
  return fetchJson("/api/admin/metrics");
}

async function loadSignature(requestId) {
  return fetchJson(`/api/admin/requests/${requestId}/signature`);
}

function departmentOptions(selectedDepartment) {
  const keys = Object.keys(departments);
  if (keys.length === 0) {
    return "<option value=''>No departments</option>";
  }

  return keys
    .map((department) => {
      const selected = department === selectedDepartment ? "selected" : "";
      return `<option value="${escapeHtml(department)}" ${selected}>${escapeHtml(department)}</option>`;
    })
    .join("");
}

function memberOptions(department, selectedMemberUsername) {
  const members = departments[department] || [];
  if (members.length === 0) {
    return "<option value=''>No active workers</option>";
  }

  return members
    .map((member) => {
      const selected = member.username === selectedMemberUsername ? "selected" : "";
      return `<option value="${escapeHtml(member.username)}" ${selected}>${escapeHtml(member.fullName)} (${escapeHtml(member.username)})</option>`;
    })
    .join("");
}

function statusOptions(selectedStatus, currentTicketStatus) {
  const statuses = ["Work In Progress", "Pending", "Awaiting Signoff"];
  if (currentTicketStatus === "Resolved" || selectedStatus === "Closed") {
    statuses.push("Closed");
  }
  return statuses
    .map((status) => {
      const selected = status === selectedStatus ? "selected" : "";
      return `<option value="${escapeHtml(status)}" ${selected}>${escapeHtml(status)}</option>`;
    })
    .join("");
}

function updateAssigneeFilterOptions(requests) {
  const safeRequests = asArray(requests);
  const currentValue = filterAssignee.value;
  const assignees = [...new Set(safeRequests.map((request) => request?.assignedUserName || request?.assignedUser).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right));

  filterAssignee.innerHTML = '<option value="">All</option>';
  assignees.forEach((assignee) => {
    const option = document.createElement("option");
    option.value = assignee;
    option.textContent = assignee;
    filterAssignee.appendChild(option);
  });

  if (assignees.includes(currentValue)) {
    filterAssignee.value = currentValue;
  }
}

function applyFilters(requests) {
  const safeRequests = asArray(requests);
  const fromDate = filterDateFrom.value ? new Date(`${filterDateFrom.value}T00:00:00`).getTime() : null;
  const toDate = filterDateTo.value ? new Date(`${filterDateTo.value}T23:59:59`).getTime() : null;
  const requesterText = filterRequester.value.trim().toLowerCase();
  const assignee = filterAssignee.value;
  const state = filterState.value;
  const priority = filterPriority.value;
  const minOpenHours = Number.parseFloat(filterMinOpenHours.value || "0");

  return safeRequests.filter((request) => {
    const createdAtMs = new Date(request.createdAt).getTime();
    if (fromDate && createdAtMs < fromDate) {
      return false;
    }
    if (toDate && createdAtMs > toDate) {
      return false;
    }

    if (requesterText) {
      const haystack = `${request.name} ${request.email} ${request.ticketKey || ""}`.toLowerCase();
      if (!haystack.includes(requesterText)) {
        return false;
      }
    }

    const requestAssignee = request.assignedUserName || request.assignedUser || "";
    if (assignee && requestAssignee !== assignee) {
      return false;
    }

    if (state && request.status !== state) {
      return false;
    }

    if (priority && request.priority !== priority) {
      return false;
    }

    if (Number.isFinite(minOpenHours) && minOpenHours > 0) {
      if (isResolvedState(request.status) || unresolvedHours(request) < minOpenHours) {
        return false;
      }
    }

    return true;
  });
}

function renderSummaryFromMetrics(metrics) {
  const safeMetrics = metrics || {};
  sumTotal.textContent = String(safeMetrics.total || 0);
  sumOpen.textContent = String(safeMetrics.stateCounts?.Open || 0);
  sumWip.textContent = String(safeMetrics.stateCounts?.["Work In Progress"] || 0);
  sumPending.textContent = String(safeMetrics.stateCounts?.Pending || 0);
  sumAwaiting.textContent = String(safeMetrics.stateCounts?.["Awaiting Signoff"] || 0);
  sumResolved.textContent = String(safeMetrics.stateCounts?.Resolved || 0);
  sumClosed.textContent = String(safeMetrics.stateCounts?.Closed || 0);
  sumAssign.textContent = `${safeMetrics.avgAssignmentMinutes || 0}m`;
  sumResolution.textContent = `${safeMetrics.avgResolutionHours || 0}h`;
}

function renderAuditLogs() {
  auditTableBody.innerHTML = "";

  if (auditLogsCache.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="5" class="empty">No audit events recorded yet.</td>';
    auditTableBody.appendChild(row);
    return;
  }

  auditLogsCache.forEach((log) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(formatDate(log.createdAt))}</td>
      <td>${escapeHtml(log.actorRole)} / ${escapeHtml(log.actorIdentifier)}</td>
      <td>${escapeHtml(log.action)}</td>
      <td>${escapeHtml(log.targetType)} ${escapeHtml(log.targetId || "")}</td>
      <td>${escapeHtml(log.metadata || "")}</td>
    `;
    auditTableBody.appendChild(row);
  });
}

function renderRows(requests) {
  const safeRequests = asArray(requests);
  adminTableBody.innerHTML = "";

  if (safeRequests.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="7" class="empty">No requests found for this filter set.</td>';
    adminTableBody.appendChild(row);
    return;
  }

  let renderedCount = 0;

  safeRequests.forEach((request) => {
    const row = document.createElement("tr");
    try {
      const availableDepartments = Object.keys(departments);
      const safeStatus = String(request.status || "Open");
      const requestedDepartment = request.assignedDepartment || request.department;
      const department = availableDepartments.includes(requestedDepartment)
        ? requestedDepartment
        : (availableDepartments[0] || "");
      const selectableStatuses = new Set(["Work In Progress", "Pending", "Awaiting Signoff", "Closed"]);
      const currentStatus = selectableStatuses.has(safeStatus) ? safeStatus : "Work In Progress";
      const canViewSignature = hasRequesterSignoff(request);

      row.innerHTML = `
        <td>
          <strong>${escapeHtml(request.ticketKey || `#${request.id}`)}</strong><br>
          #${request.id}
        </td>
        <td>
          <strong>${escapeHtml(request.name)}</strong><br>
          ${escapeHtml(request.email)}
        </td>
        <td>
          Dept: ${escapeHtml(request.department)}<br>
          Pri: ${escapeHtml(request.priority)}<br>
          Ch: ${escapeHtml(request.channel || "-")}<br>
          Cat: ${escapeHtml(request.category || "-")} / Impact: ${escapeHtml(request.impact || "-")}
        </td>
        <td>
          <span class="pill state-${escapeHtml(safeStatus.replace(/\s+/g, "-").toLowerCase())}">${escapeHtml(safeStatus)}</span>
        </td>
        <td>${escapeHtml(request.assignedDepartment || "-")} / ${escapeHtml(request.assignedUserName || request.assignedUser || "-")}</td>
        <td>
          <span class="pill ${slaClass(request)}">${formatDuration(request)}</span><br>
          Created: ${escapeHtml(formatDate(request.createdAt))}<br>
          <small>Time logged: ${escapeHtml(formatTrackedMinutes(request.totalTimeSpentMinutes))}</small>
        </td>
        <td>
          <label>
            Assign Dept
            <select data-role="department" data-id="${request.id}">
              ${departmentOptions(department)}
            </select>
          </label>
          <label>
            Assign Worker
            <select data-role="assignee" data-id="${request.id}">
              ${memberOptions(department, request.assignedUser || "")}
            </select>
          </label>
          <div class="actions compact">
            <button type="button" data-role="assign" data-id="${request.id}">Assign</button>
          </div>
          <label>
            Update State
            <select data-role="status" data-id="${request.id}">
              ${statusOptions(currentStatus, safeStatus)}
            </select>
          </label>
          <label>
            Update Note
            <input data-role="note" data-id="${request.id}" type="text" placeholder="Add update note" />
          </label>
          <div class="actions compact">
            <button type="button" data-role="update-status" data-id="${request.id}">Update</button>
            ${canViewSignature ? `<button type="button" data-role="view-signature" data-id="${request.id}">View Signature</button>` : ""}
          </div>
        </td>
      `;
      adminTableBody.appendChild(row);
      renderedCount += 1;
    } catch (error) {
      row.innerHTML = `
        <td><strong>${escapeHtml(request.ticketKey || `#${request.id}`)}</strong><br>#${escapeHtml(String(request.id || "-"))}</td>
        <td>${escapeHtml(request.name || "-")}<br>${escapeHtml(request.email || "-")}</td>
        <td>${escapeHtml(request.department || "-")} / ${escapeHtml(request.priority || "-")}</td>
        <td>${escapeHtml(String(request.status || "Open"))}</td>
        <td>${escapeHtml(request.assignedUserName || request.assignedUser || "-")}</td>
        <td>${escapeHtml(formatDate(request.createdAt))}</td>
        <td>Fallback row rendered.</td>
      `;
      adminTableBody.appendChild(row);
      renderedCount += 1;
      panelStatus.textContent = `Rendered with fallback for one or more tickets: ${error?.message || "unknown error"}`;
    }
  });

  return renderedCount;
}

function renderBoard(requests) {
  const safeRequests = asArray(requests);
  const columns = {
    Open: colOpen,
    "Work In Progress": colWip,
    Pending: colPending,
    "Awaiting Signoff": colAwaiting,
    Resolved: colResolved,
    Closed: colClosed,
  };

  Object.values(columns).forEach((column) => {
    column.innerHTML = "";
  });

  safeRequests.forEach((request) => {
    const target = columns[request.status] || colOpen;
    const card = document.createElement("article");
    card.className = `board-card ${slaClass(request)}`;
    card.innerHTML = `
      <strong>${escapeHtml(request.ticketKey || `#${request.id}`)}</strong>
      <span>${escapeHtml(request.name)}</span>
      <span>${escapeHtml(request.priority)} · ${escapeHtml(request.category || "General")}</span>
      <span>${escapeHtml(request.assignedUserName || request.assignedUser || "Unassigned")}</span>
      <span>Time logged: ${escapeHtml(formatTrackedMinutes(request.totalTimeSpentMinutes))}</span>
      <span>${escapeHtml(formatDuration(request))}</span>
    `;
    target.appendChild(card);
  });
}

function setView(isAuthenticated) {
  if (isAuthenticated) {
    loginSection.classList.add("hidden");
    panelSection.classList.remove("hidden");
  } else {
    panelSection.classList.add("hidden");
    loginSection.classList.remove("hidden");
  }
}

function updateViewButtons() {
  if (activeView === "table") {
    tableView.classList.remove("hidden");
    boardView.classList.add("hidden");
    showTableButton.classList.remove("secondary");
    showBoardButton.classList.add("secondary");
  } else {
    tableView.classList.add("hidden");
    boardView.classList.remove("hidden");
    showBoardButton.classList.remove("secondary");
    showTableButton.classList.add("secondary");
  }
}

async function refreshPanel() {
  const [requestsResult, metricsResult, departmentsResult, auditResult] = await Promise.allSettled([
    loadRequests(),
    loadMetrics(),
    loadDepartments(),
    loadAuditLogs(),
  ]);

  if (departmentsResult.status === "fulfilled") {
    departments = departmentsResult.value || {};
  } else {
    departments = {};
  }

  if (auditResult.status === "fulfilled") {
    auditLogsCache = asArray(auditResult.value);
    renderAuditLogs();
  } else {
    auditLogsCache = [];
    renderAuditLogs();
  }

  if (requestsResult.status === "fulfilled") {
    requestsCache = asArray(requestsResult.value);
    updateAssigneeFilterOptions(requestsCache);
    let filtered = applyFilters(requestsCache);

    if (requestsCache.length > 0 && filtered.length === 0) {
      clearFilters();
      filtered = applyFilters(requestsCache);
      panelStatus.textContent = "Filters were reset automatically to show available tickets.";
    }

    const renderedRowCount = renderRows(filtered);
    renderBoard(filtered);

    if (metricsResult.status === "fulfilled") {
      renderSummaryFromMetrics(metricsResult.value);
    }

    if (!panelStatus.textContent) {
      panelStatus.textContent = `Loaded ${filtered.length} filtered ticket(s). Rendered rows: ${renderedRowCount}.`;
    }
    return;
  }

  requestsCache = [];
  renderRows([]);
  renderBoard([]);
  panelStatus.textContent = `Failed to load requests: ${requestsResult.reason?.message || "Unknown error."}`;
}

function clearFilters() {
  filterDateFrom.value = "";
  filterDateTo.value = "";
  filterRequester.value = "";
  filterAssignee.value = "";
  filterState.value = "";
  filterPriority.value = "";
  filterMinOpenHours.value = "";
}

function toCsvValue(value) {
  const text = String(value ?? "").replace(/"/g, '""');
  return `"${text}"`;
}

function exportCsv(requests) {
  const headers = [
    "ticketKey", "id", "name", "email", "department", "priority", "channel", "category", "impact",
    "status", "assignedDepartment", "assignedUser", "assignedUserName", "createdAt", "updatedAt", "resolvedAt",
  ];

  const lines = [headers.join(",")];
  requests.forEach((request) => {
    const row = headers.map((header) => toCsvValue(request[header] || ""));
    lines.push(row.join(","));
  });

  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `service-desk-export-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = document.getElementById("adminPassword").value;

  try {
    await login(password);
    setView(true);
    await refreshPanel();
    loginStatus.textContent = "";
  } catch (error) {
    loginStatus.textContent = error.message;
  }
});

logoutButton.addEventListener("click", async () => {
  try {
    await logout();
    setView(false);
    panelStatus.textContent = "";
    loginStatus.textContent = "Logged out.";
  } catch (error) {
    panelStatus.textContent = error.message;
  }
});

refreshButton.addEventListener("click", async () => {
  try {
    await refreshPanel();
  } catch (error) {
    panelStatus.textContent = error.message;
  }
});

exportButton.addEventListener("click", () => {
  const filtered = applyFilters(requestsCache);
  exportCsv(filtered);
});

showTableButton.addEventListener("click", () => {
  activeView = "table";
  updateViewButtons();
});

showBoardButton.addEventListener("click", () => {
  activeView = "board";
  updateViewButtons();
});

applyFiltersButton.addEventListener("click", () => {
  const filtered = applyFilters(requestsCache);
  renderRows(filtered);
  renderBoard(filtered);
  panelStatus.textContent = `Showing ${filtered.length} ticket(s) after filters.`;
});

clearFiltersButton.addEventListener("click", () => {
  clearFilters();
  const filtered = applyFilters(requestsCache);
  renderRows(filtered);
  renderBoard(filtered);
  panelStatus.textContent = "Filters reset.";
});

closeSignatureViewer.addEventListener("click", () => {
  signatureViewerSection.classList.add("hidden");
});

adminTableBody.addEventListener("change", (event) => {
  const target = event.target;
  if (target.dataset.role !== "department") {
    return;
  }

  const requestId = target.dataset.id;
  const assigneeSelect = adminTableBody.querySelector(`select[data-role='assignee'][data-id='${requestId}']`);
  if (!assigneeSelect) {
    return;
  }

  assigneeSelect.innerHTML = memberOptions(target.value, "");
});

adminTableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) {
    return;
  }

  const requestId = button.dataset.id;

  try {
    if (button.dataset.role === "assign") {
      const department = adminTableBody.querySelector(`select[data-role='department'][data-id='${requestId}']`).value;
      const assigneeUsername = adminTableBody.querySelector(`select[data-role='assignee'][data-id='${requestId}']`).value;

      await fetchJson(`/api/admin/requests/${requestId}/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ department, assigneeUsername }),
      });

      panelStatus.textContent = `Ticket #${requestId} assigned.`;
      await refreshPanel();
      return;
    }

    if (button.dataset.role === "update-status") {
      const status = adminTableBody.querySelector(`select[data-role='status'][data-id='${requestId}']`).value;
      const note = adminTableBody.querySelector(`input[data-role='note'][data-id='${requestId}']`).value;

      await fetchJson(`/api/admin/requests/${requestId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, note }),
      });

      panelStatus.textContent = `Ticket #${requestId} updated to ${status}.`;
      await refreshPanel();
    }

    if (button.dataset.role === "view-signature") {
      panelStatus.textContent = `Loading signature for ticket #${requestId}...`;
      const signature = await loadSignature(requestId);
      signaturePreview.src = signature.signatureDataUrl;
      signatureDownloadLink.href = signature.signatureDataUrl;
      signatureDownloadLink.download = `${signature.ticketKey || `request-${requestId}`}-signature.png`;
      signatureMeta.textContent = `${signature.ticketKey || `#${requestId}`} · Signed by ${signature.signerName || "Unknown"} · ${formatDate(signature.signedAt)}`;
      signatureViewerSection.classList.remove("hidden");
      signatureViewerSection.scrollIntoView({ behavior: "smooth", block: "start" });
      panelStatus.textContent = `Loaded signature for ticket #${requestId}.`;
    }
  } catch (error) {
    panelStatus.textContent = error.message;
  }
});

(async function init() {
  updateViewButtons();

  try {
    const isAuthenticated = await checkSession();
    setView(isAuthenticated);

    if (isAuthenticated) {
      await refreshPanel();
    }
  } catch {
    setView(false);
    loginStatus.textContent = "Unable to verify admin session.";
  }
})();

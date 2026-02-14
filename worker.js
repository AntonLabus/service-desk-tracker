const workerLoginSection = document.getElementById("workerLoginSection");
const workerPasswordSection = document.getElementById("workerPasswordSection");
const workerPanelSection = document.getElementById("workerPanelSection");
const workerLoginForm = document.getElementById("workerLoginForm");
const workerPasswordForm = document.getElementById("workerPasswordForm");
const workerLoginStatus = document.getElementById("workerLoginStatus");
const workerPasswordStatus = document.getElementById("workerPasswordStatus");
const workerPanelStatus = document.getElementById("workerPanelStatus");
const workerRequestsBody = document.getElementById("workerRequestsBody");
const workerWelcome = document.getElementById("workerWelcome");
const workerRefreshButton = document.getElementById("workerRefreshButton");
const workerLogoutButton = document.getElementById("workerLogoutButton");

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function formatAge(createdAt) {
  const ms = Math.max(0, Date.now() - new Date(createdAt).getTime());
  const totalMinutes = Math.floor(ms / (1000 * 60));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;
  return `${days}d ${hours}h ${minutes}m`;
}

function formatMinutes(totalMinutesValue) {
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

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || "Request failed.");
  }
  return body;
}

function setView(mode) {
  const isLogin = mode === "login";
  const isPassword = mode === "password";
  const isPanel = mode === "panel";

  if (isPanel) {
    workerLoginSection.classList.add("hidden");
    workerPasswordSection.classList.add("hidden");
    workerPanelSection.classList.remove("hidden");
    return;
  }

  if (isPassword) {
    workerLoginSection.classList.add("hidden");
    workerPasswordSection.classList.remove("hidden");
    workerPanelSection.classList.add("hidden");
    return;
  }

  if (isLogin) {
    workerPanelSection.classList.add("hidden");
    workerLoginSection.classList.remove("hidden");
    workerPasswordSection.classList.add("hidden");
  }
}

async function loadWorkerSession() {
  return fetchJson("/api/worker/session");
}

async function loginWorker(username, password) {
  return fetchJson("/api/worker/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

async function logoutWorker() {
  const response = await fetch("/api/worker/logout", { method: "POST" });
  if (!response.ok) {
    throw new Error("Logout failed.");
  }
}

async function loadWorkerRequests() {
  return fetchJson("/api/worker/requests");
}

async function updateWorkerRequestStatus(requestId, status, note, timeSpentMinutes) {
  return fetchJson(`/api/worker/requests/${requestId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, note, timeSpentMinutes }),
  });
}

async function changeWorkerPassword(currentPassword, newPassword) {
  return fetchJson("/api/worker/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
}

function statusOptions(currentStatus) {
  const statuses = ["Work In Progress", "Pending", "Awaiting Signoff"];
  return statuses
    .map((status) => {
      const selected = status === currentStatus ? "selected" : "";
      return `<option value="${escapeHtml(status)}" ${selected}>${escapeHtml(status)}</option>`;
    })
    .join("");
}

function renderRequests(requests) {
  workerRequestsBody.innerHTML = "";

  if (requests.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="6" class="empty">No requests assigned to you.</td>';
    workerRequestsBody.appendChild(row);
    return;
  }

  requests.forEach((request) => {
    const selectableStatuses = new Set(["Work In Progress", "Pending", "Awaiting Signoff"]);
    const currentStatus = selectableStatuses.has(request.status) ? request.status : "Work In Progress";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(request.ticketKey || `#${request.id}`)}</strong><br>#${request.id}</td>
      <td>${escapeHtml(request.name)}<br>${escapeHtml(request.email)}</td>
      <td>${escapeHtml(request.details)}<br><small>${escapeHtml(request.department)} · ${escapeHtml(request.priority)} · ${escapeHtml(request.category || "General")}</small></td>
      <td><span class="pill state-${escapeHtml(request.status.replace(/\s+/g, "-").toLowerCase())}">${escapeHtml(request.status)}</span></td>
      <td>${escapeHtml(formatAge(request.createdAt))}<br><small>${escapeHtml(formatDate(request.updatedAt))}</small><br><small>Total time: ${escapeHtml(formatMinutes(request.totalTimeSpentMinutes))}</small></td>
      <td>
        <label>
          Next State
          <select data-role="status" data-id="${request.id}">${statusOptions(currentStatus)}</select>
        </label>
        <label>
          Minutes Spent
          <input type="number" min="0" max="1440" step="1" data-role="time-spent" data-id="${request.id}" value="0" />
        </label>
        <label>
          Note
          <input type="text" data-role="note" data-id="${request.id}" placeholder="Progress update" />
        </label>
        <div class="actions compact">
          <button type="button" data-role="update" data-id="${request.id}">Save</button>
        </div>
      </td>
    `;
    workerRequestsBody.appendChild(row);
  });
}

async function refreshWorkerPanel() {
  const requests = await loadWorkerRequests();
  renderRequests(requests);
  workerPanelStatus.textContent = `Loaded ${requests.length} assigned request(s).`;
}

workerLoginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = document.getElementById("workerUsername").value.trim().toLowerCase();
  const password = document.getElementById("workerPassword").value;

  try {
    const session = await loginWorker(username, password);
    if (session.requirePasswordChange) {
      setView("password");
      workerPasswordStatus.textContent = "Password update required before continuing.";
      workerLoginStatus.textContent = "";
      return;
    }

    setView("panel");
    workerWelcome.textContent = `My Assigned Requests · ${session.fullName}`;
    workerLoginStatus.textContent = "";
    await refreshWorkerPanel();
  } catch (error) {
    workerLoginStatus.textContent = error.message;
  }
});

workerPasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const currentPassword = document.getElementById("workerCurrentPassword").value;
  const newPassword = document.getElementById("workerNewPassword").value;

  try {
    await changeWorkerPassword(currentPassword, newPassword);
    workerPasswordForm.reset();
    workerPasswordStatus.textContent = "Password updated. Loading your requests...";
    const session = await loadWorkerSession();
    setView("panel");
    workerWelcome.textContent = `My Assigned Requests · ${session.fullName}`;
    await refreshWorkerPanel();
  } catch (error) {
    workerPasswordStatus.textContent = error.message;
  }
});

workerLogoutButton.addEventListener("click", async () => {
  try {
    await logoutWorker();
    setView("login");
    workerPanelStatus.textContent = "";
    workerLoginStatus.textContent = "Logged out.";
  } catch (error) {
    workerPanelStatus.textContent = error.message;
  }
});

workerRefreshButton.addEventListener("click", async () => {
  try {
    await refreshWorkerPanel();
  } catch (error) {
    workerPanelStatus.textContent = error.message;
  }
});

workerRequestsBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button || button.dataset.role !== "update") {
    return;
  }

  const requestId = button.dataset.id;
  const status = workerRequestsBody.querySelector(`select[data-role='status'][data-id='${requestId}']`).value;
  const note = workerRequestsBody.querySelector(`input[data-role='note'][data-id='${requestId}']`).value;
  const timeSpent = workerRequestsBody.querySelector(`input[data-role='time-spent'][data-id='${requestId}']`).value;
  const timeSpentMinutes = Number.parseInt(timeSpent || "0", 10);

  try {
    await updateWorkerRequestStatus(requestId, status, note, Number.isInteger(timeSpentMinutes) ? timeSpentMinutes : 0);
    workerPanelStatus.textContent = `Request #${requestId} updated to ${status}.`;
    await refreshWorkerPanel();
  } catch (error) {
    workerPanelStatus.textContent = error.message;
  }
});

(async function init() {
  try {
    const session = await loadWorkerSession();
    if (session.authenticated) {
      if (session.requirePasswordChange) {
        setView("password");
        workerPasswordStatus.textContent = "Password update required before continuing.";
        return;
      }

      setView("panel");
      workerWelcome.textContent = `My Assigned Requests · ${session.fullName}`;
      await refreshWorkerPanel();
    } else {
      setView("login");
    }
  } catch {
    setView("login");
  }
})();

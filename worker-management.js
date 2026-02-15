const wmPanelSection = document.getElementById("wmPanelSection");
const wmCreateForm = document.getElementById("wmCreateForm");
const wmStatus = document.getElementById("wmStatus");
const wmWorkersBody = document.getElementById("wmWorkersBody");
const wmRefreshButton = document.getElementById("wmRefreshButton");
const wmLogoutButton = document.getElementById("wmLogoutButton");

let workersCache = [];

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

async function logout() {
  const response = await fetch("/api/admin/logout", { method: "POST" });
  if (!response.ok) {
    throw new Error("Failed to logout.");
  }
}

async function loadWorkers() {
  return fetchJson("/api/admin/workers");
}

async function createWorker(payload) {
  return fetchJson("/api/admin/workers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function resetPassword(workerId, newPassword) {
  return fetchJson(`/api/admin/workers/${workerId}/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ newPassword }),
  });
}

async function deactivateWorker(workerId) {
  const response = await fetch(`/api/admin/workers/${workerId}`, { method: "DELETE" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "Failed to deactivate worker.");
  }
}

async function activateWorker(workerId) {
  const response = await fetch(`/api/admin/workers/${workerId}/activate`, { method: "POST" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "Failed to activate worker.");
  }
}

async function removeWorker(workerId) {
  const response = await fetch(`/api/admin/workers/${workerId}/permanent`, { method: "DELETE" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "Failed to remove worker.");
  }
}

function renderWorkers() {
  wmWorkersBody.innerHTML = "";

  if (workersCache.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="7" class="empty">No workers configured.</td>';
    wmWorkersBody.appendChild(row);
    return;
  }

  workersCache.forEach((worker) => {
    const row = document.createElement("tr");
    const statusParts = [worker.isActive ? "Active" : "Inactive"];
    if (worker.lockedUntil) {
      statusParts.push(`Locked until ${formatDate(worker.lockedUntil)}`);
    }
    if (worker.mustChangePassword) {
      statusParts.push("Password change required");
    }

    row.innerHTML = `
      <td>${escapeHtml(worker.fullName)}</td>
      <td>${escapeHtml(worker.username)}</td>
      <td>${escapeHtml(worker.department)}</td>
      <td>${escapeHtml(statusParts.join(" · "))}</td>
      <td>${escapeHtml(String(worker.activeRequestCount || 0))}</td>
      <td>${escapeHtml(formatDate(worker.lastActivityAt || worker.lastLoginAt))}</td>
      <td>
        <div class="actions compact">
          <button type="button" data-role="reset" data-id="${worker.id}" data-username="${escapeHtml(worker.username)}">Reset Password</button>
          ${worker.isActive ? `<button type="button" class="secondary" data-role="deactivate" data-id="${worker.id}">Deactivate</button>` : ""}
          ${!worker.isActive ? `<button type="button" data-role="activate" data-id="${worker.id}">Activate</button>` : ""}
          <button type="button" class="secondary" data-role="remove" data-id="${worker.id}" data-username="${escapeHtml(worker.username)}">Remove</button>
        </div>
      </td>
    `;
    wmWorkersBody.appendChild(row);
  });
}

async function refreshWorkers() {
  workersCache = await loadWorkers();
  renderWorkers();
  wmStatus.textContent = `Loaded ${workersCache.length} worker(s).`;
}

wmCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const payload = {
    fullName: document.getElementById("wmFullName").value.trim(),
    username: document.getElementById("wmUsername").value.trim().toLowerCase(),
    department: document.getElementById("wmDepartment").value.trim(),
    password: document.getElementById("wmTempPassword").value,
  };

  try {
    await createWorker(payload);
    wmCreateForm.reset();
    wmStatus.textContent = `Worker ${payload.username} added.`;
    await refreshWorkers();
  } catch (error) {
    wmStatus.textContent = error.message;
  }
});

wmWorkersBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) {
    return;
  }

  const workerId = button.dataset.id;

  try {
    if (button.dataset.role === "reset") {
      const username = button.dataset.username || "this worker";
      const newPassword = window.prompt(`Enter a new temporary password for ${username}.\nMust be at least 12 chars with upper, lower, number, and symbol.`);
      if (!newPassword) {
        return;
      }
      await resetPassword(workerId, newPassword);
      wmStatus.textContent = `Password reset for ${username}. Worker must change password on next login.`;
      await refreshWorkers();
      return;
    }

    if (button.dataset.role === "deactivate") {
      await deactivateWorker(workerId);
      wmStatus.textContent = "Worker deactivated.";
      await refreshWorkers();
      return;
    }

    if (button.dataset.role === "activate") {
      await activateWorker(workerId);
      wmStatus.textContent = "Worker activated.";
      await refreshWorkers();
      return;
    }

    if (button.dataset.role === "remove") {
      const username = button.dataset.username || "this worker";
      const confirmed = window.confirm(`Remove worker ${username} permanently? This cannot be undone.`);
      if (!confirmed) {
        return;
      }
      await removeWorker(workerId);
      wmStatus.textContent = "Worker removed permanently.";
      await refreshWorkers();
    }
  } catch (error) {
    wmStatus.textContent = error.message;
  }
});

wmRefreshButton.addEventListener("click", async () => {
  try {
    await refreshWorkers();
  } catch (error) {
    wmStatus.textContent = error.message;
  }
});

wmLogoutButton.addEventListener("click", async () => {
  try {
    await logout();
    window.location.href = "/admin.html";
  } catch (error) {
    wmStatus.textContent = error.message;
  }
});

(async function init() {
  try {
    const authenticated = await checkSession();
    if (!authenticated) {
      window.location.href = "/admin.html";
      return;
    }
    wmPanelSection.classList.remove("hidden");
    await refreshWorkers();
  } catch {
    window.location.href = "/admin.html";
  }
})();

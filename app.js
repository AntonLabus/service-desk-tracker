const requestForm = document.getElementById("requestForm");
const statusMessage = document.getElementById("statusMessage");
const lookupForm = document.getElementById("lookupForm");
const lookupStatus = document.getElementById("lookupStatus");
const requestDetails = document.getElementById("requestDetails");
const detailTicket = document.getElementById("detailTicket");
const detailState = document.getElementById("detailState");
const detailAssignedDept = document.getElementById("detailAssignedDept");
const detailAssignedUser = document.getElementById("detailAssignedUser");
const detailPriority = document.getElementById("detailPriority");
const detailUpdated = document.getElementById("detailUpdated");
const notificationsList = document.getElementById("notificationsList");
const signOffButton = document.getElementById("signOffButton");
const disputeButton = document.getElementById("disputeButton");
const signatureSection = document.getElementById("signatureSection");
const signatureNameInput = document.getElementById("signatureName");
const signaturePad = document.getElementById("signaturePad");
const clearSignatureButton = document.getElementById("clearSignatureButton");
const disputeSection = document.getElementById("disputeSection");
const disputeReasonInput = document.getElementById("disputeReason");

const signatureContext = signaturePad.getContext("2d");
let isDrawingSignature = false;
let hasSignatureStroke = false;

signatureContext.lineWidth = 2;
signatureContext.lineCap = "round";
signatureContext.strokeStyle = "#1d2838";

function getCanvasPoint(event) {
  const rect = signaturePad.getBoundingClientRect();
  const source = event.touches ? event.touches[0] : event;
  return {
    x: source.clientX - rect.left,
    y: source.clientY - rect.top,
  };
}

function startSignatureDraw(event) {
  isDrawingSignature = true;
  hasSignatureStroke = true;
  const point = getCanvasPoint(event);
  signatureContext.beginPath();
  signatureContext.moveTo(point.x, point.y);
  event.preventDefault();
}

function drawSignature(event) {
  if (!isDrawingSignature) {
    return;
  }
  const point = getCanvasPoint(event);
  signatureContext.lineTo(point.x, point.y);
  signatureContext.stroke();
  event.preventDefault();
}

function endSignatureDraw(event) {
  if (!isDrawingSignature) {
    return;
  }
  isDrawingSignature = false;
  signatureContext.closePath();
  event.preventDefault();
}

function clearSignaturePad() {
  signatureContext.clearRect(0, 0, signaturePad.width, signaturePad.height);
  hasSignatureStroke = false;
}

signaturePad.addEventListener("mousedown", startSignatureDraw);
signaturePad.addEventListener("mousemove", drawSignature);
signaturePad.addEventListener("mouseup", endSignatureDraw);
signaturePad.addEventListener("mouseleave", endSignatureDraw);
signaturePad.addEventListener("touchstart", startSignatureDraw, { passive: false });
signaturePad.addEventListener("touchmove", drawSignature, { passive: false });
signaturePad.addEventListener("touchend", endSignatureDraw, { passive: false });
clearSignatureButton.addEventListener("click", clearSignaturePad);

let currentLookup = null;

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

async function createRequest(payload) {
  return fetchJson("/api/requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function lookupRequest(reference, email) {
  const lookup = await fetchJson(`/api/requests/lookup/ref?reference=${encodeURIComponent(reference)}&email=${encodeURIComponent(email)}`);
  return fetchJson(`/api/requests/${lookup.id}?email=${encodeURIComponent(email)}`);
}

async function signOffRequest(requestId, email) {
  const signerName = signatureNameInput.value.trim();
  if (!signerName) {
    throw new Error("Enter signer name before submitting signoff.");
  }

  if (!hasSignatureStroke) {
    throw new Error("Draw your signature before submitting signoff.");
  }

  return fetchJson(`/api/requests/${requestId}/signoff`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      signerName,
      signatureDataUrl: signaturePad.toDataURL("image/png"),
    }),
  });
}

async function disputeRequest(requestId, email) {
  const reason = disputeReasonInput.value.trim();
  if (!reason) {
    throw new Error("Enter a dispute reason before submitting.");
  }

  return fetchJson(`/api/requests/${requestId}/dispute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, reason }),
  });
}

function renderRequestDetails(payload) {
  const request = payload.request;
  detailTicket.textContent = `${request.ticketKey || `#${request.id}`} (${request.id})`;
  detailState.textContent = request.status;
  detailState.className = `pill state-${request.status.replace(/\s+/g, "-").toLowerCase()}`;
  detailAssignedDept.textContent = request.assignedDepartment || "Not assigned";
  detailAssignedUser.textContent = request.assignedUser || "Not assigned";
  detailPriority.textContent = request.priority;
  detailUpdated.textContent = formatDate(request.updatedAt || request.createdAt);

  notificationsList.innerHTML = "";
  if (payload.notifications.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No updates yet.";
    notificationsList.appendChild(item);
  } else {
    payload.notifications.forEach((notification) => {
      const item = document.createElement("li");
      item.innerHTML = `<strong>${formatDate(notification.createdAt)}</strong><span>${notification.message}</span>`;
      notificationsList.appendChild(item);
    });
  }

  if (request.status === "Awaiting Signoff") {
    signOffButton.classList.remove("hidden");
    signatureSection.classList.remove("hidden");
  } else {
    signOffButton.classList.add("hidden");
    signatureSection.classList.add("hidden");
  }

  if (request.status === "Resolved") {
    disputeButton.classList.remove("hidden");
    disputeSection.classList.remove("hidden");
  } else {
    disputeButton.classList.add("hidden");
    disputeSection.classList.add("hidden");
  }

  requestDetails.classList.remove("hidden");
}

requestForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const request = {
    name: document.getElementById("name").value.trim(),
    email: document.getElementById("email").value.trim(),
    department: document.getElementById("department").value.trim(),
    priority: document.getElementById("priority").value,
    channel: document.getElementById("channel").value,
    category: document.getElementById("category").value,
    impact: document.getElementById("impact").value,
    details: document.getElementById("details").value.trim(),
  };

  if (!request.name || !request.email || !request.department || !request.details) {
    statusMessage.textContent = "Please complete all required fields.";
    return;
  }

  try {
    const created = await createRequest(request);
    requestForm.reset();
    statusMessage.textContent = `Ticket created: ${created.ticketKey} (ID ${created.id}). Save this reference for tracking.`;
  } catch (error) {
    statusMessage.textContent = error.message;
  }
});

lookupForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const reference = document.getElementById("lookupReference").value.trim();
  const email = document.getElementById("lookupEmail").value.trim().toLowerCase();

  if (!reference || !email) {
    lookupStatus.textContent = "Enter ticket reference and email.";
    return;
  }

  try {
    const payload = await lookupRequest(reference, email);
    currentLookup = { requestId: payload.request.id, email };
    renderRequestDetails(payload);
    lookupStatus.textContent = "Ticket loaded.";
  } catch (error) {
    requestDetails.classList.add("hidden");
    lookupStatus.textContent = error.message;
  }
});

signOffButton.addEventListener("click", async () => {
  if (!currentLookup) {
    return;
  }

  try {
    await signOffRequest(currentLookup.requestId, currentLookup.email);
    const payload = await fetchJson(`/api/requests/${currentLookup.requestId}?email=${encodeURIComponent(currentLookup.email)}`);
    renderRequestDetails(payload);
    clearSignaturePad();
    signatureNameInput.value = "";
    lookupStatus.textContent = "Signature submitted. Ticket is now resolved.";
  } catch (error) {
    lookupStatus.textContent = error.message;
  }
});

disputeButton.addEventListener("click", async () => {
  if (!currentLookup) {
    return;
  }

  try {
    await disputeRequest(currentLookup.requestId, currentLookup.email);
    const payload = await fetchJson(`/api/requests/${currentLookup.requestId}?email=${encodeURIComponent(currentLookup.email)}`);
    renderRequestDetails(payload);
    disputeReasonInput.value = "";
    lookupStatus.textContent = "Dispute submitted. Ticket has been returned to Work In Progress.";
  } catch (error) {
    lookupStatus.textContent = error.message;
  }
});

# Service Desk Tracker

A modern service-desk style web app for capturing inbound requests, assigning work, tracking lifecycle state, and measuring operational performance.

## Product Overview

### Public Portal

- Log a new ticket with richer intake fields:
  - Requester name and email
  - Department
  - Priority
  - Contact channel
  - Category
  - Business impact
  - Description
- Ticket key generation (e.g. `REQ-00004`)
- Self-service ticket lookup by ticket key or numeric ID + email
- Requester notification timeline
- Requester sign-off to close resolved tickets

### Admin Workspace

- Secure admin panel (session-based login)
- Worker user management (add worker, deactivate worker)
- Table + board views for all ticket states
- Filters:
  - Date range
  - Requester
  - Assigned person
  - State
  - Priority
  - Minimum unresolved open hours
- SLA style aging indicators
- Assignment workflow by department/member
- Only admin can assign requests
- State transitions (`Work In Progress`, `Pending`, `Resolved`)
- KPI summary cards and analytics:
  - Total by state
  - Average assignment time
  - Average resolution time
- CSV export of filtered ticket set

### Worker Panel

- Separate login panel for support workers
- Workers only see requests assigned to them
- Workers can update only their own assigned requests (`Work In Progress`, `Pending`, `Resolved`)
- Worker updates create requester-visible notifications

## Ticket Lifecycle

- `Open`: Ticket created and not yet assigned
- `Work In Progress`: Assigned and actively being worked
- `Pending`: Blocked by external dependencies
- `Awaiting Signoff`: Worker marked work complete and is waiting for requester signature
- `Resolved`: Requester has submitted a drawn signature signoff confirming completion
- `Closed`: Optional terminal state

## Requester Signature Signoff

- Admin/worker cannot set a request directly to `Resolved`
- Worker or admin moves request to `Awaiting Signoff`
- Requester opens the portal, loads their ticket, draws a signature, and submits signoff
- System records signer name, signature image, signoff timestamp, and transitions ticket to `Resolved`

## Tech Stack

- Node.js + Express
- SQLite
- Session auth via `express-session`
- Vanilla HTML/CSS/JavaScript frontend

## Run

1. Install dependencies:

   `"C:\Program Files\nodejs\npm.cmd" install`

2. Start the server:

   `"C:\Program Files\nodejs\npm.cmd" start`

3. Open user portal:

   `http://localhost:3000`

4. Open admin workspace:

   `http://localhost:3000/admin.html`

5. Open worker panel:

   `http://localhost:3000/worker.html`

## Default Credentials

- Admin password: `admin123`

Set environment variables for production:

- `ADMIN_PASSWORD`
- `SESSION_SECRET`

## Default Worker Accounts

Seeded workers are created automatically with temporary password `Temp#1234`.
Use admin workspace to add or deactivate workers.

## Notes

- Data is stored in `requests.db`
- Existing deployments are auto-migrated with backward-compatible schema updates

## Security Hardening

Implemented:

- `helmet` security headers (CSP, frame protection, no-sniff, referrer policy)
- API rate limiting + stricter login rate limiting (`express-rate-limit`)
- Session hardening (`httpOnly`, `sameSite=lax`, secure cookies in production, fixed session cookie name)
- Session fixation protection (session regeneration on admin/worker login)
- Strong input validation and length limits across API endpoints
- Strong worker password policy (12+ chars with upper/lower/number/symbol)
- Password hashing with PBKDF2 + per-user salt
- Worker account lockout after repeated failed login attempts
- Forced password change for workers on first login and after admin-created temporary credentials
- Persistent audit logging for authentication, user management, assignment, and status-change events

Production requirements:

- Set strong `SESSION_SECRET`
- Set strong `ADMIN_PASSWORD`
- Run behind HTTPS reverse proxy

## Worker Security Flow

- Admin creates worker with a temporary password
- Worker logs in at `http://localhost:3000/worker.html`
- On first login, worker must change password before seeing assigned requests
- Failed logins trigger temporary account lockout
- Admin can review lockouts and security events in the audit log panel

## Deploy on Render

This app is ready to deploy as a single Render Web Service (frontend + backend together).

### Option A: Blueprint (recommended)

1. Push this repository to GitHub.
2. In Render, click **New** -> **Blueprint**.
3. Select this repository.
4. Render will detect `render.yaml` and create:
   - Free web service (`service-desk-tracker`)
5. Set secret environment values in Render:
   - `SESSION_SECRET` (strong random value)
   - `ADMIN_PASSWORD` (strong admin password)

`SQLITE_PATH` is preconfigured to `/tmp/requests.db` for Render free tier compatibility.
This storage is ephemeral, so ticket data can be lost on deploy/restart.

### Option B: Manual Web Service

If not using Blueprint, create a **Web Service** and set:

- Build command: `npm install`
- Start command: `npm start`
- Environment: `Node`
- Environment variables:
  - `NODE_ENV=production`
  - `SESSION_SECRET=<strong-secret>`
  - `ADMIN_PASSWORD=<strong-password>`
   - `SQLITE_PATH=/tmp/requests.db`

After deploy:

- Portal: `https://<your-render-url>/`
- Admin: `https://<your-render-url>/admin.html`
- Worker: `https://<your-render-url>/worker.html`

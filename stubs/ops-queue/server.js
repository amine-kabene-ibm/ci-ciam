'use strict';
// STUB: IFC Operations Queue & Broker Lifecycle Webhook Receiver (UC-13).
// Port: 4040 (default).
// Responsibilities:
//   1. Ingests broker lifecycle events from SCIM sync (PROVISION, UPDATE, DEACTIVATE, REACTIVATE, SESSION_KILL).
//   2. Ingests provisioning errors and failed syncs (e.g. non-existent user, schema mismatch, duplicate) for operator remediation.
//   3. Ingests Verify SaaS Webhooks (purpose: notifications).
//   4. Provides REST API and an interactive operator dashboard.
const express = require('express');
const http = require('http');

function buildApp(options = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Event store: in-memory list with timestamps, correlation IDs, status, payload.
  const queue = [];
  let nextId = 1;

  function pushEvent(type, { brokerId, userName, action, status = 'SUCCESS', detail, error, correlationId, latencyMs, payload } = {}) {
    const item = {
      id: `EVT-${String(nextId++).padStart(5, '0')}`,
      timestamp: new Date().toISOString(),
      type, // 'SCIM_SYNC', 'DEACTIVATION', 'REACTIVATION', 'ERROR', 'WEBHOOK', 'SESSION_REVOKE'
      brokerId: brokerId || null,
      userName: userName || null,
      action: action || type,
      status, // 'SUCCESS', 'FAILED_NEEDS_REVIEW', 'ENFORCED', 'RECEIVED'
      latencyMs: latencyMs !== undefined ? latencyMs : null,
      detail: detail || '',
      error: error || null,
      correlationId: correlationId || null,
      payload: payload || null,
    };
    queue.unshift(item); // newest first
    if (queue.length > 500) queue.pop();
    return item;
  }

  // Seed sample events if empty
  if (options.seedEvents !== false) {
    pushEvent('SCIM_SYNC', {
      brokerId: 'BRK-9821',
      userName: 'ifc-demo-uc13-broker-elena',
      action: 'CREATE_USER',
      status: 'SUCCESS',
      detail: 'Broker Elena Vance provisioned with Commercial Lines department',
    });
  }

  // REST API
  app.get('/health', (req, res) => res.json({ ok: true, service: 'ifc-ops-queue', count: queue.length }));

  app.get('/api/events', (req, res) => {
    const limit = parseInt(req.query.limit, 10) || 50;
    const filterType = req.query.type;
    let list = queue;
    if (filterType) list = list.filter((e) => e.type === filterType);
    res.json({
      events: list.slice(0, limit),
      stats: {
        total: queue.length,
        success: queue.filter((e) => e.status === 'SUCCESS' || e.status === 'ENFORCED').length,
        errors: queue.filter((e) => e.status === 'FAILED_NEEDS_REVIEW').length,
        webhooks: queue.filter((e) => e.type === 'WEBHOOK').length,
        deactivations: queue.filter((e) => e.type === 'DEACTIVATION').length,
      },
    });
  });

  app.post('/api/events', (req, res) => {
    const { type = 'SCIM_SYNC', ...rest } = req.body;
    const item = pushEvent(type, rest);
    res.status(201).json({ ok: true, event: item });
  });

  app.post('/api/clear', (req, res) => {
    queue.length = 0;
    res.json({ ok: true, cleared: true });
  });

  // Verify SaaS Webhook receiver
  app.post('/webhook', (req, res) => {
    const payload = req.body;
    const correlationId = req.headers['x-correlation-id'] || req.headers['x-request-id'] || null;
    const item = pushEvent('WEBHOOK', {
      action: 'VERIFY_WEBHOOK_DELIVERY',
      status: 'RECEIVED',
      detail: `Webhook received from Verify: ${payload && payload.action ? payload.action : 'Notification event'}`,
      correlationId,
      payload,
    });
    res.status(200).json({ ok: true, received: true, eventId: item.id });
  });

  // HTML Dashboard
  app.get('/', (req, res) => {
    const total = queue.length;
    const success = queue.filter((e) => e.status === 'SUCCESS' || e.status === 'ENFORCED').length;
    const errors = queue.filter((e) => e.status === 'FAILED_NEEDS_REVIEW').length;
    const deactivations = queue.filter((e) => e.type === 'DEACTIVATION').length;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IFC Broker Operations Queue & Lifecycle Hub</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --ifc-red: #C60C30;
      --ifc-dark: #1f2328;
      --ifc-surface: #ffffff;
      --ifc-bg: #f6f8fa;
      --ifc-border: #d0d7de;
      --ifc-success: #1a7f37;
      --ifc-warn: #9a6700;
      --ifc-danger: #cf222e;
      --ifc-blue: #0969da;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--ifc-bg); color: var(--ifc-dark); padding: 24px; font-size: 14px; line-height: 1.5; }
    .container { max-width: 1100px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 2px solid var(--ifc-red); margin-bottom: 24px; }
    .brand { font-size: 22px; font-weight: 700; color: var(--ifc-red); display: flex; align-items: center; gap: 10px; }
    .tag { font-size: 11px; background: #ffebe9; color: var(--ifc-red); padding: 3px 8px; border-radius: 12px; font-weight: 600; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--ifc-surface); border: 1px solid var(--ifc-border); border-radius: 8px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .metric-title { font-size: 12px; text-transform: uppercase; color: #57606a; font-weight: 600; margin-bottom: 6px; }
    .metric-value { font-size: 28px; font-weight: 700; color: var(--ifc-dark); }
    .metric-value.success { color: var(--ifc-success); }
    .metric-value.danger { color: var(--ifc-danger); }
    .metric-value.blue { color: var(--ifc-blue); }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
    h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .btn { display: inline-block; padding: 8px 14px; border-radius: 6px; border: 1px solid transparent; font-weight: 600; font-size: 13px; cursor: pointer; text-decoration: none; }
    .btn-primary { background: var(--ifc-red); color: white; }
    .btn-primary:hover { background: #a50a28; }
    .btn-danger { background: var(--ifc-danger); color: white; }
    .btn-danger:hover { background: #b01c27; }
    .btn-outline { background: white; border-color: var(--ifc-border); color: var(--ifc-dark); }
    .btn-outline:hover { background: #f3f4f6; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; border: 1px solid var(--ifc-border); }
    th { background: #f6f8fa; text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 600; color: #57606a; border-bottom: 1px solid var(--ifc-border); }
    td { padding: 12px 14px; border-bottom: 1px solid #eaeef2; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .badge-success { background: #dafbe1; color: var(--ifc-success); }
    .badge-danger { background: #ffebe9; color: var(--ifc-danger); }
    .badge-warn { background: #fff8c5; color: var(--ifc-warn); }
    .badge-blue { background: #ddf4ff; color: var(--ifc-blue); }
    .code { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }
    .callout { background: #ddf4ff; border-left: 4px solid var(--ifc-blue); padding: 12px 16px; border-radius: 0 6px 6px 0; margin-bottom: 20px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <span>Intact Financial Corporation</span>
        <span class="tag">UC-13 Demo</span>
      </div>
      <div>
        <span style="color: #57606a; margin-right: 12px;">Port: <strong>4040</strong></span>
        <button onclick="location.reload()" class="btn btn-outline">Refresh</button>
      </div>
    </header>

    <div class="callout">
      <strong>Use Case UC-13: Broker Lifecycle via SCIM 2.0 with Immediate Revocation</strong><br>
      This dashboard monitors automated broker provisioning, role sync, immediate access revocation upon termination, and operations queue error logging.
    </div>

    <div class="metrics">
      <div class="card">
        <div class="metric-title">Total Operations</div>
        <div class="metric-value blue">${total}</div>
      </div>
      <div class="card">
        <div class="metric-title">Successful Syncs</div>
        <div class="metric-value success">${success}</div>
      </div>
      <div class="card">
        <div class="metric-title">Deactivations</div>
        <div class="metric-value danger">${deactivations}</div>
      </div>
      <div class="card">
        <div class="metric-title">Ops Queue Errors</div>
        <div class="metric-value ${errors > 0 ? 'danger' : ''}">${errors}</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <h2>
        <span>Live Operations Queue & Audit Trail</span>
        <span style="font-size: 12px; font-weight: normal; color: #57606a;">Latest 50 events</span>
      </h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID / Time</th>
              <th>Type</th>
              <th>Broker / Entity</th>
              <th>Action</th>
              <th>Status</th>
              <th>Latency / Details</th>
            </tr>
          </thead>
          <tbody>
            ${queue.length === 0 ? '<tr><td colspan="6" style="text-align: center; color: #57606a; padding: 24px;">No events in queue</td></tr>' : queue.map((e) => `
              <tr>
                <td>
                  <strong>${e.id}</strong><br>
                  <span style="font-size: 11px; color: #57606a;">${e.timestamp.replace('T', ' ').substring(0, 19)}</span>
                </td>
                <td><span class="code">${e.type}</span></td>
                <td>
                  <strong>${e.userName || e.brokerId || 'N/A'}</strong>
                  ${e.brokerId ? `<br><span class="code">${e.brokerId}</span>` : ''}
                </td>
                <td>${e.action}</td>
                <td>
                  <span class="badge ${e.status === 'SUCCESS' || e.status === 'ENFORCED' ? 'badge-success' : e.status === 'FAILED_NEEDS_REVIEW' ? 'badge-danger' : 'badge-blue'}">
                    ${e.status}
                  </span>
                </td>
                <td>
                  ${e.latencyMs !== null ? `<strong>${e.latencyMs} ms</strong> &bull; ` : ''}
                  ${e.detail || (e.error ? `<span style="color: var(--ifc-danger);">${e.error}</span>` : '')}
                  ${e.correlationId ? `<br><span class="code" style="font-size: 10px;">${e.correlationId}</span>` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });

  return { app, pushEvent, queue };
}

function startServer(port = 4040, options = {}) {
  const { app, pushEvent, queue } = buildApp(options);
  const server = http.createServer(app);
  return new Promise((resolve, reject) => {
    server.listen(port, () => {
      resolve({ server, port, pushEvent, queue, url: `http://localhost:${port}` });
    });
    server.on('error', reject);
  });
}

module.exports = { buildApp, startServer };

if (require.main === module) {
  const port = parseInt(process.env.OPS_QUEUE_PORT || process.argv[2] || '4040', 10);
  startServer(port).then((s) => {
    console.log(`IFC Ops Queue & Webhook Stub listening on ${s.url}`);
  }).catch((e) => {
    console.error('Failed to start ops-queue stub:', e.message);
    process.exit(1);
  });
}

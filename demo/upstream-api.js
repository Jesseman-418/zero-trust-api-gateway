const http = require('http');

/**
 * Mock Upstream API Server
 *
 * Simulates a protected backend service that sits behind the gateway.
 * Demonstrates how the upstream receives identity context from the gateway
 * via forwarded headers.
 */

const PORT = process.env.UPSTREAM_PORT || 4001;

const users = [
  { id: 1, name: 'Alice Johnson', email: 'alice@example.com', role: 'admin' },
  { id: 2, name: 'Bob Smith', email: 'bob@example.com', role: 'user' },
  { id: 3, name: 'Carol White', email: 'carol@example.com', role: 'viewer' },
];

const reports = [
  { id: 1, title: 'Q1 Revenue', status: 'published' },
  { id: 2, title: 'Q2 Forecast', status: 'draft' },
];

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve(body); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method = req.method;

  // Show gateway-injected headers
  const gatewayIdentity = req.headers['x-gateway-identity'] || 'none';
  const gatewayRoles = req.headers['x-gateway-roles'] || '[]';
  const gatewayAuth = req.headers['x-gateway-authenticated'] || 'false';
  const requestId = req.headers['x-gateway-request-id'] || '';

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Upstream-Request-Id', requestId);

  const respond = (status, data) => {
    const body = JSON.stringify({
      ...data,
      _gateway: {
        identity: gatewayIdentity,
        roles: JSON.parse(gatewayRoles),
        authenticated: gatewayAuth === 'true',
        requestId,
      },
    }, null, 2);
    res.writeHead(status);
    res.end(body);
  };

  // ─── Routes ────────────────────────────────

  // Health check
  if (pathname === '/health' && method === 'GET') {
    return respond(200, { status: 'healthy', service: 'upstream-api', timestamp: new Date().toISOString() });
  }

  // Users CRUD
  if (pathname === '/api/users' && method === 'GET') {
    return respond(200, { users });
  }
  if (pathname === '/api/users' && method === 'POST') {
    const body = await parseBody(req);
    const newUser = { id: users.length + 1, ...body };
    users.push(newUser);
    return respond(201, { user: newUser, message: 'User created' });
  }
  if (pathname === '/api/users' && method === 'DELETE') {
    return respond(200, { message: 'User deleted (mock)', deletedBy: gatewayIdentity });
  }

  // Reports
  if (pathname === '/api/reports' && method === 'GET') {
    return respond(200, { reports });
  }
  if (pathname === '/api/reports' && method === 'POST') {
    const body = await parseBody(req);
    const newReport = { id: reports.length + 1, ...body };
    reports.push(newReport);
    return respond(201, { report: newReport });
  }

  // Admin endpoints
  if (pathname.startsWith('/api/admin')) {
    return respond(200, {
      message: 'Admin endpoint accessed',
      path: pathname,
      method,
      accessedBy: gatewayIdentity,
      timestamp: new Date().toISOString(),
    });
  }

  // Internal endpoints
  if (pathname.startsWith('/api/internal')) {
    return respond(200, {
      message: 'Internal endpoint accessed',
      path: pathname,
      method,
      accessedBy: gatewayIdentity,
    });
  }

  // Public endpoints
  if (pathname.startsWith('/api/public')) {
    return respond(200, {
      message: 'Public endpoint — no authentication required',
      path: pathname,
      timestamp: new Date().toISOString(),
    });
  }

  // Catch-all
  respond(404, { error: 'Not Found', path: pathname });
});

server.listen(PORT, () => {
  console.log(`[upstream-api] Mock upstream API running on http://localhost:${PORT}`);
  console.log(`[upstream-api] Health: http://localhost:${PORT}/health`);
});

module.exports = server;

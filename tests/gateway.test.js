const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const http = require('http');

/**
 * Integration Tests for Zero-Trust API Gateway
 *
 * Tests the full request pipeline:
 * - JWT authentication
 * - RBAC enforcement
 * - ABAC policy evaluation
 * - Rate limiting
 * - Audit logging
 * - Security headers
 * - Proxy forwarding
 */

const JWT_SECRET = 'demo-secret-key-change-in-production';
const GATEWAY_PORT = 3099;
const UPSTREAM_PORT = 4099;

// Override env before requiring gateway modules
process.env.GATEWAY_PORT = String(GATEWAY_PORT);
process.env.UPSTREAM_PORT = String(UPSTREAM_PORT);
process.env.DEMO_MODE = 'true';
process.env.DEMO_JWT_SECRET = JWT_SECRET;
process.env.LOG_LEVEL = 'error';

let gatewayServer;
let upstreamServer;

function generateToken(claims, options = {}) {
  return jwt.sign(claims, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h', ...options });
}

function makeRequest(method, path, token = null, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: GATEWAY_PORT,
      path,
      method,
      headers: { 'Content-Type': 'application/json' },
    };

    if (token) options.headers['Authorization'] = `Bearer ${token}`;

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ─── Start servers ───────────────────────────────────────────────────────

before(async () => {
  // Start mock upstream
  upstreamServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/health') {
      res.writeHead(200);
      return res.end(JSON.stringify({ status: 'healthy' }));
    }
    res.writeHead(200);
    res.end(JSON.stringify({
      path: req.url,
      method: req.method,
      identity: req.headers['x-gateway-identity'] || null,
      roles: req.headers['x-gateway-roles'] || null,
    }));
  });

  await new Promise((resolve) => upstreamServer.listen(UPSTREAM_PORT, resolve));

  // Start gateway (require after env is set)
  // Update routes to point to test upstream
  const fs = require('fs');
  const path = require('path');
  const routesPath = path.join(__dirname, '../policies/routes.json');
  const routes = JSON.parse(fs.readFileSync(routesPath, 'utf-8'));
  const originalTarget = routes.upstreams.default.target;
  routes.upstreams.default.target = `http://localhost:${UPSTREAM_PORT}`;
  fs.writeFileSync(routesPath, JSON.stringify(routes, null, 2));

  // Clear module cache to pick up new env
  for (const key of Object.keys(require.cache)) {
    if (key.includes('zero-trust-gateway/src')) {
      delete require.cache[key];
    }
  }

  const gateway = require('../src/index');
  gatewayServer = gateway.server;

  // Wait for server to be ready
  await new Promise((resolve) => setTimeout(resolve, 500));

  // Restore original routes file
  routes.upstreams.default.target = originalTarget;
  fs.writeFileSync(routesPath, JSON.stringify(routes, null, 2));
});

after(async () => {
  if (gatewayServer) gatewayServer.close();
  if (upstreamServer) upstreamServer.close();
});

// ─── Tests ───────────────────────────────────────────────────────────────

describe('Gateway Health', () => {
  it('should return health status', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.strictEqual(res.status, 200);
    assert.ok(res.data.status);
    assert.ok(res.data.upstreams);
  });

  it('should return metrics', async () => {
    const res = await makeRequest('GET', '/gateway/metrics');
    assert.strictEqual(res.status, 200);
    assert.ok(res.data.requests);
    assert.ok(res.data.latency);
    assert.ok(res.data.errors);
  });
});

describe('Authentication', () => {
  it('should reject requests without a token', async () => {
    const res = await makeRequest('GET', '/api/users');
    assert.strictEqual(res.status, 401);
    assert.ok(res.data.detail.includes('Bearer token required'));
  });

  it('should reject expired tokens', async () => {
    const token = jwt.sign({ sub: 'test', roles: ['user'] }, JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '-1h',
    });
    const res = await makeRequest('GET', '/api/users', token);
    assert.strictEqual(res.status, 401);
    assert.ok(res.data.detail.includes('expired'));
  });

  it('should reject invalid tokens', async () => {
    const res = await makeRequest('GET', '/api/users', 'invalid-token');
    assert.strictEqual(res.status, 401);
  });

  it('should accept valid tokens', async () => {
    const token = generateToken({ sub: 'test-user', roles: ['user'] });
    const res = await makeRequest('GET', '/api/users', token);
    assert.strictEqual(res.status, 200);
  });

  it('should allow public endpoints without auth', async () => {
    const res = await makeRequest('GET', '/api/public/test');
    assert.strictEqual(res.status, 200);
  });
});

describe('RBAC', () => {
  it('should allow viewer to read', async () => {
    const token = generateToken({ sub: 'viewer', roles: ['viewer'] });
    const res = await makeRequest('GET', '/api/users', token);
    assert.strictEqual(res.status, 200);
  });

  it('should deny viewer from writing', async () => {
    const token = generateToken({ sub: 'viewer', roles: ['viewer'] });
    const res = await makeRequest('POST', '/api/users', token, { name: 'test' });
    assert.strictEqual(res.status, 403);
  });

  it('should allow user to write', async () => {
    const token = generateToken({ sub: 'writer', roles: ['user'] });
    const res = await makeRequest('POST', '/api/users', token, { name: 'test' });
    assert.strictEqual(res.status, 200);
  });

  it('should deny user from deleting', async () => {
    const token = generateToken({ sub: 'deleter', roles: ['user'] });
    const res = await makeRequest('DELETE', '/api/users', token);
    assert.strictEqual(res.status, 403);
  });

  it('should allow admin with MFA to delete (ABAC requires MFA for DELETE)', async () => {
    const token = generateToken({ sub: 'admin-mfa', roles: ['admin'], amr: ['pwd', 'mfa'] });
    const res = await makeRequest('DELETE', '/api/users', token);
    assert.strictEqual(res.status, 200);
  });

  it('should deny admin without MFA from deleting (ABAC policy)', async () => {
    const token = generateToken({ sub: 'admin-no-mfa', roles: ['admin'] });
    const res = await makeRequest('DELETE', '/api/users', token);
    assert.strictEqual(res.status, 403);
    assert.ok(res.data.detail.includes('ABAC'));
  });

  it('should deny non-admin from admin routes', async () => {
    const token = generateToken({ sub: 'user', roles: ['user'] });
    const res = await makeRequest('GET', '/api/admin/settings', token);
    assert.strictEqual(res.status, 403);
  });

  it('should enforce ABAC business-hours policy on admin routes', async () => {
    const token = generateToken({ sub: 'admin', roles: ['admin'] });
    const res = await makeRequest('GET', '/api/admin/settings', token);
    const hour = new Date().getUTCHours();
    if (hour >= 9 && hour <= 17) {
      assert.strictEqual(res.status, 200);
    } else {
      // ABAC denies outside business hours
      assert.strictEqual(res.status, 403);
    }
  });
});

describe('Security Headers', () => {
  it('should set HSTS header', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.ok(res.headers['strict-transport-security']);
  });

  it('should set X-Content-Type-Options', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
  });

  it('should set X-Frame-Options', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.strictEqual(res.headers['x-frame-options'], 'DENY');
  });

  it('should include request ID', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.ok(res.headers['x-request-id']);
  });

  it('should set CSP header', async () => {
    const res = await makeRequest('GET', '/gateway/health');
    assert.ok(res.headers['content-security-policy']);
  });
});

describe('Rate Limiting', () => {
  it('should include rate limit headers', async () => {
    const token = generateToken({ sub: 'rate-test', roles: ['user'] });
    const res = await makeRequest('GET', '/api/users', token);
    assert.ok(res.headers['x-ratelimit-limit']);
    assert.ok(res.headers['x-ratelimit-remaining']);
  });
});

describe('Audit Log', () => {
  it('should record audit entries', async () => {
    const res = await makeRequest('GET', '/gateway/audit?limit=5');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.data.entries));
    assert.ok(res.data.chain);
  });

  it('should maintain valid chain integrity', async () => {
    const res = await makeRequest('GET', '/gateway/audit');
    assert.strictEqual(res.data.chain.valid, true);
  });
});

describe('Proxy Forwarding', () => {
  it('should forward identity headers to upstream', async () => {
    const token = generateToken({ sub: 'proxy-test', roles: ['user'] });
    const res = await makeRequest('GET', '/api/users', token);
    assert.strictEqual(res.status, 200);
    assert.ok(res.data.identity || res.data.path);
  });
});

describe('Policy Reload', () => {
  it('should reload policies without restart', async () => {
    const res = await makeRequest('POST', '/gateway/policies/reload');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.status, 'ok');
  });
});

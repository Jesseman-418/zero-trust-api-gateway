const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Test Client — Demonstrates the full Zero-Trust Gateway flow
 *
 * Generates demo JWTs and sends requests through the gateway to show:
 * 1. Successful authentication + authorization
 * 2. Role-based access control (RBAC) denials
 * 3. Rate limiting behavior
 * 4. Public endpoint access (no auth)
 * 5. Admin access
 */

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3002';
const JWT_SECRET = process.env.DEMO_JWT_SECRET || 'demo-secret-key-change-in-production';

// ─── Token Generation ────────────────────────────────────────────────────

function generateToken(claims, expiresIn = '1h') {
  return jwt.sign(claims, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn,
  });
}

const tokens = {
  admin: generateToken({
    sub: 'admin-001',
    name: 'Admin User',
    email: 'admin@example.com',
    roles: ['admin'],
    amr: ['pwd', 'mfa'],
  }),
  user: generateToken({
    sub: 'user-002',
    name: 'Regular User',
    email: 'user@example.com',
    roles: ['user'],
  }),
  viewer: generateToken({
    sub: 'viewer-003',
    name: 'Viewer User',
    email: 'viewer@example.com',
    roles: ['viewer'],
  }),
  expired: jwt.sign(
    { sub: 'expired-004', roles: ['user'] },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '-1h' }
  ),
};

// ─── Request Helper ──────────────────────────────────────────────────────

async function request(method, path, token = null, body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);

  try {
    const res = await fetch(`${GATEWAY_URL}${path}`, options);
    const data = await res.json();
    return { status: res.status, data, headers: Object.fromEntries(res.headers) };
  } catch (err) {
    return { status: 0, error: err.message };
  }
}

function logResult(testName, result) {
  const statusIcon = result.status >= 200 && result.status < 400 ? 'PASS' : 'DENY';
  const rateRemaining = result.headers?.['x-ratelimit-remaining'] || '-';
  console.log(`[${statusIcon}] ${result.status} | ${testName} | Rate remaining: ${rateRemaining}`);
  if (result.status >= 400) {
    console.log(`       Reason: ${result.data?.detail || result.data?.error || 'unknown'}`);
  }
}

// ─── Test Scenarios ──────────────────────────────────────────────────────

async function runTests() {
  console.log('');
  console.log('='.repeat(80));
  console.log('  Zero-Trust API Gateway — Test Client');
  console.log('='.repeat(80));
  console.log('');

  // 1. Public endpoint — no auth
  console.log('--- Public Access (No Auth Required) ---');
  logResult('GET /api/public/info', await request('GET', '/api/public/info'));
  console.log('');

  // 2. No token — should fail
  console.log('--- Authentication Tests ---');
  logResult('GET /api/users (no token)', await request('GET', '/api/users'));

  // 3. Expired token — should fail
  logResult('GET /api/users (expired token)', await request('GET', '/api/users', tokens.expired));

  // 4. Invalid token — should fail
  logResult('GET /api/users (invalid token)', await request('GET', '/api/users', 'not-a-valid-jwt'));
  console.log('');

  // 5. Valid tokens — RBAC tests
  console.log('--- RBAC Tests ---');
  logResult('GET /api/users (viewer)', await request('GET', '/api/users', tokens.viewer));
  logResult('POST /api/users (viewer → denied)', await request('POST', '/api/users', tokens.viewer, { name: 'Test' }));
  logResult('GET /api/users (user)', await request('GET', '/api/users', tokens.user));
  logResult('POST /api/users (user)', await request('POST', '/api/users', tokens.user, { name: 'New User', email: 'new@test.com' }));
  logResult('DELETE /api/users (user → denied)', await request('DELETE', '/api/users', tokens.user));
  logResult('DELETE /api/users (admin)', await request('DELETE', '/api/users', tokens.admin));
  console.log('');

  // 6. Admin endpoints
  console.log('--- Admin Access ---');
  logResult('GET /api/admin/settings (admin)', await request('GET', '/api/admin/settings', tokens.admin));
  logResult('GET /api/admin/settings (user → denied)', await request('GET', '/api/admin/settings', tokens.user));
  logResult('GET /api/admin/settings (viewer → denied)', await request('GET', '/api/admin/settings', tokens.viewer));
  console.log('');

  // 7. Reports
  console.log('--- Reports Access ---');
  logResult('GET /api/reports (user)', await request('GET', '/api/reports', tokens.user));
  logResult('POST /api/reports (user)', await request('POST', '/api/reports', tokens.user, { title: 'Test Report' }));
  logResult('GET /api/reports (viewer)', await request('GET', '/api/reports', tokens.viewer));
  console.log('');

  // 8. Rate limiting demo
  console.log('--- Rate Limiting (sending 5 rapid requests) ---');
  for (let i = 1; i <= 5; i++) {
    const result = await request('GET', '/api/users', tokens.viewer);
    logResult(`GET /api/users (viewer, req #${i})`, result);
  }
  console.log('');

  // 9. Gateway management endpoints
  console.log('--- Gateway Management ---');
  const healthResult = await request('GET', '/gateway/health');
  logResult('GET /gateway/health', healthResult);

  const metricsResult = await request('GET', '/gateway/metrics');
  console.log(`[INFO] Metrics: ${metricsResult.data?.requests?.total || 0} total requests, ` +
    `p50=${metricsResult.data?.latency?.p50 || 0}ms, ` +
    `p99=${metricsResult.data?.latency?.p99 || 0}ms`);

  const auditResult = await request('GET', '/gateway/audit?limit=3');
  console.log(`[INFO] Audit chain: ${auditResult.data?.chain?.valid ? 'VALID' : 'BROKEN'}, ` +
    `${auditResult.data?.chain?.totalEntries || 0} entries`);

  console.log('');
  console.log('='.repeat(80));
  console.log(`  Dashboard: ${GATEWAY_URL}/gateway/dashboard`);
  console.log('='.repeat(80));
  console.log('');
}

runTests().catch(console.error);

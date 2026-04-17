const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const logger = require('./utils/logger');

// Middleware
const { securityHeaders, bodyLimit, ipFilter } = require('./middleware/security');
const { collectMetrics, getMetrics } = require('./middleware/metrics');
const { audit, getRecentEntries, verifyChain } = require('./middleware/audit');
const { authenticate, resolveRoute } = require('./middleware/authenticate');
const { authorize } = require('./middleware/authorize');
const { rateLimit, getStats: getRateLimitStats } = require('./middleware/rateLimit');
const { validateClientCert } = require('./auth/mtls');
const policyEngine = require('./policy/engine');

// Proxy
const { createProxyHandler } = require('./proxy/handler');
const upstreamManager = require('./proxy/upstream');

// Plugins
const { loadPlugins, registerPhase } = require('./plugins/loader');

// Load route configuration
const routesConfig = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../policies/routes.json'), 'utf-8')
);

// Register upstreams
for (const [name, upstream] of Object.entries(routesConfig.upstreams)) {
  upstreamManager.register(name, upstream);
}

// Load plugins
const plugins = loadPlugins(path.join(__dirname, 'plugins'));

// Create Express app
const app = express();

// Trust proxy for correct IP detection behind load balancers
app.set('trust proxy', true);

// ─── Global Middleware (applies to ALL routes including management) ───────

// CORS
app.use(cors());

// Security headers
app.use(securityHeaders());

// ─── Gateway Management Endpoints ────────────────────────────────────────

// Health check (no auth required)
app.get('/gateway/health', (req, res) => {
  const upstreamStatus = upstreamManager.getStatus();
  const allHealthy = Object.values(upstreamStatus).every((u) => u.state !== 'open');

  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    upstreams: upstreamStatus,
  });
});

// Metrics endpoint
app.get('/gateway/metrics', (req, res) => {
  res.json(getMetrics());
});

// Audit log endpoint
app.get('/gateway/audit', (req, res) => {
  const limit = parseInt(req.query.limit || '100', 10);
  res.json({
    entries: getRecentEntries(limit),
    chain: verifyChain(),
  });
});

// Rate limit stats
app.get('/gateway/ratelimit', (req, res) => {
  res.json(getRateLimitStats());
});

// Policy reload endpoint
app.post('/gateway/policies/reload', (req, res) => {
  try {
    policyEngine.reloadAll();
    res.json({ status: 'ok', message: 'Policies reloaded' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Demo dashboard (serves static HTML)
app.get('/gateway/dashboard', (req, res) => {
  const dashboardPath = path.join(__dirname, '../demo/index.html');
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.status(404).json({ error: 'Dashboard not found' });
  }
});

// ─── Request Pipeline ────────────────────────────────────────────────────

// Body size limit
app.use(bodyLimit());

// Metrics collection
app.use(collectMetrics());

// Audit logging (wraps response to capture result)
app.use(audit());

// Pre-auth plugins
registerPhase(app, plugins, 'pre-auth', config);

// Route resolution (matches request to route config)
app.use(resolveRoute(routesConfig));

// IP allowlist/denylist
app.use(ipFilter());

// mTLS validation
app.use(validateClientCert);

// Authentication pipeline
app.use(authenticate());

// Post-auth plugins
registerPhase(app, plugins, 'post-auth', config);

// Authorization (policy enforcement)
app.use(authorize());

// Per-identity rate limiting
app.use(rateLimit());

// Pre-proxy plugins
registerPhase(app, plugins, 'pre-proxy', config);

// Reverse proxy to upstream
app.use(createProxyHandler(routesConfig));

// ─── Start Server ────────────────────────────────────────────────────────

const server = app.listen(config.gateway.port, () => {
  logger.info('Zero-Trust API Gateway started', {
    port: config.gateway.port,
    demoMode: config.demo.enabled,
    upstreams: Object.keys(routesConfig.upstreams),
    plugins: [...plugins.values()].flat().map((p) => p.name),
  });

  if (config.demo.enabled) {
    logger.info('DEMO MODE: Using symmetric JWT signing for local testing');
    logger.info(`Dashboard: http://localhost:${config.gateway.port}/gateway/dashboard`);
    logger.info(`Metrics:   http://localhost:${config.gateway.port}/gateway/metrics`);
    logger.info(`Health:    http://localhost:${config.gateway.port}/gateway/health`);
  }
});

// Graceful shutdown
function shutdown(signal) {
  logger.info(`${signal} received, shutting down gracefully`);
  upstreamManager.shutdown();
  server.close(() => {
    logger.info('Gateway shut down');
    process.exit(0);
  });
  // Force kill after 10 seconds
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = { app, server };

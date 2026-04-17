const httpProxy = require('http-proxy');
const upstreamManager = require('./upstream');
const errors = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Reverse Proxy Handler
 *
 * Forwards authenticated and authorized requests to upstream services.
 * Features:
 * - Per-route timeout enforcement
 * - Circuit breaker integration (rejects if upstream is down)
 * - Request metadata forwarding (identity headers)
 * - Error handling for upstream failures
 */

// Create proxy server instance
const proxy = httpProxy.createProxyServer({
  xfwd: true,        // Add X-Forwarded-* headers
  changeOrigin: true, // Change the Host header to match the target
  ws: false,
});

// Handle proxy errors
proxy.on('error', (err, req, res) => {
  logger.error('Proxy error', {
    error: err.message,
    code: err.code,
    path: req.path,
    upstream: req.upstreamTarget,
  });

  if (!res.headersSent) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
      errors.badGateway(res, 'Upstream service is unavailable');
    } else if (err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
      errors.gatewayTimeout(res, 'Upstream request timed out');
    } else {
      errors.internalError(res, 'Proxy encountered an error');
    }
  }
});

// Log proxy responses
proxy.on('proxyRes', (proxyRes, req) => {
  logger.debug('Upstream response', {
    path: req.path,
    statusCode: proxyRes.statusCode,
    upstream: req.upstreamTarget,
  });
});

/**
 * Creates the proxy handler middleware.
 * @param {object} routesConfig - Parsed routes.json configuration
 * @returns {Function} Express middleware
 */
function createProxyHandler(routesConfig) {
  return (req, res) => {
    // Determine which upstream to route to
    const routeConfig = req.routeConfig;
    const upstreamName = routeConfig?.upstream || 'default';

    // Check circuit breaker
    if (!upstreamManager.isAvailable(upstreamName)) {
      logger.warn('Upstream circuit breaker open', {
        upstream: upstreamName,
        path: req.path,
      });
      return errors.badGateway(res, `Upstream '${upstreamName}' is currently unavailable (circuit breaker open)`);
    }

    const target = upstreamManager.getTarget(upstreamName);
    if (!target) {
      logger.error('No target found for upstream', { upstream: upstreamName });
      return errors.badGateway(res, 'No upstream target configured');
    }

    req.upstreamTarget = target;

    // Add identity headers for the upstream service
    // This enables the upstream to make identity-aware decisions
    if (req.tokenPayload) {
      req.headers['x-gateway-identity'] = req.identityId || '';
      req.headers['x-gateway-roles'] = JSON.stringify(
        req.tokenPayload.roles || req.tokenPayload.groups || []
      );
      req.headers['x-gateway-authenticated'] = 'true';
    } else {
      req.headers['x-gateway-authenticated'] = 'false';
    }

    // Add request tracing header
    req.headers['x-gateway-request-id'] = req.requestId || '';

    // Per-route timeout
    const timeout = routeConfig?.timeout || 30000;

    // Forward the request to the upstream
    proxy.web(req, res, {
      target,
      timeout,
      proxyTimeout: timeout,
    });
  };
}

module.exports = { createProxyHandler, proxy };

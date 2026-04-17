const { verifyToken, extractBearerToken } = require('../auth/jwt');
const { introspectToken } = require('../auth/introspect');
const { verifyHmac } = require('../utils/hash');
const config = require('../config');
const errors = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Authentication Middleware Pipeline
 *
 * Implements a multi-stage authentication pipeline:
 * 1. Extract bearer token from Authorization header
 * 2. Verify JWT signature via JWKS (or demo secret)
 * 3. Validate token claims (exp, iss, aud)
 * 4. Optionally introspect token for real-time revocation check
 * 5. Optionally verify request HMAC signature
 *
 * On success, attaches `req.tokenPayload` for downstream middleware.
 * On failure, returns 401 with structured error.
 */

/**
 * Resolves route configuration for the current request.
 * Attaches route-specific settings (rate limits, IP rules, etc.)
 */
function resolveRoute(routesConfig) {
  return (req, res, next) => {
    const routes = routesConfig.routes || [];
    let matched = null;

    for (const route of routes) {
      if (route.path.endsWith('/*')) {
        const prefix = route.path.slice(0, -2);
        if (req.path.startsWith(prefix)) {
          if (!matched || route.path.length > matched.path.length) {
            matched = route;
          }
        }
      } else if (route.path === req.path) {
        matched = route;
        break;
      }
    }

    req.routeConfig = matched || {
      authentication: true,
      rateLimit: { windowMs: config.rateLimit.windowMs, maxRequests: config.rateLimit.maxRequests },
    };

    next();
  };
}

/**
 * Main authentication middleware.
 * Skips authentication for routes marked with `authentication: false`.
 */
function authenticate() {
  return async (req, res, next) => {
    // Check if route requires authentication
    if (req.routeConfig && req.routeConfig.authentication === false) {
      logger.debug('Authentication skipped for route', { path: req.path });
      return next();
    }

    // Step 1: Extract bearer token
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      logger.info('Missing bearer token', { path: req.path, ip: req.ip });
      return errors.unauthorized(res, 'Bearer token required in Authorization header');
    }

    try {
      // Step 2: Verify JWT signature and claims
      const payload = await verifyToken(token);
      req.tokenPayload = payload;
      req.identityId = payload.sub || payload.client_id || 'anonymous';

      // Step 3: Token introspection (real-time revocation check)
      const introspectionResult = await introspectToken(token);
      if (!introspectionResult.active && !introspectionResult.skipped) {
        logger.warn('Token revoked/inactive via introspection', {
          sub: req.identityId,
          path: req.path,
        });
        return errors.unauthorized(res, 'Token is no longer active');
      }

      // Step 4: Optional HMAC request signature verification
      const hmacHeader = req.headers['x-request-signature'];
      if (hmacHeader && config.security.hmacSecret) {
        const signatureData = `${req.method}:${req.originalUrl}:${req.identityId}`;
        if (!verifyHmac(config.security.hmacSecret, signatureData, hmacHeader)) {
          logger.warn('HMAC signature verification failed', {
            sub: req.identityId,
            path: req.path,
          });
          return errors.unauthorized(res, 'Request signature verification failed');
        }
        logger.debug('HMAC signature verified', { sub: req.identityId });
      }

      logger.debug('Authentication successful', {
        sub: req.identityId,
        roles: payload.roles || payload.groups || [],
      });

      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return errors.unauthorized(res, 'Token has expired');
      }
      if (err.name === 'JsonWebTokenError') {
        return errors.unauthorized(res, `Invalid token: ${err.message}`);
      }
      logger.error('Authentication error', { error: err.message });
      return errors.unauthorized(res, 'Authentication failed');
    }
  };
}

module.exports = { authenticate, resolveRoute };

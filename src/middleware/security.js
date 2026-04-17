const config = require('../config');
const errors = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Security Middleware
 *
 * Applies defense-in-depth security controls:
 * 1. Security headers (HSTS, CSP, X-Content-Type-Options, etc.)
 * 2. Request body size limits
 * 3. IP allowlist/denylist per route
 * 4. Request ID generation for tracing
 */

const { v4: uuidv4 } = require('uuid');

/**
 * Sets comprehensive security headers on every response.
 * These headers defend against common web attacks.
 */
function securityHeaders() {
  return (req, res, next) => {
    // Strict Transport Security — force HTTPS for 1 year
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    // Prevent MIME type sniffing
    res.set('X-Content-Type-Options', 'nosniff');

    // Prevent clickjacking
    res.set('X-Frame-Options', 'DENY');

    // XSS Protection (legacy, but defense-in-depth)
    res.set('X-XSS-Protection', '1; mode=block');

    // Content Security Policy
    res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");

    // Referrer Policy
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy (disable sensitive APIs)
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

    // Remove powered-by header
    res.removeHeader('X-Powered-By');

    // Cache control — no caching for API responses
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');

    // Add request ID for distributed tracing
    const requestId = req.headers['x-request-id'] || uuidv4();
    req.requestId = requestId;
    res.set('X-Request-Id', requestId);

    // Add gateway identifier
    res.set('X-Gateway', 'zero-trust-gateway/1.0');

    next();
  };
}

/**
 * Enforces request body size limits.
 * Prevents denial-of-service via oversized payloads.
 */
function bodyLimit() {
  const maxSize = parseSize(config.security.requestBodyMaxSize);

  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);

    if (contentLength > maxSize) {
      logger.warn('Request body too large', {
        contentLength,
        maxSize,
        path: req.path,
        ip: req.ip,
      });
      return res.status(413).json({
        status: 413,
        error: 'Payload Too Large',
        detail: `Request body exceeds ${config.security.requestBodyMaxSize} limit`,
      });
    }

    next();
  };
}

/**
 * Parses human-readable size strings (e.g., "1mb", "500kb") to bytes.
 * @param {string} size - Size string
 * @returns {number} Size in bytes
 */
function parseSize(size) {
  const units = { b: 1, kb: 1024, mb: 1024 * 1024, gb: 1024 * 1024 * 1024 };
  const match = String(size).toLowerCase().match(/^(\d+)(b|kb|mb|gb)?$/);
  if (!match) return 1024 * 1024; // Default 1MB
  return parseInt(match[1], 10) * (units[match[2]] || 1);
}

/**
 * IP allowlist/denylist enforcement per route.
 * Checks the route configuration for IP restrictions.
 */
function ipFilter() {
  return (req, res, next) => {
    const routeConfig = req.routeConfig;
    if (!routeConfig) return next();

    let clientIp = (req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');
    // Normalize IPv6 loopback to IPv4 loopback
    if (clientIp === '::1') clientIp = '127.0.0.1';

    // Check denylist first (deny takes precedence)
    if (routeConfig.ipDenylist && routeConfig.ipDenylist.length > 0) {
      if (matchesIpList(clientIp, routeConfig.ipDenylist)) {
        logger.warn('IP denied by denylist', { ip: clientIp, path: req.path });
        return errors.ipDenied(res, 'Your IP address is not permitted for this endpoint');
      }
    }

    // Check allowlist (if configured, only listed IPs are allowed)
    if (routeConfig.ipAllowlist && routeConfig.ipAllowlist.length > 0) {
      if (!matchesIpList(clientIp, routeConfig.ipAllowlist)) {
        logger.warn('IP denied by allowlist', { ip: clientIp, path: req.path });
        return errors.ipDenied(res, 'Your IP address is not permitted for this endpoint');
      }
    }

    next();
  };
}

/**
 * Checks if an IP address matches any entry in an IP list.
 * Supports exact IPs and CIDR notation.
 *
 * @param {string} ip - Client IP
 * @param {string[]} list - Array of IPs or CIDR ranges
 * @returns {boolean}
 */
function matchesIpList(ip, list) {
  for (const entry of list) {
    if (entry.includes('/')) {
      // CIDR match
      if (ipInCIDR(ip, entry)) return true;
    } else {
      // Exact match
      if (ip === entry) return true;
    }
  }
  return false;
}

/**
 * Simple CIDR matcher for IPv4.
 */
function ipInCIDR(ip, cidr) {
  const [network, bits] = cidr.split('/');
  const mask = parseInt(bits, 10);
  const ipParts = ip.split('.').map(Number);
  const netParts = network.split('.').map(Number);
  if (ipParts.length !== 4 || netParts.length !== 4) return false;
  const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const netNum = (netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3];
  const maskNum = mask === 0 ? 0 : ~0 << (32 - mask);
  return (ipNum & maskNum) === (netNum & maskNum);
}

module.exports = { securityHeaders, bodyLimit, ipFilter };

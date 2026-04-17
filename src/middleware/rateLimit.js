const errors = require('../utils/errors');
const logger = require('../utils/logger');
const config = require('../config');

/**
 * Per-Identity Sliding Window Rate Limiter
 *
 * Unlike IP-based rate limiting, this limits by the JWT `sub` claim.
 * This ensures that:
 * - A single identity can't overwhelm the gateway regardless of IP
 * - Different identities sharing an IP aren't penalized together
 * - Service accounts get their own rate limit budget
 *
 * Uses an in-memory sliding window algorithm with Map storage.
 * Each identity tracks individual request timestamps, and the window
 * slides forward in real time.
 */

// Map<identityId, { timestamps: number[], windowMs: number, maxRequests: number }>
const identityWindows = new Map();

// Periodic cleanup of expired entries
const CLEANUP_INTERVAL = 60000; // 1 minute

setInterval(() => {
  const now = Date.now();
  for (const [identity, data] of identityWindows) {
    // Remove timestamps outside the window
    data.timestamps = data.timestamps.filter((ts) => now - ts < data.windowMs);
    // Remove empty entries
    if (data.timestamps.length === 0) {
      identityWindows.delete(identity);
    }
  }
}, CLEANUP_INTERVAL).unref();

/**
 * Rate limiting middleware.
 * Uses per-route configuration if available, otherwise falls back to global defaults.
 */
function rateLimit() {
  return (req, res, next) => {
    // Determine identity — use JWT sub, fall back to IP
    const identity = req.identityId || req.ip || 'anonymous';

    // Get rate limit config from route or global defaults
    const routeConfig = req.routeConfig?.rateLimit || {};
    const windowMs = routeConfig.windowMs || config.rateLimit.windowMs;
    const maxRequests = routeConfig.maxRequests || config.rateLimit.maxRequests;

    const now = Date.now();

    // Get or create window for this identity
    if (!identityWindows.has(identity)) {
      identityWindows.set(identity, {
        timestamps: [],
        windowMs,
        maxRequests,
      });
    }

    const window = identityWindows.get(identity);
    window.windowMs = windowMs;
    window.maxRequests = maxRequests;

    // Slide the window — remove expired timestamps
    window.timestamps = window.timestamps.filter((ts) => now - ts < windowMs);

    // Check if limit exceeded
    if (window.timestamps.length >= maxRequests) {
      const oldestInWindow = window.timestamps[0];
      const retryAfterMs = windowMs - (now - oldestInWindow);
      const retryAfterSec = Math.ceil(retryAfterMs / 1000);

      // Set standard rate limit headers
      res.set({
        'X-RateLimit-Limit': String(maxRequests),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(Math.ceil((oldestInWindow + windowMs) / 1000)),
        'Retry-After': String(retryAfterSec),
      });

      logger.warn('Rate limit exceeded', {
        identity,
        path: req.path,
        limit: maxRequests,
        windowMs,
        retryAfterSec,
      });

      return errors.rateLimited(
        res,
        `Rate limit exceeded: ${maxRequests} requests per ${windowMs / 1000}s. Retry after ${retryAfterSec}s.`
      );
    }

    // Record this request
    window.timestamps.push(now);

    // Set rate limit headers
    res.set({
      'X-RateLimit-Limit': String(maxRequests),
      'X-RateLimit-Remaining': String(maxRequests - window.timestamps.length),
      'X-RateLimit-Reset': String(Math.ceil((now + windowMs) / 1000)),
    });

    next();
  };
}

/**
 * Returns current rate limit stats. Used by metrics endpoint.
 * @returns {{ totalIdentities: number, entries: Array }}
 */
function getStats() {
  const entries = [];
  for (const [identity, data] of identityWindows) {
    entries.push({
      identity,
      currentRequests: data.timestamps.length,
      maxRequests: data.maxRequests,
      windowMs: data.windowMs,
    });
  }
  return { totalIdentities: identityWindows.size, entries };
}

/**
 * Clears all rate limit state. Used for testing.
 */
function clearAll() {
  identityWindows.clear();
}

module.exports = { rateLimit, getStats, clearAll };

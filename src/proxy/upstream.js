const http = require('http');
const logger = require('../utils/logger');

/**
 * Upstream Health Checking and Circuit Breaker
 *
 * Monitors upstream service health via periodic HTTP health checks.
 * Implements a circuit breaker pattern:
 *
 * CLOSED (normal) → failures exceed threshold → OPEN (reject requests)
 * OPEN → after cooldown period → HALF-OPEN (allow single test request)
 * HALF-OPEN → test succeeds → CLOSED | test fails → OPEN
 *
 * This prevents cascading failures when an upstream is down.
 */

const CIRCUIT_STATES = { CLOSED: 'closed', OPEN: 'open', HALF_OPEN: 'half-open' };

class UpstreamManager {
  constructor() {
    this.upstreams = new Map();
    this.healthCheckIntervals = [];
  }

  /**
   * Registers an upstream service for health monitoring.
   * @param {string} name - Upstream identifier
   * @param {object} config - Upstream configuration from routes.json
   */
  register(name, config) {
    this.upstreams.set(name, {
      name,
      target: config.target,
      healthCheck: config.healthCheck || null,
      state: CIRCUIT_STATES.CLOSED,
      failures: 0,
      successes: 0,
      lastFailure: null,
      lastSuccess: null,
      unhealthyThreshold: config.healthCheck?.unhealthyThreshold || 3,
      healthyThreshold: config.healthCheck?.healthyThreshold || 2,
      cooldownMs: 30000, // 30 seconds before trying again
    });

    logger.info('Upstream registered', { name, target: config.target });

    // Start health checks if configured
    if (config.healthCheck) {
      this.startHealthCheck(name, config);
    }
  }

  /**
   * Starts periodic health checks for an upstream.
   */
  startHealthCheck(name, config) {
    const hc = config.healthCheck;
    const intervalMs = hc.intervalMs || 10000;
    const timeoutMs = hc.timeoutMs || 5000;

    const interval = setInterval(async () => {
      await this.checkHealth(name, hc.path, timeoutMs);
    }, intervalMs);

    interval.unref();
    this.healthCheckIntervals.push(interval);

    // Run first check immediately
    this.checkHealth(name, hc.path, timeoutMs);
  }

  /**
   * Performs a health check against an upstream.
   */
  async checkHealth(name, path, timeoutMs) {
    const upstream = this.upstreams.get(name);
    if (!upstream) return;

    try {
      const url = new URL(path, upstream.target);
      const healthy = await this.httpCheck(url.href, timeoutMs);

      if (healthy) {
        upstream.successes++;
        upstream.lastSuccess = Date.now();

        if (upstream.state === CIRCUIT_STATES.HALF_OPEN) {
          if (upstream.successes >= upstream.healthyThreshold) {
            upstream.state = CIRCUIT_STATES.CLOSED;
            upstream.failures = 0;
            logger.info('Circuit breaker CLOSED (upstream recovered)', { name });
          }
        } else if (upstream.state === CIRCUIT_STATES.OPEN) {
          // Shouldn't happen, but handle gracefully
          upstream.state = CIRCUIT_STATES.HALF_OPEN;
          upstream.successes = 1;
        }
      } else {
        this.recordFailure(upstream);
      }
    } catch (err) {
      this.recordFailure(upstream);
    }
  }

  /**
   * Records a failure and potentially trips the circuit breaker.
   */
  recordFailure(upstream) {
    upstream.failures++;
    upstream.successes = 0;
    upstream.lastFailure = Date.now();

    if (upstream.state === CIRCUIT_STATES.CLOSED && upstream.failures >= upstream.unhealthyThreshold) {
      upstream.state = CIRCUIT_STATES.OPEN;
      logger.warn('Circuit breaker OPEN (upstream unhealthy)', {
        name: upstream.name,
        failures: upstream.failures,
      });

      // Schedule transition to half-open
      setTimeout(() => {
        if (upstream.state === CIRCUIT_STATES.OPEN) {
          upstream.state = CIRCUIT_STATES.HALF_OPEN;
          upstream.successes = 0;
          logger.info('Circuit breaker HALF-OPEN (testing upstream)', { name: upstream.name });
        }
      }, upstream.cooldownMs).unref();
    } else if (upstream.state === CIRCUIT_STATES.HALF_OPEN) {
      upstream.state = CIRCUIT_STATES.OPEN;
      logger.warn('Circuit breaker back to OPEN (test request failed)', { name: upstream.name });

      setTimeout(() => {
        if (upstream.state === CIRCUIT_STATES.OPEN) {
          upstream.state = CIRCUIT_STATES.HALF_OPEN;
          upstream.successes = 0;
        }
      }, upstream.cooldownMs).unref();
    }
  }

  /**
   * Makes an HTTP GET request for health checking.
   */
  httpCheck(url, timeoutMs) {
    return new Promise((resolve) => {
      const req = http.get(url, { timeout: timeoutMs }, (res) => {
        // Consume response data to free up memory
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 400);
      });

      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
    });
  }

  /**
   * Checks if an upstream is available for routing.
   * @param {string} name - Upstream name
   * @returns {boolean}
   */
  isAvailable(name) {
    const upstream = this.upstreams.get(name);
    if (!upstream) return false;
    return upstream.state !== CIRCUIT_STATES.OPEN;
  }

  /**
   * Gets the target URL for an upstream.
   * @param {string} name - Upstream name
   * @returns {string|null}
   */
  getTarget(name) {
    const upstream = this.upstreams.get(name);
    return upstream ? upstream.target : null;
  }

  /**
   * Returns status of all upstreams for health/metrics endpoints.
   */
  getStatus() {
    const status = {};
    for (const [name, upstream] of this.upstreams) {
      status[name] = {
        target: upstream.target,
        state: upstream.state,
        failures: upstream.failures,
        lastFailure: upstream.lastFailure ? new Date(upstream.lastFailure).toISOString() : null,
        lastSuccess: upstream.lastSuccess ? new Date(upstream.lastSuccess).toISOString() : null,
      };
    }
    return status;
  }

  /**
   * Stops all health check intervals.
   */
  shutdown() {
    for (const interval of this.healthCheckIntervals) {
      clearInterval(interval);
    }
    this.healthCheckIntervals = [];
  }
}

// Singleton instance
const upstreamManager = new UpstreamManager();

module.exports = upstreamManager;

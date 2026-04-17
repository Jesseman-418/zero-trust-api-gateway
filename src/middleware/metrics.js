/**
 * Metrics Collection Middleware
 *
 * Tracks gateway performance and health metrics in-memory:
 * - Total request count (by status code, method, path)
 * - Latency percentiles (p50, p95, p99)
 * - Error rates
 * - Active connections
 * - Rate limit hit count
 * - Policy denial count
 *
 * Exposed via /gateway/metrics endpoint for monitoring/alerting.
 */

const metrics = {
  startTime: Date.now(),
  requests: {
    total: 0,
    byStatus: {},   // { "200": count, "401": count, ... }
    byMethod: {},   // { "GET": count, "POST": count, ... }
    byPath: {},     // { "/api/users": count, ... }
  },
  latencies: [],       // Recent latencies for percentile calculation
  errors: {
    total: 0,
    auth: 0,           // 401s
    forbidden: 0,      // 403s
    rateLimited: 0,    // 429s
    upstream: 0,       // 502/504s
    internal: 0,       // 500s
  },
  activeConnections: 0,
};

const MAX_LATENCY_SAMPLES = 10000;

/**
 * Metrics collection middleware.
 * Records request/response metrics for every proxied request.
 */
function collectMetrics() {
  return (req, res, next) => {
    const startTime = Date.now();
    metrics.requests.total++;
    metrics.activeConnections++;

    // Count by method
    metrics.requests.byMethod[req.method] = (metrics.requests.byMethod[req.method] || 0) + 1;

    // Normalize path for aggregation (collapse path params)
    const normalizedPath = normalizePath(req.path);
    metrics.requests.byPath[normalizedPath] = (metrics.requests.byPath[normalizedPath] || 0) + 1;

    // Capture on response finish
    res.on('finish', () => {
      metrics.activeConnections--;
      const latency = Date.now() - startTime;

      // Record latency
      metrics.latencies.push(latency);
      if (metrics.latencies.length > MAX_LATENCY_SAMPLES) {
        metrics.latencies = metrics.latencies.slice(-MAX_LATENCY_SAMPLES);
      }

      // Count by status
      const status = String(res.statusCode);
      metrics.requests.byStatus[status] = (metrics.requests.byStatus[status] || 0) + 1;

      // Categorize errors
      if (res.statusCode >= 400) {
        metrics.errors.total++;
        if (res.statusCode === 401) metrics.errors.auth++;
        else if (res.statusCode === 403) metrics.errors.forbidden++;
        else if (res.statusCode === 429) metrics.errors.rateLimited++;
        else if (res.statusCode === 502 || res.statusCode === 504) metrics.errors.upstream++;
        else if (res.statusCode === 500) metrics.errors.internal++;
      }
    });

    next();
  };
}

/**
 * Normalizes a path for metrics aggregation.
 * Collapses UUIDs and numeric IDs to `:id`.
 */
function normalizePath(p) {
  return p
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
    .replace(/\/\d+/g, '/:id');
}

/**
 * Calculates percentile from sorted array.
 * @param {number[]} sorted - Sorted array of values
 * @param {number} p - Percentile (0-100)
 * @returns {number}
 */
function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

/**
 * Returns current metrics snapshot.
 * @returns {object} Metrics data
 */
function getMetrics() {
  const sorted = [...metrics.latencies].sort((a, b) => a - b);
  const uptimeMs = Date.now() - metrics.startTime;

  return {
    gateway: {
      uptime: {
        ms: uptimeMs,
        human: formatUptime(uptimeMs),
      },
      startTime: new Date(metrics.startTime).toISOString(),
    },
    requests: {
      total: metrics.requests.total,
      byStatus: metrics.requests.byStatus,
      byMethod: metrics.requests.byMethod,
      topPaths: getTopPaths(10),
      requestsPerSecond: metrics.requests.total / (uptimeMs / 1000) || 0,
    },
    latency: {
      samples: sorted.length,
      p50: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      p99: percentile(sorted, 99),
      min: sorted[0] || 0,
      max: sorted[sorted.length - 1] || 0,
      avg: sorted.length > 0 ? Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length) : 0,
    },
    errors: { ...metrics.errors },
    connections: {
      active: metrics.activeConnections,
    },
  };
}

/**
 * Returns the top N most-requested paths.
 */
function getTopPaths(n) {
  return Object.entries(metrics.requests.byPath)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([path, count]) => ({ path, count }));
}

/**
 * Formats milliseconds into human-readable uptime.
 */
function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

/**
 * Resets all metrics. Used for testing.
 */
function resetMetrics() {
  metrics.requests.total = 0;
  metrics.requests.byStatus = {};
  metrics.requests.byMethod = {};
  metrics.requests.byPath = {};
  metrics.latencies = [];
  metrics.errors = { total: 0, auth: 0, forbidden: 0, rateLimited: 0, upstream: 0, internal: 0 };
  metrics.activeConnections = 0;
  metrics.startTime = Date.now();
}

module.exports = { collectMetrics, getMetrics, resetMetrics };

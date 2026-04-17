const logger = require('../utils/logger');

/**
 * Example Plugin: Request Transformation
 *
 * Demonstrates the plugin architecture by adding custom headers
 * and logging request metadata. This serves as a template for
 * building custom plugins.
 *
 * To create a new plugin:
 * 1. Create a new .js file in this directory
 * 2. Export an object matching the plugin interface below
 * 3. The gateway will auto-discover and load it on startup
 */

module.exports = {
  name: 'request-transformer',
  version: '1.0.0',
  phase: 'pre-proxy',
  description: 'Adds custom headers and normalizes request metadata before proxying',

  /**
   * Called once during gateway startup.
   * Use for one-time setup (connections, caches, etc.)
   */
  init(app, config) {
    logger.info('Request Transformer plugin initialized');
  },

  /**
   * Returns Express middleware function.
   * Called for every request during the plugin's phase.
   */
  middleware() {
    return (req, res, next) => {
      // Add timestamp header for upstream latency tracking
      req.headers['x-gateway-timestamp'] = Date.now().toString();

      // Add correlation ID if not present
      if (!req.headers['x-correlation-id']) {
        req.headers['x-correlation-id'] = req.requestId || '';
      }

      // Normalize content-type for JSON APIs
      if (req.headers['content-type'] === 'text/json') {
        req.headers['content-type'] = 'application/json';
      }

      // Strip internal-only headers that clients shouldn't send
      delete req.headers['x-internal-only'];
      delete req.headers['x-debug-mode'];

      next();
    };
  },
};

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * Plugin Architecture
 *
 * Allows extending the gateway with custom middleware plugins.
 * Plugins are loaded from the plugins directory and must export:
 *
 * {
 *   name: string,          // Plugin identifier
 *   version: string,       // Semver version
 *   phase: string,         // 'pre-auth' | 'post-auth' | 'pre-proxy' | 'post-proxy'
 *   init: function(app, config) => void,   // Setup function
 *   middleware: function() => Express middleware,  // Optional middleware factory
 * }
 *
 * Phases determine when the plugin's middleware runs in the pipeline:
 * - pre-auth:   Before authentication (e.g., custom header injection)
 * - post-auth:  After authentication, before authorization
 * - pre-proxy:  After authorization, before proxying
 * - post-proxy: After proxy response (response transformation)
 */

const VALID_PHASES = ['pre-auth', 'post-auth', 'pre-proxy', 'post-proxy'];

/**
 * Discovers and loads all plugins from the plugins directory.
 * Skips the loader itself and any files starting with '_'.
 *
 * @param {string} pluginDir - Path to plugins directory
 * @returns {Map<string, object>} Map of phase -> plugin array
 */
function loadPlugins(pluginDir) {
  const plugins = new Map();
  for (const phase of VALID_PHASES) {
    plugins.set(phase, []);
  }

  const dir = pluginDir || path.join(__dirname);

  if (!fs.existsSync(dir)) {
    logger.warn('Plugin directory not found', { dir });
    return plugins;
  }

  const files = fs.readdirSync(dir).filter((f) => {
    return f.endsWith('.js') && f !== 'loader.js' && !f.startsWith('_');
  });

  for (const file of files) {
    try {
      const pluginPath = path.join(dir, file);
      const plugin = require(pluginPath);

      if (!plugin.name || !plugin.phase) {
        logger.warn('Plugin missing required fields (name, phase)', { file });
        continue;
      }

      if (!VALID_PHASES.includes(plugin.phase)) {
        logger.warn('Plugin has invalid phase', { file, phase: plugin.phase });
        continue;
      }

      plugins.get(plugin.phase).push(plugin);
      logger.info('Plugin loaded', {
        name: plugin.name,
        version: plugin.version || '1.0.0',
        phase: plugin.phase,
      });
    } catch (err) {
      logger.error('Failed to load plugin', { file, error: err.message });
    }
  }

  return plugins;
}

/**
 * Registers plugin middleware with the Express app.
 *
 * @param {object} app - Express app
 * @param {Map} plugins - Plugin map from loadPlugins()
 * @param {string} phase - Which phase to register
 * @param {object} config - Gateway configuration
 */
function registerPhase(app, plugins, phase, config) {
  const phasePlugins = plugins.get(phase) || [];
  for (const plugin of phasePlugins) {
    try {
      if (plugin.init) {
        plugin.init(app, config);
      }
      if (plugin.middleware) {
        app.use(plugin.middleware());
        logger.info('Plugin middleware registered', {
          name: plugin.name,
          phase,
        });
      }
    } catch (err) {
      logger.error('Failed to register plugin', {
        name: plugin.name,
        phase,
        error: err.message,
      });
    }
  }
}

module.exports = { loadPlugins, registerPhase, VALID_PHASES };

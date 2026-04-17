const config = require('../config');
const logger = require('../utils/logger');

/**
 * RFC 7662 Token Introspection
 *
 * Validates an access token by querying the authorization server's
 * introspection endpoint. This provides real-time token validation
 * including revocation checking — critical for zero-trust architectures
 * where token revocation must be enforced immediately.
 *
 * The introspection response includes:
 * - active: boolean indicating if token is valid
 * - scope: granted scopes
 * - client_id: the client that requested the token
 * - sub: the resource owner (user)
 * - exp: expiration timestamp
 */

// Cache introspection results briefly to avoid hammering the auth server
const introspectionCache = new Map();
const CACHE_TTL_MS = 30000; // 30 seconds

/**
 * Introspects a token against the configured authorization server.
 *
 * @param {string} token - The access token to introspect
 * @returns {Promise<object>} Introspection response with `active` field
 */
async function introspectToken(token) {
  if (!config.introspection.endpoint) {
    logger.debug('Token introspection not configured, skipping');
    return { active: true, skipped: true };
  }

  // Check cache first
  const cached = introspectionCache.get(token);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    logger.debug('Token introspection cache hit');
    return cached.result;
  }

  try {
    const credentials = Buffer.from(
      `${config.introspection.clientId}:${config.introspection.clientSecret}`
    ).toString('base64');

    const response = await fetch(config.introspection.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
        Accept: 'application/json',
      },
      body: `token=${encodeURIComponent(token)}&token_type_hint=access_token`,
    });

    if (!response.ok) {
      logger.error('Token introspection HTTP error', {
        status: response.status,
        statusText: response.statusText,
      });
      return { active: false, error: 'introspection_endpoint_error' };
    }

    const result = await response.json();

    // Cache the result
    introspectionCache.set(token, { result, timestamp: Date.now() });

    // Prune cache if it grows too large
    if (introspectionCache.size > 10000) {
      const now = Date.now();
      for (const [key, value] of introspectionCache) {
        if (now - value.timestamp > CACHE_TTL_MS) {
          introspectionCache.delete(key);
        }
      }
    }

    logger.debug('Token introspection result', { active: result.active });
    return result;
  } catch (err) {
    logger.error('Token introspection failed', { error: err.message });
    // Fail closed — if we can't verify, deny access
    return { active: false, error: 'introspection_request_failed' };
  }
}

/**
 * Clears the introspection cache. Useful for testing.
 */
function clearIntrospectionCache() {
  introspectionCache.clear();
}

module.exports = { introspectToken, clearIntrospectionCache };

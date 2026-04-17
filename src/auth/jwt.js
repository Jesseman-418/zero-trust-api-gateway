const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * JWKS-based JWT verification with key caching and rotation support.
 *
 * In production mode, fetches public keys from the OIDC provider's
 * /.well-known/jwks.json endpoint. Keys are cached and automatically
 * rotated when the provider publishes new keys.
 *
 * In demo mode, uses a symmetric secret for local testing.
 */

let client = null;

function getJwksClient() {
  if (!client && !config.demo.enabled) {
    client = jwksClient({
      jwksUri: config.jwks.uri,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 600000, // 10 minutes
      rateLimit: true,
      jwksRequestsPerMinute: 10,
    });
    logger.info('JWKS client initialized', { uri: config.jwks.uri });
  }
  return client;
}

/**
 * Retrieves the signing key from JWKS endpoint for a given key ID.
 * @param {object} header - JWT header containing `kid`
 * @returns {Promise<string>} The public key or secret
 */
function getSigningKey(header) {
  return new Promise((resolve, reject) => {
    if (config.demo.enabled) {
      return resolve(config.demo.jwtSecret);
    }

    const jwks = getJwksClient();
    jwks.getSigningKey(header.kid, (err, key) => {
      if (err) {
        logger.error('JWKS key retrieval failed', {
          kid: header.kid,
          error: err.message,
        });
        return reject(err);
      }
      const signingKey = key.getPublicKey();
      resolve(signingKey);
    });
  });
}

/**
 * Verifies a JWT token and returns decoded payload.
 * Validates signature, expiration, issuer, and audience.
 *
 * @param {string} token - The raw JWT string
 * @returns {Promise<object>} Decoded token payload
 * @throws {Error} If verification fails
 */
async function verifyToken(token) {
  // Decode header first to get kid for JWKS lookup
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) {
    throw new Error('Invalid token format: unable to decode');
  }

  const signingKey = await getSigningKey(decoded.header);

  const verifyOptions = {
    algorithms: config.demo.enabled ? ['HS256'] : ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'],
  };

  // In production, validate issuer and audience
  if (!config.demo.enabled) {
    if (config.jwks.issuer) verifyOptions.issuer = config.jwks.issuer;
    if (config.jwks.audience) verifyOptions.audience = config.jwks.audience;
  }

  return new Promise((resolve, reject) => {
    jwt.verify(token, signingKey, verifyOptions, (err, payload) => {
      if (err) {
        logger.debug('JWT verification failed', {
          error: err.message,
          code: err.name,
        });
        reject(err);
      } else {
        resolve(payload);
      }
    });
  });
}

/**
 * Extracts a bearer token from the Authorization header.
 * @param {string} authHeader - The Authorization header value
 * @returns {string|null} The token or null
 */
function extractBearerToken(authHeader) {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1];
}

module.exports = { verifyToken, extractBearerToken, getJwksClient };

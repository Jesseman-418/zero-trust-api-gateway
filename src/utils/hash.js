const crypto = require('crypto');

/**
 * Generates a SHA-256 hash of the given data.
 * @param {string} data - Input string to hash
 * @returns {string} Hex-encoded SHA-256 hash
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Creates a chain hash by combining the previous hash with current entry data.
 * This produces a tamper-proof log chain — altering any entry invalidates
 * all subsequent hashes.
 *
 * @param {string} previousHash - Hash of the previous log entry (or "GENESIS" for first)
 * @param {object} entry - The current log entry data
 * @returns {string} The chain hash for this entry
 */
function chainHash(previousHash, entry) {
  const payload = previousHash + JSON.stringify(entry);
  return sha256(payload);
}

/**
 * Computes HMAC-SHA256 for request signing verification.
 * @param {string} secret - HMAC secret key
 * @param {string} data - Data to sign
 * @returns {string} Hex-encoded HMAC
 */
function hmacSha256(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Verifies an HMAC signature against expected value.
 * Uses timing-safe comparison to prevent timing attacks.
 * @param {string} secret - HMAC secret key
 * @param {string} data - Original data
 * @param {string} signature - Signature to verify
 * @returns {boolean}
 */
function verifyHmac(secret, data, signature) {
  const expected = hmacSha256(secret, data);
  if (expected.length !== signature.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

module.exports = { sha256, chainHash, hmacSha256, verifyHmac };

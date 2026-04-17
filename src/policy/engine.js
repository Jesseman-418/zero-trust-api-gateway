const rbac = require('./rbac');
const abac = require('./abac');
const logger = require('../utils/logger');

/**
 * Unified Policy Engine
 *
 * Orchestrates RBAC and ABAC evaluation in a single decision point.
 * Follows the XACML-inspired pattern:
 *
 * 1. Extract identity attributes (roles, claims) from JWT
 * 2. Evaluate RBAC — does this role have permission for this route+method?
 * 3. Evaluate ABAC — do environmental conditions permit access?
 * 4. Combine results — BOTH must allow for access to be granted
 *
 * This deny-override combination ensures defense-in-depth:
 * even an admin is denied if ABAC conditions aren't met.
 */

/**
 * Makes an access decision for a request.
 *
 * @param {object} req - Express request with tokenPayload attached
 * @returns {{
 *   allowed: boolean,
 *   rbac: {allowed: boolean, reason: string},
 *   abac: {allowed: boolean, policy: string|null, reason: string},
 *   reason: string
 * }}
 */
function decide(req) {
  const tokenPayload = req.tokenPayload || {};
  const roles = rbac.extractRoles(tokenPayload);
  const requestPath = req.path;
  const method = req.method;

  // Step 1: RBAC evaluation
  const rbacResult = rbac.checkAccess(roles, requestPath, method);

  // Step 2: ABAC evaluation
  const abacResult = abac.evaluate(req);

  // Step 3: Combine — both must allow (deny-override)
  const allowed = rbacResult.allowed && abacResult.allowed;

  const decision = {
    allowed,
    rbac: rbacResult,
    abac: abacResult,
    identity: {
      sub: tokenPayload.sub || 'unknown',
      roles,
    },
    resource: {
      path: requestPath,
      method,
    },
    reason: allowed
      ? 'Access granted'
      : !rbacResult.allowed
        ? `RBAC: ${rbacResult.reason}`
        : `ABAC: ${abacResult.reason}`,
  };

  logger.debug('Policy decision', {
    sub: decision.identity.sub,
    path: requestPath,
    method,
    allowed,
    rbacAllowed: rbacResult.allowed,
    abacAllowed: abacResult.allowed,
  });

  return decision;
}

/**
 * Reloads all policies from disk.
 * Useful for dynamic policy updates without restart.
 */
function reloadAll() {
  rbac.reloadPolicy();
  abac.reloadPolicy();
  logger.info('All policies reloaded');
}

module.exports = { decide, reloadAll };

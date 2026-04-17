const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * Role-Based Access Control (RBAC)
 *
 * Maps JWT claims to permissions. The token's `roles` or `groups` claim
 * determines which permissions the identity has. Each route+method combination
 * requires specific permissions.
 *
 * Supports wildcard routes (/api/admin/*) and wildcard methods (*).
 */

let rbacPolicy = null;

/**
 * Loads RBAC policy from the JSON policy file.
 * @returns {object} The parsed RBAC policy
 */
function loadPolicy() {
  if (!rbacPolicy) {
    const policyPath = path.join(__dirname, '../../policies/rbac.json');
    rbacPolicy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    logger.info('RBAC policy loaded', {
      roles: Object.keys(rbacPolicy.roles).length,
      routes: Object.keys(rbacPolicy.routes).length,
    });
  }
  return rbacPolicy;
}

/**
 * Reloads the RBAC policy (for hot-reload support).
 */
function reloadPolicy() {
  rbacPolicy = null;
  return loadPolicy();
}

/**
 * Extracts roles from a JWT payload.
 * Supports multiple claim formats used by different identity providers:
 * - Okta: `groups` or `scp` claims
 * - Auth0: `permissions` or custom namespace claims
 * - Generic: `roles` claim
 *
 * @param {object} tokenPayload - Decoded JWT payload
 * @returns {string[]} Array of role names
 */
function extractRoles(tokenPayload) {
  // Check common role/group claim locations
  const roles = tokenPayload.roles
    || tokenPayload.groups
    || tokenPayload['cognito:groups']
    || tokenPayload.realm_access?.roles
    || [];

  // Ensure we always return an array
  return Array.isArray(roles) ? roles : [roles];
}

/**
 * Gets all permissions for a set of roles.
 * @param {string[]} roles - The identity's roles
 * @returns {Set<string>} Combined permissions from all roles
 */
function getPermissions(roles) {
  const policy = loadPolicy();
  const permissions = new Set();

  for (const role of roles) {
    const roleDef = policy.roles[role];
    if (roleDef) {
      for (const perm of roleDef.permissions) {
        permissions.add(perm);
      }
    }
  }

  return permissions;
}

/**
 * Finds the matching route config for a given path.
 * Supports exact match and wildcard (*) matching.
 *
 * @param {string} requestPath - The incoming request path
 * @returns {object|null} Route permission config or null
 */
function findRouteConfig(requestPath) {
  const policy = loadPolicy();
  const routes = policy.routes;

  // Try exact match first
  if (routes[requestPath]) {
    return routes[requestPath];
  }

  // Try wildcard matches (longest prefix wins)
  let bestMatch = null;
  let bestLength = 0;

  for (const routePattern of Object.keys(routes)) {
    if (routePattern.endsWith('/*')) {
      const prefix = routePattern.slice(0, -2);
      if (requestPath.startsWith(prefix) && prefix.length > bestLength) {
        bestMatch = routes[routePattern];
        bestLength = prefix.length;
      }
    }
  }

  return bestMatch;
}

/**
 * Checks if an identity with given roles can access a route+method.
 *
 * @param {string[]} roles - The identity's roles
 * @param {string} requestPath - The request path
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @returns {{allowed: boolean, reason: string}}
 */
function checkAccess(roles, requestPath, method) {
  const routeConfig = findRouteConfig(requestPath);

  if (!routeConfig) {
    // No route config = no restrictions defined, allow by default
    return { allowed: true, reason: 'No RBAC policy for this route' };
  }

  // Get required permissions for this method
  let requiredPerms = routeConfig[method] || routeConfig['*'];

  if (!requiredPerms) {
    return { allowed: false, reason: `Method ${method} not permitted on this route` };
  }

  // Empty array means no permissions required (public)
  if (requiredPerms.length === 0) {
    return { allowed: true, reason: 'No permissions required' };
  }

  const identityPerms = getPermissions(roles);

  // Check if identity has ANY of the required permissions
  const hasPermission = requiredPerms.some((perm) => identityPerms.has(perm));

  if (hasPermission) {
    return {
      allowed: true,
      reason: `Identity has required permission for ${method} ${requestPath}`,
    };
  }

  return {
    allowed: false,
    reason: `Missing required permissions: [${requiredPerms.join(', ')}]. Identity has: [${[...identityPerms].join(', ')}]`,
  };
}

module.exports = { loadPolicy, reloadPolicy, extractRoles, getPermissions, checkAccess, findRouteConfig };

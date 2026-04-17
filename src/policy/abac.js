const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * Attribute-Based Access Control (ABAC)
 *
 * Evaluates access decisions based on attributes of:
 * - Subject (identity claims from JWT)
 * - Resource (the requested path/endpoint)
 * - Action (HTTP method)
 * - Environment (time of day, IP address, etc.)
 *
 * Policies are evaluated in order. A "deny" effect blocks access
 * if all conditions match. This follows a deny-override model.
 */

let abacPolicy = null;

function loadPolicy() {
  if (!abacPolicy) {
    const policyPath = path.join(__dirname, '../../policies/abac.json');
    abacPolicy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    logger.info('ABAC policy loaded', {
      policies: abacPolicy.policies.length,
    });
  }
  return abacPolicy;
}

function reloadPolicy() {
  abacPolicy = null;
  return loadPolicy();
}

/**
 * Checks if a request path matches a resource pattern.
 * @param {string} requestPath - Actual request path
 * @param {string} pattern - Resource pattern (supports trailing /*)
 * @returns {boolean}
 */
function matchesResource(requestPath, pattern) {
  if (pattern === requestPath) return true;
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return requestPath.startsWith(prefix);
  }
  return false;
}

/**
 * Parses a CIDR notation string and checks if an IP falls within it.
 * @param {string} ip - IP address to check
 * @param {string} cidr - CIDR notation (e.g., "10.0.0.0/8")
 * @returns {boolean}
 */
function ipInCIDR(ip, cidr) {
  // Handle IPv4-mapped IPv6 addresses
  const cleanIp = ip.replace(/^::ffff:/, '');

  const [network, bits] = cidr.split('/');
  const mask = parseInt(bits, 10);

  const ipParts = cleanIp.split('.').map(Number);
  const networkParts = network.split('.').map(Number);

  if (ipParts.length !== 4 || networkParts.length !== 4) return false;

  const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
  const netNum = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
  const maskNum = mask === 0 ? 0 : (~0 << (32 - mask));

  return (ipNum & maskNum) === (netNum & maskNum);
}

/**
 * Evaluates a single condition against the request context.
 * @param {string} attribute - The attribute key (e.g., "time.hour")
 * @param {object} operator - The operator and value (e.g., { "notBetween": [9, 17] })
 * @param {object} context - The request context
 * @returns {boolean} Whether the condition matches (true = condition is met)
 */
function evaluateCondition(attribute, operator, context) {
  const [operatorName, operatorValue] = Object.entries(operator)[0];

  let actualValue;

  // Resolve the attribute from context
  switch (attribute) {
    case 'time.hour':
      actualValue = context.time.hour;
      break;
    case 'time.dayOfWeek':
      actualValue = context.time.dayOfWeek;
      break;
    case 'request.ip':
      actualValue = context.request.ip;
      break;
    case 'request.method':
      actualValue = context.request.method;
      break;
    case 'token.amr':
      actualValue = context.token?.amr || [];
      break;
    case 'token.sub':
      actualValue = context.token?.sub;
      break;
    case 'token.scope':
      actualValue = context.token?.scope || context.token?.scp || '';
      break;
    default:
      // Support dot-notation traversal for custom attributes
      actualValue = attribute.split('.').reduce((obj, key) => obj?.[key], context);
  }

  // Evaluate the operator
  switch (operatorName) {
    case 'equals':
      return actualValue === operatorValue;

    case 'notEquals':
      return actualValue !== operatorValue;

    case 'in':
      return Array.isArray(operatorValue) && operatorValue.includes(actualValue);

    case 'notIn':
      return Array.isArray(operatorValue) && !operatorValue.includes(actualValue);

    case 'between':
      return actualValue >= operatorValue[0] && actualValue <= operatorValue[1];

    case 'notBetween':
      return actualValue < operatorValue[0] || actualValue > operatorValue[1];

    case 'contains':
      return Array.isArray(actualValue) && actualValue.includes(operatorValue);

    case 'notContains':
      if (Array.isArray(actualValue)) return !actualValue.includes(operatorValue);
      return true; // If not an array, condition is met (attribute doesn't contain value)

    case 'inCIDR':
      return Array.isArray(operatorValue) && operatorValue.some((cidr) => ipInCIDR(actualValue, cidr));

    case 'notInCIDR':
      return Array.isArray(operatorValue) && !operatorValue.some((cidr) => ipInCIDR(actualValue, cidr));

    case 'matches':
      return new RegExp(operatorValue).test(actualValue);

    case 'greaterThan':
      return actualValue > operatorValue;

    case 'lessThan':
      return actualValue < operatorValue;

    default:
      logger.warn('Unknown ABAC operator', { operator: operatorName });
      return false;
  }
}

/**
 * Builds the evaluation context from a request.
 * @param {object} req - Express request
 * @returns {object} Context object for policy evaluation
 */
function buildContext(req) {
  const now = new Date();
  return {
    time: {
      hour: now.getUTCHours(),
      minute: now.getUTCMinutes(),
      dayOfWeek: now.getUTCDay(), // 0 = Sunday
      date: now.toISOString().split('T')[0],
    },
    request: {
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
      method: req.method,
      path: req.path,
      userAgent: req.get('user-agent') || '',
      contentType: req.get('content-type') || '',
    },
    token: req.tokenPayload || {},
  };
}

/**
 * Evaluates all ABAC policies against a request.
 * Returns the first denying policy or an allow result.
 *
 * @param {object} req - Express request (with tokenPayload attached)
 * @returns {{allowed: boolean, policy: string|null, reason: string}}
 */
function evaluate(req) {
  const policy = loadPolicy();
  const context = buildContext(req);

  for (const p of policy.policies) {
    // Check if this policy applies to the requested resource
    const resourceMatch = p.resources.some((res) => matchesResource(req.path, res));
    if (!resourceMatch) continue;

    // Evaluate all conditions — all must match for the policy to apply
    const allConditionsMatch = Object.entries(p.condition).every(([attr, op]) =>
      evaluateCondition(attr, op, context)
    );

    if (allConditionsMatch && p.effect === 'deny') {
      logger.info('ABAC policy denied request', {
        policy: p.name,
        path: req.path,
        method: req.method,
        ip: context.request.ip,
      });
      return {
        allowed: false,
        policy: p.name,
        reason: p.description || `Denied by ABAC policy: ${p.name}`,
      };
    }
  }

  return { allowed: true, policy: null, reason: 'All ABAC policies passed' };
}

module.exports = { loadPolicy, reloadPolicy, evaluate, buildContext, ipInCIDR, evaluateCondition };

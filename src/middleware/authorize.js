const policyEngine = require('../policy/engine');
const errors = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Authorization Middleware (Policy Enforcement Point)
 *
 * Sits between authentication and the proxy handler.
 * After the identity is verified (authentication), this middleware
 * evaluates whether the verified identity is permitted to perform
 * the requested action on the requested resource.
 *
 * Uses the unified policy engine which combines RBAC + ABAC.
 */

function authorize() {
  return (req, res, next) => {
    // Skip authorization for unauthenticated routes
    if (req.routeConfig && req.routeConfig.authentication === false) {
      return next();
    }

    // If no token payload, authentication didn't run or failed
    if (!req.tokenPayload) {
      return errors.unauthorized(res, 'No identity context available for authorization');
    }

    const decision = policyEngine.decide(req);

    // Attach decision to request for audit logging
    req.policyDecision = decision;

    if (!decision.allowed) {
      logger.info('Authorization denied', {
        sub: req.identityId,
        path: req.path,
        method: req.method,
        reason: decision.reason,
      });

      if (!decision.rbac.allowed) {
        return errors.forbidden(res, decision.reason);
      }

      if (!decision.abac.allowed) {
        return errors.policyDenied(res, decision.abac.policy, decision.reason);
      }

      return errors.forbidden(res, decision.reason);
    }

    logger.debug('Authorization granted', {
      sub: req.identityId,
      path: req.path,
      method: req.method,
    });

    next();
  };
}

module.exports = { authorize };

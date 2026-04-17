/**
 * Standard error response factory.
 * All gateway errors follow RFC 7807 (Problem Details) structure.
 */

function errorResponse(res, statusCode, error, detail = null) {
  const body = {
    status: statusCode,
    error,
    detail,
    timestamp: new Date().toISOString(),
    gateway: 'zero-trust-gateway',
  };
  res.status(statusCode).json(body);
}

const errors = {
  unauthorized(res, detail = 'Authentication required') {
    errorResponse(res, 401, 'Unauthorized', detail);
  },

  forbidden(res, detail = 'Insufficient permissions') {
    errorResponse(res, 403, 'Forbidden', detail);
  },

  notFound(res, detail = 'Resource not found') {
    errorResponse(res, 404, 'Not Found', detail);
  },

  rateLimited(res, detail = 'Rate limit exceeded') {
    errorResponse(res, 429, 'Too Many Requests', detail);
  },

  badRequest(res, detail = 'Invalid request') {
    errorResponse(res, 400, 'Bad Request', detail);
  },

  badGateway(res, detail = 'Upstream service unavailable') {
    errorResponse(res, 502, 'Bad Gateway', detail);
  },

  gatewayTimeout(res, detail = 'Upstream request timed out') {
    errorResponse(res, 504, 'Gateway Timeout', detail);
  },

  internalError(res, detail = 'Internal gateway error') {
    errorResponse(res, 500, 'Internal Server Error', detail);
  },

  ipDenied(res, detail = 'IP address not permitted') {
    errorResponse(res, 403, 'IP Denied', detail);
  },

  policyDenied(res, policyName, detail) {
    errorResponse(res, 403, 'Policy Violation', detail || `Denied by policy: ${policyName}`);
  },
};

module.exports = errors;

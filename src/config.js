require('dotenv').config();

const config = {
  gateway: {
    port: parseInt(process.env.GATEWAY_PORT || '3002', 10),
    upstreamPort: parseInt(process.env.UPSTREAM_PORT || '4001', 10),
  },

  jwks: {
    uri: process.env.JWKS_URI || '',
    issuer: process.env.JWT_ISSUER || '',
    audience: process.env.JWT_AUDIENCE || 'api://default',
  },

  introspection: {
    endpoint: process.env.INTROSPECTION_ENDPOINT || '',
    clientId: process.env.INTROSPECTION_CLIENT_ID || '',
    clientSecret: process.env.INTROSPECTION_CLIENT_SECRET || '',
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  },

  security: {
    hmacSecret: process.env.HMAC_SECRET || '',
    requestBodyMaxSize: process.env.REQUEST_BODY_MAX_SIZE || '1mb',
  },

  mtls: {
    enabled: process.env.MTLS_ENABLED === 'true',
    caCertPath: process.env.MTLS_CA_CERT_PATH || './certs/ca.pem',
    certPath: process.env.MTLS_CERT_PATH || './certs/server.pem',
    keyPath: process.env.MTLS_KEY_PATH || './certs/server-key.pem',
  },

  logging: {
    level: process.env.LOG_LEVEL || 'info',
    auditLogPath: process.env.AUDIT_LOG_PATH || './audit-logs',
  },

  demo: {
    enabled: process.env.DEMO_MODE === 'true',
    jwtSecret: process.env.DEMO_JWT_SECRET || 'demo-secret-key-change-in-production',
  },
};

module.exports = config;

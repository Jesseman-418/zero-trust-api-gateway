const fs = require('fs');
const tls = require('tls');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Mutual TLS (mTLS) Validation
 *
 * In zero-trust architecture, mTLS ensures both client and server
 * authenticate each other using X.509 certificates. This provides:
 *
 * 1. Client authentication — server verifies client's certificate
 * 2. Server authentication — client verifies server's certificate
 * 3. Transport encryption — all data encrypted in transit
 *
 * The gateway can require mTLS for specific routes (configured in routes.json),
 * providing defense-in-depth alongside JWT authentication.
 */

let tlsOptions = null;

/**
 * Loads TLS certificates and creates mTLS configuration.
 * @returns {object|null} TLS options for https.createServer, or null if disabled
 */
function loadMTLSConfig() {
  if (!config.mtls.enabled) {
    logger.info('mTLS is disabled');
    return null;
  }

  try {
    tlsOptions = {
      // Server certificate and key
      cert: fs.readFileSync(config.mtls.certPath),
      key: fs.readFileSync(config.mtls.keyPath),
      // CA certificate for verifying client certificates
      ca: fs.readFileSync(config.mtls.caCertPath),
      // Require client certificate
      requestCert: true,
      // Reject connections without valid client cert
      rejectUnauthorized: true,
    };

    logger.info('mTLS configuration loaded', {
      certPath: config.mtls.certPath,
      caPath: config.mtls.caCertPath,
    });

    return tlsOptions;
  } catch (err) {
    logger.error('Failed to load mTLS certificates', {
      error: err.message,
      certPath: config.mtls.certPath,
      caPath: config.mtls.caCertPath,
    });
    return null;
  }
}

/**
 * Express middleware that validates client certificate for routes requiring mTLS.
 * The route configuration specifies `requireMTLS: true` for protected routes.
 */
function validateClientCert(req, res, next) {
  // If mTLS is not enabled globally, skip
  if (!config.mtls.enabled) {
    return next();
  }

  // Check if the route requires mTLS
  const routeConfig = req.routeConfig;
  if (!routeConfig || !routeConfig.requireMTLS) {
    return next();
  }

  const cert = req.socket.getPeerCertificate();

  if (!cert || Object.keys(cert).length === 0) {
    logger.warn('mTLS required but no client certificate provided', {
      path: req.path,
      ip: req.ip,
    });
    return res.status(401).json({
      status: 401,
      error: 'Client Certificate Required',
      detail: 'This endpoint requires mutual TLS authentication',
    });
  }

  if (!req.client.authorized) {
    logger.warn('mTLS client certificate not authorized', {
      path: req.path,
      ip: req.ip,
      subject: cert.subject?.CN,
      issuer: cert.issuer?.CN,
    });
    return res.status(403).json({
      status: 403,
      error: 'Certificate Not Authorized',
      detail: 'Client certificate failed verification',
    });
  }

  // Attach cert info to request for downstream use
  req.clientCert = {
    subject: cert.subject,
    issuer: cert.issuer,
    fingerprint: cert.fingerprint256,
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
  };

  logger.debug('mTLS client certificate verified', {
    subject: cert.subject?.CN,
    fingerprint: cert.fingerprint256,
  });

  next();
}

module.exports = { loadMTLSConfig, validateClientCert };

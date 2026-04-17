const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { chainHash } = require('../utils/hash');
const logger = require('../utils/logger');
const config = require('../config');

/**
 * Tamper-Proof Audit Logging
 *
 * Every request through the gateway produces an immutable audit log entry.
 * Each entry includes a chain hash — the SHA-256 hash of the previous entry's
 * hash combined with the current entry's data. This creates a blockchain-like
 * chain where modifying any entry invalidates all subsequent hashes.
 *
 * Audit fields:
 * - Unique event ID (UUIDv4)
 * - Timestamp (ISO 8601)
 * - Identity (JWT sub claim)
 * - Action (HTTP method + path)
 * - Source IP
 * - Policy decision (allow/deny + reason)
 * - Response status code
 * - Latency
 * - Chain hash (links to previous entry)
 */

let previousHash = 'GENESIS';
const auditLog = []; // In-memory log for metrics/dashboard access
const MAX_IN_MEMORY_ENTRIES = 10000;

/**
 * Ensures the audit log directory exists.
 */
function ensureAuditDir() {
  const auditDir = path.resolve(config.logging.auditLogPath);
  if (!fs.existsSync(auditDir)) {
    fs.mkdirSync(auditDir, { recursive: true });
  }
  return auditDir;
}

/**
 * Writes an audit entry to the log file and in-memory store.
 * @param {object} entry - The audit log entry
 */
function writeAuditEntry(entry) {
  // Add chain hash
  entry.chainHash = chainHash(previousHash, entry);
  entry.previousHash = previousHash;
  previousHash = entry.chainHash;

  // Store in memory (ring buffer)
  auditLog.push(entry);
  if (auditLog.length > MAX_IN_MEMORY_ENTRIES) {
    auditLog.shift();
  }

  // Write to file
  try {
    const auditDir = ensureAuditDir();
    const date = new Date().toISOString().split('T')[0];
    const filePath = path.join(auditDir, `audit-${date}.jsonl`);
    fs.appendFileSync(filePath, JSON.stringify(entry) + '\n');
  } catch (err) {
    logger.error('Failed to write audit log', { error: err.message });
  }
}

/**
 * Audit logging middleware.
 * Captures request details on the way in, and response details on the way out.
 */
function audit() {
  return (req, res, next) => {
    const startTime = Date.now();
    const eventId = uuidv4();

    // Capture response finish
    const originalEnd = res.end;
    res.end = function (...args) {
      const latencyMs = Date.now() - startTime;

      const entry = {
        eventId,
        timestamp: new Date(startTime).toISOString(),
        identity: req.identityId || 'anonymous',
        action: {
          method: req.method,
          path: req.path,
          originalUrl: req.originalUrl,
        },
        source: {
          ip: req.ip || req.connection?.remoteAddress,
          userAgent: req.get('user-agent') || '',
        },
        authentication: {
          authenticated: !!req.tokenPayload,
          roles: req.tokenPayload?.roles || req.tokenPayload?.groups || [],
        },
        authorization: req.policyDecision
          ? {
              allowed: req.policyDecision.allowed,
              rbac: req.policyDecision.rbac?.allowed,
              abac: req.policyDecision.abac?.allowed,
              reason: req.policyDecision.reason,
              deniedByPolicy: req.policyDecision.abac?.policy || null,
            }
          : { allowed: true, reason: 'No policy evaluation (unauthenticated route)' },
        response: {
          statusCode: res.statusCode,
          latencyMs,
        },
      };

      writeAuditEntry(entry);
      originalEnd.apply(res, args);
    };

    next();
  };
}

/**
 * Returns recent audit log entries for the dashboard.
 * @param {number} limit - Max entries to return
 * @returns {object[]}
 */
function getRecentEntries(limit = 100) {
  return auditLog.slice(-limit);
}

/**
 * Verifies the integrity of the audit chain.
 * Walks through entries and recomputes chain hashes.
 * @returns {{ valid: boolean, brokenAt: number|null, totalEntries: number }}
 */
function verifyChain() {
  let prevHash = 'GENESIS';

  for (let i = 0; i < auditLog.length; i++) {
    const entry = auditLog[i];
    const entryData = { ...entry };
    delete entryData.chainHash;
    delete entryData.previousHash;

    const expectedHash = chainHash(prevHash, entryData);
    if (entry.chainHash !== expectedHash) {
      return { valid: false, brokenAt: i, totalEntries: auditLog.length };
    }
    prevHash = entry.chainHash;
  }

  return { valid: true, brokenAt: null, totalEntries: auditLog.length };
}

module.exports = { audit, getRecentEntries, verifyChain };

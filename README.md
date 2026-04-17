# Zero-Trust API Gateway

A production-grade reverse proxy implementing **zero-trust security architecture** with JWT/JWKS authentication, dual policy engines (RBAC + ABAC), per-identity rate limiting, and tamper-proof audit logging.

Built to demonstrate deep understanding of identity-aware access control, API security patterns, and the principles that underpin modern identity platforms like Okta.

---

## Architecture

```
                                    ZERO-TRUST API GATEWAY

  Client Request                    Policy Decision Point
  ─────────────┐                   ┌──────────────────────┐
               │                   │                      │
               ▼                   │   ┌──────────────┐   │
  ┌─────────────────────┐         │   │  RBAC Engine  │   │
  │   Security Headers  │         │   │  (roles.json) │   │
  │   Body Size Limit   │         │   └──────┬───────┘   │
  │   Request ID        │         │          │           │
  └──────────┬──────────┘         │   ┌──────▼───────┐   │
             │                     │   │  ABAC Engine  │   │
  ┌──────────▼──────────┐         │   │  (abac.json)  │   │
  │   Metrics Collector │         │   └──────┬─────���─┘   │
  │   Audit Logger      │         │          │           │
  └──────────┬──────────┘         │   ┌──────▼───────┐   │
             │                     │   │   Combined    │   │
  ┌──────────▼─���────────┐         │   │   Decision    │   │
  │   Route Resolution  │────────▶│   │  (deny wins)  │   │
  │   IP Allow/Deny     │         │   └──────────────┘   │
  └─────────��┬──────────┘         └──────────────────────┘
             │                                │
  ┌───���──────▼──────────┐                    │
  │   mTLS Validation   │                    │
  │   (if configured)   │                    │
  └──────────┬──────────┘                    │
             │                                │
  ┌──────────▼──────────┐         ┌──────────▼──────────┐
  │   JWT Authentication│         │   Authorization     │
  │   ┌───────────────┐ │         │   (Policy Engine)   │
  │   │ JWKS Fetch +  │ │         └──────────┬────���─────┘
  │   │ Key Cache     │ │                    │
  │   └───────────────┘ │         ┌──────────▼─��────────┐
  │   ┌───────────────┐ │         │  Per-Identity Rate  │
  │   │ Token         │ │         │  Limiter (sliding   │
  │   │ Introspection │ │         │  window by `sub`)   │
  │   │ (RFC 7662)    │ │         └──────────┬─────────��┘
  │   └───────────────┘ │                    │
  │   ┌────��──────────┐ │         ┌──────────▼──��───────┐
  │   │ HMAC Verify   │ │         │   Reverse Proxy     │
  │   │ (optional)    │ │         │   ┌───────────────┐ │
  │   └───────────────┘ │         │   │ Circuit       │ │
  └──────────┬──────────┘         ���   │ Breaker       │ │
             │                     │   └───────────────┘ │
             └─────────────────────│   ┌───────────────┐ │
                                   │   │ Health Check  │ │
                                   │   └───────────────┘ │
                                   └─���────────┬──────────┘
                                              │
                                              ▼
                                   ┌─────────────────────┐
                                   │   Upstream Service   │
                                   │   (port 4001)        │
                                   └──��──────────────────┘
```

### Request Pipeline

Every request traverses the full pipeline — **no shortcuts, no bypasses**. This is the core zero-trust principle: *never trust, always verify*.

```
Request → Security Headers → Metrics → Audit → Route Resolution → IP Filter
        → mTLS → JWT Auth → JWKS Verify → Introspection → HMAC Verify
        → RBAC Check → ABAC Check → Rate Limit → Proxy → Upstream
```

---

## What This Demonstrates

### Zero-Trust Principles
- **Verify explicitly** — every request is authenticated via JWT/JWKS regardless of network origin
- **Least privilege** — RBAC ensures identities only access what their role permits
- **Assume breach** — ABAC policies enforce environmental constraints (time, IP, MFA) as defense-in-depth
- **Continuous validation** — token introspection (RFC 7662) catches revoked tokens in real-time

### Identity & Access Management Concepts
- **JWKS key rotation** — automatic public key fetching with cache and rotation support
- **Claim-based identity** — roles extracted from JWT claims (`roles`, `groups`, Okta/Auth0 formats)
- **Policy-as-code** — declarative JSON policies, hot-reloadable without restart
- **Separation of concerns** — authentication (who are you?) vs authorization (what can you do?)

### Security Engineering
- **Tamper-proof audit chain** — SHA-256 chain hashing (blockchain-style) for log integrity
- **Per-identity rate limiting** — rate limits by `sub` claim, not IP (prevents cross-identity throttling)
- **Circuit breaker pattern** — upstream health monitoring with automatic failover
- **Defense-in-depth** — mTLS + JWT + RBAC + ABAC + IP filtering + HMAC + security headers

---

## Quick Start

### Prerequisites
- Node.js 18+
- npm

### Setup

```bash
# Clone and install
cd zero-trust-gateway
npm install

# Copy environment config
cp .env.example .env
# Default .env uses DEMO_MODE=true for local testing
```

### Run the Demo

Terminal 1 — Start the mock upstream API:
```bash
npm run demo:upstream
# → Mock upstream API running on http://localhost:4001
```

Terminal 2 — Start the gateway:
```bash
npm start
# → Zero-Trust API Gateway running on http://localhost:3002
```

Terminal 3 — Run the test client:
```bash
npm run demo:client
```

### What the Demo Shows

The test client sends requests with different identity tokens:

| Scenario | Token | Expected |
|----------|-------|----------|
| No auth on public route | None | 200 OK |
| Missing token | None | 401 Unauthorized |
| Expired token | Expired JWT | 401 Token expired |
| Viewer reads users | `roles: [viewer]` | 200 OK |
| Viewer tries to write | `roles: [viewer]` | 403 Forbidden |
| User writes | `roles: [user]` | 200 OK |
| User tries to delete | `roles: [user]` | 403 Forbidden |
| Admin deletes | `roles: [admin]` | 200 OK |
| Non-admin hits /admin | `roles: [user]` | 403 Forbidden |

### Dashboard

Open `http://localhost:3002/gateway/dashboard` for a real-time monitoring dashboard showing:
- Request volume and throughput
- Latency percentiles (p50, p95, p99)
- Error breakdown by category
- Upstream health and circuit breaker state
- Audit chain integrity verification
- Per-identity rate limit status

---

## Policy Engine

### RBAC (Role-Based Access Control)

Defined in `policies/rbac.json`. Maps roles to permissions, and routes to required permissions.

```json
{
  "roles": {
    "admin": { "permissions": ["read", "write", "delete", "admin"] },
    "user": { "permissions": ["read", "write"] },
    "viewer": { "permissions": ["read"] }
  },
  "routes": {
    "/api/users": {
      "GET": ["read"],
      "POST": ["write"],
      "DELETE": ["admin"]
    },
    "/api/admin/*": { "*": ["admin"] }
  }
}
```

**How it works:** The gateway extracts roles from the JWT's `roles` or `groups` claim, resolves permissions for those roles, then checks if the identity has any of the permissions required for the route + HTTP method.

### ABAC (Attribute-Based Access Control)

Defined in `policies/abac.json`. Evaluates environmental conditions at request time.

```json
{
  "policies": [
    {
      "name": "business-hours-only",
      "effect": "deny",
      "condition": { "time.hour": { "notBetween": [9, 17] } },
      "resources": ["/api/admin/*"]
    }
  ]
}
```

**Supported attributes:**
| Attribute | Description |
|-----------|-------------|
| `time.hour` | Current UTC hour (0-23) |
| `time.dayOfWeek` | Day of week (0=Sunday) |
| `request.ip` | Client IP address |
| `request.method` | HTTP method |
| `token.amr` | Authentication methods (from JWT) |
| `token.sub` | Subject identifier |
| `token.scope` | OAuth scopes |

**Supported operators:**
`equals`, `notEquals`, `in`, `notIn`, `between`, `notBetween`, `contains`, `notContains`, `inCIDR`, `notInCIDR`, `matches` (regex), `greaterThan`, `lessThan`

### Combined Evaluation

The policy engine uses **deny-override combination**: both RBAC and ABAC must allow access. Even an admin is denied if ABAC conditions aren't met (e.g., accessing admin routes outside business hours).

### Hot Reload

Policies can be reloaded without restarting the gateway:

```bash
curl -X POST http://localhost:3002/gateway/policies/reload
```

---

## API Endpoints

### Gateway Management (no auth required)

| Endpoint | Description |
|----------|-------------|
| `GET /gateway/health` | Health check with upstream status |
| `GET /gateway/metrics` | Request count, latency percentiles, error rates |
| `GET /gateway/audit` | Audit log entries with chain integrity check |
| `GET /gateway/ratelimit` | Per-identity rate limit status |
| `POST /gateway/policies/reload` | Hot-reload all policies |
| `GET /gateway/dashboard` | Real-time monitoring dashboard |

### Proxied Routes (auth required unless configured otherwise)

All other routes are proxied to the configured upstream after passing through the full security pipeline.

---

## Security Model

### Authentication Layer
1. **JWT Verification** — JWKS-based signature verification with key caching and automatic rotation
2. **Token Introspection** — RFC 7662 real-time token validation for revocation checking
3. **HMAC Request Signing** — Optional request integrity verification via `X-Request-Signature` header

### Authorization Layer
4. **RBAC** — Role-permission mapping with wildcard route support
5. **ABAC** — Environmental policy evaluation (time, IP, claims, methods)

### Transport Layer
6. **mTLS** — Mutual TLS for service-to-service authentication (configurable per route)
7. **Security Headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy

### Operational Layer
8. **Per-Identity Rate Limiting** — Sliding window by JWT `sub` claim
9. **IP Allowlist/Denylist** — Per-route network restrictions
10. **Request Body Limits** — Protection against oversized payloads
11. **Circuit Breaker** — Upstream health monitoring with automatic failover

### Audit Layer
12. **Tamper-Proof Logging** — SHA-256 chain hashing (each entry includes hash of previous entry)
13. **Chain Verification** — API endpoint to verify log integrity at any time

---

## Plugin Architecture

Extend the gateway with custom middleware. Plugins are auto-discovered from `src/plugins/`.

```javascript
// src/plugins/my-plugin.js
module.exports = {
  name: 'my-plugin',
  version: '1.0.0',
  phase: 'pre-proxy',  // pre-auth | post-auth | pre-proxy | post-proxy

  init(app, config) {
    // One-time setup
  },

  middleware() {
    return (req, res, next) => {
      // Custom logic
      next();
    };
  },
};
```

---

## Testing

```bash
npm test
```

Runs integration tests covering:
- Authentication pipeline (valid/invalid/expired tokens)
- RBAC enforcement (role-permission checks)
- Security headers
- Rate limiting
- Audit chain integrity
- Proxy forwarding with identity headers
- Policy hot-reload

---

## Production Deployment

For production use, update `.env`:

```bash
DEMO_MODE=false
JWKS_URI=https://your-okta-domain.okta.com/oauth2/default/v1/keys
JWT_ISSUER=https://your-okta-domain.okta.com/oauth2/default
JWT_AUDIENCE=api://default
INTROSPECTION_ENDPOINT=https://your-okta-domain.okta.com/oauth2/default/v1/introspect
MTLS_ENABLED=true
```

The gateway is designed to sit in front of any microservice, enforcing identity verification and access policies at the network edge — exactly as Okta's identity platform enables across enterprise architectures.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js 18+ |
| Framework | Express |
| Proxy | http-proxy |
| JWT | jsonwebtoken + jwks-rsa |
| Hashing | Node.js crypto (SHA-256) |
| Rate Limiting | In-memory sliding window (Map) |
| Metrics | In-memory counters + percentile calculation |
| Audit | JSONL files + chain hashing |

---

## License

MIT

'use strict';
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const discoveryCache = new Map();
const jwksClients = new Map();

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return res.json();
}

async function getOidcDiscovery(issuerUrl) {
  const url = issuerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const cached = discoveryCache.get(url);
  if (cached && Date.now() - cached.ts < 3600000) return cached.data;
  const data = await fetchJson(url);
  discoveryCache.set(url, { data, ts: Date.now() });
  return data;
}

function getJwksClient(jwksUri) {
  if (!jwksClients.has(jwksUri)) {
    jwksClients.set(jwksUri, jwksClient({
      jwksUri,
      cache: true,
      cacheMaxAge: 3600000,
      rateLimit: true,
    }));
  }
  return jwksClients.get(jwksUri);
}

async function validateJwt(token, expectedIssuer, expectedAudience) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new Error('Malformed token');

  const iss = decoded.payload.iss;
  if (expectedIssuer && iss !== expectedIssuer) throw new Error('Wrong issuer');

  const discovery = await getOidcDiscovery(iss);
  const client = getJwksClient(discovery.jwks_uri);

  const signingKey = (await client.getSigningKey(decoded.header.kid)).getPublicKey();

  const payload = jwt.verify(token, signingKey, {
    algorithms: ['RS256', 'ES256', 'PS256'],
    ...(expectedIssuer && { issuer: expectedIssuer }),
    ...(expectedAudience && { audience: expectedAudience }),
  });

  return { iss: payload.iss, sub: payload.sub, email: payload.email || null };
}

module.exports = { getOidcDiscovery, validateJwt };

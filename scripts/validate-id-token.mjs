import { timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export class IDTokenValidationError extends Error {
  constructor() {
    super('ID token validation failed. Signature, claims, or nonce did not pass verification.');
    this.name = 'IDTokenValidationError';
  }
}

export function providerKeys(metadata) {
  try {
    const url = new URL(metadata.jwks_uri);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error();
    // OIDC's default registered ID-token signing algorithm is RS256. Fail closed
    // for other algorithms rather than trusting an algorithm supplied by the JWT.
    if (metadata.id_token_signing_alg_values_supported !== undefined &&
        (!Array.isArray(metadata.id_token_signing_alg_values_supported) ||
         !metadata.id_token_signing_alg_values_supported.includes('RS256'))) throw new Error();
    return createRemoteJWKSet(url, { timeoutDuration: 15_000 });
  } catch { throw new IDTokenValidationError(); }
}

/** Live-test validation only; intentionally not exported by the npm package. */
export async function validateIdToken(idToken, { keys, issuer, clientId, nonce }) {
  try {
    if (typeof idToken !== 'string' || !idToken || typeof nonce !== 'string' || !nonce) throw new Error();
    const { payload } = await jwtVerify(idToken, keys, {
      algorithms: ['RS256'], issuer, audience: clientId,
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'],
    });
    if (typeof payload.sub !== 'string' || !payload.sub ||
        typeof payload.iat !== 'number' || !Number.isFinite(payload.iat) ||
        payload.iat > Math.floor(Date.now() / 1000) || payload.exp <= payload.iat) throw new Error();
    if ((Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId) ||
        (payload.azp !== undefined && payload.azp !== clientId)) throw new Error();
    if (typeof payload.nonce !== 'string') throw new Error();
    const actual = Buffer.from(payload.nonce), expected = Buffer.from(nonce);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error();
    // Do not return or log personal claims or the token itself.
    return { idTokenValidated: true, nonceValidated: true };
  } catch { throw new IDTokenValidationError(); }
}

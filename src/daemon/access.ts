import { createRemoteJWKSet, jwtVerify, type RemoteJWKSetOptions } from 'jose';
import { fail } from '../util.js';

export interface AccessOptions { teamDomain: string; audience: string }

export function accessOptions(teamDomain?: string, audience?: string): AccessOptions | undefined {
  if (teamDomain === undefined && audience === undefined) return undefined;
  if (!teamDomain || !audience?.trim()) fail('INVALID_OPTIONS', 'Cloudflare Access requires both a team domain and an audience.');
  // Accept a team hostname only, never a caller-selected JWKS URL or URL from a JWT.
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/i.test(teamDomain)) {
    fail('INVALID_OPTIONS', 'Access team domain must be a hostname such as your-team.cloudflareaccess.com (without https:// or a path).');
  }
  return { teamDomain: teamDomain.toLowerCase(), audience: audience.trim() };
}

export function createAccessVerifier(options: AccessOptions, jwksOptions?: RemoteJWKSetOptions) {
  const config = accessOptions(options.teamDomain, options.audience)!;
  const issuer = `https://${config.teamDomain}`;
  const keys = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), {
    timeoutDuration: 5000, cacheMaxAge: 600_000, cooldownDuration: 30_000, ...jwksOptions,
  });
  return async (assertion: string): Promise<boolean> => {
    try {
      await jwtVerify(assertion, keys, { issuer, audience: config.audience, algorithms: ['RS256'], requiredClaims: ['exp', 'iat'] });
      return true;
    } catch {
      // Neither assertions nor provider/network errors belong in HTTP responses or logs.
      return false;
    }
  };
}

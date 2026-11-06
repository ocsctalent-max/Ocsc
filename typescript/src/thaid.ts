import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { config } from './config.js';

interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
}

interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

let metadataPromise: Promise<ProviderMetadata> | undefined;
let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

export function randomUrlSafe(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export async function getMetadata(): Promise<ProviderMetadata> {
  metadataPromise ??= (async () => {
    const response = await fetch(config.wellKnownUrl, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new Error(`ThaID discovery failed (HTTP ${response.status})`);
    const data = await response.json() as Partial<ProviderMetadata>;
    for (const key of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
      if (!data[key]) throw new Error(`ThaID discovery response is missing ${key}`);
    }
    return data as ProviderMetadata;
  })();
  return metadataPromise;
}

export async function authorizationUrl(state: string, nonce: string, challenge: string): Promise<string> {
  const metadata = await getMetadata();
  const url = new URL(metadata.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  return url.toString();
}

async function tokenRequest(params: URLSearchParams): Promise<TokenResponse> {
  const metadata = await getMetadata();
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: params,
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.json().catch(() => ({})) as Record<string, unknown>;
  if (!response.ok) {
    const description = typeof body.error_description === 'string' ? body.error_description : `Token request failed (HTTP ${response.status})`;
    throw new Error(description);
  }
  if (typeof body.access_token !== 'string') throw new Error('Token response did not contain an access_token');
  return body as unknown as TokenResponse;
}

export function exchangeCode(code: string, verifier: string): Promise<TokenResponse> {
  return tokenRequest(new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  }));
}

export function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  return tokenRequest(new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken }));
}

export async function verifyIdToken(idToken: string, expectedNonce?: string): Promise<JWTPayload> {
  const metadata = await getMetadata();
  jwks ??= createRemoteJWKSet(new URL(metadata.jwks_uri));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: metadata.issuer,
    audience: config.clientId,
  });
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error('ID token nonce did not match the login session');
  return payload;
}

export async function introspectToken(token: string): Promise<string> {
  if (!config.introspectUrl) throw new Error('Set THAID_INTROSPECT_URL to the endpoint registered for this RP');
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  const response = await fetch(config.introspectUrl, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    // The sample PHP sends "Bearer <token>". Confirm whether ThaID expects that
    // format or the raw token for your registered endpoint before production use.
    body: new URLSearchParams({ token: `Bearer ${token}` }),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`Introspection request failed (HTTP ${response.status})`);
  return text;
}

export async function revokeToken(token: string): Promise<void> {
  const metadata = await getMetadata();
  if (!metadata.revocation_endpoint) throw new Error('ThaID discovery has no revocation_endpoint');
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');
  const response = await fetch(metadata.revocation_endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ token }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Token revocation failed (HTTP ${response.status})`);
}

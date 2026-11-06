import type { JWTPayload } from 'jose';

declare module 'express-session' {
  interface SessionData {
    oauthState?: string;
    oauthNonce?: string;
    pkceVerifier?: string;
    accessToken?: string;
    refreshToken?: string;
    idToken?: string;
    expiresAt?: number;
    scope?: string;
    tokenType?: string;
    claims?: JWTPayload;
    csrfToken?: string;
  }
}

import 'dotenv/config';

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  production: process.env.NODE_ENV === 'production',
  sessionSecret: required('SESSION_SECRET'),
  clientId: required('THAID_CLIENT_ID'),
  clientSecret: required('THAID_CLIENT_SECRET'),
  redirectUri: required('THAID_REDIRECT_URI'),
  wellKnownUrl: process.env.THAID_WELL_KNOWN_URL ?? 'https://imauth.bora.dopa.go.th/.well-known/openid-configuration',
  introspectUrl: process.env.THAID_INTROSPECT_URL,
  scope: process.env.THAID_SCOPE ?? 'openid pid',
};

if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
  throw new Error('PORT must be a valid TCP port');
}
if (config.sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters');
}

import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { authorizationUrl, exchangeCode, introspectToken, pkceChallenge, randomUrlSafe, refreshTokens, revokeToken, verifyIdToken } from './thaid.js';

const app = express();
app.set('view engine', 'ejs');
// Keep templates in src/views for both tsx development and compiled dist execution.
app.set('views', fileURLToPath(new URL('../src/views/', import.meta.url)));
app.disable('x-powered-by');
if (config.production) app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  name: 'thaid.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.production,
    maxAge: 60 * 60 * 1000,
  },
}));

app.use((req, res, next) => {
  req.session.csrfToken ??= randomUrlSafe();
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  const submitted = req.body?._csrf;
  if (typeof submitted !== 'string' || submitted !== req.session.csrfToken) {
    res.status(403).render('error', { message: 'คำขอไม่ถูกต้อง กรุณาลองใหม่' });
    return;
  }
  next();
}

function requireLogin(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.accessToken) {
    res.redirect('/');
    return;
  }
  next();
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'เกิดข้อผิดพลาดที่ไม่ทราบสาเหตุ';
}

app.get('/', (_req, res) => res.render('index'));

app.get('/auth/login', async (req, res, next) => {
  try {
    const state = randomUrlSafe();
    const nonce = randomUrlSafe();
    const verifier = randomUrlSafe(48);
    req.session.oauthState = state;
    req.session.oauthNonce = nonce;
    req.session.pkceVerifier = verifier;
    res.redirect(await authorizationUrl(state, nonce, pkceChallenge(verifier)));
  } catch (error) { next(error); }
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    res.status(400).render('error', { message: 'การเข้าสู่ระบบ ThaID ไม่สำเร็จ' });
    return;
  }
  if (typeof code !== 'string' || typeof state !== 'string' || state !== req.session.oauthState || !req.session.pkceVerifier || !req.session.oauthNonce) {
    res.status(400).render('error', { message: 'OAuth callback ไม่ถูกต้องหรือหมดอายุ กรุณาเริ่มเข้าสู่ระบบใหม่' });
    return;
  }
  try {
    const expectedNonce = req.session.oauthNonce;
    const tokens = await exchangeCode(code, req.session.pkceVerifier);
    if (!tokens.id_token) throw new Error('ThaID did not return an ID token');
    const claims = await verifyIdToken(tokens.id_token, expectedNonce);

    // Rotate the session identifier after authentication to prevent fixation.
    req.session.regenerate((sessionError) => {
      if (sessionError) {
        res.status(500).render('error', { message: 'ไม่สามารถเริ่ม session ได้' });
        return;
      }
      req.session.accessToken = tokens.access_token;
      req.session.refreshToken = tokens.refresh_token;
      req.session.idToken = tokens.id_token;
      req.session.expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
      req.session.scope = tokens.scope;
      req.session.tokenType = tokens.token_type;
      req.session.claims = claims;
      req.session.csrfToken = randomUrlSafe();
      req.session.save((saveError) => saveError
        ? res.status(500).render('error', { message: 'ไม่สามารถบันทึก session ได้' })
        : res.redirect('/dashboard'));
    });
  } catch (caught) {
    console.error('ThaID callback failed:', messageOf(caught));
    res.status(400).render('error', { message: 'ตรวจสอบ callback หรือ ID token ไม่ผ่าน กรุณาตรวจ��่า ThaID และลองใหม่' });
  }
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', {
    claims: req.session.claims ?? {},
    expiresAt: req.session.expiresAt ? new Date(req.session.expiresAt).toISOString() : 'ไม่ระบุ',
    scope: req.session.scope ?? 'ไม่ระบุ',
    tokenType: req.session.tokenType ?? 'ไม่ระบุ',
  });
});

app.post('/auth/refresh', requireCsrf, requireLogin, async (req, res) => {
  if (!req.session.refreshToken) {
    res.status(400).render('error', { message: 'ไม่พบ refresh token' });
    return;
  }
  try {
    const tokens = await refreshTokens(req.session.refreshToken);
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token ?? req.session.refreshToken;
    req.session.idToken = tokens.id_token ?? req.session.idToken;
    req.session.expiresAt = tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined;
    req.session.scope = tokens.scope ?? req.session.scope;
    req.session.tokenType = tokens.token_type ?? req.session.tokenType;
    if (req.session.idToken) req.session.claims = await verifyIdToken(req.session.idToken);
    res.redirect('/dashboard');
  } catch (error) {
    console.error('ThaID refresh failed:', messageOf(error));
    res.status(400).render('error', { message: 'ต่ออายุ token ไม่สำเร็จ กรุณาเข้าสู่ระบบใหม่' });
  }
});

app.post('/auth/introspect', requireCsrf, requireLogin, async (req, res) => {
  try {
    const result = await introspectToken(req.session.accessToken!);
    res.type('text/plain').send(result);
  } catch (error) { res.status(502).render('error', { message: messageOf(error) }); }
});

app.post('/auth/validate-token', requireCsrf, requireLogin, async (req, res) => {
  try {
    if (!req.session.idToken) throw new Error('ไม่พบ ID token ใน session');
    const claims = await verifyIdToken(req.session.idToken);
    res.type('application/json').send(JSON.stringify(claims, null, 2));
  } catch (error) { res.status(400).render('error', { message: messageOf(error) }); }
});

app.post('/auth/revoke', requireCsrf, requireLogin, async (req, res) => {
  try {
    await revokeToken(req.session.refreshToken ?? req.session.accessToken!);
    req.session.destroy((error) => error
      ? res.status(500).render('error', { message: 'ยกเลิก token แล้ว แต่ล้าง session ไม่สำเร็จ' })
      : res.redirect('/'));
  } catch (error) { res.status(502).render('error', { message: messageOf(error) }); }
});

app.post('/auth/logout', requireCsrf, (req, res) => {
  req.session.destroy((error) => error
    ? res.status(500).render('error', { message: 'ออกจากระบบไม่สำเร็จ' })
    : res.redirect('/'));
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled request error:', messageOf(error));
  res.status(500).render('error', { message: 'เกิดข้อผิดพลาดภายในระบบ' });
});

app.listen(config.port, () => {
  console.log(`ThaID TypeScript example listening on port ${config.port}`);
});

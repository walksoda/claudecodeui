/**
 * The client's half of the JWT session: parsing, expiry, storage and the two
 * events the auth context listens to.
 *
 * Extracted from api.ts, which is meant to be the endpoint map plus its request
 * helpers. This is the security-sensitive part and it is what WebSocketContext,
 * AuthContext, the shell socket and the file-tree uploader actually import.
 */

export const AUTH_TOKEN_REFRESHED_EVENT = 'auth-token-refreshed';
export const AUTH_SESSION_EXPIRED_EVENT = 'auth-session-expired';

// Only accept a refreshed token that has this app's issued JWT shape
// (three base64url segments). An attacker-injected/malformed header value
// must never overwrite the stored auth token.
export const isValidRefreshedToken = (token: unknown): token is string =>
  typeof token === 'string' &&
  /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);

type TokenClaims = {
  issuedAt: number;
  expiresAt: number;
};

const readTokenClaims = (token: unknown): TokenClaims | null => {
  if (!isValidRefreshedToken(token)) {
    return null;
  }

  try {
    const encodedPayload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const paddedPayload = encodedPayload.padEnd(
      encodedPayload.length + ((4 - (encodedPayload.length % 4)) % 4),
      '=',
    );
    const payload = JSON.parse(atob(paddedPayload)) as { iat?: unknown; exp?: unknown };

    if (
      typeof payload.iat !== 'number' ||
      !Number.isFinite(payload.iat) ||
      typeof payload.exp !== 'number' ||
      !Number.isFinite(payload.exp)
    ) {
      return null;
    }

    return { issuedAt: payload.iat * 1000, expiresAt: payload.exp * 1000 };
  } catch {
    return null;
  }
};

// Tolerance for client/server clock skew. The server's own jwt.verify is the
// real authority; this check only decides whether the client should discard a
// token locally. Without an allowance, a browser clock running slightly ahead
// reads a still-server-valid token as expired and drops the session.
export const TOKEN_EXPIRY_SKEW_MS = 60_000;

export const isAuthTokenExpired = (token: unknown): boolean => {
  const claims = readTokenClaims(token);
  return claims ? Date.now() >= claims.expiresAt + TOKEN_EXPIRY_SKEW_MS : false;
};

export const getAuthTokenRefreshDelay = (token: unknown): number | null => {
  const claims = readTokenClaims(token);
  if (!claims) {
    return null;
  }

  const refreshAt = claims.issuedAt + ((claims.expiresAt - claims.issuedAt) / 2);
  return Math.max(0, refreshAt - Date.now());
};

export const expireAuthSession = (): void => {
  localStorage.removeItem('auth-token');
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(AUTH_SESSION_EXPIRED_EVENT));
  }
};

export const getStoredAuthToken = (): string | null => {
  const token = localStorage.getItem('auth-token');
  if (token && isAuthTokenExpired(token)) {
    expireAuthSession();
    return null;
  }
  return token;
};

export const storeAuthToken = (token: unknown): boolean => {
  if (!isValidRefreshedToken(token)) {
    return false;
  }

  localStorage.setItem('auth-token', token);
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_TOKEN_REFRESHED_EVENT, { detail: token }));
  }
  return true;
};

// Apply a token rotated by the server via the X-Refreshed-Token response header.
//
// Unlike `storeAuthToken` (used by the login/refresh paths, where any valid
// token legitimately replaces the current one), a header-borne token is only
// accepted when it does not move the session's expiry backwards. A cached or
// proxied response can replay a stale X-Refreshed-Token days after it was
// issued; applying it would downgrade a valid session to an expired token, and
// `getStoredAuthToken` would then expire the session and bounce the user to the
// login screen on the very next API call.
//
// Unparseable claims on either side fall through to the permissive path so that
// a legacy or non-standard token shape can never wedge the session.
//
// The comparison is `<` rather than `<=` on purpose: the server mints rotated
// tokens with a *sliding* expiry (auth.middleware.ts signs with
// `expiresIn: '7d'`) and only rotates past half-life, so a genuine rotation
// always carries a strictly later exp — rejecting equal-exp tokens would buy no
// protection while failing a same-expiry re-issue. If upstream ever switches to
// an absolute session deadline, every rotation inherits the same exp; compare
// `issuedAt` instead of `expiresAt` in that case.
//
// NOTE: the guard must stay out of `storeAuthToken` itself. `AuthContext`'s
// token persistence and the login path (`setSession`) both go through that
// function, so a freshness check there would reject a different user's login.
// Only the header-borne replay paths are guarded.
export const storeRotatedAuthToken = (token: unknown): boolean => {
  if (!isValidRefreshedToken(token)) {
    return false;
  }

  // Read the raw item rather than `getStoredAuthToken()`, which expires the
  // session as a side effect when the held token is already past its deadline.
  const currentClaims = readTokenClaims(localStorage.getItem('auth-token'));
  const rotatedClaims = readTokenClaims(token);
  if (currentClaims && rotatedClaims && rotatedClaims.expiresAt < currentClaims.expiresAt) {
    return false;
  }

  return storeAuthToken(token);
};

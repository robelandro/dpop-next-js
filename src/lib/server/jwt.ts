import { SignJWT, jwtVerify } from 'jose';
import type { DPoPAccessTokenPayload } from '../types';

const JWT_SECRET_STRING = process.env.JWT_SECRET || 'dpop-super-secure-production-ready-jwt-secret-key-2026';
const JWT_SECRET = new TextEncoder().encode(JWT_SECRET_STRING);
export const COOKIE_NAME = 'dpop_access_token';

export async function createDPoPAccessToken(
  user: { id: string; username: string; name: string; role: string },
  jkt: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();

  return new SignJWT({
    sub: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    token_type: 'DPoP',
    cnf: {
      jkt,
    },
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setIssuer('https://auth.dpop-demo.local')
    .setAudience('https://api.dpop-demo.local')
    .setJti(jti)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600) // 1 hour validity
    .sign(JWT_SECRET);
}

export async function verifyAccessToken(token: string): Promise<DPoPAccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      issuer: 'https://auth.dpop-demo.local',
      audience: 'https://api.dpop-demo.local',
    });

    return payload as unknown as DPoPAccessTokenPayload;
  } catch (error) {
    console.error('Access token verification failed:', error);
    return null;
  }
}

import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, verifyAccessToken } from '@/lib/server/jwt';

export async function GET(req: NextRequest) {
  const cookieToken = req.cookies.get(COOKIE_NAME)?.value;
  const authHeader = req.headers.get('authorization');
  let token = cookieToken;

  if (!token && authHeader) {
    if (authHeader.startsWith('DPoP ') || authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }
  }

  if (!token) {
    return NextResponse.json(
      { authenticated: false, message: 'No access token found in cookie or header' },
      { status: 401 }
    );
  }

  const payload = await verifyAccessToken(token);
  if (!payload) {
    return NextResponse.json(
      { authenticated: false, message: 'Invalid or expired access token' },
      { status: 401 }
    );
  }

  return NextResponse.json({
    authenticated: true,
    user: {
      id: payload.sub,
      username: payload.username,
      name: payload.name,
      role: payload.role,
    },
    jkt: payload.cnf?.jkt,
    exp: payload.exp,
    tokenPreview: `${token.substring(0, 20)}...${token.substring(token.length - 12)}`,
    fullToken: token,
  });
}

import { NextRequest, NextResponse } from 'next/server';
import { validateDPoPProof } from '@/lib/server/dpop';
import { createDPoPAccessToken, COOKIE_NAME } from '@/lib/server/jwt';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const username = (body.username || 'alice').trim();
    const password = body.password || '';

    // Standard demo authentication check (accepts demo credentials or any non-empty password)
    if (!username || (password !== 'password123' && password !== 'demo' && password.length < 3)) {
      return NextResponse.json(
        {
          success: false,
          error: 'invalid_credentials',
          message: 'Invalid username or password. Demo credentials: alice / password123',
        },
        { status: 401 }
      );
    }

    // Extract DPoP header
    const dpopHeader = req.headers.get('dpop');

    // RFC 9449 Section 5: Authorization Server Token Endpoint validation
    const dpopResult = await validateDPoPProof({
      dpopHeader,
      method: 'POST',
      url: req.url,
    });

    if (!dpopResult.valid || !dpopResult.jkt) {
      return NextResponse.json(
        {
          success: false,
          error: dpopResult.code || 'invalid_dpop_proof',
          message: dpopResult.error || 'DPoP proof validation failed on login.',
          auditTrail: dpopResult.auditTrail,
        },
        { status: 400 }
      );
    }

    const user = {
      id: `usr_${Math.abs(username.split('').reduce((a: number, b: string) => a + b.charCodeAt(0), 100))}`,
      username,
      name: username === 'alice' ? 'Alice Vance (Security Lead)' : `${username.charAt(0).toUpperCase() + username.slice(1)}`,
      role: 'Cryptographic Security Engineer',
    };

    // Generate real DPoP-bound JWT containing cnf: { jkt }
    const accessToken = await createDPoPAccessToken(user, dpopResult.jkt);

    // Prepare response
    const response = NextResponse.json({
      success: true,
      token_type: 'DPoP',
      access_token: accessToken,
      expires_in: 3600,
      jkt: dpopResult.jkt,
      user,
      auditTrail: dpopResult.auditTrail,
      message: 'Successfully authenticated. Access token cryptographically bound to client DPoP key.',
    });

    // Set HTTP-only secure cookie containing the DPoP-bound JWT
    response.cookies.set({
      name: COOKIE_NAME,
      value: accessToken,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 3600,
    });

    return response;
  } catch (error: unknown) {
    console.error('Login error:', error);
    const msg = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json(
      {
        success: false,
        error: 'server_error',
        message: msg,
      },
      { status: 500 }
    );
  }
}

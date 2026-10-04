import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, verifyAccessToken } from '@/lib/server/jwt';
import { validateDPoPProof } from '@/lib/server/dpop';
import type { DashboardData, VerificationAuditStep } from '@/lib/types';

export async function GET(req: NextRequest) {
  const auditTrail: VerificationAuditStep[] = [];

  // 1. Extract Access Token from Authorization header or Cookie
  const authHeader = req.headers.get('authorization');
  const cookieToken = req.cookies.get(COOKIE_NAME)?.value;
  let token: string | null = null;
  let authScheme = 'none';

  if (authHeader) {
    if (authHeader.startsWith('DPoP ')) {
      token = authHeader.substring(5).trim();
      authScheme = 'DPoP';
    } else if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
      authScheme = 'Bearer';
    }
  } else if (cookieToken) {
    token = cookieToken;
    authScheme = 'Cookie (dpop_access_token)';
  }

  if (!token) {
    auditTrail.push({
      step: 'Access Token Extraction',
      description: 'Checking for Access Token in Authorization header or cookie',
      status: 'failed',
      details: 'No access token found in request.',
    });

    return NextResponse.json(
      {
        success: false,
        error: 'missing_token',
        message: 'Access token required. Please login first or supply an Authorization header.',
        auditTrail,
      },
      {
        status: 401,
        headers: {
          'WWW-Authenticate': 'DPoP error="invalid_token", error_description="Missing access token"',
        },
      }
    );
  }

  auditTrail.push({
    step: 'Access Token Extraction',
    description: 'Checking for Access Token in Authorization header or cookie',
    status: 'passed',
    details: `Token retrieved via ${authScheme} (${token.substring(0, 16)}...${token.substring(token.length - 8)}).`,
  });

  // 2. Cryptographic Access Token Verification
  const tokenPayload = await verifyAccessToken(token);
  if (!tokenPayload) {
    auditTrail.push({
      step: 'Server JWT Verification',
      description: 'Verifying server signature and expiration on access token',
      status: 'failed',
      details: 'Access token signature verification failed or token expired.',
    });

    return NextResponse.json(
      {
        success: false,
        error: 'invalid_token',
        message: 'The presented access token is invalid or has expired.',
        auditTrail,
      },
      {
        status: 401,
        headers: {
          'WWW-Authenticate': 'DPoP error="invalid_token", error_description="Token signature invalid or expired"',
        },
      }
    );
  }

  auditTrail.push({
    step: 'Server JWT Verification',
    description: 'Verifying server signature and expiration on access token',
    status: 'passed',
    details: `JWT signed by server valid for subject "${tokenPayload.sub}" until ${new Date(tokenPayload.exp * 1000).toLocaleTimeString()}.`,
  });

  // 3. Confirm DPoP Binding Claim (cnf.jkt) exists in token
  const expectedJkt = tokenPayload.cnf?.jkt;
  if (!expectedJkt) {
    auditTrail.push({
      step: 'DPoP Confirmation Claim (cnf.jkt)',
      description: 'Checking for RFC 9449 sender-constraining cnf.jkt claim in token',
      status: 'failed',
      details: 'Token does not contain a cnf.jkt claim. It is an unconstrained Bearer token, which is rejected by this DPoP-only resource.',
    });

    return NextResponse.json(
      {
        success: false,
        error: 'token_not_dpop_bound',
        message: 'This resource requires DPoP-bound tokens. Bearer tokens without cnf.jkt are prohibited.',
        auditTrail,
      },
      { status: 403 }
    );
  }

  auditTrail.push({
    step: 'DPoP Confirmation Claim (cnf.jkt)',
    description: 'Checking for RFC 9449 sender-constraining cnf.jkt claim in token',
    status: 'passed',
    details: `Token is bound to client key thumbprint: ${expectedJkt}`,
  });

  // 4. Validate DPoP Proof
  const dpopHeader = req.headers.get('dpop');

  const dpopValidation = await validateDPoPProof({
    dpopHeader,
    method: 'GET',
    url: req.url,
    expectedJkt,
    accessToken: token,
  });

  // Combine audit trails
  const fullAuditTrail = [...auditTrail, ...dpopValidation.auditTrail];

  if (!dpopValidation.valid) {
    const errorDetails = dpopValidation.error || 'DPoP proof verification failed.';
    const errorCode = dpopValidation.code || 'invalid_dpop_proof';

    return NextResponse.json(
      {
        success: false,
        error: errorCode,
        message: errorDetails,
        tokenJkt: expectedJkt,
        proofJkt: dpopValidation.jkt || 'none',
        auditTrail: fullAuditTrail,
      },
      {
        status: 401,
        headers: {
          'WWW-Authenticate': `DPoP error="${errorCode}", error_description="${errorDetails}"`,
        },
      }
    );
  }

  // 5. Success! Return Protected High-Security Dashboard Data
  const dashboardPayload: DashboardData = {
    systemStatus: 'SECURE_DPOP_ENCLAVE_ACTIVE',
    metrics: {
      threatsPrevented: 142,
      dpopTokensActive: 1,
      replayAttacksBlocked: 39,
      securityScore: 100,
    },
    confidentialData: {
      vaultId: 'VLT-9449-ALPHA-ZULU',
      masterEnclaveKey: 'ENCLAVE::' + crypto.randomUUID().replace(/-/g, '').toUpperCase(),
      accessLevel: 'TOP-SECRET::PROOF-OF-POSSESSION-VERIFIED',
      auditLogId: 'AUDIT-' + Date.now().toString(36).toUpperCase(),
      timestamp: new Date().toISOString(),
    },
    user: {
      id: tokenPayload.sub,
      username: tokenPayload.username,
      name: tokenPayload.name,
      role: tokenPayload.role,
    },
    tokenBinding: {
      tokenJkt: expectedJkt,
      proofJkt: dpopValidation.jkt || '',
      matched: true,
      authMethod: authScheme,
    },
    auditTrail: fullAuditTrail,
  };

  return NextResponse.json({
    success: true,
    data: dashboardPayload,
    message: 'DPoP proof-of-possession successfully verified. Access granted.',
  });
}

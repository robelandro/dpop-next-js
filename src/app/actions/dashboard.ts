'use server';

import { cookies, headers } from 'next/headers';
import { COOKIE_NAME, verifyAccessToken } from '@/lib/server/jwt';
import { validateDPoPProof } from '@/lib/server/dpop';
import type { VerificationAuditStep, DashboardData } from '@/lib/types';

export interface ServerActionDPoPInput {
  dpopProof?: string;
  accessTokenOverride?: string;
  operation: string;
}

export interface ServerActionDPoPResult {
  success: boolean;
  message: string;
  error?: string;
  code?: string;
  tokenJkt?: string;
  proofJkt?: string;
  executedOperation?: string;
  timestamp?: string;
  auditTrail: VerificationAuditStep[];
  data?: Partial<DashboardData['confidentialData']>;
}

/**
 * Next.js Server Action protected by RFC 9449 DPoP sender-constraining.
 * Can be called directly from Client Components via RPC with end-to-end cryptographic proof.
 */
export async function executeSecureEnclaveAction(
  input: ServerActionDPoPInput
): Promise<ServerActionDPoPResult> {
  const auditTrail: VerificationAuditStep[] = [];
  const { dpopProof, accessTokenOverride, operation } = input;

  auditTrail.push({
    step: 'Server Action Invocation',
    description: 'Received Server Action invocation for secure enclave operation',
    status: 'passed',
    details: `Operation: "${operation}". Execution context: Next.js 'use server' RPC runtime.`,
  });

  // 1. Resolve Access Token (from HTTP-only Cookie or explicit input override)
  const cookieStore = await cookies();
  const cookieToken = cookieStore.get(COOKIE_NAME)?.value;
  const token = accessTokenOverride || cookieToken;

  if (!token) {
    auditTrail.push({
      step: 'Access Token Extraction',
      description: 'Resolving access token from HTTP-only cookie or input payload',
      status: 'failed',
      details: 'No access token found in cookie or parameters.',
    });

    return {
      success: false,
      error: 'missing_token',
      code: 'unauthorized',
      message: 'Authentication token required to invoke this Server Action.',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'Access Token Extraction',
    description: 'Resolving access token from HTTP-only cookie or input payload',
    status: 'passed',
    details: `Access token resolved (${token.substring(0, 16)}...).`,
  });

  // 2. Verify server-signed Access Token JWT
  const tokenPayload = await verifyAccessToken(token);
  if (!tokenPayload) {
    auditTrail.push({
      step: 'Server JWT Verification',
      description: 'Verifying cryptographic signature and expiration on access token',
      status: 'failed',
      details: 'Access token signature invalid or expired.',
    });

    return {
      success: false,
      error: 'invalid_token',
      code: 'token_invalid',
      message: 'Access token signature verification failed in Server Action.',
      auditTrail,
    };
  }

  const expectedJkt = tokenPayload.cnf?.jkt;
  if (!expectedJkt) {
    auditTrail.push({
      step: 'DPoP Confirmation Claim (cnf.jkt)',
      description: 'Checking for sender-constraining cnf.jkt in token',
      status: 'failed',
      details: 'Presented token does not contain a cnf.jkt claim.',
    });

    return {
      success: false,
      error: 'token_not_dpop_bound',
      code: 'missing_cnf_jkt',
      message: 'This Server Action only accepts sender-constrained DPoP tokens.',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'DPoP Confirmation Claim (cnf.jkt)',
    description: 'Checking for sender-constraining cnf.jkt in token',
    status: 'passed',
    details: `Token is cryptographically bound to client thumbprint: ${expectedJkt}`,
  });

  // 3. Resolve incoming request URL / origin for htu validation
  const reqHeaders = await headers();
  const host = reqHeaders.get('host') || 'localhost:3000';
  const proto = reqHeaders.get('x-forwarded-proto') || 'http';
  const targetUrl = `${proto}://${host}/dashboard`;

  // 4. Validate client DPoP Proof
  const dpopResult = await validateDPoPProof({
    dpopHeader: dpopProof || null,
    method: 'POST', // Server Actions are invoked via POST
    url: targetUrl,
    expectedJkt,
    accessToken: token,
  });

  const fullAuditTrail = [...auditTrail, ...dpopResult.auditTrail];

  if (!dpopResult.valid) {
    return {
      success: false,
      error: dpopResult.error || 'DPoP proof verification failed in Server Action.',
      code: dpopResult.code || 'invalid_dpop_proof',
      message: dpopResult.error || 'Unauthorized Server Action invocation.',
      tokenJkt: expectedJkt,
      proofJkt: dpopResult.jkt,
      auditTrail: fullAuditTrail,
    };
  }

  // 5. Success! Execute protected operation in enclave
  return {
    success: true,
    message: `Server Action "${operation}" executed successfully with verified DPoP proof-of-possession!`,
    tokenJkt: expectedJkt,
    proofJkt: dpopResult.jkt,
    executedOperation: operation,
    timestamp: new Date().toISOString(),
    auditTrail: fullAuditTrail,
    data: {
      vaultId: 'VLT-SERVER-ACTION-' + Math.floor(Math.random() * 9000 + 1000),
      masterEnclaveKey: 'ENCLAVE-ACTION::' + crypto.randomUUID().toUpperCase(),
      accessLevel: 'PRIVILEGED-SERVER-ACTION-AUTHORIZED',
      auditLogId: 'ACTION-LOG-' + Date.now().toString(36).toUpperCase(),
      timestamp: new Date().toISOString(),
    },
  };
}

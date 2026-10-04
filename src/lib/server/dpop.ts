import { importJWK, jwtVerify, calculateJwkThumbprint, base64url, decodeProtectedHeader } from 'jose';
import type { DPoPProofPayload, DPoPValidationResult, VerificationAuditStep } from '../types';

// In-memory replay cache for jti with automatic cleanup
const replayCache = new Map<string, number>();

function isReplayed(jti: string, exp: number): boolean {
  const now = Date.now();
  // Clean expired JTIs periodically
  if (replayCache.size > 1000) {
    for (const [k, expiry] of replayCache.entries()) {
      if (expiry < now) replayCache.delete(k);
    }
  }

  if (replayCache.has(jti)) {
    return true;
  }
  replayCache.set(jti, exp);
  return false;
}

export async function computeAccessTokenHash(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}

export interface ValidateDPoPOptions {
  dpopHeader: string | null;
  method: string;
  url: string;
  expectedJkt?: string; // If bound to an access token's cnf.jkt
  accessToken?: string; // If verifying ath claim
}

export async function validateDPoPProof({
  dpopHeader,
  method,
  url,
  expectedJkt,
  accessToken,
}: ValidateDPoPOptions): Promise<DPoPValidationResult> {
  const auditTrail: VerificationAuditStep[] = [];

  // Step 1: Check header presence
  if (!dpopHeader) {
    auditTrail.push({
      step: 'DPoP Header Check',
      description: 'Checking presence of HTTP DPoP request header',
      status: 'failed',
      details: 'Missing "DPoP" header. RFC 9449 requires a signed DPoP proof for DPoP-protected requests.',
    });
    return {
      valid: false,
      code: 'missing_dpop_header',
      error: 'Missing DPoP proof header. A valid DPoP proof is required.',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'DPoP Header Check',
    description: 'Checking presence of HTTP DPoP request header',
    status: 'passed',
    details: 'Header "DPoP" received with length ' + dpopHeader.length + ' chars.',
  });

  // Step 2: Parse and inspect JOSE header
  let header;
  try {
    header = decodeProtectedHeader(dpopHeader);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'Unknown error';
    auditTrail.push({
      step: 'DPoP JOSE Header Decoding',
      description: 'Decoding JWT header of the DPoP proof',
      status: 'failed',
      details: `Failed to decode JOSE header: ${msg}`,
    });
    return {
      valid: false,
      code: 'invalid_dpop_header',
      error: 'Malformed DPoP proof header.',
      auditTrail,
    };
  }

  if (header.typ !== 'dpop+jwt') {
    auditTrail.push({
      step: 'Header "typ" Validation',
      description: 'Verifying typ parameter is "dpop+jwt"',
      status: 'failed',
      details: `Expected typ "dpop+jwt", received: "${header.typ || 'undefined'}".`,
    });
    return {
      valid: false,
      code: 'invalid_typ',
      error: 'Invalid DPoP header typ. Must be "dpop+jwt".',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'Header "typ" Validation',
    description: 'Verifying typ parameter is "dpop+jwt"',
    status: 'passed',
    details: 'typ is valid "dpop+jwt".',
  });

  // Step 3: Validate JWK presence in header
  if (!header.jwk || typeof header.jwk !== 'object') {
    auditTrail.push({
      step: 'Public Key (jwk) Check',
      description: 'Extracting client public key JWK from header',
      status: 'failed',
      details: 'Header is missing the embedded public key "jwk" claim.',
    });
    return {
      valid: false,
      code: 'missing_jwk',
      error: 'DPoP proof header must contain client public key in "jwk" parameter.',
      auditTrail,
    };
  }

  const clientJwk = header.jwk as Record<string, unknown>;

  // Check for private key leakage in JWK (RFC 9449 Section 4.3 item 4)
  if ('d' in clientJwk) {
    auditTrail.push({
      step: 'Public Key (jwk) Check',
      description: 'Checking that jwk contains only public key parameters',
      status: 'failed',
      details: 'Private key parameter "d" detected in public JWK header. Security violation.',
    });
    return {
      valid: false,
      code: 'invalid_jwk_private_key',
      error: 'DPoP proof jwk must not contain private key material.',
      auditTrail,
    };
  }

  // Compute JWK thumbprint (jkt)
  let computedJkt = '';
  try {
    computedJkt = await calculateJwkThumbprint(clientJwk, 'sha256');
    auditTrail.push({
      step: 'JWK Thumbprint Calculation',
      description: 'Computing RFC 7638 SHA-256 thumbprint of the client public key',
      status: 'passed',
      details: `Computed jkt: ${computedJkt}`,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown thumbprint error';
    auditTrail.push({
      step: 'JWK Thumbprint Calculation',
      description: 'Computing RFC 7638 SHA-256 thumbprint of the client public key',
      status: 'failed',
      details: `Thumbprint calculation failed: ${msg}`,
    });
    return {
      valid: false,
      code: 'invalid_jwk',
      error: 'Invalid public JWK.',
      auditTrail,
    };
  }

  // Step 4: Verify cryptographic signature of the DPoP proof
  let payload: DPoPProofPayload;
  try {
    const publicKey = await importJWK(clientJwk, header.alg || 'ES256');
    const verifyResult = await jwtVerify(dpopHeader, publicKey, {
      typ: 'dpop+jwt',
    });
    payload = verifyResult.payload as unknown as DPoPProofPayload;
    auditTrail.push({
      step: 'Cryptographic Signature Verification',
      description: 'Verifying DPoP proof signature using embedded public key',
      status: 'passed',
      details: `Signature verified with algorithm ${header.alg}.`,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'Signature check error';
    auditTrail.push({
      step: 'Cryptographic Signature Verification',
      description: 'Verifying DPoP proof signature using embedded public key',
      status: 'failed',
      details: `Signature verification failed: ${msg}`,
    });
    return {
      valid: false,
      code: 'invalid_signature',
      error: 'DPoP proof signature verification failed.',
      auditTrail,
    };
  }

  // Step 5: Verify HTTP Method (htm)
  const incomingMethod = method.toUpperCase();
  if (payload.htm !== incomingMethod) {
    auditTrail.push({
      step: 'HTTP Method (htm) Match',
      description: 'Comparing proof htm claim to incoming HTTP method',
      status: 'failed',
      details: `Method mismatch: proof states "${payload.htm}", but request method is "${incomingMethod}".`,
    });
    return {
      valid: false,
      code: 'invalid_htm',
      error: `DPoP proof htm mismatch. Expected ${incomingMethod}, got ${payload.htm}.`,
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'HTTP Method (htm) Match',
    description: 'Comparing proof htm claim to incoming HTTP method',
    status: 'passed',
    details: `HTTP method matches: ${incomingMethod}`,
  });

  // Step 6: Verify HTTP URI (htu)
  // RFC 9449 Section 4.3: htu without query or fragment.
  // We compare pathname or full URL for flexibility across dev/prod environments
  const normalizedIncomingPath = new URL(url, 'http://localhost:3000').pathname;
  let normalizedProofPath = '';
  try {
    normalizedProofPath = new URL(payload.htu, 'http://localhost:3000').pathname;
  } catch {
    normalizedProofPath = payload.htu;
  }

  if (normalizedProofPath !== normalizedIncomingPath && payload.htu !== url) {
    auditTrail.push({
      step: 'HTTP URI (htu) Match',
      description: 'Comparing proof htu claim to request URI',
      status: 'failed',
      details: `URI mismatch: proof targeted "${payload.htu}", but request hit "${normalizedIncomingPath}".`,
    });
    return {
      valid: false,
      code: 'invalid_htu',
      error: `DPoP proof htu mismatch. Expected ${normalizedIncomingPath}, got ${payload.htu}.`,
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'HTTP URI (htu) Match',
    description: 'Comparing proof htu claim to request URI',
    status: 'passed',
    details: `URI target matches: ${normalizedIncomingPath}`,
  });

  // Step 7: Timestamp Freshness (iat)
  const now = Math.floor(Date.now() / 1000);
  const timeDiff = Math.abs(now - payload.iat);
  const MAX_CLOCK_SKEW_SECONDS = 120; // 2 minutes window

  if (timeDiff > MAX_CLOCK_SKEW_SECONDS) {
    auditTrail.push({
      step: 'Timestamp Freshness (iat)',
      description: 'Ensuring DPoP proof was created within acceptable time window',
      status: 'failed',
      details: `Proof iat is stale (${timeDiff} seconds difference, allowed: ${MAX_CLOCK_SKEW_SECONDS}s).`,
    });
    return {
      valid: false,
      code: 'proof_expired',
      error: 'DPoP proof has expired or client clock skew is excessive.',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'Timestamp Freshness (iat)',
    description: 'Ensuring DPoP proof was created within acceptable time window',
    status: 'passed',
    details: `Freshness verified. Timestamp drift: ${timeDiff}s.`,
  });

  // Step 8: Replay Protection (jti)
  if (!payload.jti) {
    auditTrail.push({
      step: 'Replay Protection (jti)',
      description: 'Checking unique identifier jti in proof payload',
      status: 'failed',
      details: 'Proof payload missing jti identifier.',
    });
    return {
      valid: false,
      code: 'missing_jti',
      error: 'DPoP proof missing jti claim.',
      auditTrail,
    };
  }

  if (isReplayed(payload.jti, (payload.iat + MAX_CLOCK_SKEW_SECONDS) * 1000)) {
    auditTrail.push({
      step: 'Replay Protection (jti)',
      description: 'Verifying jti has not been seen before in the cache',
      status: 'failed',
      details: `Replay detected! jti "${payload.jti}" was previously submitted. Proof replay blocked.`,
    });
    return {
      valid: false,
      code: 'proof_replayed',
      error: 'DPoP proof jti has already been used. Replay attacks are prohibited.',
      auditTrail,
    };
  }

  auditTrail.push({
    step: 'Replay Protection (jti)',
    description: 'Verifying jti has not been seen before in the cache',
    status: 'passed',
    details: `Unique jti accepted: ${payload.jti}`,
  });

  // Step 9: Access Token Hash (ath) check if access token is provided and proof contains ath
  if (accessToken && payload.ath) {
    const computedAth = await computeAccessTokenHash(accessToken);
    if (payload.ath !== computedAth) {
      auditTrail.push({
        step: 'Access Token Hash (ath) Match',
        description: 'Verifying proof is bound to the specific access token presented',
        status: 'failed',
        details: `Access token hash mismatch! Expected ath: ${computedAth}, received: ${payload.ath}.`,
      });
      return {
        valid: false,
        code: 'invalid_ath',
        error: 'DPoP proof ath claim does not match the access token presented.',
        auditTrail,
      };
    }
    auditTrail.push({
      step: 'Access Token Hash (ath) Match',
      description: 'Verifying proof is bound to the specific access token presented',
      status: 'passed',
      details: `ath hash verified: ${computedAth}`,
    });
  }

  // Step 10: Sender-Constrained Binding Verification (CNF.JKT MATCH!)
  // THIS IS THE CRITICAL SECURITY VALUE PROPOSITION OF DPoP!
  if (expectedJkt) {
    if (computedJkt !== expectedJkt) {
      auditTrail.push({
        step: 'DPoP Key Binding (cnf.jkt) Check',
        description: 'Comparing token cnf.jkt with public key thumbprint in DPoP proof',
        status: 'failed',
        details: `CRITICAL SECURITY FAILURE: Token is cryptographically bound to jkt "${expectedJkt}", but DPoP proof was signed with key thumbprint "${computedJkt}". Stolen token replay thwarted!`,
      });
      return {
        valid: false,
        code: 'jkt_mismatch',
        error: `DPoP key binding mismatch. The access token is bound to jkt '${expectedJkt}', but the request proof was signed with key '${computedJkt}'.`,
        auditTrail,
      };
    }

    auditTrail.push({
      step: 'DPoP Key Binding (cnf.jkt) Check',
      description: 'Comparing token cnf.jkt with public key thumbprint in DPoP proof',
      status: 'passed',
      details: `CONFIRMED: Client possesses the exact private key bound in token cnf.jkt (${computedJkt}). Proof-of-Possession verified!`,
    });
  }

  return {
    valid: true,
    jkt: computedJkt,
    proofPayload: payload,
    auditTrail,
  };
}

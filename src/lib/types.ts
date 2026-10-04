export interface DPoPProofHeader {
  typ: 'dpop+jwt';
  alg: 'ES256';
  jwk: {
    kty: 'EC';
    crv: string;
    x: string;
    y: string;
    [key: string]: unknown;
  };
}

export interface DPoPProofPayload {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  nonce?: string;
  [key: string]: unknown;
}

export interface DPoPAccessTokenPayload {
  sub: string;
  username: string;
  name: string;
  role: string;
  token_type: 'DPoP';
  cnf: {
    jkt: string;
  };
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  [key: string]: unknown;
}

export interface ClientKeyPairExport {
  publicKeyJwk: {
    kty: 'EC';
    crv: string;
    x: string;
    y: string;
  };
  privateKey?: CryptoKey;
  publicKey?: CryptoKey;
  privateKeyJwk?: Record<string, unknown>;
  jkt: string;
  extractable: boolean;
  storage: 'IndexedDB (Non-Extractable)' | 'In-Memory Fallback';
  createdAt: number;
}

export interface VerificationAuditStep {
  step: string;
  description: string;
  status: 'passed' | 'failed' | 'warning';
  details?: string;
}

export interface DPoPValidationResult {
  valid: boolean;
  error?: string;
  code?: string;
  jkt?: string;
  proofPayload?: DPoPProofPayload;
  auditTrail: VerificationAuditStep[];
}

export interface DashboardData {
  systemStatus: string;
  metrics: {
    threatsPrevented: number;
    dpopTokensActive: number;
    replayAttacksBlocked: number;
    securityScore: number;
  };
  confidentialData: {
    vaultId: string;
    masterEnclaveKey: string;
    accessLevel: string;
    auditLogId: string;
    timestamp: string;
  };
  user: {
    id: string;
    username: string;
    role: string;
    name: string;
  };
  tokenBinding: {
    tokenJkt: string;
    proofJkt: string;
    matched: boolean;
    authMethod: string;
  };
  auditTrail: VerificationAuditStep[];
}

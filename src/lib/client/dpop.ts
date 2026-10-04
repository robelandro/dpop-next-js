import {
  generateKeyPair,
  exportJWK,
  importJWK,
  calculateJwkThumbprint,
  SignJWT,
  base64url,
} from 'jose';
import type { ClientKeyPairExport } from '../types';

const STORAGE_KEY = 'dpop_demo_client_keypair_v1';

export async function computeClientAth(accessToken: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(accessToken);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}

export async function generateNewClientKeyPair(): Promise<ClientKeyPairExport> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicKeyJwk = (await exportJWK(publicKey)) as ClientKeyPairExport['publicKeyJwk'];
  const privateKeyJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

  const record: ClientKeyPairExport = {
    publicKeyJwk,
    privateKeyJwk,
    jkt,
    createdAt: Date.now(),
  };

  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
  }

  return record;
}

export async function getClientKeyPair(): Promise<ClientKeyPairExport> {
  if (typeof window === 'undefined') {
    return generateNewClientKeyPair();
  }

  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      const parsed = JSON.parse(stored) as ClientKeyPairExport;
      if (parsed.publicKeyJwk && parsed.privateKeyJwk && parsed.jkt) {
        return parsed;
      }
    } catch (e) {
      console.warn('Failed to parse stored keypair, generating fresh one', e);
    }
  }

  return generateNewClientKeyPair();
}

export async function generateAttackerKeyPair(): Promise<ClientKeyPairExport> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicKeyJwk = (await exportJWK(publicKey)) as ClientKeyPairExport['publicKeyJwk'];
  const privateKeyJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

  return {
    publicKeyJwk,
    privateKeyJwk,
    jkt,
    createdAt: Date.now(),
  };
}

export interface CreateProofParams {
  method: string;
  url: string;
  accessToken?: string;
  keyPair?: ClientKeyPairExport;
  overridePayload?: Record<string, unknown>;
  overrideHeader?: Record<string, unknown>;
}

export async function createClientDPoPProof({
  method,
  url,
  accessToken,
  keyPair,
  overridePayload = {},
  overrideHeader = {},
}: CreateProofParams): Promise<string> {
  const activeKeys = keyPair || (await getClientKeyPair());
  const privateKey = await importJWK(activeKeys.privateKeyJwk, 'ES256');

  // RFC 9449: htu must not contain query or fragment
  let cleanUrl = url;
  try {
    const parsed = new URL(url, window.location.origin);
    cleanUrl = `${parsed.origin}${parsed.pathname}`;
  } catch {
    cleanUrl = url.split('?')[0].split('#')[0];
  }

  const payload: Record<string, unknown> = {
    htm: method.toUpperCase(),
    htu: cleanUrl,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    ...overridePayload,
  };

  if (accessToken && !overridePayload.ath) {
    payload.ath = await computeClientAth(accessToken);
  }

  const header = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: activeKeys.publicKeyJwk,
    ...overrideHeader,
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader(header as unknown as { alg: string; typ: string; [key: string]: unknown })
    .sign(privateKey);

  return jwt;
}

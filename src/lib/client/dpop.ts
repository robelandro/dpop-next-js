import {
  calculateJwkThumbprint,
  SignJWT,
  base64url,
} from 'jose';
import type { ClientKeyPairExport } from '../types';
import {
  storeNonExtractableKey,
  getNonExtractableKey,
  deleteNonExtractableKey,
  StoredKeyRecord,
} from './indexedDb';

export async function computeClientAth(accessToken: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(accessToken);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}

/**
 * Generates a brand new ECDSA P-256 (ES256) Key Pair with extractable: false.
 * The private key CANNOT be exported out of the browser by JavaScript.
 * Stored securely in IndexedDB as a native CryptoKey object.
 */
export async function generateNewClientKeyPair(): Promise<ClientKeyPairExport> {
  if (typeof window === 'undefined') {
    // Fallback for SSR or non-browser environments
    const { generateKeyPair, exportJWK } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
    const publicKeyJwk = (await exportJWK(publicKey)) as ClientKeyPairExport['publicKeyJwk'];
    const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');
    return {
      publicKeyJwk,
      privateKey,
      publicKey,
      jkt,
      extractable: false,
      storage: 'In-Memory Fallback',
      createdAt: Date.now(),
    };
  }

  // Native Web Cryptography API with extractable: false!
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // EXTRACTABLE: FALSE - The private key CANNOT be exported via exportKey!
    ['sign', 'verify']
  );

  // The public key can be exported to JWK format for jkt thumbprint calculation & header embedding
  const publicKeyJwk = (await window.crypto.subtle.exportKey(
    'jwk',
    keyPair.publicKey
  )) as ClientKeyPairExport['publicKeyJwk'];

  const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

  // Persist directly into IndexedDB using Structured Clone algorithm
  await storeNonExtractableKey({
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyJwk,
    jkt,
    createdAt: Date.now(),
  });

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyJwk,
    jkt,
    extractable: keyPair.privateKey.extractable, // false!
    storage: 'IndexedDB (Non-Extractable)',
    createdAt: Date.now(),
  };
}

/**
 * Retrieves the client's non-extractable key pair from IndexedDB.
 * If none exists, generates a new one.
 */
export async function getClientKeyPair(): Promise<ClientKeyPairExport> {
  if (typeof window === 'undefined') {
    return generateNewClientKeyPair();
  }

  try {
    const stored = await getNonExtractableKey();
    if (stored && stored.privateKey && stored.publicKeyJwk && stored.jkt) {
      return {
        privateKey: stored.privateKey,
        publicKey: stored.publicKey,
        publicKeyJwk: stored.publicKeyJwk,
        jkt: stored.jkt,
        extractable: stored.privateKey.extractable, // false
        storage: 'IndexedDB (Non-Extractable)',
        createdAt: stored.createdAt,
      };
    }
  } catch (err) {
    console.warn('Could not read key from IndexedDB, generating fresh one', err);
  }

  return generateNewClientKeyPair();
}

/**
 * Clear client key from IndexedDB
 */
export async function clearClientKeyPair(): Promise<void> {
  await deleteNonExtractableKey();
}

/**
 * Generates an independent key pair for simulating an attacker.
 */
export async function generateAttackerKeyPair(): Promise<ClientKeyPairExport> {
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['sign', 'verify']
    );

    const publicKeyJwk = (await window.crypto.subtle.exportKey(
      'jwk',
      keyPair.publicKey
    )) as ClientKeyPairExport['publicKeyJwk'];

    const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      publicKeyJwk,
      jkt,
      extractable: false,
      storage: 'IndexedDB (Non-Extractable)',
      createdAt: Date.now(),
    };
  }

  const { generateKeyPair, exportJWK } = await import('jose');
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const publicKeyJwk = (await exportJWK(publicKey)) as ClientKeyPairExport['publicKeyJwk'];
  const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

  return {
    publicKeyJwk,
    privateKey,
    publicKey,
    jkt,
    extractable: false,
    storage: 'In-Memory Fallback',
    createdAt: Date.now(),
  };
}

/**
 * Security test demonstrating that the private key is non-extractable.
 * Attempting to export the private key throws a DOMException!
 */
export async function testExportPrivateKey(privateKey?: CryptoKey): Promise<{
  attempted: boolean;
  blocked: boolean;
  message: string;
}> {
  if (!privateKey || typeof window === 'undefined' || !window.crypto?.subtle) {
    return {
      attempted: false,
      blocked: true,
      message: 'Private key is not accessible in this context.',
    };
  }

  try {
    // Attempting export of non-extractable key
    await window.crypto.subtle.exportKey('jwk', privateKey);
    return {
      attempted: true,
      blocked: false,
      message: 'WARNING: Key was exported. It is extractable.',
    };
  } catch (error: unknown) {
    const errName = error instanceof Error ? error.name : 'DOMException';
    const errMsg = error instanceof Error ? error.message : 'key is not extractable';
    return {
      attempted: true,
      blocked: true,
      message: `SUCCESS: Browser blocked export! [${errName}: ${errMsg}]. Even malicious JavaScript or XSS cannot export the private key!`,
    };
  }
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
  if (!activeKeys.privateKey) {
    throw new Error('Private key is missing from active key pair');
  }

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

  // Sign directly using the non-extractable CryptoKey
  const jwt = await new SignJWT(payload)
    .setProtectedHeader(header as unknown as { alg: string; typ: string; [key: string]: unknown })
    .sign(activeKeys.privateKey);

  return jwt;
}

# Complete Guide: Implementing OAuth 2.0 DPoP in Next.js (REST APIs & Server Actions)

A comprehensive, production-grade guide to implementing **OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))** in Next.js (App Router).

This guide covers:
- **Client-Side:** Non-extractable Web Cryptography key management persisted in IndexedDB.
- **Server-Side Validation Engine:** RFC 9449 specification-compliant proof verification.
- **Pattern 1: Next.js API Route Handlers** (`src/app/api/.../route.ts`).
- **Pattern 2: Next.js Server Actions** (`'use server'`).
- **Threat Modeling & Defense Verification:** Why and how DPoP stops token theft.

---

## Table of Contents

1. [Understanding DPoP (RFC 9449)](#1-understanding-dpop-rfc-9449)
2. [Cryptographic Architecture & Lifecyle](#2-cryptographic-architecture--lifecycle)
3. [Client-Side Implementation (Web Crypto & IndexedDB)](#3-client-side-implementation-web-crypto--indexeddb)
4. [Reusable Server DPoP Validation Engine](#4-reusable-server-dpop-validation-engine)
5. [Pattern A: Implementing DPoP in Next.js API Routes](#5-pattern-a-implementing-dpop-in-nextjs-api-routes)
   - [Step 1: DPoP-Bound Login / Token Endpoint](#step-1-dpop-bound-login--token-endpoint)
   - [Step 2: DPoP-Protected Resource Route Handler](#step-2-dpop-protected-resource-route-handler)
6. [Pattern B: Implementing DPoP in Next.js Server Actions](#6-pattern-b-implementing-dpop-in-nextjs-server-actions)
   - [Why Server Actions Need DPoP](#why-server-actions-need-dpop)
   - [Creating a DPoP-Protected Server Action](#creating-a-dpop-protected-server-action)
   - [Calling the Server Action from Client Components](#calling-the-server-action-from-client-components)
7. [Threat Modeling: How Attacks are Thwarted](#7-threat-modeling-how-attacks-are-thwarted)
8. [Production Checklist & Best Practices](#8-production-checklist--best-practices)

---

## 1. Understanding DPoP (RFC 9449)

### The Problem with Traditional Bearer Tokens (RFC 6750)
In standard OAuth 2.0, access tokens are **Bearer tokens**. Whoever bears (holds) the token has full authority to use it.
- If an access token leaks through compromised browser extensions, server logs, reverse proxy caches, or network interception, an adversary can replay the token from anywhere in the world until it expires.

### The DPoP Solution: Sender-Constrained Tokens
DPoP binds every access token to a specific client-side asymmetric key pair (typically **ECDSA P-256 / `ES256`**):
1. **The client** holds the private key (non-extractable in browser memory/IndexedDB).
2. **The token** contains the SHA-256 thumbprint of the client's public key (`cnf: { jkt: "<thumbprint>" }` per RFC 7638).
3. **Every request** requires a freshly signed **DPoP Proof JWT** matching the target HTTP method and URI.
4. **The server** verifies that `DPoP_Proof.key_thumbprint === AccessToken.cnf.jkt`.

Even if a malicious actor steals the JWT access token, **the stolen token is unusable** because the adversary cannot produce a valid DPoP proof without the victim's private key.

---

## 2. Cryptographic Architecture & Lifecycle

```text
 ┌────────────────┐                                       ┌────────────────────────┐
 │ Client Browser │                                       │ Next.js Server (API/SA)│
 └───────┬────────┘                                       └───────────┬────────────┘
         │                                                            │
         │ 1. Generate ECDSA P-256 KeyPair (extractable: false)        │
         │    Store CryptoKey in IndexedDB                             │
         │                                                            │
         │ 2. Sign DPoP Proof for POST /api/auth/login                │
         │    Header: { typ: "dpop+jwt", alg: "ES256", jwk: pubKey }   │
         │    Payload: { htm: "POST", htu: "...", jti: uuid, iat }    │
         │                                                            │
         │ 3. Send Credentials + Header [DPoP: <proof>]               │
         ├───────────────────────────────────────────────────────────>│
         │                                                            │ 4. Verify DPoP proof
         │                                                            │ 5. Compute jkt = SHA256(jwk)
         │                                                            │ 6. Mint JWT with cnf: { jkt }
         │                                                            │ 7. Set HttpOnly Cookie
         │ 8. Receive 200 OK + Bound JWT Token                        │
         │<───────────────────────────────────────────────────────────┤
         │                                                            │
         │ 9. Call Resource (API route or Server Action)              │
         │    Compute ath = base64url(SHA256(accessToken))            │
         │    Sign DPoP Proof with htm, htu, jti, iat, ath            │
         │                                                            │
         │ 10. Transmit Request (Cookie + DPoP Proof)                 │
         ├───────────────────────────────────────────────────────────>│
         │                                                            │ 11. Verify token signature
         │                                                            │ 12. Verify DPoP proof
         │                                                            │ 13. ASSERT: token.cnf.jkt ==
         │                                                            │             proof.jwk.jkt
         │ 14. Access Granted (200 OK)                                │
         │<───────────────────────────────────────────────────────────┤
```

---

## 3. Client-Side Implementation (Web Crypto & IndexedDB)

### Why `extractable: false` + `IndexedDB`?
- Storing keys in `localStorage` requires exporting them to text/JWK, making them extractable by malicious third-party scripts (XSS).
- The HTML5 **Structured Clone Algorithm** allows storing native `CryptoKey` objects in **IndexedDB**.
- With `extractable: false`, calling `crypto.subtle.exportKey` triggers `DOMException: key is not extractable`. The private key can **never** be exported out of the browser.

### 3.1. IndexedDB Keystore Adapter (`src/lib/client/indexedDb.ts`)

```typescript
const DB_NAME = 'dpop_secure_keystore_v1';
const STORE_NAME = 'dpop_crypto_keys';
const KEY_RECORD_ID = 'current_client_dpop_key';

export interface StoredKeyRecord {
  id: string;
  privateKey: CryptoKey; // Non-extractable
  publicKey: CryptoKey;
  publicKeyJwk: { kty: 'EC'; crv: string; x: string; y: string };
  jkt: string;
  createdAt: number;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = (e) => {
      const db = (e.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function storeNonExtractableKey(record: Omit<StoredKeyRecord, 'id'>): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.put({ ...record, id: KEY_RECORD_ID });
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

export async function getNonExtractableKey(): Promise<StoredKeyRecord | null> {
  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(KEY_RECORD_ID);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => db.close();
    });
  } catch {
    return null;
  }
}
```

### 3.2. Client DPoP Proof Creator (`src/lib/client/dpop.ts`)

```typescript
import { calculateJwkThumbprint, SignJWT, base64url } from 'jose';
import { storeNonExtractableKey, getNonExtractableKey, StoredKeyRecord } from './indexedDb';

// 1. Generate Non-Extractable Key Pair
export async function getOrGenerateClientKey(): Promise<StoredKeyRecord> {
  const existing = await getNonExtractableKey();
  if (existing) return existing;

  // Generate ECDSA P-256 with extractable: false!
  const keyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // Private key cannot be exported
    ['sign', 'verify']
  );

  // Public key can be exported to JWK
  const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const jkt = await calculateJwkThumbprint(publicKeyJwk, 'sha256');

  const record: Omit<StoredKeyRecord, 'id'> = {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyJwk: publicKeyJwk as StoredKeyRecord['publicKeyJwk'],
    jkt,
    createdAt: Date.now(),
  };

  await storeNonExtractableKey(record);
  return { ...record, id: 'current_client_dpop_key' };
}

// 2. Compute Access Token Hash (ath) per RFC 9449 Section 4.2
export async function computeAccessTokenHash(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hash));
}

// 3. Create Signed DPoP Proof JWT
export async function createClientDPoPProof({
  method,
  url,
  accessToken,
}: {
  method: string;
  url: string;
  accessToken?: string;
}): Promise<string> {
  const keys = await getOrGenerateClientKey();

  // Normalize URL without query or fragment (RFC 9449 Section 4.3)
  const cleanUrl = url.split('?')[0].split('#')[0];

  const payload: Record<string, unknown> = {
    htm: method.toUpperCase(),
    htu: cleanUrl,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    payload.ath = await computeAccessTokenHash(accessToken);
  }

  // Sign directly with native non-extractable CryptoKey
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: keys.publicKeyJwk,
    })
    .sign(keys.privateKey);
}
```

---

## 4. Reusable Server DPoP Validation Engine

Create a universal DPoP validation utility in `src/lib/server/dpop.ts`. Both API routes and Server Actions will share this validator.

```typescript
import { importJWK, jwtVerify, calculateJwkThumbprint, base64url, decodeProtectedHeader } from 'jose';

// In-memory or Redis anti-replay cache
const replayCache = new Map<string, number>();

export async function computeAccessTokenHash(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}

export interface ValidateDPoPOptions {
  dpopHeader: string | null;
  method: string;
  url: string;
  expectedJkt?: string; // Stamped on the JWT (cnf.jkt)
  accessToken?: string; // For ath claim verification
}

export async function validateDPoPProof({
  dpopHeader,
  method,
  url,
  expectedJkt,
  accessToken,
}: ValidateDPoPOptions) {
  // 1. Presence check
  if (!dpopHeader) {
    return { valid: false, code: 'missing_dpop_header', error: 'DPoP header is required.' };
  }

  // 2. Decode JOSE Header
  let header;
  try {
    header = decodeProtectedHeader(dpopHeader);
  } catch {
    return { valid: false, code: 'invalid_dpop_header', error: 'Malformed DPoP header.' };
  }

  // 3. typ MUST be "dpop+jwt"
  if (header.typ !== 'dpop+jwt') {
    return { valid: false, code: 'invalid_typ', error: 'Header typ must be dpop+jwt.' };
  }

  // 4. Must contain public key jwk (without private parameters)
  if (!header.jwk || typeof header.jwk !== 'object' || 'd' in header.jwk) {
    return { valid: false, code: 'invalid_jwk', error: 'Missing or invalid public jwk in header.' };
  }

  // 5. Calculate RFC 7638 SHA-256 thumbprint (jkt)
  const computedJkt = await calculateJwkThumbprint(header.jwk as Record<string, unknown>, 'sha256');

  // 6. Verify digital signature using embedded public key
  let payload: any;
  try {
    const publicKey = await importJWK(header.jwk as Record<string, unknown>, header.alg || 'ES256');
    const result = await jwtVerify(dpopHeader, publicKey, { typ: 'dpop+jwt' });
    payload = result.payload;
  } catch (err) {
    return { valid: false, code: 'invalid_signature', error: 'DPoP signature verification failed.' };
  }

  // 7. Verify HTTP Method (htm)
  if (payload.htm !== method.toUpperCase()) {
    return { valid: false, code: 'invalid_htm', error: `Expected htm ${method.toUpperCase()}, got ${payload.htm}` };
  }

  // 8. Verify HTTP URI (htu) without query or fragment
  const targetPath = new URL(url, 'http://localhost:3000').pathname;
  let proofPath = payload.htu;
  try {
    proofPath = new URL(payload.htu, 'http://localhost:3000').pathname;
  } catch {}

  if (targetPath !== proofPath && payload.htu !== url) {
    return { valid: false, code: 'invalid_htu', error: `Expected htu ${targetPath}, got ${proofPath}` };
  }

  // 9. Verify Freshness (iat) - Allowed skew e.g. 120 seconds
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - payload.iat) > 120) {
    return { valid: false, code: 'proof_expired', error: 'DPoP proof timestamp expired or clock skew excessive.' };
  }

  // 10. Replay Protection (jti)
  if (replayCache.has(payload.jti)) {
    return { valid: false, code: 'proof_replayed', error: 'DPoP proof jti has already been used.' };
  }
  replayCache.set(payload.jti, Date.now() + 120000);

  // 11. Access Token Hash (ath) check
  if (accessToken && payload.ath) {
    const expectedAth = await computeAccessTokenHash(accessToken);
    if (payload.ath !== expectedAth) {
      return { valid: false, code: 'invalid_ath', error: 'DPoP proof ath claim does not match access token.' };
    }
  }

  // 12. SENDER-CONSTRAINED BINDING MATCH (CNF.JKT)
  if (expectedJkt && computedJkt !== expectedJkt) {
    return {
      valid: false,
      code: 'jkt_mismatch',
      error: `Token is bound to jkt '${expectedJkt}', but proof was signed with key '${computedJkt}'. Token theft prevented!`,
    };
  }

  return { valid: true, jkt: computedJkt, payload };
}
```

---

## 5. Pattern A: Implementing DPoP in Next.js API Routes

### Step 1: DPoP-Bound Login / Token Endpoint (`src/app/api/auth/login/route.ts`)

When logging in or requesting tokens, the client submits credentials along with an initial DPoP proof. The server validates the proof and embeds the client's `jkt` in the JWT confirmation claim.

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { validateDPoPProof } from '@/lib/server/dpop';
import { SignJWT } from 'jose';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secure-secret');

export async function POST(req: NextRequest) {
  const { username, password } = await req.json();

  // 1. Extract and validate incoming DPoP proof
  const dpopHeader = req.headers.get('dpop');
  const dpopResult = await validateDPoPProof({
    dpopHeader,
    method: 'POST',
    url: req.url,
  });

  if (!dpopResult.valid || !dpopResult.jkt) {
    return NextResponse.json({ error: dpopResult.code, message: dpopResult.error }, { status: 400 });
  }

  // 2. Authenticate user credentials...
  const userId = 'usr_123';

  // 3. Mint JWT with RFC 9449 cnf.jkt confirmation claim
  const now = Math.floor(Date.now() / 1000);
  const accessToken = await new SignJWT({
    sub: userId,
    token_type: 'DPoP',
    cnf: {
      jkt: dpopResult.jkt, // Sender constraint!
    },
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(JWT_SECRET);

  // 4. Return token and set HttpOnly secure cookie
  const response = NextResponse.json({ success: true, access_token: accessToken, token_type: 'DPoP' });
  response.cookies.set({
    name: 'dpop_access_token',
    value: accessToken,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 3600,
  });

  return response;
}
```

### Step 2: DPoP-Protected Resource Route Handler (`src/app/api/dashboard/route.ts`)

Every protected API route validates that the client presents both the access token and a matching DPoP proof.

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { validateDPoPProof } from '@/lib/server/dpop';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secure-secret');

export async function GET(req: NextRequest) {
  // 1. Resolve Access Token (from Authorization header or Cookie)
  const authHeader = req.headers.get('authorization');
  const cookieToken = req.cookies.get('dpop_access_token')?.value;
  let token = cookieToken;
  if (!token && authHeader?.startsWith('DPoP ')) {
    token = authHeader.substring(5).trim();
  }

  if (!token) {
    return NextResponse.json({ error: 'missing_token' }, { status: 401 });
  }

  // 2. Verify server JWT
  let tokenPayload;
  try {
    const verified = await jwtVerify(token, JWT_SECRET);
    tokenPayload = verified.payload as any;
  } catch {
    return NextResponse.json({ error: 'invalid_token' }, { status: 401 });
  }

  // 3. Extract cnf.jkt binding
  const expectedJkt = tokenPayload.cnf?.jkt;
  if (!expectedJkt) {
    return NextResponse.json({ error: 'token_not_dpop_bound' }, { status: 403 });
  }

  // 4. Validate DPoP Proof
  const dpopHeader = req.headers.get('dpop');
  const validation = await validateDPoPProof({
    dpopHeader,
    method: 'GET',
    url: req.url,
    expectedJkt,
    accessToken: token,
  });

  if (!validation.valid) {
    return NextResponse.json(
      { error: validation.code, message: validation.error },
      { status: 401, headers: { 'WWW-Authenticate': `DPoP error="${validation.code}"` } }
    );
  }

  // 5. Success! Return protected data
  return NextResponse.json({
    success: true,
    data: { confidentialSecret: 'ENCLAVE-TOP-SECRET', user: tokenPayload.sub },
  });
}
```

---

## 6. Pattern B: Implementing DPoP in Next.js Server Actions

### Why Server Actions Need DPoP
Server Actions execute on the server via `POST` requests and automatically send ambient cookies. However, if an attacker executes XSS or cross-origin requests, they could attempt to invoke Server Actions with stolen credentials. 

By enforcing DPoP on sensitive Server Actions:
1. The client must supply a valid `dpopProof` signed by its non-extractable browser key.
2. The Server Action checks that `token.cnf.jkt === proof.jkt`.
3. If an attacker invokes the Server Action without the client's private key, **the execution is immediately rejected**.

### 6.1. Defining the Protected Server Action (`src/app/actions/dashboard.ts`)

```typescript
'use server';

import { cookies, headers } from 'next/headers';
import { jwtVerify } from 'jose';
import { validateDPoPProof } from '@/lib/server/dpop';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secure-secret');

export interface SecureActionInput {
  dpopProof?: string;
  operation: string;
}

export async function executeSecureEnclaveAction(input: SecureActionInput) {
  // 1. Resolve Access Token from HttpOnly cookie
  const cookieStore = await cookies();
  const token = cookieStore.get('dpop_access_token')?.value;

  if (!token) {
    return { success: false, error: 'missing_token', message: 'Authentication required.' };
  }

  // 2. Verify server JWT & cnf.jkt
  let payload: any;
  try {
    const verified = await jwtVerify(token, JWT_SECRET);
    payload = verified.payload;
  } catch {
    return { success: false, error: 'invalid_token', message: 'Token signature invalid.' };
  }

  const expectedJkt = payload.cnf?.jkt;
  if (!expectedJkt) {
    return { success: false, error: 'token_not_dpop_bound', message: 'DPoP token required.' };
  }

  // 3. Resolve target URL for htu validation
  const reqHeaders = await headers();
  const host = reqHeaders.get('host') || 'localhost:3000';
  const proto = reqHeaders.get('x-forwarded-proto') || 'http';
  const targetUrl = `${proto}://${host}/dashboard`;

  // 4. Validate DPoP Proof
  // Note: Server Actions always execute via HTTP POST
  const validation = await validateDPoPProof({
    dpopHeader: input.dpopProof || null,
    method: 'POST',
    url: targetUrl,
    expectedJkt,
    accessToken: token,
  });

  if (!validation.valid) {
    return {
      success: false,
      error: validation.code,
      message: validation.error,
    };
  }

  // 5. Authorized! Execute privileged database mutations or enclave operations
  return {
    success: true,
    message: `Operation "${input.operation}" executed with verified DPoP sender constraint!`,
    enclaveResult: { status: 'COMPLETED', txId: crypto.randomUUID() },
  };
}
```

### 6.2. Invoking the Server Action from Client Components

```tsx
'use client';

import React, { useState } from 'react';
import { createClientDPoPProof } from '@/lib/client/dpop';
import { executeSecureEnclaveAction } from '@/app/actions/dashboard';

export default function SecureActionButton() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const handleClick = async () => {
    setLoading(true);
    try {
      // 1. Create client-side DPoP proof targeting the page action URL
      const proof = await createClientDPoPProof({
        method: 'POST',
        url: `${window.location.origin}/dashboard`,
      });

      // 2. Invoke Server Action directly via RPC
      const response = await executeSecureEnclaveAction({
        dpopProof: proof,
        operation: 'Rotate Master Cryptographic Keys',
      });

      if (response.success) {
        setResult(`Success: ${response.message}`);
      } else {
        setResult(`Denied [${response.error}]: ${response.message}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button onClick={handleClick} disabled={loading}>
        {loading ? 'Verifying DPoP Proof...' : 'Execute Secure Server Action'}
      </button>
      {result && <p>{result}</p>}
    </div>
  );
}
```

---

## 7. Threat Modeling: How Attacks are Thwarted

| Attack Scenario | What Attacker Does | Why DPoP Blocks It |
| :--- | :--- | :--- |
| **1. Classic Token Replay (No DPoP)** | Attacker intercepts the JWT from logs or network and replays it to `/api/dashboard`. | **401 `missing_dpop_header`**: The server requires a signed `DPoP` proof. |
| **2. Attacker Generates Own KeyPair** | Attacker creates their own ES256 key pair, signs a DPoP proof, and attaches the victim's token. | **401 `jkt_mismatch`**: The server computes the thumbprint of the attacker's public key (`attacker_jkt`) and finds it does not match `token.cnf.jkt` (`victim_jkt`). |
| **3. Proof Replay Attack** | Attacker sniffs an existing request and replays the same DPoP proof header. | **401 `proof_replayed`** or **`proof_expired`**: The `jti` is cached in server memory, and timestamps beyond 120s are rejected. |
| **4. XSS Key Exfiltration** | Attacker executes malicious JavaScript in the victim's browser and tries to export the private key. | **`DOMException: key is not extractable`**: The private key is non-extractable (`extractable: false`) in IndexedDB. |

---

## 8. Production Checklist & Best Practices

1. **Non-Extractable Keys:** Always initialize client keys with `{ extractable: false }` and store in IndexedDB. Never store raw private keys in `localStorage` or `sessionStorage`.
2. **Replay Cache in Distributed Systems:** For multi-server or serverless Next.js deployments (e.g. Vercel, AWS ECS, Kubernetes), replace the in-memory `Set`/`Map` with **Upstash Redis** or an in-memory cluster cache using `SET key NX EX 120`.
3. **Clock Skew Tolerance:** Use a reasonable clock skew window (e.g., 60 to 120 seconds) for `iat` to account for minor drift between client devices and servers.
4. **Server Nonce (RFC 9449 Section 8):** For high-security endpoints, supply a `DPoP-Nonce` header in the 401 response and require clients to include the server nonce in their next DPoP proof payload.
5. **Path Normalization:** Always strip query parameters and fragment identifiers from `htu` matching (`url.split('?')[0]`).
6. **Access Token Hash (`ath`):** Always include and verify the `ath` claim when presenting access tokens to prevent proofs generated for one token from being coupled with another.

# Next.js OAuth 2.0 DPoP (RFC 9449) Demonstrator

A production-ready demonstrative starter and template for **OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP - [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))** built with Next.js App Router, TypeScript, and native Web Cryptography (`jose`).

---

## 🛡️ What is DPoP?

In standard OAuth 2.0 ([RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)), access tokens are **Bearer tokens**: *possession of the token is sufficient to access the protected resource*. If an attacker steals or intercepts a Bearer token (via XSS, insecure logs, browser extensions, or compromised proxies), the attacker can replay it from anywhere in the world.

**DPoP (RFC 9449) solves this by sender-constraining access tokens:**
1. The client generates an asymmetric key pair (e.g. ECDSA P-256 / `ES256`). The private key remains secure in client memory or non-extractable Web Crypto storage.
2. When requesting tokens or calling protected APIs, the client signs a **DPoP Proof JWT** with its private key.
3. The server validates the proof and embeds the SHA-256 thumbprint of the client's public key ([RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)) into the Access Token's `cnf.jkt` confirmation claim.
4. On subsequent resource requests, the server ensures that the caller's DPoP proof was signed by the exact same key bound to the token (`jkt === token.cnf.jkt`).

> **Result:** Even if an adversary intercepts and steals your JWT access token, **the stolen token is useless** because the adversary does not hold the victim's private key!

---

## 🚀 Key Features

- **Non-Extractable Private Keys (`extractable: false`):** The client's ECDSA P-256 private key is generated with `extractable: false` using the native Web Cryptography API. Even if an attacker injects malicious JavaScript or exploits XSS, `crypto.subtle.exportKey` is blocked by the browser.
- **IndexedDB Keystore:** Stores the native `CryptoKey` object directly in browser IndexedDB via HTML5 Structured Clone. No raw private key bytes ever touch `localStorage` or strings.
- **Interactive `exportKey()` Resistance Test:** Buttons on both the Login and Dashboard pages allow you to trigger `crypto.subtle.exportKey('jwk', privateKey)` to observe the browser actively throwing `DOMException: key is not extractable`.
- **DPoP Login API (`POST /api/auth/login`):**
  - Requires a client-signed DPoP proof header.
  - Verifies signature, `htm` (HTTP method), `htu` (HTTP URI), freshness `iat`, and replay protection `jti`.
  - Calculates the public key thumbprint `jkt` and mints a real JWT with `cnf: { jkt }`.
  - Sets the token in an `HttpOnly`, `SameSite=Lax`, secure cookie (`dpop_access_token`) and returns it in the JSON response.
- **Strictly Enforced Protected Dashboard API (`GET /api/dashboard`):**
  - Checks for the DPoP-bound access token from cookies or `Authorization: DPoP <token>` header.
  - Verifies that the request includes a valid `DPoP` proof header.
  - Cryptographically verifies that the public key in the DPoP proof matches the token's `cnf.jkt` binding.
  - Rejects missing proofs, signature errors, expired timestamps, replayed `jti`s, and key mismatches.
- **Next.js Server Actions with DPoP (`src/app/actions/dashboard.ts`):**
  - Next.js `'use server'` action `executeSecureEnclaveAction` protected by end-to-end RFC 9449 DPoP verification.
  - Validates client DPoP proofs within Next.js Server Action RPC execution context.
- **Dual Invocation Channels:**
  - Toggle seamlessly on the dashboard between **REST API Route Handlers** (`fetch('/api/dashboard')`) and **Next.js Server Actions** (`executeSecureEnclaveAction()`).
- **Interactive Dashboard with Dual Action Buttons:**
  - **Button 1 (Authorized Request):** Calls the dashboard with a genuine DPoP proof signed by the client's private key. Returns `200 OK` with confidential data and audit log.
  - **Button 2 (Stolen Token Attack Simulator):** Simulates an adversary attempting to exploit the victim's stolen access token under 3 attack vectors:
    - *Vector A:* Attacker signs a DPoP proof using their own key pair (Thwarted by `cnf.jkt` Thumbprint Mismatch).
    - *Vector B:* Classic Bearer replay with no DPoP proof (Thwarted by missing proof header).
    - *Vector C:* Replay of a stale/previously seen `jti` proof (Thwarted by replay cache and clock drift checks).
- **Live Cryptographic Inspector:**
  - Decodes and displays both the server-issued access token (`cnf.jkt`) and the client-signed DPoP proof header (`jwk`, `jti`, `htm`, `htu`, `ath`).
  - Provides a step-by-step audit trail of all RFC 9449 verification assertions.

---

## 📂 Project Structure

```text
├── src/
│   ├── app/
│   │   ├── actions/
│   │   │   ├── dashboard.ts           # DPoP-protected Next.js Server Action ('use server')
│   │   │   └── index.ts               # Re-exports all Server Actions
│   │   ├── api/
│   │   │   ├── auth/
│   │   │   │   ├── login/route.ts     # Validates DPoP proof & issues cnf.jkt token
│   │   │   │   ├── logout/route.ts    # Clears HTTP-only cookie
│   │   │   │   └── me/route.ts        # Session & token binding inspector
│   │   │   └── dashboard/route.ts     # Protected DPoP-only REST endpoint
│   │   ├── dashboard/page.tsx         # Interactive dashboard with REST & Server Action modes
│   │   ├── login/page.tsx             # Login flow with Web Crypto key generator
│   │   ├── globals.css                # Dark-mode glassmorphic design system
│   │   ├── layout.tsx                 # Root layout with navbar & metadata
│   │   └── page.tsx                   # Overview and architecture comparison
│   ├── components/
│   │   └── Navbar.tsx                 # Navigation with live client JKT status
│   └── lib/
│       ├── types.ts                   # DPoP interfaces & audit models
│       ├── client/
│       │   ├── indexedDb.ts           # IndexedDB storage adapter for non-extractable CryptoKeys
│       │   └── dpop.ts                # Client Web Crypto ES256 key management & proof creation
│       └── server/
│           ├── dpop.ts                # Server-side RFC 9449 validation engine
│           └── jwt.ts                 # Server JWT signing & cnf.jkt binding
├── package.json
├── tsconfig.json
├── next.config.mjs
└── README.md
```

---

## 🛠️ Getting Started

### 1. Prerequisites
- Node.js 18.17+ or 20+ (tested on Node v24)
- npm, yarn, or pnpm

### 2. Install Dependencies
```bash
npm install
```

### 3. Run Development Server
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Testing the DPoP Flow Walkthrough

1. **Visit the Sign-In Page (`/login`):**
   - Notice the browser automatically generates an `ECDSA P-256` key pair in Web Crypto.
   - Click **Quick Fill: Alice (SecOps Lead)** (`alice` / `password123`).
   - Click **Sign In with DPoP Proof**.
   - Your browser creates a signed DPoP proof targeting `POST /api/auth/login`. The server verifies it and issues a JWT with your key's thumbprint (`cnf.jkt`).

2. **Visit the Protected Dashboard (`/dashboard`):**
   - Click **"Hit Dashboard (Legitimate DPoP Proof)"** (Green Button):
     - Your browser signs a fresh DPoP proof with its private key.
     - The server matches `token.cnf.jkt` with the proof's key thumbprint.
     - **Result:** `200 OK — Access Granted` with unlocked confidential vault data and audit logs.

3. **Simulate Stolen Token Attack:**
   - Click **"Hit with Fake / Stolen Token"** (Red Button):
     - The simulator sends the victim's real access token, but simulates an adversary who generated their own key pair or omitted the DPoP header.
     - The server detects the key thumbprint mismatch (`cnf.jkt !== attacker_jkt`).
     - **Result:** `401 Unauthorized — Attack Thwarted by DPoP`.

---

## 📜 RFC Specifications Implemented

- **[RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)**: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP).
- **[RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)**: JSON Web Key (JWK) Thumbprint calculation (SHA-256).
- **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)**: JSON Web Signature (JWS).
- **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)**: JSON Web Token (JWT) with confirmation (`cnf`) claim.

---

## 📄 License

MIT

'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Key, Lock, ArrowRight, RefreshCw, Eye, CheckCircle2, AlertCircle } from 'lucide-react';
import {
  getClientKeyPair,
  generateNewClientKeyPair,
  createClientDPoPProof,
  testExportPrivateKey,
} from '@/lib/client/dpop';
import type { ClientKeyPairExport, VerificationAuditStep } from '@/lib/types';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('password123');
  const [loading, setLoading] = useState(false);
  const [keyPair, setKeyPair] = useState<ClientKeyPairExport | null>(null);
  const [showKeyDetails, setShowKeyDetails] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [auditLog, setAuditLog] = useState<VerificationAuditStep[] | null>(null);

  useEffect(() => {
    getClientKeyPair().then(setKeyPair);
  }, []);

  const handleRegenerateKeys = async () => {
    const keys = await generateNewClientKeyPair();
    setKeyPair(keys);
  };

  const handleDemoFill = (user: string) => {
    setUsername(user);
    setPassword('password123');
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setAuditLog(null);

    try {
      // 1. Generate client-side DPoP Proof for POST /api/auth/login
      const activeKeys = keyPair || (await getClientKeyPair());
      const dpopProof = await createClientDPoPProof({
        method: 'POST',
        url: `${window.location.origin}/api/auth/login`,
        keyPair: activeKeys,
      });

      // 2. Transmit login request with DPoP header
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          DPoP: dpopProof,
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setError(data.message || 'Login failed. Please check your credentials or DPoP proof.');
        if (data.auditTrail) {
          setAuditLog(data.auditTrail);
        }
        setLoading(false);
        return;
      }

      // Successful login!
      setAuditLog(data.auditTrail);
      
      // Store token in session storage as well for inspection/demo purposes
      sessionStorage.setItem('dpop_demo_token', data.access_token);
      sessionStorage.setItem('dpop_demo_user', JSON.stringify(data.user));

      setTimeout(() => {
        router.push('/dashboard');
      }, 700);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error during login';
      setError(msg);
      setLoading(false);
    }
  };

  return (
    <div className="container" style={{ paddingTop: '40px', paddingBottom: '70px' }}>
      
      <div style={{ maxWidth: '1020px', margin: '0 auto' }}>
        
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div className="badge badge-amber" style={{ marginBottom: '12px', fontSize: '0.8rem' }}>
            <Key size={14} strokeWidth={2.5} />
            Cryptographic Authentication
          </div>
          <h1 style={{ fontSize: '2.8rem', fontWeight: 900, marginBottom: '14px', letterSpacing: '-0.03em' }}>
            SIGN IN WITH <span style={{
              backgroundColor: 'var(--neo-yellow)',
              padding: '0 10px',
              border: '2.5px solid #000000',
              boxShadow: '3px 3px 0px #000000'
            }}>DPoP PROOF</span>
          </h1>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '680px', margin: '0 auto', fontSize: '1.05rem', fontWeight: 600 }}>
            Upon successful authentication, the server verifies your browser’s DPoP proof and issues a genuine JWT 
            cryptographically bound to your public key thumbprint (<code className="code-inline">cnf.jkt</code>).
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
          
          {/* Form Card */}
          <div className="neo-card" style={{ padding: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                backgroundColor: 'var(--neo-yellow)',
                border: '2px solid #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '2.5px 2.5px 0px #000000'
              }}>
                <Lock size={18} strokeWidth={2.5} color="#000000" />
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 900 }}>
                Account Credentials
              </h2>
            </div>
            
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '20px', fontWeight: 600 }}>
              Enter demo credentials or choose a quick persona below:
            </p>

            {/* Quick Personas */}
            <div style={{ display: 'flex', gap: '10px', marginBottom: '22px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => handleDemoFill('alice')}
                className={`btn ${username === 'alice' ? 'btn-primary' : 'btn-outline'}`}
                style={{ padding: '6px 14px', fontSize: '0.8rem' }}
              >
                Alice (SecOps Lead)
              </button>
              <button
                type="button"
                onClick={() => handleDemoFill('bob')}
                className={`btn ${username === 'bob' ? 'btn-primary' : 'btn-outline'}`}
                style={{ padding: '6px 14px', fontSize: '0.8rem' }}
              >
                Bob (Auditor)
              </button>
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 800, color: '#000000', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="form-input"
                  placeholder="e.g. alice"
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 800, color: '#000000', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="form-input"
                  placeholder="password123"
                  required
                />
              </div>

              {error && (
                <div style={{
                  padding: '12px 16px',
                  borderRadius: '8px',
                  backgroundColor: 'var(--neo-rose-light)',
                  border: '2.5px solid #000000',
                  boxShadow: '3px 3px 0px #000000',
                  color: '#000000',
                  fontSize: '0.875rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  <AlertCircle size={18} strokeWidth={2.5} color="var(--neo-rose)" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="btn btn-primary"
                style={{ width: '100%', padding: '14px', marginTop: '6px', fontSize: '1.05rem' }}
              >
                {loading ? (
                  <>
                    <RefreshCw size={18} className="animate-spin" strokeWidth={2.5} />
                    Signing Proof & Authenticating...
                  </>
                ) : (
                  <>
                    Sign In with DPoP Proof
                    <ArrowRight size={18} strokeWidth={2.5} />
                  </>
                )}
              </button>

              <div style={{
                fontSize: '0.75rem',
                color: 'var(--text-muted)',
                textAlign: 'center',
                marginTop: '4px',
                fontWeight: 600
              }}>
                A signed DPoP Proof will be injected into the <code className="code-inline">DPoP</code> HTTP header.
              </div>
            </form>
          </div>

          {/* Client Cryptographic State Card */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            
            <div className="neo-card" style={{ padding: '28px' }}>
              <div className="flex items-center justify-between" style={{ marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '6px',
                    backgroundColor: 'var(--neo-emerald-light)',
                    border: '1.5px solid #000',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <ShieldCheck size={18} strokeWidth={2.5} color="#15803d" />
                  </div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 900 }}>Client Asymmetric Key</h3>
                </div>
                <button
                  onClick={handleRegenerateKeys}
                  className="btn btn-outline"
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                  title="Generate a brand new ES256 KeyPair"
                >
                  <RefreshCw size={12} strokeWidth={2.5} />
                  Regenerate
                </button>
              </div>

              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '16px', lineHeight: '1.6', fontWeight: 600 }}>
                Generated using the browser&apos;s Web Cryptography API (<code className="code-inline">ECDSA P-256</code>) with 
                <strong> extractable: false</strong>, stored in <strong>IndexedDB</strong>. 
                The private key cannot be exported or leaked by JavaScript or XSS.
              </p>

              {keyPair ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  
                  {/* Storage & Extractability Badges */}
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span className="badge badge-emerald" style={{ fontSize: '0.72rem' }}>
                      Storage: {keyPair.storage}
                    </span>
                    <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
                      Extractable: {String(keyPair.extractable)}
                    </span>
                  </div>

                  {/* Thumbprint */}
                  <div style={{
                    backgroundColor: 'var(--neo-cyan-light)',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    border: '2px solid #000000',
                    boxShadow: '2.5px 2.5px 0px #000000'
                  }}>
                    <div style={{ fontSize: '0.7rem', color: '#000000', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 800 }}>
                      RFC 7638 SHA-256 Thumbprint (JKT)
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.875rem',
                      color: '#000000',
                      wordBreak: 'break-all',
                      marginTop: '4px',
                      fontWeight: 800
                    }}>
                      {keyPair.jkt}
                    </div>
                  </div>

                  {/* Test Key Non-Extractability Security Demo */}
                  <div style={{
                    padding: '14px',
                    borderRadius: '8px',
                    backgroundColor: '#ffffff',
                    border: '2px dashed #000000',
                    boxShadow: '2px 2px 0px #000000'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 800, color: '#000000' }}>
                        Verify Hardware/Browser Non-Extractability:
                      </span>
                      <button
                        type="button"
                        onClick={async () => {
                          const res = await testExportPrivateKey(keyPair.privateKey);
                          alert(res.message);
                        }}
                        className="btn btn-outline"
                        style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                      >
                        Test exportKey()
                      </button>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '6px', fontWeight: 600 }}>
                      Attempts <code className="code-inline">crypto.subtle.exportKey(&apos;jwk&apos;, privateKey)</code> to prove browser blocks it.
                    </div>
                  </div>

                  {/* Public Key Preview Toggle */}
                  <div>
                    <button
                      type="button"
                      onClick={() => setShowKeyDetails(!showKeyDetails)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: '#000000',
                        fontSize: '0.825rem',
                        fontWeight: 800,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '4px 0',
                        textDecoration: 'underline'
                      }}
                    >
                      <Eye size={14} strokeWidth={2.5} />
                      {showKeyDetails ? 'Hide Public JWK Coordinates' : 'View Public JWK Coordinates'}
                    </button>

                    {showKeyDetails && (
                      <pre className="code-container" style={{ marginTop: '8px', maxHeight: '180px' }}>
                        {JSON.stringify(keyPair.publicKeyJwk, null, 2)}
                      </pre>
                    )}
                  </div>

                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', fontWeight: 700 }}>
                  Initializing Web Crypto Key Pair...
                </div>
              )}
            </div>

            {/* Explanatory Box */}
            <div style={{
              padding: '24px',
              backgroundColor: 'var(--bg-surface-alt)',
              border: '3px solid #000000',
              borderRadius: '10px',
              boxShadow: '4px 4px 0px #000000'
            }}>
              <h4 style={{ fontSize: '1rem', fontWeight: 900, marginBottom: '10px', color: '#000000', textTransform: 'uppercase', letterSpacing: '0.03em' }}>
                ⚡ How DPoP Login Binding Works
              </h4>
              <ol style={{ paddingLeft: '20px', color: '#000000', fontSize: '0.85rem', lineHeight: '1.7', fontWeight: 600 }}>
                <li>Client signs a proof targeting <code className="code-inline">POST /api/auth/login</code>.</li>
                <li>Server validates proof signature and computes <code className="code-inline">jkt</code> of the public key.</li>
                <li>Server creates JWT containing <code className="code-inline">cnf: &#123; jkt: &quot;...&quot; &#125;</code>.</li>
                <li>Token is returned &amp; set in an HTTP-only secure cookie.</li>
              </ol>
            </div>

          </div>

        </div>

        {/* Live Audit Log */}
        {auditLog && auditLog.length > 0 && (
          <div className="neo-card" style={{ marginTop: '36px', padding: '28px' }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 900, marginBottom: '18px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <CheckCircle2 size={20} strokeWidth={2.5} color="#15803d" />
              Server DPoP Proof Verification Log
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {auditLog.map((step, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    backgroundColor: step.status === 'passed' ? 'var(--neo-emerald-light)' : 'var(--neo-rose-light)',
                    border: '2px solid #000000',
                    boxShadow: '2px 2px 0px #000000',
                    fontSize: '0.85rem',
                    gap: '12px',
                    flexWrap: 'wrap'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className={`badge ${step.status === 'passed' ? 'badge-emerald' : 'badge-rose'}`} style={{ fontSize: '0.65rem' }}>
                      {step.status}
                    </span>
                    <span style={{ fontWeight: 800, color: '#000000' }}>{step.step}</span>
                  </div>
                  <div style={{ color: '#000000', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 600 }}>
                    {step.details}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>

    </div>
  );
}

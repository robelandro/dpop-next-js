'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Key, Lock, ArrowRight, RefreshCw, Eye, CheckCircle2, AlertCircle } from 'lucide-react';
import { getClientKeyPair, generateNewClientKeyPair, createClientDPoPProof } from '@/lib/client/dpop';
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
    <div className="container" style={{ paddingTop: '40px', paddingBottom: '60px' }}>
      
      <div style={{ maxWidth: '980px', margin: '0 auto' }}>
        
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <div className="badge badge-cyan" style={{ marginBottom: '12px' }}>
            <Key size={12} />
            Cryptographic Authentication
          </div>
          <h1 style={{ fontSize: '2.4rem', fontWeight: 800, marginBottom: '12px', letterSpacing: '-0.03em' }}>
            Sign In with <span style={{ color: 'var(--accent-cyan)' }}>DPoP Proof</span>
          </h1>
          <p style={{ color: 'var(--text-secondary)', maxWidth: '640px', margin: '0 auto', fontSize: '1.05rem' }}>
            Upon successful authentication, the server verifies your browser’s DPoP proof and issues a genuine JWT 
            cryptographically bound to your public key thumbprint (<code className="code-inline">cnf.jkt</code>).
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
          
          {/* Form Card */}
          <div className="glass-panel" style={{ padding: '32px' }}>
            <h2 style={{ fontSize: '1.3rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock size={18} color="var(--accent-cyan)" />
              Account Credentials
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '24px' }}>
              Enter demo credentials or choose a quick persona below:
            </p>

            {/* Quick Personas */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => handleDemoFill('alice')}
                className={`btn ${username === 'alice' ? 'btn-primary' : 'btn-outline'}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
              >
                Alice (SecOps Lead)
              </button>
              <button
                type="button"
                onClick={() => handleDemoFill('bob')}
                className={`btn ${username === 'bob' ? 'btn-primary' : 'btn-outline'}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
              >
                Bob (Auditor)
              </button>
            </div>

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
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
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
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
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'rgba(244, 63, 94, 0.1)',
                  border: '1px solid rgba(244, 63, 94, 0.3)',
                  color: '#fb7185',
                  fontSize: '0.875rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <AlertCircle size={16} />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="btn btn-primary"
                style={{ width: '100%', padding: '14px', marginTop: '8px', fontSize: '1rem' }}
              >
                {loading ? (
                  <>
                    <RefreshCw size={16} className="animate-spin" />
                    Signing Proof & Authenticating...
                  </>
                ) : (
                  <>
                    Sign In with DPoP Proof
                    <ArrowRight size={16} />
                  </>
                )}
              </button>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: '4px' }}>
                A signed DPoP Proof will be injected into the <code className="code-inline">DPoP</code> HTTP header.
              </div>
            </form>
          </div>

          {/* Client Cryptographic State Card */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            
            <div className="glass-panel" style={{ padding: '28px' }}>
              <div className="flex items-center justify-between" style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={20} color="var(--accent-emerald)" />
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Client Asymmetric Key</h3>
                </div>
                <button
                  onClick={handleRegenerateKeys}
                  className="btn btn-outline"
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                  title="Generate a brand new ES256 KeyPair"
                >
                  <RefreshCw size={12} />
                  Regenerate
                </button>
              </div>

              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '16px' }}>
                Generated using the browser&apos;s Web Cryptography API (<code className="code-inline">ECDSA P-256</code>). 
                The private key stays strictly in client memory/storage and never leaves your browser.
              </p>

              {keyPair ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  
                  {/* Thumbprint */}
                  <div style={{
                    backgroundColor: 'rgba(8, 12, 20, 0.7)',
                    padding: '12px 14px',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-subtle)'
                  }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      RFC 7638 SHA-256 Thumbprint (JKT)
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.875rem',
                      color: 'var(--accent-cyan)',
                      wordBreak: 'break-all',
                      marginTop: '4px',
                      fontWeight: 600
                    }}>
                      {keyPair.jkt}
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
                        color: 'var(--text-secondary)',
                        fontSize: '0.8rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '4px 0'
                      }}
                    >
                      <Eye size={14} />
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
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  Initializing Web Crypto Key Pair...
                </div>
              )}
            </div>

            {/* Explanatory Box */}
            <div className="glass-panel" style={{ padding: '24px', backgroundColor: 'rgba(13, 18, 31, 0.4)' }}>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '8px', color: 'var(--text-primary)' }}>
                How DPoP Login Binding Works
              </h4>
              <ol style={{ paddingLeft: '18px', color: 'var(--text-secondary)', fontSize: '0.825rem', lineHeight: '1.7' }}>
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
          <div className="glass-panel" style={{ marginTop: '36px', padding: '24px' }}>
            <h3 style={{ fontSize: '1.05rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={18} color="var(--accent-emerald)" />
              Server DPoP Proof Verification Log
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {auditLog.map((step, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'rgba(8, 12, 20, 0.6)',
                    fontSize: '0.825rem',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className={`badge ${step.status === 'passed' ? 'badge-emerald' : 'badge-rose'}`} style={{ fontSize: '0.65rem' }}>
                      {step.status}
                    </span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{step.step}</span>
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.775rem' }}>
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

import React from 'react';
import Link from 'next/link';
import {
  Shield,
  Key,
  Lock,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Layers,
  FileCheck,
  Check,
  X,
  Sparkles,
} from 'lucide-react';

export default function HomePage() {
  return (
    <div className="container" style={{ paddingTop: '60px', paddingBottom: '80px' }}>
      
      {/* Hero Section */}
      <div style={{ textAlign: 'center', maxWidth: '880px', margin: '0 auto 60px auto' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '10px', marginBottom: '24px', flexWrap: 'wrap', justifyContent: 'center' }}>
          <span className="badge badge-amber" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
            <Shield size={14} strokeWidth={2.5} />
            OAuth 2.0 Security Upgrade
          </span>
          <span className="badge badge-cyan" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
            RFC 9449 Standard
          </span>
          <span className="badge badge-emerald" style={{ padding: '6px 14px', fontSize: '0.8rem' }}>
            <Sparkles size={14} strokeWidth={2.5} />
            Zero-Mock Cryptography
          </span>
        </div>

        <h1 style={{ fontSize: '3.6rem', fontWeight: 900, marginBottom: '24px', letterSpacing: '-0.04em', lineHeight: 1.1 }}>
          DEMONSTRATING <br />
          <span style={{
            backgroundColor: 'var(--neo-yellow)',
            padding: '2px 14px',
            border: '3px solid #000000',
            boxShadow: '4px 4px 0px #000000',
            display: 'inline-block',
            margin: '6px 0',
            transform: 'rotate(-1deg)'
          }}>
            PROOF-OF-POSSESSION
          </span><br />
          AT THE APPLICATION LAYER
        </h1>

        <p style={{
          color: 'var(--text-secondary)',
          fontSize: '1.25rem',
          lineHeight: '1.6',
          marginBottom: '36px',
          fontWeight: 600,
          maxWidth: '740px',
          margin: '0 auto 36px auto'
        }}>
          A complete, production-grade Next.js demonstration of sender-constrained OAuth 2.0 tokens (DPoP). 
          Protects your REST APIs and Server Actions from token exfiltration, leakage, and replay attacks.
        </p>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <Link href="/login" className="btn btn-primary" style={{ padding: '14px 30px', fontSize: '1.1rem' }}>
            Try Demo Login
            <ArrowRight size={20} strokeWidth={2.5} />
          </Link>
          <Link href="/dashboard" className="btn btn-outline" style={{ padding: '14px 30px', fontSize: '1.1rem' }}>
            <Lock size={20} strokeWidth={2.5} />
            Open DPoP Dashboard
          </Link>
        </div>
      </div>

      {/* Side-by-Side Comparison: Bearer vs DPoP */}
      <div style={{ marginBottom: '60px' }}>
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <div className="badge badge-purple" style={{ marginBottom: '10px' }}>COMPARATIVE ARCHITECTURE</div>
          <h2 style={{ fontSize: '2.2rem', fontWeight: 900 }}>The Security Difference</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '1rem', fontWeight: 600 }}>
            Why modern high-security specifications mandate sender-constrained tokens over traditional Bearer tokens.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          
          {/* Traditional Bearer Token Card */}
          <div style={{
            padding: '32px',
            border: '3.5px solid #000000',
            borderRadius: '12px',
            backgroundColor: 'var(--neo-rose-light)',
            boxShadow: '7px 7px 0px #000000',
            position: 'relative'
          }}>
            <div style={{ position: 'absolute', top: '-14px', right: '20px' }}>
              <span className="badge badge-rose" style={{ padding: '4px 12px', fontSize: '0.75rem' }}>
                DEPRECATED PATTERN
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '20px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '8px',
                backgroundColor: 'var(--neo-rose)',
                border: '2.5px solid #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '3px 3px 0px #000000',
                color: '#ffffff'
              }}>
                <ShieldAlert size={26} strokeWidth={2.5} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 900, color: '#000000' }}>
                  Traditional Bearer Tokens (RFC 6750)
                </h3>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#991b1b', textTransform: 'uppercase' }}>
                  Bearer = Possession of token equals full authorization
                </span>
              </div>
            </div>

            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '0.925rem', color: '#000000' }}>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-rose)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <X size={14} strokeWidth={3} />
                </div>
                <span><strong>Vulnerable to Exfiltration:</strong> If an attacker steals the JWT from localStorage, server logs, or compromised network proxies, they have complete access.</span>
              </li>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-rose)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <X size={14} strokeWidth={3} />
                </div>
                <span><strong>No Sender Verification:</strong> The resource server cannot confirm whether the HTTP caller is the legitimate user or an adversary replaying the token.</span>
              </li>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-rose)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <X size={14} strokeWidth={3} />
                </div>
                <span><strong>Global Replay Exploit:</strong> Any leaked token can be replayed from any device, IP, or country worldwide until expiration.</span>
              </li>
            </ul>
          </div>

          {/* DPoP Sender-Constrained Card */}
          <div style={{
            padding: '32px',
            border: '3.5px solid #000000',
            borderRadius: '12px',
            backgroundColor: 'var(--neo-emerald-light)',
            boxShadow: '7px 7px 0px #000000',
            position: 'relative'
          }}>
            <div style={{ position: 'absolute', top: '-14px', right: '20px' }}>
              <span className="badge badge-emerald" style={{ padding: '4px 12px', fontSize: '0.75rem' }}>
                RECOMMENDED BEST PRACTICE
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '20px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '8px',
                backgroundColor: 'var(--neo-emerald)',
                border: '2.5px solid #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '3px 3px 0px #000000',
                color: '#000000'
              }}>
                <ShieldCheck size={26} strokeWidth={2.5} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 900, color: '#000000' }}>
                  DPoP Sender-Constrained (RFC 9449)
                </h3>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#15803d', textTransform: 'uppercase' }}>
                  Cryptographically bound to client private key
                </span>
              </div>
            </div>

            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '0.925rem', color: '#000000' }}>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-emerald)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#000000',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <Check size={14} strokeWidth={3} />
                </div>
                <span><strong>Sender-Constrained Binding:</strong> Access token embeds <code className="code-inline">cnf.jkt</code> (SHA-256 thumbprint of client public key).</span>
              </li>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-emerald)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#000000',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <Check size={14} strokeWidth={3} />
                </div>
                <span><strong>Thwarts Token Theft:</strong> If an attacker steals the JWT, they CANNOT use it without the private key stored non-extractable in the browser.</span>
              </li>
              <li style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                backgroundColor: '#ffffff',
                padding: '12px',
                border: '2px solid #000000',
                borderRadius: '8px',
                boxShadow: '2px 2px 0px #000000'
              }}>
                <div style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--neo-emerald)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#000000',
                  fontWeight: 900,
                  flexShrink: 0,
                  border: '1.5px solid #000'
                }}>
                  <Check size={14} strokeWidth={3} />
                </div>
                <span><strong>Replay &amp; Tamper Defense:</strong> Each request requires a fresh signed proof with unique <code className="code-inline">jti</code>, method <code className="code-inline">htm</code>, and URL <code className="code-inline">htu</code>.</span>
              </li>
            </ul>
          </div>

        </div>
      </div>

      {/* Feature Grid */}
      <div style={{ marginBottom: '60px' }}>
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <div className="badge badge-cyan" style={{ marginBottom: '10px' }}>CORE ENGINE FEATURES</div>
          <h2 style={{ fontSize: '2.2rem', fontWeight: 900 }}>Included Implementation Architecture</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '1rem', fontWeight: 600 }}>
            Zero mocked logic — built using genuine cryptographic standards.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="neo-card neo-card-interactive" style={{ padding: '28px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '8px',
              backgroundColor: 'var(--neo-cyan-light)',
              border: '2px solid #000000',
              boxShadow: '3px 3px 0px #000000',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '18px'
            }}>
              <Key size={24} strokeWidth={2.5} color="#000000" />
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '10px' }}>Web Crypto ECDSA P-256</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6', fontWeight: 500 }}>
              Client browser generates asymmetric key pairs using native Web Cryptography API, calculating RFC 7638 SHA-256 thumbprints.
            </p>
          </div>

          <div className="neo-card neo-card-interactive" style={{ padding: '28px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '8px',
              backgroundColor: 'var(--neo-emerald-light)',
              border: '2px solid #000000',
              boxShadow: '3px 3px 0px #000000',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '18px'
            }}>
              <FileCheck size={24} strokeWidth={2.5} color="#000000" />
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '10px' }}>DPoP-Bound JWT Tokens</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6', fontWeight: 500 }}>
              Login API validates DPoP proof on authentication and sets an HTTP-only secure cookie with the confirmed <code className="code-inline">cnf.jkt</code> claim.
            </p>
          </div>

          <div className="neo-card neo-card-interactive" style={{ padding: '28px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '8px',
              backgroundColor: 'var(--neo-purple-light)',
              border: '2px solid #000000',
              boxShadow: '3px 3px 0px #000000',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '18px'
            }}>
              <Cpu size={24} strokeWidth={2.5} color="#000000" />
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '10px' }}>Interactive Attack Simulator</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6', fontWeight: 500 }}>
              The protected dashboard includes side-by-side test buttons: authentic DPoP proof vs simulated attacker replay attempts.
            </p>
          </div>
        </div>
      </div>

      {/* Call to Action Box */}
      <div style={{
        padding: '44px 32px',
        textAlign: 'center',
        backgroundColor: 'var(--neo-yellow)',
        border: '3.5px solid #000000',
        borderRadius: '16px',
        boxShadow: '8px 8px 0px #000000'
      }}>
        <div style={{
          width: '56px',
          height: '56px',
          borderRadius: '10px',
          backgroundColor: '#ffffff',
          border: '2.5px solid #000000',
          boxShadow: '3px 3px 0px #000000',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto 20px auto'
        }}>
          <Layers size={30} strokeWidth={2.5} color="#000000" />
        </div>
        <h2 style={{ fontSize: '2.2rem', fontWeight: 900, marginBottom: '12px', color: '#000000' }}>
          READY TO TEST THE DPoP FLOW?
        </h2>
        <p style={{ color: '#000000', maxWidth: '640px', margin: '0 auto 28px auto', fontSize: '1.05rem', fontWeight: 600 }}>
          Sign in to generate your browser key pair and acquire a DPoP-bound JWT, then test the protected dashboard endpoints with real cryptographic verification.
        </p>
        <Link href="/login" className="btn btn-secondary" style={{ padding: '14px 32px', fontSize: '1.05rem', backgroundColor: '#ffffff' }}>
          Launch Sign In Flow
          <ArrowRight size={18} strokeWidth={2.5} />
        </Link>
      </div>

    </div>
  );
}

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
} from 'lucide-react';

export default function HomePage() {
  return (
    <div className="container" style={{ paddingTop: '60px', paddingBottom: '80px' }}>
      
      {/* Hero Section */}
      <div style={{ textAlign: 'center', maxWidth: '840px', margin: '0 auto 60px auto' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <span className="badge badge-cyan" style={{ padding: '6px 14px' }}>
            <Shield size={14} />
            OAuth 2.0 Security Extension
          </span>
          <span className="badge badge-purple" style={{ padding: '6px 14px' }}>
            RFC 9449 Standard
          </span>
        </div>

        <h1 style={{ fontSize: '3.2rem', fontWeight: 800, marginBottom: '20px', letterSpacing: '-0.04em', lineHeight: 1.15 }}>
          Demonstrating <span style={{ color: 'var(--accent-cyan)' }}>Proof-of-Possession</span> at the Application Layer
        </h1>

        <p style={{ color: 'var(--text-secondary)', fontSize: '1.2rem', lineHeight: '1.6', marginBottom: '32px' }}>
          A complete, production-grade Next.js starter illustrating sender-constrained OAuth 2.0 tokens (DPoP). 
          Protects your APIs from token theft, leakage, and unauthorized replay attacks.
        </p>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <Link href="/login" className="btn btn-primary" style={{ padding: '14px 28px', fontSize: '1.05rem' }}>
            Try Demo Login
            <ArrowRight size={18} />
          </Link>
          <Link href="/dashboard" className="btn btn-outline" style={{ padding: '14px 28px', fontSize: '1.05rem' }}>
            <Lock size={18} />
            Open DPoP Dashboard
          </Link>
        </div>
      </div>

      {/* Side-by-Side Comparison: Bearer vs DPoP */}
      <div style={{ marginBottom: '60px' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 800 }}>The Security Difference</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
            Why modern high-security standards are deprecating unconstrained Bearer tokens.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Traditional Bearer Token Card */}
          <div className="glass-panel" style={{
            padding: '30px',
            border: '1px solid rgba(244, 63, 94, 0.25)',
            background: 'linear-gradient(180deg, rgba(244, 63, 94, 0.04) 0%, rgba(19, 27, 46, 0.8) 100%)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: '10px',
                backgroundColor: 'rgba(244, 63, 94, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <ShieldAlert size={22} color="var(--accent-rose)" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.2rem', color: '#fb7185' }}>Traditional Bearer Tokens (RFC 6750)</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Bearer = Possession of token equals authorization</span>
              </div>
            </div>

            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-rose)', fontWeight: 700 }}>✗</span>
                <span><strong>Vulnerable to Exfiltration:</strong> If an attacker steals the JWT from localStorage, server logs, or compromised network proxies, they have full access.</span>
              </li>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-rose)', fontWeight: 700 }}>✗</span>
                <span><strong>No Sender Proof:</strong> The resource server cannot confirm whether the HTTP caller is the legitimate user or an attacker replaying the token.</span>
              </li>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-rose)', fontWeight: 700 }}>✗</span>
                <span><strong>Token Leakage Replay:</strong> Any leaked token can be replayed from any device or IP worldwide until expiration.</span>
              </li>
            </ul>
          </div>

          {/* DPoP Sender-Constrained Card */}
          <div className="glass-panel" style={{
            padding: '30px',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            background: 'linear-gradient(180deg, rgba(16, 185, 129, 0.05) 0%, rgba(19, 27, 46, 0.8) 100%)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: '10px',
                backgroundColor: 'rgba(16, 185, 129, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <ShieldCheck size={22} color="var(--accent-emerald)" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.2rem', color: '#34d399' }}>DPoP Sender-Constrained (RFC 9449)</h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Cryptographically bound to client private key</span>
              </div>
            </div>

            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-emerald)', fontWeight: 700 }}>✓</span>
                <span><strong>Sender-Constrained Binding:</strong> Access token embeds <code className="code-inline">cnf.jkt</code> (SHA-256 thumbprint of client public key).</span>
              </li>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-emerald)', fontWeight: 700 }}>✓</span>
                <span><strong>Thwarts Token Theft:</strong> If an attacker steals the JWT, they CANNOT use it without the private key stored non-extractable in the client&apos;s browser.</span>
              </li>
              <li style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ color: 'var(--accent-emerald)', fontWeight: 700 }}>✓</span>
                <span><strong>Replay &amp; Tamper Protection:</strong> Each request carries a fresh proof with unique <code className="code-inline">jti</code>, method <code className="code-inline">htm</code>, and URI <code className="code-inline">htu</code>.</span>
              </li>
            </ul>
          </div>

        </div>
      </div>

      {/* Feature Grid */}
      <div style={{ marginBottom: '60px' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 800 }}>Included Implementation Architecture</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
            Zero mocked logic — built using genuine cryptographic standards.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="glass-panel" style={{ padding: '24px' }}>
            <Key size={24} color="var(--accent-cyan)" style={{ marginBottom: '14px' }} />
            <h3 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>Web Crypto ECDSA P-256</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Client browser generates asymmetric key pairs using native Web Cryptography API, calculating RFC 7638 SHA-256 thumbprints.
            </p>
          </div>

          <div className="glass-panel" style={{ padding: '24px' }}>
            <FileCheck size={24} color="var(--accent-emerald)" style={{ marginBottom: '14px' }} />
            <h3 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>DPoP-Bound JWT Tokens</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Login API validates DPoP proof on authentication and sets an HTTP-only secure cookie with the confirmed <code className="code-inline">cnf.jkt</code> claim.
            </p>
          </div>

          <div className="glass-panel" style={{ padding: '24px' }}>
            <Cpu size={24} color="var(--accent-purple)" style={{ marginBottom: '14px' }} />
            <h3 style={{ fontSize: '1.1rem', marginBottom: '8px' }}>Interactive Attack Simulator</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              The protected dashboard includes side-by-side buttons: hit with genuine DPoP proof vs simulated attacker replay attempts.
            </p>
          </div>
        </div>
      </div>

      {/* Call to Action Box */}
      <div className="glass-panel" style={{
        padding: '36px',
        textAlign: 'center',
        background: 'radial-gradient(ellipse 80% 50% at 50% 50%, rgba(56, 189, 248, 0.12), rgba(19, 27, 46, 0.8))',
        border: '1px solid rgba(56, 189, 248, 0.3)'
      }}>
        <Layers size={36} color="var(--accent-cyan)" style={{ margin: '0 auto 16px auto' }} />
        <h2 style={{ fontSize: '1.75rem', fontWeight: 800, marginBottom: '10px' }}>Ready to explore the DPoP flow?</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '580px', margin: '0 auto 24px auto', fontSize: '0.95rem' }}>
          Sign in to generate your browser key pair and acquire a DPoP-bound JWT, then test the protected dashboard endpoints.
        </p>
        <Link href="/login" className="btn btn-primary" style={{ padding: '12px 28px', fontSize: '1rem' }}>
          Launch Sign In Flow
          <ArrowRight size={16} />
        </Link>
      </div>

    </div>
  );
}

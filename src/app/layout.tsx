import type { Metadata } from 'next';
import './globals.css';
import Navbar from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'Next.js DPoP Demonstrator | RFC 9449 OAuth 2.0 Proof-of-Possession',
  description:
    'Production-grade demonstration of RFC 9449 DPoP (Demonstrating Proof-of-Possession) in Next.js. Features genuine cryptographic ES256 key generation, real DPoP-bound JWTs with cnf.jkt, and interactive token theft attack simulations.',
  keywords: [
    'DPoP',
    'RFC 9449',
    'OAuth 2.0',
    'Sender-Constrained Tokens',
    'Next.js',
    'Web Cryptography',
    'JWT',
    'Security',
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Navbar />
        {/* Signature Neo-Brutalist Marquee Banner */}
        <div className="neo-marquee-container" aria-hidden="true">
          <div className="neo-marquee-content">
            ⚡ RFC 9449 SENDER-CONSTRAINED TOKENS &nbsp;✦&nbsp; HARDWARE NON-EXTRACTABLE ECDSA P-256 KEYS &nbsp;✦&nbsp; REPLAY ATTACK DEFENSE &nbsp;✦&nbsp; CRYPTOGRAPHIC BINDING CNF.JKT &nbsp;✦&nbsp; ZERO BEARER EXPLOITATION &nbsp;✦&nbsp; NEXT.JS APP ROUTER ENGINE &nbsp;✦&nbsp; 
          </div>
          <div className="neo-marquee-content">
            ⚡ RFC 9449 SENDER-CONSTRAINED TOKENS &nbsp;✦&nbsp; HARDWARE NON-EXTRACTABLE ECDSA P-256 KEYS &nbsp;✦&nbsp; REPLAY ATTACK DEFENSE &nbsp;✦&nbsp; CRYPTOGRAPHIC BINDING CNF.JKT &nbsp;✦&nbsp; ZERO BEARER EXPLOITATION &nbsp;✦&nbsp; NEXT.JS APP ROUTER ENGINE &nbsp;✦&nbsp; 
          </div>
        </div>

        <main>{children}</main>

        <footer style={{
          marginTop: '80px',
          borderTop: '3px solid #000000',
          padding: '40px 0',
          backgroundColor: '#ffffff',
          color: '#000000',
          fontSize: '0.9rem',
          boxShadow: '0 -4px 0px rgba(0, 0, 0, 0.04)'
        }}>
          <div className="container flex flex-col md:flex-row items-center justify-between gap-4" style={{ textAlign: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', justifyContent: 'center' }}>
              <span className="badge badge-amber" style={{ fontSize: '0.75rem' }}>RFC 9449</span>
              <span style={{ fontWeight: 800 }}>DPoP Engine for Next.js App Router</span>
              <span style={{ color: 'var(--text-muted)' }}>· Hardware-bound Proofs</span>
            </div>
            <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap', justifyContent: 'center' }}>
              <a
                href="https://datatracker.ietf.org/doc/html/rfc9449"
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
                style={{ padding: '6px 12px', fontSize: '0.8rem', textDecoration: 'none' }}
              >
                IETF RFC 9449 Spec ↗
              </a>
              <a
                href="https://datatracker.ietf.org/doc/html/rfc7638"
                target="_blank"
                rel="noreferrer"
                className="btn btn-outline"
                style={{ padding: '6px 12px', fontSize: '0.8rem', textDecoration: 'none' }}
              >
                RFC 7638 Thumbprints ↗
              </a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

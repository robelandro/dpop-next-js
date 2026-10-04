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
        <main>{children}</main>
        <footer style={{
          marginTop: '80px',
          borderTop: '1px solid var(--border-subtle)',
          padding: '40px 0',
          backgroundColor: 'rgba(7, 9, 14, 0.95)',
          color: 'var(--text-muted)',
          fontSize: '0.85rem'
        }}>
          <div className="container flex flex-col md:flex-row items-center justify-between gap-4" style={{ textAlign: 'center' }}>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>RFC 9449 DPoP Engine</span> · Built for Next.js App Router
            </div>
            <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
              <a href="https://datatracker.ietf.org/doc/html/rfc9449" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-cyan)' }}>
                IETF RFC 9449 Spec ↗
              </a>
              <a href="https://datatracker.ietf.org/doc/html/rfc7638" target="_blank" rel="noreferrer" style={{ color: 'var(--text-secondary)' }}>
                RFC 7638 (JWK Thumbprints) ↗
              </a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

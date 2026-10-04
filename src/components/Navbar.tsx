'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Shield, Key, Lock, LogOut, CheckCircle2 } from 'lucide-react';
import { getClientKeyPair, generateNewClientKeyPair } from '@/lib/client/dpop';
import type { ClientKeyPairExport } from '@/lib/types';

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [keyPair, setKeyPair] = useState<ClientKeyPairExport | null>(null);
  const [isCopied, setIsCopied] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const loadKeys = async () => {
    try {
      const keys = await getClientKeyPair();
      setKeyPair(keys);
    } catch (e) {
      console.error('Failed to load keys', e);
    }
  };

  const checkAuth = async () => {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      setIsLoggedIn(data.authenticated === true);
    } catch {
      setIsLoggedIn(false);
    }
  };

  useEffect(() => {
    loadKeys();
    checkAuth();
  }, [pathname]);

  const handleRegenerateKeys = async () => {
    if (confirm('Regenerate client ES256 key pair? This will change your browser thumbprint (jkt). Any previous token bound to your old key will be rejected until you re-login.')) {
      const newKeys = await generateNewClientKeyPair();
      setKeyPair(newKeys);
      window.dispatchEvent(new CustomEvent('dpop_key_regenerated', { detail: newKeys }));
    }
  };

  const handleCopyJkt = () => {
    if (keyPair?.jkt) {
      navigator.clipboard.writeText(keyPair.jkt);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setIsLoggedIn(false);
      router.push('/login');
    } catch (e) {
      console.error('Logout error', e);
    }
  };

  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      backgroundColor: 'rgba(7, 9, 14, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '12px 0'
    }}>
      <div className="container flex items-center justify-between" style={{ flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Logo and Brand */}
        <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '12px', textDecoration: 'none' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.4)'
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontWeight: 800, fontSize: '1.15rem', color: '#f8fafc', letterSpacing: '-0.02em' }}>
                Next.js <span style={{ color: 'var(--accent-cyan)' }}>DPoP</span>
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.65rem' }}>RFC 9449</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Demonstrating Proof-of-Possession
            </div>
          </div>
        </Link>

        {/* Client Key & Thumbprint Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          background: 'rgba(19, 27, 46, 0.7)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-full)',
          border: '1px solid var(--border-subtle)',
          fontSize: '0.8rem'
        }}>
          <Key size={14} color="var(--accent-cyan)" />
          <span style={{ color: 'var(--text-secondary)' }}>Client JKT:</span>
          {keyPair ? (
            <span
              onClick={handleCopyJkt}
              title="Click to copy client thumbprint"
              style={{
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent-cyan)',
                cursor: 'pointer',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px'
              }}
            >
              {keyPair.jkt.slice(0, 8)}...{keyPair.jkt.slice(-6)}
              {isCopied ? <CheckCircle2 size={12} color="var(--accent-emerald)" /> : null}
            </span>
          ) : (
            <span style={{ color: 'var(--text-muted)' }}>Generating...</span>
          )}
          <button
            onClick={handleRegenerateKeys}
            title="Rotate Client Key Pair"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              fontSize: '0.72rem',
              padding: '2px 6px',
              borderRadius: '4px'
            }}
          >
            ↻ Rotate
          </button>
        </div>

        {/* Navigation Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Link
            href="/"
            className={`btn ${pathname === '/' ? 'btn-secondary' : 'btn-outline'}`}
            style={{ padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Overview
          </Link>

          <Link
            href="/dashboard"
            className={`btn ${pathname === '/dashboard' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '6px 14px', fontSize: '0.85rem' }}
          >
            <Lock size={14} />
            Dashboard
          </Link>

          {isLoggedIn ? (
            <button
              onClick={handleLogout}
              className="btn btn-outline"
              style={{ padding: '6px 14px', fontSize: '0.85rem', color: 'var(--accent-rose)' }}
            >
              <LogOut size={14} />
              Logout
            </button>
          ) : (
            <Link
              href="/login"
              className={`btn ${pathname === '/login' ? 'btn-primary' : 'btn-outline'}`}
              style={{ padding: '6px 14px', fontSize: '0.85rem' }}
            >
              Sign In
            </Link>
          )}
        </div>

      </div>
    </header>
  );
}

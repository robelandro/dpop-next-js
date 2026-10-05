'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Shield, Key, Lock, LogOut, CheckCircle2, RotateCcw } from 'lucide-react';
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
      borderBottom: '3px solid #000000',
      backgroundColor: '#ffffff',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '12px 0',
      boxShadow: '0 4px 0px rgba(0, 0, 0, 0.08)'
    }}>
      <div className="container flex items-center justify-between" style={{ flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Logo and Brand */}
        <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '12px', textDecoration: 'none' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '8px',
            background: 'var(--neo-yellow)',
            border: '2.5px solid #000000',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '3px 3px 0px #000000',
            color: '#000000'
          }}>
            <Shield size={24} strokeWidth={2.5} color="#000000" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontWeight: 900, fontSize: '1.25rem', color: '#000000', letterSpacing: '-0.03em' }}>
                NEXT.JS <span style={{ backgroundColor: 'var(--neo-yellow)', padding: '0 6px', border: '1.5px solid #000' }}>DPoP</span>
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.65rem', padding: '2px 6px' }}>RFC 9449</span>
            </div>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Proof-of-Possession Engine
            </div>
          </div>
        </Link>

        {/* Client Key & Thumbprint Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          background: '#ffffff',
          padding: '6px 14px',
          borderRadius: '8px',
          border: '2px solid #000000',
          boxShadow: '2.5px 2.5px 0px #000000',
          fontSize: '0.8rem',
          fontWeight: 700
        }}>
          <Key size={16} strokeWidth={2.5} color="#000000" />
          <span style={{ color: 'var(--text-muted)' }}>CLIENT JKT:</span>
          {keyPair ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                onClick={handleCopyJkt}
                title="Click to copy client thumbprint"
                style={{
                  fontFamily: 'var(--font-mono)',
                  color: '#000000',
                  backgroundColor: 'var(--neo-cyan-light)',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  border: '1px solid #000000',
                  cursor: 'pointer',
                  fontWeight: 800,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                {keyPair.jkt.slice(0, 8)}...{keyPair.jkt.slice(-6)}
                {isCopied ? <CheckCircle2 size={12} color="#15803d" /> : null}
              </span>
              <span className="badge badge-emerald" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                Hardware/IDB Bound
              </span>
            </div>
          ) : (
            <span style={{ color: 'var(--text-muted)' }}>Generating...</span>
          )}
          <button
            onClick={handleRegenerateKeys}
            title="Rotate Client Key Pair"
            style={{
              background: '#ffffff',
              border: '1.5px solid #000000',
              color: '#000000',
              cursor: 'pointer',
              fontSize: '0.72rem',
              fontWeight: 800,
              padding: '2px 6px',
              borderRadius: '4px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '4px',
              boxShadow: '1.5px 1.5px 0px #000000'
            }}
          >
            <RotateCcw size={11} strokeWidth={2.5} /> Rotate
          </button>
        </div>

        {/* Navigation Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Link
            href="/"
            className={`btn ${pathname === '/' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '6px 14px', fontSize: '0.825rem' }}
          >
            Overview
          </Link>

          <Link
            href="/dashboard"
            className={`btn ${pathname === '/dashboard' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '6px 14px', fontSize: '0.825rem' }}
          >
            <Lock size={14} strokeWidth={2.5} />
            Dashboard
          </Link>

          {isLoggedIn ? (
            <button
              onClick={handleLogout}
              className="btn btn-danger"
              style={{ padding: '6px 14px', fontSize: '0.825rem' }}
            >
              <LogOut size={14} strokeWidth={2.5} />
              Logout
            </button>
          ) : (
            <Link
              href="/login"
              className={`btn ${pathname === '/login' ? 'btn-primary' : 'btn-outline'}`}
              style={{ padding: '6px 14px', fontSize: '0.825rem' }}
            >
              Sign In
            </Link>
          )}
        </div>

      </div>
    </header>
  );
}

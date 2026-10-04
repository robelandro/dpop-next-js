'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Copy,
  Terminal,
  Zap,
  Info,
} from 'lucide-react';
import {
  getClientKeyPair,
  createClientDPoPProof,
  generateAttackerKeyPair,
  testExportPrivateKey,
} from '@/lib/client/dpop';
import { executeSecureEnclaveAction } from '@/app/actions';
import type {
  ClientKeyPairExport,
  DashboardData,
  VerificationAuditStep,
} from '@/lib/types';

type AttackMode = 'no_dpop' | 'attacker_key' | 'replayed_jti';

export default function DashboardPage() {
  const [keyPair, setKeyPair] = useState<ClientKeyPairExport | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [tokenPayload, setTokenPayload] = useState<Record<string, unknown> | null>(null);
  const [user, setUser] = useState<{ id: string; username: string; role: string; name: string } | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  // Request & Execution States
  const [channel, setChannel] = useState<'api' | 'action'>('api');
  const [executing, setExecuting] = useState(false);
  const [lastAction, setLastAction] = useState<'legitimate' | 'attack' | null>(null);
  const [attackMode, setAttackMode] = useState<AttackMode>('attacker_key');
  
  // Results
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [errorResponse, setErrorResponse] = useState<{
    code: string;
    message: string;
    tokenJkt?: string;
    proofJkt?: string;
  } | null>(null);
  const [auditLog, setAuditLog] = useState<VerificationAuditStep[]>([]);
  const [lastDPoPProof, setLastDPoPProof] = useState<string | null>(null);
  const [lastDPoPDecoded, setLastDPoPDecoded] = useState<{ header: unknown; payload: unknown } | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // Helper to decode JWT parts without external deps
  const decodeJwtUnsafe = (jwtStr: string) => {
    try {
      const parts = jwtStr.split('.');
      if (parts.length !== 3) return null;
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      return { header, payload };
    } catch {
      return null;
    }
  };

  // Check current session from /api/auth/me or sessionStorage
  const fetchSession = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      if (data.authenticated && data.fullToken) {
        setToken(data.fullToken);
        setUser(data.user);
        const decoded = decodeJwtUnsafe(data.fullToken);
        if (decoded) setTokenPayload(decoded.payload);
      } else {
        const storedToken = sessionStorage.getItem('dpop_demo_token');
        if (storedToken) {
          setToken(storedToken);
          const decoded = decodeJwtUnsafe(storedToken);
          if (decoded) setTokenPayload(decoded.payload);
          const storedUser = sessionStorage.getItem('dpop_demo_user');
          if (storedUser) setUser(JSON.parse(storedUser));
        }
      }
    } catch (e) {
      console.error('Session check error', e);
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    getClientKeyPair().then(setKeyPair);
    fetchSession();
  }, [fetchSession]);

  // BUTTON 1: Real JWT + Genuine Client DPoP Proof (SUCCESS)
  const handleLegitimateRequest = async () => {
    setExecuting(true);
    setLastAction('legitimate');
    setErrorResponse(null);
    setDashboardData(null);
    setAuditLog([]);

    try {
      const activeKeys = keyPair || (await getClientKeyPair());
      const currentToken = token || sessionStorage.getItem('dpop_demo_token') || '';

      if (channel === 'action') {
        // NEXT.JS SERVER ACTION EXECUTION
        const proofUrl = `${window.location.origin}/dashboard`;
        const proof = await createClientDPoPProof({
          method: 'POST', // Server Actions use POST
          url: proofUrl,
          accessToken: currentToken || undefined,
          keyPair: activeKeys,
        });

        setLastDPoPProof(proof);
        setLastDPoPDecoded(decodeJwtUnsafe(proof));

        const actionResult = await executeSecureEnclaveAction({
          dpopProof: proof,
          accessTokenOverride: currentToken,
          operation: 'Rotate Quantum Enclave Keys',
        });

        if (actionResult.success) {
          setDashboardData({
            systemStatus: 'SECURE_SERVER_ACTION_VERIFIED',
            metrics: {
              threatsPrevented: 143,
              dpopTokensActive: 1,
              replayAttacksBlocked: 40,
              securityScore: 100,
            },
            confidentialData: {
              vaultId: actionResult.data?.vaultId || 'VLT-ACTION-ALPHA',
              masterEnclaveKey: actionResult.data?.masterEnclaveKey || 'ENCLAVE-ACTION::VERIFIED',
              accessLevel: 'SERVER-ACTION::PROOF-OF-POSSESSION-VERIFIED',
              auditLogId: actionResult.data?.auditLogId || 'ACTION-AUDIT',
              timestamp: actionResult.timestamp || new Date().toISOString(),
            },
            user: {
              id: user?.id || 'usr_42',
              username: user?.username || 'alice',
              name: user?.name || 'Alice Vance',
              role: user?.role || 'Security Engineer',
            },
            tokenBinding: {
              tokenJkt: actionResult.tokenJkt || '',
              proofJkt: actionResult.proofJkt || '',
              matched: true,
              authMethod: 'Server Action (Next.js RPC)',
            },
            auditTrail: actionResult.auditTrail,
          });
          setAuditLog(actionResult.auditTrail);
        } else {
          setErrorResponse({
            code: actionResult.code || 'action_failed',
            message: actionResult.message || 'Server Action verification failed.',
            tokenJkt: actionResult.tokenJkt,
            proofJkt: actionResult.proofJkt,
          });
          setAuditLog(actionResult.auditTrail);
        }
      } else {
        // REST API ROUTE HANDLER (/api/dashboard)
        const proofUrl = `${window.location.origin}/api/dashboard`;
        const proof = await createClientDPoPProof({
          method: 'GET',
          url: proofUrl,
          accessToken: currentToken || undefined,
          keyPair: activeKeys,
        });

        setLastDPoPProof(proof);
        setLastDPoPDecoded(decodeJwtUnsafe(proof));

        const headers: Record<string, string> = {
          DPoP: proof,
        };

        if (currentToken) {
          headers['Authorization'] = `DPoP ${currentToken}`;
        }

        const res = await fetch('/api/dashboard', {
          method: 'GET',
          headers,
        });

        const json = await res.json();

        if (res.ok && json.success) {
          setDashboardData(json.data);
          setAuditLog(json.data.auditTrail || []);
        } else {
          setErrorResponse({
            code: json.error || 'request_failed',
            message: json.message || 'Verification failed unexpectedly.',
            tokenJkt: json.tokenJkt,
            proofJkt: json.proofJkt,
          });
          setAuditLog(json.auditTrail || []);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error during request';
      setErrorResponse({
        code: 'client_network_error',
        message: msg,
      });
    } finally {
      setExecuting(false);
    }
  };

  // BUTTON 2: Stolen Token Attack Simulation (FAIL / THWARTED)
  const handleAttackRequest = async () => {
    setExecuting(true);
    setLastAction('attack');
    setErrorResponse(null);
    setDashboardData(null);
    setAuditLog([]);

    try {
      const currentToken = token || sessionStorage.getItem('dpop_demo_token') || '';
      const targetEndpoint = channel === 'action' ? '/dashboard' : '/api/dashboard';
      const proofUrl = `${window.location.origin}${targetEndpoint}`;
      const method = channel === 'action' ? 'POST' : 'GET';

      let attackerProof: string | undefined = undefined;

      if (attackMode === 'no_dpop') {
        // Vector B: Stolen token without DPoP proof
        attackerProof = undefined;
        setLastDPoPProof(null);
        setLastDPoPDecoded(null);
      } else if (attackMode === 'attacker_key') {
        // Vector A: Attacker signs proof using attacker's own key pair
        const attackerKeys = await generateAttackerKeyPair();
        attackerProof = await createClientDPoPProof({
          method,
          url: proofUrl,
          accessToken: currentToken || undefined,
          keyPair: attackerKeys,
        });
        setLastDPoPProof(attackerProof);
        setLastDPoPDecoded(decodeJwtUnsafe(attackerProof));
      } else if (attackMode === 'replayed_jti') {
        // Vector C: Stale / replayed proof
        const activeKeys = keyPair || (await getClientKeyPair());
        attackerProof = await createClientDPoPProof({
          method,
          url: proofUrl,
          accessToken: currentToken || undefined,
          keyPair: activeKeys,
          overridePayload: {
            jti: 'replayed-static-jti-victim-nonce-12345',
            iat: Math.floor(Date.now() / 1000) - 300,
          },
        });
        setLastDPoPProof(attackerProof);
        setLastDPoPDecoded(decodeJwtUnsafe(attackerProof));
      }

      if (channel === 'action') {
        // EXECUTE SERVER ACTION ATTACK
        const actionResult = await executeSecureEnclaveAction({
          dpopProof: attackerProof,
          accessTokenOverride: currentToken,
          operation: 'Unauthorized Enclave Data Exfiltration',
        });

        if (!actionResult.success) {
          setErrorResponse({
            code: actionResult.code || 'attack_thwarted',
            message: actionResult.message || 'Server Action blocked exploit.',
            tokenJkt: actionResult.tokenJkt,
            proofJkt: actionResult.proofJkt,
          });
          setAuditLog(actionResult.auditTrail || []);
        } else {
          setDashboardData(null);
          setAuditLog(actionResult.auditTrail || []);
        }
      } else {
        // EXECUTE REST API ATTACK
        const headers: Record<string, string> = {};
        if (currentToken) {
          headers['Authorization'] = `DPoP ${currentToken}`;
        }
        if (attackerProof) {
          headers['DPoP'] = attackerProof;
        }

        const res = await fetch('/api/dashboard', {
          method: 'GET',
          headers,
        });

        const json = await res.json();

        if (!res.ok || !json.success) {
          setErrorResponse({
            code: json.error || 'attack_thwarted',
            message: json.message || 'Attack blocked by DPoP enforcement.',
            tokenJkt: json.tokenJkt,
            proofJkt: json.proofJkt,
          });
          setAuditLog(json.auditTrail || []);
        } else {
          setDashboardData(json.data);
          setAuditLog(json.data.auditTrail || []);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error during simulated attack';
      setErrorResponse({
        code: 'client_network_error',
        message: msg,
      });
    } finally {
      setExecuting(false);
    }
  };

  const copyTokenToClipboard = () => {
    if (token) {
      navigator.clipboard.writeText(token);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  if (!authChecked) {
    return (
      <div className="container" style={{ padding: '80px 20px', textAlign: 'center' }}>
        <RefreshCw size={28} className="animate-spin" color="var(--accent-cyan)" />
        <p style={{ marginTop: '16px', color: 'var(--text-secondary)' }}>Verifying session and DPoP keys...</p>
      </div>
    );
  }

  const tokenJkt = (tokenPayload?.cnf as { jkt?: string })?.jkt || null;
  const isKeyMatched = keyPair?.jkt && tokenJkt && keyPair.jkt === tokenJkt;

  return (
    <div className="container" style={{ paddingTop: '32px', paddingBottom: '80px' }}>
      
      {/* Page Title & Status Header */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <span className="badge badge-cyan">Protected Enclave</span>
              <span className="badge badge-purple">RFC 9449 Enforcement</span>
            </div>
            <h1 style={{ fontSize: '2.2rem', fontWeight: 800, letterSpacing: '-0.03em' }}>
              DPoP Protected Dashboard
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
              This resource endpoint (<code className="code-inline">GET /api/dashboard</code>) strictly demands 
              a cryptographically verified DPoP proof matching the access token&apos;s sender constraint.
            </p>
          </div>

          {/* User profile / session pill */}
          {user ? (
            <div className="glass-panel" style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '0.9rem'
              }}>
                {user.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{user.name}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>{user.role}</div>
              </div>
            </div>
          ) : (
            <Link href="/login" className="btn btn-primary" style={{ padding: '10px 18px' }}>
              Login to Obtain DPoP Token
            </Link>
          )}
        </div>
      </div>

      {/* Cryptographic Binding Visualizer Bar */}
      <div className="glass-panel" style={{ padding: '20px 24px', marginBottom: '28px', backgroundColor: 'rgba(13, 18, 31, 0.65)' }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          
          {/* Client Private/Public Key Status */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              1. Browser Private Key (Possession)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <Key size={16} color="var(--accent-cyan)" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                {keyPair?.jkt ? `${keyPair.jkt.slice(0, 10)}...${keyPair.jkt.slice(-6)}` : 'No key generated'}
              </span>
              <span className="badge badge-emerald" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                IndexedDB (Non-Extractable)
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                ES256 (extractable: false)
              </span>
              <button
                type="button"
                onClick={async () => {
                  const res = await testExportPrivateKey(keyPair?.privateKey);
                  alert(res.message);
                }}
                className="btn btn-outline"
                style={{ padding: '2px 6px', fontSize: '0.7rem' }}
                title="Verify that browser blocks exportKey()"
              >
                Test exportKey()
              </button>
            </div>
          </div>

          {/* Access Token Confirmation Claim (cnf.jkt) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              2. Token Confirmation Claim (cnf.jkt)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={16} color={tokenJkt ? 'var(--accent-purple)' : 'var(--accent-rose)'} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: tokenJkt ? '#a5b4fc' : '#fb7185', fontWeight: 600 }}>
                {tokenJkt ? `${tokenJkt.slice(0, 10)}...${tokenJkt.slice(-6)}` : 'No DPoP Token in Session'}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Source: {token ? 'HTTP Cookie / JWT' : 'Not Authenticated'}
            </div>
          </div>

          {/* Cryptographic Matching Status */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              3. Sender-Constrained Binding
            </div>
            <div>
              {isKeyMatched ? (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--accent-emerald)', fontWeight: 700, fontSize: '0.875rem' }}>
                  <CheckCircle2 size={16} />
                  <span>PERFECT BINDING MATCH</span>
                </div>
              ) : (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--accent-amber)', fontWeight: 700, fontSize: '0.875rem' }}>
                  <AlertTriangle size={16} />
                  <span>{token ? 'KEY MISMATCH / UNBOUND' : 'LOGIN REQUIRED'}</span>
                </div>
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {isKeyMatched
                ? 'Your browser holds the exact private key bound to this token'
                : 'Login to bind your current browser key'}
            </div>
          </div>

        </div>
      </div>

      <div style={{ marginBottom: '36px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 800 }}>
              Interactive DPoP Verification Testing
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Test legitimate sender-constrained access versus simulated token theft attacks side-by-side.
            </p>
          </div>

          {/* Invocation Channel Toggle: REST API vs Server Action */}
          <div style={{
            display: 'inline-flex',
            padding: '4px',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'rgba(8, 12, 20, 0.8)',
            border: '1px solid var(--border-subtle)',
            gap: '4px'
          }}>
            <button
              type="button"
              onClick={() => setChannel('api')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontSize: '0.825rem',
                fontWeight: 600,
                transition: 'all 0.2s ease',
                backgroundColor: channel === 'api' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                color: channel === 'api' ? 'var(--accent-cyan)' : 'var(--text-muted)',
              }}
            >
              🌐 REST API Route (/api/dashboard)
            </button>
            <button
              type="button"
              onClick={() => setChannel('action')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontSize: '0.825rem',
                fontWeight: 600,
                transition: 'all 0.2s ease',
                backgroundColor: channel === 'action' ? 'rgba(129, 140, 248, 0.25)' : 'transparent',
                color: channel === 'action' ? '#a5b4fc' : 'var(--text-muted)',
              }}
            >
              ⚡ Next.js Server Action (actions/dashboard.ts)
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* BUTTON 1 CARD: LEGITIMATE CLIENT */}
          <div
            className="glass-panel glass-card-interactive"
            style={{
              padding: '28px',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              background: 'radial-gradient(ellipse 100% 80% at 50% 0%, rgba(16, 185, 129, 0.1), rgba(19, 27, 46, 0.85))'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(16, 185, 129, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <ShieldCheck size={20} color="var(--accent-emerald)" />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#34d399' }}>
                    1. Authorized DPoP Request
                  </h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Genuine Client + Matching Private Key
                  </span>
                </div>
              </div>
              <span className="badge badge-emerald">Expected: 200 OK</span>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '20px', lineHeight: '1.6' }}>
              Signs a real-time DPoP proof with your browser&apos;s private key, hashes the access token into <code className="code-inline">ath</code>, 
              and submits to <code className="code-inline">/api/dashboard</code>. The server validates that <code className="code-inline">jkt == cnf.jkt</code>.
            </p>

            <button
              onClick={handleLegitimateRequest}
              disabled={executing || !token}
              className="btn btn-emerald"
              style={{ width: '100%', padding: '14px', fontSize: '0.95rem' }}
            >
              {executing && lastAction === 'legitimate' ? (
                <>
                  <RefreshCw size={18} className="animate-spin" />
                  Cryptographic Verification in Progress...
                </>
              ) : (
                <>
                  <Zap size={18} />
                  Hit Dashboard (Legitimate DPoP Proof)
                </>
              )}
            </button>

            {!token && (
              <div style={{ marginTop: '10px', fontSize: '0.775rem', color: 'var(--accent-amber)', textAlign: 'center' }}>
                Please <Link href="/login" style={{ textDecoration: 'underline' }}>Sign In</Link> first to obtain a valid DPoP-bound JWT.
              </div>
            )}
          </div>

          {/* BUTTON 2 CARD: ATTACKER REPLAY SIMULATOR */}
          <div
            className="glass-panel glass-card-interactive"
            style={{
              padding: '28px',
              border: '1px solid rgba(244, 63, 94, 0.35)',
              background: 'radial-gradient(ellipse 100% 80% at 50% 0%, rgba(244, 63, 94, 0.1), rgba(19, 27, 46, 0.85))'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(244, 63, 94, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <ShieldAlert size={20} color="var(--accent-rose)" />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#fb7185' }}>
                    2. Stolen Token Attack Simulator
                  </h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Adversary Replaying Stolen JWT
                  </span>
                </div>
              </div>
              <span className="badge badge-rose">Expected: 401 Blocked</span>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '14px', lineHeight: '1.6' }}>
              Simulates an adversary who sniffed or stolen the user&apos;s real JWT. Choose the adversary&apos;s exploit vector:
            </p>

            {/* Attack Vector Selectors */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '18px' }}>
              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '0.8rem',
                cursor: 'pointer',
                padding: '6px 10px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'attacker_key' ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
                border: '1px solid ' + (attackMode === 'attacker_key' ? 'rgba(244, 63, 94, 0.4)' : 'transparent')
              }}>
                <input
                  type="radio"
                  name="attack_mode"
                  checked={attackMode === 'attacker_key'}
                  onChange={() => setAttackMode('attacker_key')}
                />
                <span><strong>Vector A:</strong> Attacker signs proof using Attacker&apos;s Key (Thumbprint Mismatch)</span>
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '0.8rem',
                cursor: 'pointer',
                padding: '6px 10px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'no_dpop' ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
                border: '1px solid ' + (attackMode === 'no_dpop' ? 'rgba(244, 63, 94, 0.4)' : 'transparent')
              }}>
                <input
                  type="radio"
                  name="attack_mode"
                  checked={attackMode === 'no_dpop'}
                  onChange={() => setAttackMode('no_dpop')}
                />
                <span><strong>Vector B:</strong> Classic Bearer Replay (Stolen Token without DPoP Proof)</span>
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '0.8rem',
                cursor: 'pointer',
                padding: '6px 10px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'replayed_jti' ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
                border: '1px solid ' + (attackMode === 'replayed_jti' ? 'rgba(244, 63, 94, 0.4)' : 'transparent')
              }}>
                <input
                  type="radio"
                  name="attack_mode"
                  checked={attackMode === 'replayed_jti'}
                  onChange={() => setAttackMode('replayed_jti')}
                />
                <span><strong>Vector C:</strong> Stale / Replayed Proof Replay Attack</span>
              </label>
            </div>

            <button
              onClick={handleAttackRequest}
              disabled={executing || !token}
              className="btn btn-danger"
              style={{ width: '100%', padding: '14px', fontSize: '0.95rem' }}
            >
              {executing && lastAction === 'attack' ? (
                <>
                  <RefreshCw size={18} className="animate-spin" />
                  Testing Attack Defense...
                </>
              ) : (
                <>
                  <ShieldAlert size={18} />
                  Hit with Fake / Stolen Token (Simulate Exploit)
                </>
              )}
            </button>
          </div>

        </div>
      </div>

      {/* ========================================================================= */}
      {/* LIVE EXECUTION RESULTS DISPLAY                                            */}
      {/* ========================================================================= */}
      {dashboardData && (
        <div className="glass-panel" style={{
          padding: '30px',
          marginBottom: '32px',
          border: '1px solid rgba(16, 185, 129, 0.5)',
          boxShadow: 'var(--shadow-glow-emerald)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '12px',
                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Unlock size={24} color="var(--accent-emerald)" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.3rem', color: '#34d399', fontWeight: 800 }}>
                  200 OK — DPoP Proof Verified: Access Granted
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                  The server verified that you possess the private key corresponding to <code className="code-inline">{dashboardData.tokenBinding.tokenJkt}</code>.
                </p>
              </div>
            </div>
            <span className="badge badge-emerald" style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
              SECURE ENCLAVE UNLOCKED
            </span>
          </div>

          {/* Confidential Vault Data Unlocked */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4" style={{ marginBottom: '24px' }}>
            <div style={{ backgroundColor: 'rgba(8, 12, 20, 0.7)', padding: '16px', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Enclave Status</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '4px' }}>
                {dashboardData.systemStatus}
              </div>
            </div>

            <div style={{ backgroundColor: 'rgba(8, 12, 20, 0.7)', padding: '16px', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Vault Identifier</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                {dashboardData.confidentialData.vaultId}
              </div>
            </div>

            <div style={{ backgroundColor: 'rgba(8, 12, 20, 0.7)', padding: '16px', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Restricted Master Key</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc', marginTop: '6px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                {dashboardData.confidentialData.masterEnclaveKey}
              </div>
            </div>

            <div style={{ backgroundColor: 'rgba(8, 12, 20, 0.7)', padding: '16px', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Replay Defenses Active</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-purple)', marginTop: '4px' }}>
                {dashboardData.metrics.replayAttacksBlocked} Blocked / 100% Score
              </div>
            </div>
          </div>
        </div>
      )}

      {errorResponse && (
        <div className="glass-panel" style={{
          padding: '30px',
          marginBottom: '32px',
          border: '1px solid rgba(244, 63, 94, 0.5)',
          boxShadow: 'var(--shadow-glow-rose)'
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{
                width: '44px',
                height: '44px',
                borderRadius: '12px',
                backgroundColor: 'rgba(244, 63, 94, 0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <XCircle size={26} color="var(--accent-rose)" />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h3 style={{ fontSize: '1.3rem', color: '#fb7185', fontWeight: 800 }}>
                    401 Unauthorized — Attack Thwarted by DPoP
                  </h3>
                  <span className="badge badge-rose">{errorResponse.code}</span>
                </div>
                <p style={{ color: '#fda4af', fontSize: '0.95rem', marginTop: '4px', fontWeight: 500 }}>
                  {errorResponse.message}
                </p>
              </div>
            </div>
          </div>

          {/* Cryptographic Thumbprint Mismatch Box */}
          {errorResponse.tokenJkt && errorResponse.proofJkt && errorResponse.proofJkt !== 'none' && (
            <div style={{
              backgroundColor: 'rgba(8, 12, 20, 0.85)',
              padding: '18px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              marginBottom: '18px'
            }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-rose)', marginBottom: '8px' }}>
                PROOF-OF-POSSESSION DISCREPANCY ANALYSIS:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.825rem' }}>
                <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.03)', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>ACCESS TOKEN SENDER BINDING (cnf.jkt):</div>
                  <div style={{ color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: '4px' }}>
                    {errorResponse.tokenJkt}
                  </div>
                </div>
                <div style={{ backgroundColor: 'rgba(244, 63, 94, 0.1)', padding: '10px', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--accent-rose)', fontSize: '0.7rem' }}>ATTACKER DPOP PROOF KEY (jkt):</div>
                  <div style={{ color: '#fb7185', wordBreak: 'break-all', marginTop: '4px' }}>
                    {errorResponse.proofJkt}
                  </div>
                </div>
              </div>
              <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', marginTop: '10px' }}>
                💡 <strong>Why this stopped the attack:</strong> Even though the attacker had the victim&apos;s real access token, 
                they did not possess the victim&apos;s private key. The server detected that the DPoP signature key thumbprint did not 
                match the <code className="code-inline">cnf.jkt</code> stamped inside the JWT!
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* AUDIT TRAIL CHECKLIST                                                     */}
      {/* ========================================================================= */}
      {auditLog.length > 0 && (
        <div className="glass-panel" style={{ padding: '24px', marginBottom: '32px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={18} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>
                Server Cryptographic Verification Audit Trail (RFC 9449)
              </h3>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {auditLog.length} Security Assertions Evaluated
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {auditLog.map((step, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: step.status === 'passed' ? 'rgba(8, 12, 20, 0.7)' : 'rgba(244, 63, 94, 0.1)',
                  border: '1px solid ' + (step.status === 'passed' ? 'var(--border-subtle)' : 'rgba(244, 63, 94, 0.3)'),
                  fontSize: '0.85rem',
                  gap: '14px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {step.status === 'passed' ? (
                    <CheckCircle2 size={16} color="var(--accent-emerald)" />
                  ) : (
                    <XCircle size={16} color="var(--accent-rose)" />
                  )}
                  <span style={{ fontWeight: 600, color: step.status === 'passed' ? 'var(--text-primary)' : '#fb7185' }}>
                    {step.step}
                  </span>
                </div>
                <div style={{ color: step.status === 'passed' ? 'var(--text-muted)' : '#fda4af', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                  {step.details}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TECHNICAL INSPECTOR (JWT & DPOP PROOF)                                     */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Token Card */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lock size={16} color="var(--accent-cyan)" />
              <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Access Token (Server Signed JWT)</h4>
            </div>
            {token && (
              <button
                onClick={copyTokenToClipboard}
                className="btn btn-outline"
                style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              >
                <Copy size={12} />
                {copiedToken ? 'Copied' : 'Copy'}
              </button>
            )}
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '12px' }}>
            Issued by Authorization Server with sender-constraining claim <code className="code-inline">cnf.jkt</code>:
          </p>

          {tokenPayload ? (
            <pre className="code-container" style={{ maxHeight: '240px' }}>
              {JSON.stringify(tokenPayload, null, 2)}
            </pre>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '16px 0' }}>
              No active token. Please login to generate one.
            </div>
          )}
        </div>

        {/* DPoP Proof Card */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Key size={16} color="var(--accent-purple)" />
              <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>Last DPoP Proof Header (Client Signed)</h4>
            </div>
            <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>typ: dpop+jwt</span>
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '12px' }}>
            Generated in-memory by client browser with embedded public JWK:
          </p>

          {lastDPoPDecoded ? (
            <pre className="code-container" style={{ maxHeight: '240px' }}>
              {JSON.stringify(lastDPoPDecoded, null, 2)}
            </pre>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', padding: '16px 0' }}>
              Click either test button above to dispatch a request and inspect the client DPoP proof.
            </div>
          )}
        </div>

      </div>

      {/* Explanatory RFC 9449 Security Architecture Banner */}
      <div className="glass-panel" style={{ marginTop: '32px', padding: '24px', backgroundColor: 'rgba(13, 18, 31, 0.45)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
          <Info size={20} color="var(--accent-cyan)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '6px' }}>
              RFC 9449 Sender-Constrained Security Architecture
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: '1.6' }}>
              Traditional Bearer tokens (RFC 6750) act like cash: anyone who intercepts the token can spend it. 
              <strong> DPoP (RFC 9449) binds the token to the client&apos;s private key.</strong> Even if an adversary intercepts 
              the access token from an insecure log, browser memory, or compromised proxy, the token is completely useless to the attacker 
              because they do not possess the private key required to generate matching DPoP proofs for subsequent API requests.
            </p>
          </div>
        </div>
      </div>

    </div>
  );
}

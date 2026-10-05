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
          method: 'POST',
          url: proofUrl,
          accessToken: currentToken || undefined,
          keyPair: activeKeys,
        });

        setLastDPoPProof(proof);
        setLastDPoPDecoded(decodeJwtUnsafe(proof));

        const actionResult = await executeSecureEnclaveAction({
          dpopProof: proof,
          accessTokenOverride: currentToken,
          operation: 'Authorized Enclave Query',
        });

        if (actionResult.success && actionResult.data) {
          setDashboardData({
            systemStatus: 'ONLINE (SECURE ENCLAVE - SERVER ACTION)',
            metrics: {
              threatsPrevented: 42,
              dpopTokensActive: 1,
              replayAttacksBlocked: 19,
              securityScore: 100,
            },
            confidentialData: {
              vaultId: actionResult.data.vaultId || 'VLT-ACTION-DEFAULT',
              masterEnclaveKey: actionResult.data.masterEnclaveKey || 'SECRET-KEY',
              accessLevel: actionResult.data.accessLevel || 'AUTHORIZED',
              auditLogId: actionResult.data.auditLogId || 'LOG-1',
              timestamp: actionResult.data.timestamp || new Date().toISOString(),
            },
            user: user || { id: 'u1', username: 'alice', role: 'SecOps', name: 'Alice' },
            tokenBinding: {
              tokenJkt: actionResult.tokenJkt || '',
              proofJkt: actionResult.proofJkt || '',
              matched: true,
              authMethod: 'Next.js Server Action (RPC)',
            },
            auditTrail: actionResult.auditTrail || [],
          });
          setAuditLog(actionResult.auditTrail || []);
        } else {
          setErrorResponse({
            code: actionResult.code || 'action_failed',
            message: actionResult.message || 'Server Action execution rejected.',
            tokenJkt: actionResult.tokenJkt,
            proofJkt: actionResult.proofJkt,
          });
          setAuditLog(actionResult.auditTrail || []);
        }
      } else {
        // REST API ROUTE EXECUTION (/api/dashboard)
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
        <div className="neo-card" style={{ maxWidth: '400px', margin: '0 auto', padding: '36px' }}>
          <RefreshCw size={32} className="animate-spin" color="#000000" strokeWidth={2.5} style={{ margin: '0 auto' }} />
          <p style={{ marginTop: '16px', fontWeight: 800, fontSize: '1rem' }}>Verifying session and DPoP keys...</p>
        </div>
      </div>
    );
  }

  const tokenJkt = (tokenPayload?.cnf as { jkt?: string })?.jkt || null;
  const isKeyMatched = keyPair?.jkt && tokenJkt && keyPair.jkt === tokenJkt;

  return (
    <div className="container" style={{ paddingTop: '36px', paddingBottom: '80px' }}>
      
      {/* Page Title & Status Header */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span className="badge badge-cyan" style={{ fontSize: '0.75rem' }}>Protected Enclave</span>
              <span className="badge badge-purple" style={{ fontSize: '0.75rem' }}>RFC 9449 Enforcement</span>
            </div>
            <h1 style={{ fontSize: '2.5rem', fontWeight: 900, letterSpacing: '-0.03em' }}>
              DPoP PROTECTED DASHBOARD
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', fontWeight: 600 }}>
              This resource endpoint (<code className="code-inline">GET /api/dashboard</code>) strictly demands 
              a cryptographically verified DPoP proof matching the access token&apos;s sender constraint.
            </p>
          </div>

          {/* User profile / session pill */}
          {user ? (
            <div className="neo-card" style={{ padding: '12px 20px', display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '8px',
                background: 'var(--neo-yellow)',
                border: '2px solid #000000',
                boxShadow: '2px 2px 0px #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 900,
                fontSize: '1rem',
                color: '#000000'
              }}>
                {user.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div style={{ fontWeight: 900, fontSize: '0.95rem' }}>{user.name}</div>
                <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{user.role}</div>
              </div>
            </div>
          ) : (
            <Link href="/login" className="btn btn-primary" style={{ padding: '10px 20px' }}>
              Login to Obtain DPoP Token
            </Link>
          )}
        </div>
      </div>

      {/* Cryptographic Binding Visualizer Bar */}
      <div className="neo-card" style={{ padding: '24px', marginBottom: '32px' }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
          
          {/* Client Private/Public Key Status */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            backgroundColor: 'var(--neo-cyan-light)',
            padding: '16px',
            borderRadius: '8px',
            border: '2px solid #000000',
            boxShadow: '3px 3px 0px #000000'
          }}>
            <div style={{ fontSize: '0.72rem', color: '#000000', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 900 }}>
              1. Browser Private Key (Possession)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <Key size={18} strokeWidth={2.5} color="#000000" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: '#000000', fontWeight: 800 }}>
                {keyPair?.jkt ? `${keyPair.jkt.slice(0, 10)}...${keyPair.jkt.slice(-6)}` : 'No key generated'}
              </span>
              <span className="badge badge-emerald" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                Hardware IDB
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px', marginTop: 'auto' }}>
              <span style={{ fontSize: '0.75rem', color: '#000000', fontWeight: 700 }}>
                ES256 (non-extractable)
              </span>
              <button
                type="button"
                onClick={async () => {
                  const res = await testExportPrivateKey(keyPair?.privateKey);
                  alert(res.message);
                }}
                className="btn btn-outline"
                style={{ padding: '2px 8px', fontSize: '0.7rem' }}
                title="Verify browser blocks exportKey()"
              >
                Test exportKey()
              </button>
            </div>
          </div>

          {/* Access Token Confirmation Claim (cnf.jkt) */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            backgroundColor: 'var(--neo-purple-light)',
            padding: '16px',
            borderRadius: '8px',
            border: '2px solid #000000',
            boxShadow: '3px 3px 0px #000000'
          }}>
            <div style={{ fontSize: '0.72rem', color: '#000000', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 900 }}>
              2. Token Confirmation Claim (cnf.jkt)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} strokeWidth={2.5} color="#000000" />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: '#000000', fontWeight: 800 }}>
                {tokenJkt ? `${tokenJkt.slice(0, 10)}...${tokenJkt.slice(-6)}` : 'No DPoP Token in Session'}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#000000', fontWeight: 700, marginTop: 'auto' }}>
              Source: {token ? 'HTTP Cookie / JWT cnf' : 'Not Authenticated'}
            </div>
          </div>

          {/* Cryptographic Matching Status */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            backgroundColor: isKeyMatched ? 'var(--neo-emerald-light)' : 'var(--neo-yellow)',
            padding: '16px',
            borderRadius: '8px',
            border: '2px solid #000000',
            boxShadow: '3px 3px 0px #000000'
          }}>
            <div style={{ fontSize: '0.72rem', color: '#000000', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 900 }}>
              3. Sender-Constrained Binding
            </div>
            <div>
              {isKeyMatched ? (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#15803d', fontWeight: 900, fontSize: '0.9rem' }}>
                  <CheckCircle2 size={18} strokeWidth={2.5} />
                  <span>PERFECT BINDING MATCH</span>
                </div>
              ) : (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#000000', fontWeight: 900, fontSize: '0.9rem' }}>
                  <AlertTriangle size={18} strokeWidth={2.5} />
                  <span>{token ? 'KEY MISMATCH / UNBOUND' : 'LOGIN REQUIRED'}</span>
                </div>
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#000000', fontWeight: 700, marginTop: 'auto' }}>
              {isKeyMatched
                ? 'Your browser holds the exact private key bound to this token'
                : 'Login to bind your current browser key pair'}
            </div>
          </div>

        </div>
      </div>

      <div style={{ marginBottom: '36px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 900 }}>
              Interactive DPoP Verification Testing
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem', fontWeight: 600 }}>
              Test authentic sender-constrained access versus simulated token theft attacks side-by-side.
            </p>
          </div>

          {/* Invocation Channel Toggle: REST API vs Server Action */}
          <div style={{
            display: 'inline-flex',
            padding: '4px',
            borderRadius: '8px',
            backgroundColor: '#ffffff',
            border: '2.5px solid #000000',
            boxShadow: '3px 3px 0px #000000',
            gap: '6px'
          }}>
            <button
              type="button"
              onClick={() => setChannel('api')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: channel === 'api' ? '2px solid #000000' : '2px solid transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 800,
                transition: 'all 0.15s ease',
                backgroundColor: channel === 'api' ? 'var(--neo-yellow)' : 'transparent',
                color: '#000000',
                boxShadow: channel === 'api' ? '2px 2px 0px #000000' : 'none'
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
                border: channel === 'action' ? '2px solid #000000' : '2px solid transparent',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 800,
                transition: 'all 0.15s ease',
                backgroundColor: channel === 'action' ? 'var(--neo-purple-light)' : 'transparent',
                color: '#000000',
                boxShadow: channel === 'action' ? '2px 2px 0px #000000' : 'none'
              }}
            >
              ⚡ Next.js Server Action
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          
          {/* BUTTON 1 CARD: LEGITIMATE CLIENT */}
          <div
            style={{
              padding: '30px',
              border: '3.5px solid #000000',
              borderRadius: '12px',
              backgroundColor: 'var(--neo-emerald-light)',
              boxShadow: '7px 7px 0px #000000',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '8px',
                  backgroundColor: 'var(--neo-emerald)',
                  border: '2px solid #000000',
                  boxShadow: '2.5px 2.5px 0px #000000',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#000000'
                }}>
                  <ShieldCheck size={22} strokeWidth={2.5} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 900, color: '#000000' }}>
                    1. Authorized DPoP Request
                  </h3>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#15803d', textTransform: 'uppercase' }}>
                    Genuine Client + Matching Private Key
                  </span>
                </div>
              </div>
              <span className="badge badge-emerald">Expected: 200 OK</span>
            </div>

            <p style={{ color: '#000000', fontSize: '0.9rem', marginBottom: '22px', lineHeight: '1.6', fontWeight: 600 }}>
              Signs a real-time DPoP proof with your browser&apos;s private key, hashes the access token into <code className="code-inline">ath</code>, 
              and submits to <code className="code-inline">/api/dashboard</code>. The server validates that <code className="code-inline">jkt == cnf.jkt</code>.
            </p>

            <div style={{ marginTop: 'auto' }}>
              <button
                onClick={handleLegitimateRequest}
                disabled={executing || !token}
                className="btn btn-emerald"
                style={{ width: '100%', padding: '14px', fontSize: '1rem' }}
              >
                {executing && lastAction === 'legitimate' ? (
                  <>
                    <RefreshCw size={18} className="animate-spin" strokeWidth={2.5} />
                    Cryptographic Verification in Progress...
                  </>
                ) : (
                  <>
                    <Zap size={18} strokeWidth={2.5} />
                    Hit Dashboard (Legitimate DPoP Proof)
                  </>
                )}
              </button>

              {!token && (
                <div style={{ marginTop: '12px', fontSize: '0.8rem', color: '#000000', fontWeight: 700, textAlign: 'center' }}>
                  Please <Link href="/login" style={{ textDecoration: 'underline' }}>Sign In</Link> first to obtain a valid DPoP-bound JWT.
                </div>
              )}
            </div>
          </div>

          {/* BUTTON 2 CARD: ATTACKER REPLAY SIMULATOR */}
          <div
            style={{
              padding: '30px',
              border: '3.5px solid #000000',
              borderRadius: '12px',
              backgroundColor: 'var(--neo-rose-light)',
              boxShadow: '7px 7px 0px #000000',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '8px',
                  backgroundColor: 'var(--neo-rose)',
                  border: '2px solid #000000',
                  boxShadow: '2.5px 2.5px 0px #000000',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff'
                }}>
                  <ShieldAlert size={22} strokeWidth={2.5} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 900, color: '#000000' }}>
                    2. Stolen Token Attack Simulator
                  </h3>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#991b1b', textTransform: 'uppercase' }}>
                    Adversary Replaying Stolen JWT
                  </span>
                </div>
              </div>
              <span className="badge badge-rose">Expected: 401 Blocked</span>
            </div>

            <p style={{ color: '#000000', fontSize: '0.9rem', marginBottom: '14px', lineHeight: '1.6', fontWeight: 600 }}>
              Simulates an adversary who sniffed or stolen the user&apos;s real JWT. Choose the adversary&apos;s exploit vector:
            </p>

            {/* Attack Vector Selectors */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '22px' }}>
              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                fontSize: '0.85rem',
                cursor: 'pointer',
                padding: '8px 12px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'attacker_key' ? '#ffffff' : 'rgba(255, 255, 255, 0.5)',
                border: '2px solid #000000',
                boxShadow: attackMode === 'attacker_key' ? '3px 3px 0px #000000' : 'none',
                fontWeight: 700,
                color: '#000000'
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
                gap: '10px',
                fontSize: '0.85rem',
                cursor: 'pointer',
                padding: '8px 12px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'no_dpop' ? '#ffffff' : 'rgba(255, 255, 255, 0.5)',
                border: '2px solid #000000',
                boxShadow: attackMode === 'no_dpop' ? '3px 3px 0px #000000' : 'none',
                fontWeight: 700,
                color: '#000000'
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
                gap: '10px',
                fontSize: '0.85rem',
                cursor: 'pointer',
                padding: '8px 12px',
                borderRadius: '6px',
                backgroundColor: attackMode === 'replayed_jti' ? '#ffffff' : 'rgba(255, 255, 255, 0.5)',
                border: '2px solid #000000',
                boxShadow: attackMode === 'replayed_jti' ? '3px 3px 0px #000000' : 'none',
                fontWeight: 700,
                color: '#000000'
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

            <div style={{ marginTop: 'auto' }}>
              <button
                onClick={handleAttackRequest}
                disabled={executing || !token}
                className="btn btn-danger"
                style={{ width: '100%', padding: '14px', fontSize: '1rem' }}
              >
                {executing && lastAction === 'attack' ? (
                  <>
                    <RefreshCw size={18} className="animate-spin" strokeWidth={2.5} />
                    Testing Attack Defense...
                  </>
                ) : (
                  <>
                    <ShieldAlert size={18} strokeWidth={2.5} />
                    Hit with Fake / Stolen Token (Simulate Exploit)
                  </>
                )}
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* ========================================================================= */}
      {/* LIVE EXECUTION RESULTS DISPLAY                                            */}
      {/* ========================================================================= */}
      {dashboardData && (
        <div style={{
          padding: '32px',
          marginBottom: '36px',
          border: '4px solid #000000',
          borderRadius: '14px',
          backgroundColor: '#bbf7d0',
          boxShadow: '8px 8px 0px #000000'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '8px',
                backgroundColor: 'var(--neo-emerald)',
                border: '2.5px solid #000000',
                boxShadow: '3px 3px 0px #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#000000'
              }}>
                <Unlock size={26} strokeWidth={2.5} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.45rem', color: '#000000', fontWeight: 900 }}>
                  200 OK — DPoP Proof Verified: Access Granted
                </h3>
                <p style={{ color: '#000000', fontSize: '0.9rem', fontWeight: 600 }}>
                  The server verified that you possess the private key corresponding to <code className="code-inline">{dashboardData.tokenBinding.tokenJkt}</code>.
                </p>
              </div>
            </div>
            <span className="badge badge-emerald" style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
              SECURE ENCLAVE UNLOCKED
            </span>
          </div>

          {/* Confidential Vault Data Unlocked */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4" style={{ marginBottom: '8px' }}>
            <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '2px solid #000000', boxShadow: '3px 3px 0px #000000' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Enclave Status</div>
              <div style={{ fontSize: '1rem', fontWeight: 900, color: '#15803d', marginTop: '4px' }}>
                {dashboardData.systemStatus}
              </div>
            </div>

            <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '2px solid #000000', boxShadow: '3px 3px 0px #000000' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Vault Identifier</div>
              <div style={{ fontSize: '1rem', fontWeight: 900, color: '#000000', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                {dashboardData.confidentialData.vaultId}
              </div>
            </div>

            <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '2px solid #000000', boxShadow: '3px 3px 0px #000000' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Restricted Master Key</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 900, color: '#000000', marginTop: '6px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                {dashboardData.confidentialData.masterEnclaveKey}
              </div>
            </div>

            <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '2px solid #000000', boxShadow: '3px 3px 0px #000000' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>Replay Defenses Active</div>
              <div style={{ fontSize: '1rem', fontWeight: 900, color: '#000000', marginTop: '4px' }}>
                {dashboardData.metrics.replayAttacksBlocked} Blocked / 100% Score
              </div>
            </div>
          </div>
        </div>
      )}

      {errorResponse && (
        <div style={{
          padding: '32px',
          marginBottom: '36px',
          border: '4px solid #000000',
          borderRadius: '14px',
          backgroundColor: '#fecdd3',
          boxShadow: '8px 8px 0px #000000'
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '8px',
                backgroundColor: 'var(--neo-rose)',
                border: '2.5px solid #000000',
                boxShadow: '3px 3px 0px #000000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                color: '#ffffff'
              }}>
                <XCircle size={28} strokeWidth={2.5} />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h3 style={{ fontSize: '1.45rem', color: '#000000', fontWeight: 900 }}>
                    401 Unauthorized — Attack Thwarted by DPoP
                  </h3>
                  <span className="badge badge-rose">{errorResponse.code}</span>
                </div>
                <p style={{ color: '#000000', fontSize: '0.95rem', marginTop: '4px', fontWeight: 700 }}>
                  {errorResponse.message}
                </p>
              </div>
            </div>
          </div>

          {/* Cryptographic Thumbprint Mismatch Box */}
          {errorResponse.tokenJkt && errorResponse.proofJkt && errorResponse.proofJkt !== 'none' && (
            <div style={{
              backgroundColor: '#ffffff',
              padding: '20px',
              borderRadius: '8px',
              border: '2.5px solid #000000',
              boxShadow: '3px 3px 0px #000000',
              marginBottom: '10px'
            }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 900, color: 'var(--accent-rose)', marginBottom: '10px', textTransform: 'uppercase' }}>
                PROOF-OF-POSSESSION DISCREPANCY ANALYSIS:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.825rem' }}>
                <div style={{ backgroundColor: 'var(--neo-cyan-light)', padding: '12px', borderRadius: '6px', border: '1.5px solid #000' }}>
                  <div style={{ color: '#000000', fontSize: '0.72rem', fontWeight: 800 }}>ACCESS TOKEN SENDER BINDING (cnf.jkt):</div>
                  <div style={{ color: '#000000', wordBreak: 'break-all', marginTop: '4px', fontWeight: 800 }}>
                    {errorResponse.tokenJkt}
                  </div>
                </div>
                <div style={{ backgroundColor: 'var(--neo-rose-light)', padding: '12px', borderRadius: '6px', border: '1.5px solid #000' }}>
                  <div style={{ color: '#000000', fontSize: '0.72rem', fontWeight: 800 }}>ATTACKER DPOP PROOF KEY (jkt):</div>
                  <div style={{ color: '#991b1b', wordBreak: 'break-all', marginTop: '4px', fontWeight: 800 }}>
                    {errorResponse.proofJkt}
                  </div>
                </div>
              </div>
              <div style={{ fontSize: '0.825rem', color: '#000000', marginTop: '12px', fontWeight: 600 }}>
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
        <div className="neo-card" style={{ padding: '28px', marginBottom: '36px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '6px',
                backgroundColor: 'var(--neo-yellow)',
                border: '1.5px solid #000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Terminal size={18} strokeWidth={2.5} color="#000000" />
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 900 }}>
                Server Cryptographic Verification Audit Trail (RFC 9449)
              </h3>
            </div>
            <span className="badge badge-amber" style={{ fontSize: '0.75rem' }}>
              {auditLog.length} Security Assertions Evaluated
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {auditLog.map((step, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  borderRadius: '6px',
                  backgroundColor: step.status === 'passed' ? 'var(--neo-emerald-light)' : 'var(--neo-rose-light)',
                  border: '2px solid #000000',
                  boxShadow: '2px 2px 0px #000000',
                  fontSize: '0.875rem',
                  gap: '14px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {step.status === 'passed' ? (
                    <CheckCircle2 size={18} strokeWidth={2.5} color="#15803d" />
                  ) : (
                    <XCircle size={18} strokeWidth={2.5} color="var(--neo-rose)" />
                  )}
                  <span style={{ fontWeight: 800, color: '#000000' }}>
                    {step.step}
                  </span>
                </div>
                <div style={{ color: '#000000', fontSize: '0.825rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        
        {/* Token Card */}
        <div className="neo-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '6px',
                backgroundColor: 'var(--neo-cyan-light)',
                border: '1.5px solid #000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Lock size={16} strokeWidth={2.5} color="#000000" />
              </div>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 900 }}>Access Token (Server Signed JWT)</h4>
            </div>
            {token && (
              <button
                onClick={copyTokenToClipboard}
                className="btn btn-outline"
                style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              >
                <Copy size={12} strokeWidth={2.5} />
                {copiedToken ? 'Copied' : 'Copy'}
              </button>
            )}
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '14px', fontWeight: 600 }}>
            Issued by Authorization Server with sender-constraining claim <code className="code-inline">cnf.jkt</code>:
          </p>

          {tokenPayload ? (
            <pre className="code-container" style={{ maxHeight: '240px' }}>
              {JSON.stringify(tokenPayload, null, 2)}
            </pre>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '16px 0', fontWeight: 600 }}>
              No active token. Please login to generate one.
            </div>
          )}
        </div>

        {/* DPoP Proof Card */}
        <div className="neo-card" style={{ padding: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '6px',
                backgroundColor: 'var(--neo-purple-light)',
                border: '1.5px solid #000',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Key size={16} strokeWidth={2.5} color="#000000" />
              </div>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 900 }}>Last DPoP Proof Header (Client Signed)</h4>
            </div>
            <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>typ: dpop+jwt</span>
          </div>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '14px', fontWeight: 600 }}>
            Generated in-memory by client browser with embedded public JWK:
          </p>

          {lastDPoPDecoded ? (
            <pre className="code-container" style={{ maxHeight: '240px' }}>
              {JSON.stringify(lastDPoPDecoded, null, 2)}
            </pre>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '16px 0', fontWeight: 600 }}>
              Click either test button above to dispatch a request and inspect the client DPoP proof.
            </div>
          )}
        </div>

      </div>

      {/* Explanatory RFC 9449 Security Architecture Banner */}
      <div style={{
        marginTop: '36px',
        padding: '28px',
        backgroundColor: 'var(--bg-surface-alt)',
        border: '3px solid #000000',
        borderRadius: '12px',
        boxShadow: '5px 5px 0px #000000'
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            backgroundColor: '#ffffff',
            border: '2px solid #000000',
            boxShadow: '2px 2px 0px #000000',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <Info size={20} strokeWidth={2.5} color="#000000" />
          </div>
          <div>
            <h4 style={{ fontSize: '1.05rem', fontWeight: 900, marginBottom: '8px', textTransform: 'uppercase' }}>
              RFC 9449 Sender-Constrained Security Architecture
            </h4>
            <p style={{ color: '#000000', fontSize: '0.875rem', lineHeight: '1.7', fontWeight: 600 }}>
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

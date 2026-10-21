import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Activity, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  Layers, 
  Cpu, 
  Server,
  Terminal,
  ExternalLink
} from 'lucide-react';

export default function App() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [latencyMs, setLatencyMs] = useState(null);

  const checkHealth = async () => {
    setLoading(true);
    setError(null);
    const start = performance.now();
    try {
      const response = await fetch('/api/v1/health');
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      const elapsed = Math.round(performance.now() - start);
      setHealth(data);
      setLatencyMs(elapsed);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur px-6 py-4 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                RISE-Phish
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                  Phase 0: Initialized
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Cross-Representation Discrepancy-Aware Phishing Detection
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <a 
              href="http://127.0.0.1:8000/docs" 
              target="_blank" 
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1 transition-colors px-3 py-1.5 rounded-md hover:bg-slate-800 border border-transparent hover:border-slate-700"
            >
              <span>FastAPI Swagger Docs</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <button
              onClick={checkHealth}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition shadow-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh Status</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl w-full mx-auto p-6 space-y-6">
        {/* Banner */}
        <section className="bg-gradient-to-r from-blue-950/40 via-slate-900 to-slate-900 border border-blue-900/40 rounded-2xl p-6 relative overflow-hidden">
          <div className="max-w-2xl">
            <span className="text-xs font-semibold uppercase tracking-wider text-blue-400 font-mono">
              Final-Year B.Tech Research Project
            </span>
            <h2 className="text-2xl font-bold text-white mt-1 mb-2">
              System Environment & Core Infrastructure
            </h2>
            <p className="text-slate-300 text-sm leading-relaxed">
              Phase 0 verification confirmed. The unified research environment connects
              a modern React UI, FastAPI backend, controlled Chromium browser engine, 
              and initial configuration ready for multi-representation discrepancy modeling.
            </p>
          </div>
        </section>

        {/* Health Check Live Status Card */}
        <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-sm">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Activity className="w-5 h-5 text-blue-400" />
              <h3 className="text-sm font-semibold text-slate-200">
                Backend Service Connectivity (GET /api/v1/health)
              </h3>
            </div>
            {loading ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-yellow-400">
                <span className="w-2 h-2 rounded-full bg-yellow-400 animate-ping" />
                Connecting...
              </span>
            ) : health?.status === 'ok' ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                <CheckCircle2 className="w-4 h-4" />
                Healthy ({latencyMs}ms)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs text-rose-400 font-medium">
                <XCircle className="w-4 h-4" />
                Unreachable
              </span>
            )}
          </div>

          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400">API Status</span>
              <p className="text-base font-semibold text-emerald-400 mt-0.5">
                {health?.status ? health.status.toUpperCase() : (loading ? 'Checking...' : 'OFFLINE')}
              </p>
            </div>
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400">Application Name</span>
              <p className="text-base font-semibold text-white mt-0.5">
                {health?.app_name || 'RISE-Phish API'}
              </p>
            </div>
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400">API Version</span>
              <p className="text-base font-semibold text-white mt-0.5">
                {health?.version || 'v0.1.0'}
              </p>
            </div>
            <div className="p-3.5 bg-slate-950/60 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400">Environment</span>
              <p className="text-base font-semibold text-blue-400 mt-0.5 capitalize">
                {health?.environment || 'development'}
              </p>
            </div>
          </div>

          {error && (
            <div className="mt-4 p-3.5 bg-rose-950/30 border border-rose-900/50 rounded-lg text-rose-300 text-xs flex items-start gap-2">
              <XCircle className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
              <div>
                <p className="font-semibold">Failed to query backend health endpoint:</p>
                <p className="mt-0.5 font-mono">{error}</p>
                <p className="mt-1 text-slate-400">Ensure the backend is running with: <code className="bg-slate-900 px-1 py-0.5 rounded text-slate-300">uvicorn backend.app.main:app --reload</code></p>
              </div>
            </div>
          )}

          {health?.timestamp && (
            <p className="mt-3 text-[11px] text-slate-500 font-mono">
              Server Timestamp: {health.timestamp}
            </p>
          )}
        </section>

        {/* Architectural Pillars */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
            <h4 className="font-semibold text-slate-200 text-sm">
              Controlled Crawler (Playwright)
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Headless Chromium with strict timeouts, zero credentials, no saved state, and
              isolated temporary storage ready for Phase 1.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
              <Layers className="w-4 h-4" />
            </div>
            <h4 className="font-semibold text-slate-200 text-sm">
              CRCE Discrepancy Engine
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-representation comparison matrix: Raw DOM vs Canonical Normalized vs Visual/OCR vs URL vs Brand.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center">
              <Cpu className="w-4 h-4" />
            </div>
            <h4 className="font-semibold text-slate-200 text-sm">
              Lightweight SLM Abstraction
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Engineered for RTX 3050 (4GB VRAM) using quantized local models and API fallbacks with structured JSON schemas.
            </p>
          </div>
        </section>

        {/* Phase Roadmap Progression */}
        <section className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Terminal className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-semibold text-slate-200">
              Project Execution Roadmap Status
            </h4>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 bg-emerald-950/30 border border-emerald-900/40 rounded-lg">
              <span className="text-[10px] uppercase font-mono text-emerald-400 font-semibold">Phase 0</span>
              <p className="font-semibold text-white mt-0.5">Project Initialization</p>
              <span className="text-[11px] text-emerald-400 mt-1 inline-block">✓ Complete & Verified</span>
            </div>
            <div className="p-3 bg-blue-950/30 border border-blue-900/40 rounded-lg">
              <span className="text-[10px] uppercase font-mono text-blue-400 font-semibold">Phase 1</span>
              <p className="font-semibold text-white mt-0.5">Playwright Crawler</p>
              <span className="text-[11px] text-blue-400 mt-1 inline-block">Ready to Begin</span>
            </div>
            <div className="p-3 bg-slate-950/40 border border-slate-800/60 rounded-lg opacity-70">
              <span className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Phases 2-6</span>
              <p className="font-semibold text-slate-300 mt-0.5">Features & Representations</p>
              <span className="text-[11px] text-slate-500 mt-1 inline-block">Pending Phase 1</span>
            </div>
            <div className="p-3 bg-slate-950/40 border border-slate-800/60 rounded-lg opacity-70">
              <span className="text-[10px] uppercase font-mono text-slate-400 font-semibold">Phases 7-12</span>
              <p className="font-semibold text-slate-300 mt-0.5">CRCE, SLM, Fusion Engine</p>
              <span className="text-[11px] text-slate-500 mt-1 inline-block">Core Research Engine</span>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500">
        RISE-Phish Research System • Final-Year B.Tech Capstone Project • Phase 0 Verified
      </footer>
    </div>
  );
}

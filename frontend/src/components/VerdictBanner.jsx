import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Zap, CheckCircle2, XCircle } from 'lucide-react';

export default function VerdictBanner({ result }) {
  if (!result) return null;

  const verdict = result.verdict || 'INVESTIGATE';
  const score = result.composite_threat_score ?? 0.0;
  const confidence = result.confidence_score ?? 0.0;
  const isConvergence = result.visual_normalization_convergence;
  const brand = result.target_brand;
  const domain = result.registered_domain;
  const action = result.recommended_action || 'WARN_USER';

  const verdictConfig = {
    PHISHING: {
      title: 'CONFIRMED PHISHING ATTACK',
      badge: 'PHISHING',
      bg: 'bg-gradient-to-r from-rose-950/60 via-slate-900 to-slate-900',
      border: 'border-rose-900/60',
      badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
      icon: ShieldAlert,
      iconColor: 'text-rose-400',
      barColor: 'bg-rose-500',
      textColor: 'text-rose-400',
    },
    INVESTIGATE: {
      title: 'SUSPICIOUS / INVESTIGATION REQUIRED',
      badge: 'INVESTIGATE',
      bg: 'bg-gradient-to-r from-amber-950/60 via-slate-900 to-slate-900',
      border: 'border-amber-900/60',
      badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
      barColor: 'bg-amber-500',
      textColor: 'text-amber-400',
    },
    SAFE: {
      title: 'AUTHENTIC & VERIFIED SAFE',
      badge: 'SAFE',
      bg: 'bg-gradient-to-r from-emerald-950/60 via-slate-900 to-slate-900',
      border: 'border-emerald-900/60',
      badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
      barColor: 'bg-emerald-500',
      textColor: 'text-emerald-400',
    },
  };

  const cfg = verdictConfig[verdict] || verdictConfig.INVESTIGATE;
  const Icon = cfg.icon;

  return (
    <div className={`${cfg.bg} border ${cfg.border} rounded-2xl p-6 shadow-2xl relative overflow-hidden transition-all`}>
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left: Verdict info */}
        <div className="space-y-3 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className={`text-xs px-2.5 py-1 rounded-full font-mono font-bold tracking-wider uppercase border ${cfg.badgeBg}`}>
              {cfg.badge}
            </span>

            <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
              Action: <strong className="text-white">{action}</strong>
            </span>

            {result.status === 'DEGRADED' && (
              <span className="text-xs px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono font-semibold">
                Network: Host Unreachable
              </span>
            )}

            {isConvergence && (
              <span className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 font-mono font-semibold animate-pulse">
                <Zap className="w-3.5 h-3.5" />
                <span>Visual-Normalization Convergence Signature</span>
              </span>
            )}
          </div>

          <div className="flex items-center gap-3">
            <div className={`p-3 rounded-xl bg-slate-900/80 border border-slate-800 ${cfg.iconColor} shadow-inner`}>
              <Icon className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-2xl font-black tracking-tight text-white">
                {cfg.title}
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-xl">
                Target URL: <span className="text-slate-200">{result.url}</span>
              </p>
            </div>
          </div>

          {/* Target attribution pills */}
          <div className="flex flex-wrap items-center gap-3 text-xs pt-1">
            <div className="px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Claimed Brand: </span>
              <strong className="text-white font-medium">{brand || 'None Detected'}</strong>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Registered Host: </span>
              <strong className="text-white font-mono">{domain || 'Unknown'}</strong>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800">
              <span className="text-slate-400">Confidence: </span>
              <strong className="text-blue-400 font-mono">{(confidence * 100).toFixed(1)}%</strong>
            </div>
          </div>
        </div>

        {/* Right: Threat Score Gauge */}
        <div className="lg:w-64 bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-center space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400 font-medium uppercase tracking-wider font-mono">
              Composite Threat
            </span>
            <span className={`font-black font-mono text-lg ${cfg.textColor}`}>
              {(score * 100).toFixed(1)}%
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden p-0.5 border border-slate-700/60">
            <div
              className={`h-full rounded-full transition-all duration-700 ${cfg.barColor}`}
              style={{ width: `${Math.min(100, Math.max(5, score * 100))}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
            <span>Safe &le; 35%</span>
            <span>Investigate</span>
            <span>Phish &ge; 65%</span>
          </div>
        </div>
      </div>
    </div>
  );
}

import React from 'react';
import { ShieldAlert, AlertCircle, CheckCircle2, ArrowRight } from 'lucide-react';

export default function UserAdvisoryCard({ advisory }) {
  if (!advisory) return null;

  const isDanger = advisory.status_level === 'DANGER';
  const isWarning = advisory.status_level === 'WARNING';

  const badgeColor = isDanger
    ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
    : isWarning
    ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
    : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';

  const Icon = isDanger ? ShieldAlert : isWarning ? AlertCircle : CheckCircle2;
  const iconColor = isDanger ? 'text-rose-400' : isWarning ? 'text-amber-400' : 'text-emerald-400';

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-xl bg-slate-950/60 border border-slate-800 ${iconColor}`}>
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">
                Dual-Audience Explainability
              </span>
              <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold uppercase border ${badgeColor}`}>
                {advisory.status_level}
              </span>
            </div>
            <h4 className="text-lg font-bold text-white mt-0.5">
              {advisory.headline}
            </h4>
          </div>
        </div>
      </div>

      {/* Narrative summary */}
      <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/50 p-4 rounded-xl border border-slate-800/80">
        {advisory.summary}
      </p>

      {/* Bullet points */}
      {advisory.bullet_points && advisory.bullet_points.length > 0 && (
        <div className="space-y-2 pt-1">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
            Key Findings & Observations:
          </span>
          <ul className="space-y-2">
            {advisory.bullet_points.map((pt, i) => (
              <li key={i} className="flex items-start gap-2.5 text-xs text-slate-300">
                <span className="text-blue-400 mt-1">&bull;</span>
                <span className="leading-relaxed">{pt}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Action Advice Box */}
      {advisory.action_advice && (
        <div className="pt-2">
          <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/30 to-slate-900 border border-blue-900/40 space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-bold text-blue-400 font-mono uppercase tracking-wider">
              <ArrowRight className="w-3.5 h-3.5" />
              <span>Recommended User Action:</span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-medium">
              {advisory.action_advice}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

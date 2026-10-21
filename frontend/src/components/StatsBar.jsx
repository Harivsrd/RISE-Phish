import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Layers, BarChart3, Zap } from 'lucide-react';

export default function StatsBar({ stats }) {
  if (!stats) return null;

  const cards = [
    {
      label: 'Total Scanned',
      value: stats.total_scans,
      icon: BarChart3,
      color: 'text-slate-300',
      bg: 'bg-slate-800/50',
      border: 'border-slate-700/60',
    },
    {
      label: 'Confirmed Phishing',
      value: stats.phishing_detected,
      icon: ShieldAlert,
      color: 'text-rose-400',
      bg: 'bg-rose-950/20',
      border: 'border-rose-900/40',
    },
    {
      label: 'Verified Safe',
      value: stats.safe_sites,
      icon: ShieldCheck,
      color: 'text-emerald-400',
      bg: 'bg-emerald-950/20',
      border: 'border-emerald-900/40',
    },
    {
      label: 'Investigate Required',
      value: stats.investigate_sites,
      icon: AlertTriangle,
      color: 'text-amber-400',
      bg: 'bg-amber-950/20',
      border: 'border-amber-900/40',
    },
    {
      label: 'Visual Convergences',
      value: stats.visual_convergences_detected,
      icon: Zap,
      color: 'text-purple-400',
      bg: 'bg-purple-950/20',
      border: 'border-purple-900/40',
    },
    {
      label: 'Mean Threat Score',
      value: `${(stats.average_threat_score * 100).toFixed(1)}%`,
      icon: Layers,
      color: 'text-blue-400',
      bg: 'bg-blue-950/20',
      border: 'border-blue-900/40',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`${card.bg} border ${card.border} rounded-xl p-3.5 flex flex-col justify-between transition-all hover:translate-y-[-1px]`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-medium tracking-tight truncate">{card.label}</span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className={`text-xl font-bold tracking-tight font-mono ${card.color}`}>
              {card.value}
            </div>
          </div>
        );
      })}
    </div>
  );
}

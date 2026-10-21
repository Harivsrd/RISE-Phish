import React from 'react';
import { 
  History, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Zap, 
  Trash2, 
  ExternalLink, 
  Clock, 
  Globe, 
  RefreshCw,
  Search,
  Filter
} from 'lucide-react';

export default function ScanHistory({
  items = [],
  total = 0,
  loading = false,
  onSelect,
  onDelete,
  onRefresh,
  selectedId = null,
  verdictFilter = 'ALL',
  onFilterChange,
}) {
  const verdictBadges = {
    PHISHING: {
      bg: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
      icon: ShieldAlert,
      iconColor: 'text-rose-400',
    },
    INVESTIGATE: {
      bg: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
    },
    SAFE: {
      bg: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: ShieldCheck,
      iconColor: 'text-emerald-400',
    },
  };

  const formatDate = (isoStr) => {
    if (!isoStr) return 'N/A';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
        ' · ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  const filterOptions = [
    { key: 'ALL', label: 'All Scans' },
    { key: 'PHISHING', label: 'Phishing' },
    { key: 'INVESTIGATE', label: 'Investigate' },
    { key: 'SAFE', label: 'Safe' },
  ];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden space-y-0">
      {/* Header & Controls */}
      <div className="p-5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4 bg-slate-900/50">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <History className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">Scan History & Forensic Archive</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                {total} {total === 1 ? 'record' : 'records'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Persisted multi-representation forensic scan evaluations
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Verdict Filter Buttons */}
          <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
            {filterOptions.map((opt) => (
              <button
                key={opt.key}
                type="button"
                onClick={() => onFilterChange && onFilterChange(opt.key)}
                className={`px-3 py-1 rounded-lg font-medium transition ${
                  verdictFilter === opt.key
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Refresh Button */}
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            title="Refresh historical logs"
            className="p-2 rounded-xl bg-slate-800/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Content List / Table */}
      {items.length === 0 ? (
        <div className="p-12 text-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-slate-800/50 text-slate-500 flex items-center justify-center mx-auto border border-slate-800">
            <Search className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-slate-300">No Scan Records Found</p>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            {verdictFilter !== 'ALL'
              ? `No historical analyses match the '${verdictFilter}' filter criteria.`
              : 'Execute your first URL evaluation using the input bar above to populate this historical forensic archive.'}
          </p>
        </div>
      ) : (
        <div className="divide-y divide-slate-800/60 max-h-[520px] overflow-y-auto">
          {items.map((scan) => {
            const isSelected = selectedId === scan.analysis_id;
            const badgeCfg = verdictBadges[scan.verdict] || verdictBadges.INVESTIGATE;
            const Icon = badgeCfg.icon;
            const scorePct = Math.round((scan.composite_threat_score ?? 0) * 100);

            return (
              <div
                key={scan.analysis_id}
                onClick={() => onSelect && onSelect(scan.analysis_id)}
                className={`p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer transition ${
                  isSelected
                    ? 'bg-blue-950/30 border-l-4 border-l-blue-500 pl-3.5'
                    : 'hover:bg-slate-800/40 border-l-4 border-l-transparent'
                }`}
              >
                {/* Left: Verdict + URL + Metadata */}
                <div className="flex items-start gap-3 min-w-0 flex-1">
                  <div className={`p-2 rounded-lg mt-0.5 border shrink-0 ${badgeCfg.bg}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[11px] font-bold font-mono px-2 py-0.5 rounded border ${badgeCfg.bg}`}>
                        {scan.verdict}
                      </span>
                      {scan.visual_normalization_convergence && (
                        <span className="inline-flex items-center gap-1 text-[10px] font-semibold font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                          <Zap className="w-3 h-3 text-purple-400" />
                          CONVERGENCE
                        </span>
                      )}
                      {scan.target_brand && (
                        <span className="text-[10px] font-medium font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          Target: <strong className="text-white">{scan.target_brand}</strong>
                        </span>
                      )}
                      <span className="text-[11px] text-slate-500 flex items-center gap-1 font-mono">
                        <Clock className="w-3 h-3" />
                        {formatDate(scan.created_at)}
                      </span>
                    </div>

                    <div className="mt-1.5 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <p className="text-xs font-mono text-slate-200 truncate select-all" title={scan.url}>
                        {scan.url}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Right: Score Gauge + Actions */}
                <div className="flex items-center gap-4 shrink-0 pl-9 md:pl-0">
                  {/* Score Pill */}
                  <div className="text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <span className="text-[10px] text-slate-400 uppercase font-mono">Threat</span>
                      <span className="text-xs font-bold font-mono text-white">{scorePct}%</span>
                    </div>
                    <div className="w-20 bg-slate-800 rounded-full h-1.5 overflow-hidden mt-1">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${
                          scorePct >= 70 ? 'bg-rose-500' : scorePct >= 35 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.min(100, Math.max(0, scorePct))}%` }}
                      />
                    </div>
                  </div>

                  {/* Load Report Pill */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect && onSelect(scan.analysis_id);
                    }}
                    className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition flex items-center gap-1 ${
                      isSelected
                        ? 'bg-blue-600 text-white border-blue-500'
                        : 'bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 border-slate-700'
                    }`}
                  >
                    <span>{isSelected ? 'Viewing' : 'Inspect'}</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>

                  {/* Delete Button */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (window.confirm(`Delete analysis record for ${scan.url}?`)) {
                        onDelete && onDelete(scan.analysis_id);
                      }
                    }}
                    title="Delete record"
                    className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-950/30 transition"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

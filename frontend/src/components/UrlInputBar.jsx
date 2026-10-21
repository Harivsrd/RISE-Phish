import React, { useState } from 'react';
import { Search, Globe, RefreshCw, Sparkles } from 'lucide-react';

export default function UrlInputBar({ onAnalyze, loading }) {
  const [url, setUrl] = useState('');
  const [forceFresh, setForceFresh] = useState(false);

  const sampleTargets = [
    {
      label: 'Zero-Day Math Alphanumeric',
      url: 'http://127.0.0.1:8000/demo/zero-day-math',
      badge: 'Unseen Phishing',
      badgeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    },
    {
      label: 'Cyrillic Homoglyph Spoof',
      url: 'http://127.0.0.1:8000/demo/cyrillic-homoglyph',
      badge: 'Visual Phishing',
      badgeColor: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
    },
    {
      label: 'Credential Harvest Portal',
      url: 'http://127.0.0.1:8000/demo/credential-harvest',
      badge: 'Brand Spoof',
      badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    },
    {
      label: 'Authentic Official Portal',
      url: 'https://www.google.com',
      badge: 'Benign Control',
      badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    },
    {
      label: 'European French Portal',
      url: 'https://www.service-public.fr',
      badge: 'Localized Accents',
      badgeColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    },
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    onAnalyze(url.trim(), forceFresh);
  };

  const handleSelectSample = (sampleUrl) => {
    setUrl(sampleUrl);
    onAnalyze(sampleUrl, true);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
      <div>
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Globe className="w-4 h-4 text-blue-400" />
          <span>Real-Time URL Security Analysis</span>
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Submit any webpage URL to execute cross-representation discrepancy detection, Unicode forensic extraction, and lightweight SLM reasoning.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter target URL (e.g. https://portal-session-sync.net/auth)"
              className="w-full bg-slate-950/80 border border-slate-700/80 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 font-mono transition"
              disabled={loading}
            />
          </div>

          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold transition shadow-lg shadow-blue-600/20 whitespace-nowrap"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Analyzing Discrepancies...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Run Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs">
          <label className="flex items-center gap-2 text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={forceFresh}
              onChange={(e) => setForceFresh(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-blue-500 w-3.5 h-3.5"
            />
            <span>Bypass cache (Force fresh sandbox crawl & OCR)</span>
          </label>

          <span className="text-[11px] text-slate-500 font-mono">
            RTX 3050 Modular Engine &bull; Zero-VRAM Baseline
          </span>
        </div>
      </form>

      {/* Preset Target Samples */}
      <div className="pt-2 border-t border-slate-800/80">
        <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block mb-2 font-mono">
          Quick Research Demo Lures:
        </span>
        <div className="flex flex-wrap gap-2">
          {sampleTargets.map((item, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSelectSample(item.url)}
              disabled={loading}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/70 hover:bg-slate-750 border border-slate-700/60 hover:border-slate-600 text-left transition group disabled:opacity-50"
            >
              <span className="text-xs text-slate-200 group-hover:text-blue-400 font-medium">
                {item.label}
              </span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${item.badgeColor}`}>
                {item.badge}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

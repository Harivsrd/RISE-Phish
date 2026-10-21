import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldCheck, 
  Activity, 
  RefreshCw, 
  AlertCircle, 
  Clock, 
  Layers, 
  Cpu, 
  Server,
  FileSearch,
  ExternalLink,
  ChevronRight,
  Database
} from 'lucide-react';

import Navbar from './components/Navbar';
import StatsBar from './components/StatsBar';
import UrlInputBar from './components/UrlInputBar';
import VerdictBanner from './components/VerdictBanner';
import UserAdvisoryCard from './components/UserAdvisoryCard';
import RepresentationViewer from './components/RepresentationViewer';
import AnalystDrawer from './components/AnalystDrawer';
import ScanHistory from './components/ScanHistory';

export default function App() {
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [historyItems, setHistoryItems] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [verdictFilter, setVerdictFilter] = useState('ALL');

  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [selectedId, setSelectedId] = useState(null);

  const [loadingHealth, setLoadingHealth] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzingStep, setAnalyzingStep] = useState('');
  const [error, setError] = useState(null);

  // 1. Health check
  const fetchHealth = useCallback(async () => {
    setLoadingHealth(true);
    try {
      const res = await fetch('/api/v1/health');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      } else {
        setHealth(null);
      }
    } catch {
      setHealth(null);
    } finally {
      setLoadingHealth(false);
    }
  }, []);

  // 2. Fetch dashboard telemetry stats
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  }, []);

  // 3. Fetch historical scans
  const fetchHistory = useCallback(async (filterKey = verdictFilter) => {
    setLoadingHistory(true);
    try {
      const url = filterKey && filterKey !== 'ALL'
        ? `/api/v1/history?limit=50&verdict=${filterKey}`
        : '/api/v1/history?limit=50';
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setHistoryItems(data.items || []);
        setHistoryTotal(data.total || 0);
      }
    } catch (err) {
      console.error('Failed to fetch scan history:', err);
    } finally {
      setLoadingHistory(false);
    }
  }, [verdictFilter]);

  // Initial load
  useEffect(() => {
    fetchHealth();
    fetchStats();
    fetchHistory('ALL');
  }, [fetchHealth, fetchStats, fetchHistory]);

  // Handle URL Analysis execution
  const handleAnalyze = async (targetUrl, forceFresh = false) => {
    setAnalyzing(true);
    setError(null);
    setAnalyzingStep('Initializing controlled browser and capturing DOM...');

    // Progress animation milestones
    const t1 = setTimeout(() => {
      setAnalyzingStep('Generating Multi-Representations (R1 Raw, R2 Normalized, R3 Visual, R4 Semantic, R5 URL)...');
    }, 800);

    const t2 = setTimeout(() => {
      setAnalyzingStep('Executing CRCE Pairwise Discrepancy Matrix & Unicode Normalization Convergence...');
    }, 1800);

    const t3 = setTimeout(() => {
      setAnalyzingStep('Running Lightweight SLM Dual-Task (Semantic Recovery & Threat Reasoning)...');
    }, 2800);

    const t4 = setTimeout(() => {
      setAnalyzingStep('Synthesizing Non-linear Evidence Fusion & Dual-Audience Explainability Reports...');
    }, 3800);

    try {
      const res = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, force_fresh: forceFresh }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Analysis request failed with HTTP ${res.status}`);
      }

      const data = await res.json();
      setCurrentAnalysis(data);
      setSelectedId(data.analysis_id);

      // Refresh stats & history in background
      fetchStats();
      fetchHistory(verdictFilter);
    } catch (err) {
      setError(err.message || 'An unexpected error occurred during URL evaluation.');
    } finally {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
      setAnalyzing(false);
      setAnalyzingStep('');
    }
  };

  // Select historical scan to inspect
  const handleSelectHistoryItem = async (analysisId) => {
    if (selectedId === analysisId && currentAnalysis) {
      // Already displaying this record; scroll to it
      window.scrollTo({ top: 380, behavior: 'smooth' });
      return;
    }

    try {
      const res = await fetch(`/api/v1/analysis/${analysisId}`);
      if (!res.ok) {
        throw new Error(`Failed to load analysis record (HTTP ${res.status})`);
      }
      const data = await res.json();
      setCurrentAnalysis(data);
      setSelectedId(analysisId);
      window.scrollTo({ top: 380, behavior: 'smooth' });
    } catch (err) {
      setError(err.message || 'Failed to retrieve detailed historical analysis.');
    }
  };

  // Delete historical scan
  const handleDeleteHistoryItem = async (analysisId) => {
    try {
      const res = await fetch(`/api/v1/analysis/${analysisId}`, { method: 'DELETE' });
      if (!res.ok) {
        throw new Error(`Failed to delete record (HTTP ${res.status})`);
      }
      if (selectedId === analysisId) {
        setCurrentAnalysis(null);
        setSelectedId(null);
      }
      fetchHistory(verdictFilter);
      fetchStats();
    } catch (err) {
      setError(err.message || 'Failed to delete analysis record.');
    }
  };

  // Handle filter change
  const handleFilterChange = (newFilter) => {
    setVerdictFilter(newFilter);
    fetchHistory(newFilter);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* 1. Top Navbar */}
      <Navbar 
        health={health} 
        loading={loadingHealth} 
        onRefresh={() => {
          fetchHealth();
          fetchStats();
          fetchHistory(verdictFilter);
        }} 
      />

      {/* 2. Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Research Telemetry Statistics Bar */}
        <StatsBar stats={stats} />

        {/* Target URL Input & Quick Lure Samples */}
        <UrlInputBar onAnalyze={handleAnalyze} loading={analyzing} />

        {/* Error Notification Alert */}
        {error && (
          <div className="bg-rose-950/40 border border-rose-900/60 rounded-2xl p-4 text-rose-200 text-sm flex items-start justify-between gap-3 shadow-lg">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-rose-300">Analysis Pipeline Notice</p>
                <p className="text-xs text-rose-200/90 font-mono mt-0.5">{error}</p>
              </div>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-xs text-rose-400 hover:text-rose-200 font-medium px-2 py-1 rounded bg-rose-900/30 hover:bg-rose-900/50 transition"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Live Scan Pipeline Loading Card */}
        {analyzing && (
          <div className="bg-gradient-to-r from-blue-950/40 via-slate-900 to-indigo-950/40 border border-blue-900/50 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/30">
                <RefreshCw className="w-6 h-6 animate-spin text-blue-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-semibold text-white">
                    RISE-Phish Forensic Pipeline Active
                  </h3>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30 animate-pulse">
                    Processing
                  </span>
                </div>
                <p className="text-xs font-mono text-blue-300/80 mt-1">
                  {analyzingStep || 'Orchestrating pipeline analysis across representation generators...'}
                </p>
              </div>
            </div>

            {/* Stepper tracker */}
            <div className="mt-5 grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] font-mono">
              <div className="p-2 rounded-lg bg-slate-950/50 border border-slate-800 flex items-center gap-1.5 text-blue-300">
                <Server className="w-3.5 h-3.5" />
                <span>1. DOM Crawler</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-950/50 border border-slate-800 flex items-center gap-1.5 text-blue-300">
                <Layers className="w-3.5 h-3.5" />
                <span>2. R1-R5 Suite</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-950/50 border border-slate-800 flex items-center gap-1.5 text-blue-300">
                <FileSearch className="w-3.5 h-3.5" />
                <span>3. CRCE Matrix</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-950/50 border border-slate-800 flex items-center gap-1.5 text-blue-300">
                <Cpu className="w-3.5 h-3.5" />
                <span>4. SLM & Fusion</span>
              </div>
            </div>
          </div>
        )}

        {/* Current Forensic Analysis Results */}
        {currentAnalysis && (
          <div className="space-y-6 pt-2">
            <div className="flex items-center justify-between pb-1 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider font-mono text-blue-400">
                  Forensic Evaluation Report
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  ID: {currentAnalysis.analysis_id?.slice(0, 8)}...
                </span>
              </div>
              <span className="text-xs text-slate-400 flex items-center gap-1 font-mono">
                <Clock className="w-3.5 h-3.5" />
                {currentAnalysis.completed_at ? new Date(currentAnalysis.completed_at).toLocaleTimeString() : 'Just now'}
              </span>
            </div>

            {/* High-Impact Verdict Banner */}
            <VerdictBanner result={currentAnalysis} />

            {/* Explainable Insights: User Advisory */}
            {currentAnalysis.explanation?.user_advisory && (
              <UserAdvisoryCard advisory={currentAnalysis.explanation.user_advisory} />
            )}

            {/* Multi-Representation Viewer (R1 - R5) */}
            {currentAnalysis.representations && (
              <RepresentationViewer representations={currentAnalysis.representations} />
            )}

            {/* SOC Analyst Deep Forensic Drawer */}
            {currentAnalysis.explanation?.analyst_forensic_report && (
              <AnalystDrawer 
                report={currentAnalysis.explanation.analyst_forensic_report} 
                crce={currentAnalysis.crce}
                unicodeAnalysis={currentAnalysis.unicode_analysis}
              />
            )}
          </div>
        )}

        {/* Historical Scans Archive */}
        <ScanHistory
          items={historyItems}
          total={historyTotal}
          loading={loadingHistory}
          selectedId={selectedId}
          verdictFilter={verdictFilter}
          onSelect={handleSelectHistoryItem}
          onDelete={handleDeleteHistoryItem}
          onRefresh={() => fetchHistory(verdictFilter)}
          onFilterChange={handleFilterChange}
        />
      </main>

      {/* 3. Footer */}
      <footer className="border-t border-slate-800/80 py-6 px-6 bg-slate-900/40 mt-12 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <p className="font-mono">
            RISE-Phish Research System • Final-Year B.Tech Capstone Project
          </p>
          <p className="text-slate-400">
            Multi-Representation Discrepancy Architecture • RTX 3050 Optimized
          </p>
        </div>
      </footer>
    </div>
  );
}

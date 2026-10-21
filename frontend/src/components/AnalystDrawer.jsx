import React, { useState } from 'react';
import { 
  Terminal, 
  ChevronDown, 
  ChevronUp, 
  Zap, 
  Cpu, 
  Lock, 
  FileSearch, 
  AlertCircle,
  Code
} from 'lucide-react';

export default function AnalystDrawer({ report, crce, unicodeAnalysis }) {
  const [isOpen, setIsOpen] = useState(false);

  if (!report) return null;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden transition-all">
      {/* Drawer Toggle Header */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4.5 flex items-center justify-between text-left hover:bg-slate-800/40 transition border-b border-slate-800/60"
      >
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white">
                SOC Analyst Technical Forensics
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/20 font-mono">
                Expert Investigation Mode
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deep inspection of CRCE divergence metrics, Unicode codepoints, credential traps, and SLM recovery traces.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span>{isOpen ? 'Collapse Forensics' : 'Expand Full Forensics'}</span>
          {isOpen ? <ChevronUp className="w-4 h-4 text-purple-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </div>
      </button>

      {/* Expanded Technical Content */}
      {isOpen && (
        <div className="p-6 space-y-6 bg-slate-950/60">
          {/* 1. CRCE Pairwise Matrix */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
              <FileSearch className="w-3.5 h-3.5 text-blue-400" />
              <span>1. Cross-Representation Discrepancy Engine (CRCE) Metrics</span>
            </h4>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[11px] mb-1">R1 vs R2 (Raw vs Norm)</span>
                <span className="text-lg font-black text-rose-400">
                  {report.discrepancy_forensics?.r1_r2_discrepancy?.toFixed(4) ?? '0.0000'}
                </span>
                <span className="text-[10px] text-slate-500 block mt-1">RapidFuzz Levenshtein NED</span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[11px] mb-1">R1 vs R3 (Raw vs Visual)</span>
                <span className="text-lg font-black text-rose-400">
                  {report.discrepancy_forensics?.r1_r3_discrepancy?.toFixed(4) ?? '0.0000'}
                </span>
                <span className="text-[10px] text-slate-500 block mt-1">Visual Divergence Score</span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[11px] mb-1">R2 vs R3 (Norm vs Visual)</span>
                <span className="text-lg font-black text-emerald-400">
                  {report.discrepancy_forensics?.r2_r3_discrepancy?.toFixed(4) ?? '0.0000'}
                </span>
                <span className="text-[10px] text-slate-500 block mt-1">Convergence Metric</span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[11px] mb-1">R5 vs Brand Authority</span>
                <span className="text-lg font-black text-amber-400">
                  {report.discrepancy_forensics?.r5_brand_discrepancy?.toFixed(4) ?? '0.0000'}
                </span>
                <span className="text-[10px] text-slate-500 block mt-1">Host Ownership Verification</span>
              </div>
            </div>

            {report.discrepancy_forensics?.visual_normalization_convergence && (
              <div className="p-3.5 rounded-xl bg-purple-950/30 border border-purple-800/40 flex items-start gap-3">
                <Zap className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
                <div className="text-xs">
                  <span className="font-bold text-purple-300 font-mono block">
                    CRITICAL: Visual-Normalization Convergence Evasion Detected
                  </span>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    The raw DOM markup ($R_1$) purposefully diverges from browser visual rendering ($R_3$), but canonical NFKC normalization ($R_2$) traceably matches visual OCR. This proves active, deliberate security filter evasion.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* 2. Unicode Forensics Audit */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
                <Code className="w-3.5 h-3.5 text-purple-400" />
                <span>2. Unicode Forensic Inspection & Codepoints</span>
              </h4>
              <span className="text-xs font-mono text-purple-400">
                Total Anomalies: {report.unicode_anomalies_count}
              </span>
            </div>

            {/* Unicode findings summary */}
            {report.key_unicode_findings && report.key_unicode_findings.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                {report.key_unicode_findings.map((f, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                    <span className="truncate">{f}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 bg-slate-900 p-3 rounded-lg border border-slate-800">
                No suspicious Unicode codepoint anomalies detected.
              </p>
            )}

            {/* Detailed anomaly codepoint table if present */}
            {unicodeAnalysis && unicodeAnalysis.anomalies && unicodeAnalysis.anomalies.length > 0 && (
              <div className="overflow-x-auto rounded-xl border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px]">
                    <tr>
                      <th className="py-2.5 px-3">Codepoint</th>
                      <th className="py-2.5 px-3">Glyph</th>
                      <th className="py-2.5 px-3">Script</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">NFKC Norm</th>
                      <th className="py-2.5 px-3">Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 bg-slate-950">
                    {unicodeAnalysis.anomalies.slice(0, 8).map((a, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-purple-400 font-bold">{a.codepoint}</td>
                        <td className="py-2 px-3 text-white font-mono bg-slate-900/60">{a.character}</td>
                        <td className="py-2 px-3 text-slate-300">{a.script}</td>
                        <td className="py-2 px-3 text-amber-400">{a.anomaly_type}</td>
                        <td className="py-2 px-3 text-emerald-400">{a.normalized_nfkc || '-'}</td>
                        <td className="py-2 px-3 text-slate-400 text-[11px] truncate max-w-xs">{a.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* 3. Credential Harvesting Vectors */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-rose-400" />
              <span>3. Interactive Credential Interception Vectors</span>
            </h4>

            {report.credential_vectors && report.credential_vectors.length > 0 ? (
              <div className="space-y-2">
                {report.credential_vectors.map((vec, i) => (
                  <div key={i} className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-rose-300 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-rose-400 shrink-0"></span>
                    <span>{vec}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 bg-slate-900 p-3 rounded-lg border border-slate-800">
                No interactive credential inputs or sensitive password forms discovered.
              </p>
            )}
          </div>

          {/* 4. SLM Dual-Task Narrative */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span>4. Lightweight SLM Reasoning & Semantic De-Obfuscation</span>
            </h4>

            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3 text-xs">
              {report.slm_recovery_summary && (
                <div>
                  <span className="text-[11px] font-bold text-slate-400 uppercase font-mono block">
                    Task 1: Semantic Recovery Trace
                  </span>
                  <p className="text-slate-300 mt-1 leading-relaxed font-mono">
                    {report.slm_recovery_summary}
                  </p>
                </div>
              )}

              {report.slm_reasoning_summary && (
                <div className="pt-2 border-t border-slate-800">
                  <span className="text-[11px] font-bold text-slate-400 uppercase font-mono block">
                    Task 2: Phishing Intent Reasoning Narrative
                  </span>
                  <p className="text-slate-300 mt-1 leading-relaxed">
                    {report.slm_reasoning_summary}
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* 5. Deterministic Rules Triggered */}
          {report.rules_triggered && report.rules_triggered.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <span className="text-[11px] font-bold text-slate-400 uppercase font-mono block">
                Triggered Decision Policy Rules:
              </span>
              <div className="flex flex-wrap gap-2">
                {report.rules_triggered.map((rule, idx) => (
                  <span key={idx} className="px-2.5 py-1 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/20 text-xs font-mono">
                    {rule}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

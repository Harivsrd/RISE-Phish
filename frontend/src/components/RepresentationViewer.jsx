import React, { useState } from 'react';
import { Layers, FileCode, CheckCircle2, Image, Brain, Globe, Copy, Check } from 'lucide-react';

export default function RepresentationViewer({ representations }) {
  if (!representations) return null;

  const [activeTab, setActiveTab] = useState('r1');
  const [copied, setCopied] = useState(false);

  const tabs = [
    {
      id: 'r1',
      label: 'R1: Raw Text',
      icon: FileCode,
      desc: 'Direct DOM string extraction before normalization',
    },
    {
      id: 'r2',
      label: 'R2: Normalized',
      icon: CheckCircle2,
      desc: 'Traceable NFKC decomposition and control stripping',
    },
    {
      id: 'r3',
      label: 'R3: Visual / OCR',
      icon: Image,
      desc: 'Tesseract OCR rasterization ground truth',
    },
    {
      id: 'r4',
      label: 'R4: Semantic',
      icon: Brain,
      desc: 'Form intents, titles, and layout structure',
    },
    {
      id: 'r5',
      label: 'R5: URL Lexical',
      icon: Globe,
      desc: 'Decomposed hostname, subdomain, and domain tokens',
    },
  ];

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const r1 = representations.r1_raw;
  const r2 = representations.r2_normalized;
  const r3 = representations.r3_visual;
  const r4 = representations.r4_semantic;
  const r5 = representations.r5_url;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <span>Multi-Representation Suite (R1 - R5)</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Inspect the 5 parallel representations generated for Cross-Representation Discrepancy Analysis (CRCE).
          </p>
        </div>

        {/* Tab selector buttons */}
        <div className="flex flex-wrap gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label.split(':')[0]}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Panels */}
      <div className="space-y-3">
        {/* R1: RAW */}
        {activeTab === 'r1' && r1 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{tabs[0].desc}</span>
              <div className="flex items-center gap-3">
                <span className="font-mono">Length: {r1.character_count} chars</span>
                <button
                  onClick={() => handleCopy(r1.text)}
                  className="flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy</span>
                </button>
              </div>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 whitespace-pre-wrap max-h-64 overflow-y-auto leading-relaxed">
              {r1.text || '<Empty DOM Text>'}
            </pre>
          </div>
        )}

        {/* R2: NORMALIZED */}
        {activeTab === 'r2' && r2 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{tabs[1].desc}</span>
              <div className="flex items-center gap-3">
                <span className="font-mono">Altered Chars: {r2.characters_altered_count}</span>
                <button
                  onClick={() => handleCopy(r2.text)}
                  className="flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy</span>
                </button>
              </div>
            </div>

            {/* Transformations applied badge row */}
            {r2.transformations_applied && r2.transformations_applied.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px]">
                <span className="text-slate-400 font-mono">Applied Audits:</span>
                {r2.transformations_applied.map((t, idx) => (
                  <span key={idx} className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            )}

            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 whitespace-pre-wrap max-h-64 overflow-y-auto leading-relaxed">
              {r2.text || '<Empty Normalized Text>'}
            </pre>
          </div>
        )}

        {/* R3: VISUAL OCR */}
        {activeTab === 'r3' && r3 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{tabs[2].desc}</span>
              <div className="flex items-center gap-3">
                <span className="font-mono">OCR Confidence: {r3.confidence?.toFixed(1) || 'N/A'}%</span>
                <button
                  onClick={() => handleCopy(r3.text)}
                  className="flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy</span>
                </button>
              </div>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-purple-300 whitespace-pre-wrap max-h-64 overflow-y-auto leading-relaxed">
              {r3.text || '<No OCR Text Available - Empty Screenshot>'}
            </pre>
          </div>
        )}

        {/* R4: SEMANTIC */}
        {activeTab === 'r4' && r4 && (
          <div className="space-y-3">
            <div className="text-xs text-slate-400">{tabs[3].desc}</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 font-mono text-[11px] uppercase">Page Title:</span>
                <p className="font-semibold text-white">{r4.title || 'Untitled'}</p>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 font-mono text-[11px] uppercase">Form Intent Summary:</span>
                <p className="font-semibold text-amber-400">{r4.form_intent_summary || 'General Info'}</p>
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 font-mono text-[11px] uppercase">Headings Hierarchy:</span>
              <p className="font-mono text-xs text-slate-300">{r4.headings_text || 'No headings detected'}</p>
            </div>
          </div>
        )}

        {/* R5: URL */}
        {activeTab === 'r5' && r5 && (
          <div className="space-y-3">
            <div className="text-xs text-slate-400">{tabs[4].desc}</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Registered Domain</span>
                <span className="text-blue-400 font-bold truncate block">{r5.registered_domain || 'N/A'}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Subdomain</span>
                <span className="text-slate-200 truncate block">{r5.subdomain || 'None'}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">TLD</span>
                <span className="text-slate-200 truncate block">.{r5.tld}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Path</span>
                <span className="text-slate-200 truncate block">{r5.path || '/'}</span>
              </div>
            </div>

            {r5.domain_tokens && r5.domain_tokens.length > 0 && (
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs flex items-center gap-2">
                <span className="text-slate-400 font-mono">Lexical Tokens:</span>
                <div className="flex flex-wrap gap-1">
                  {r5.domain_tokens.map((tok, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono text-[11px]">
                      {tok}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

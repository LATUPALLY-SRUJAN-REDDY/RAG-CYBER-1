import React, { useState } from 'react';
import { Search, Zap, CheckCircle2, AlertTriangle, ShieldAlert, Cpu, Sparkles, BookOpen, Clock, Tag } from 'lucide-react';

const PRESET_QUERIES = [
  "What attack patterns and ATT&CK techniques exploit SQL Injection (CWE-89)?",
  "How does buffer overflow lead to arbitrary code execution and adversary persistence?",
  "What are the mitigations and defensive measures for Cross-Site Scripting (CWE-79)?",
  "Describe adversary techniques (MITRE ATT&CK) linked to credential dumping.",
];

export default function RagPlayground({ onExecuteQuery, isQuerying }) {
  const [question, setQuestion] = useState(PRESET_QUERIES[0]);
  const [mode, setMode] = useState("hybrid");
  const [topK, setTopK] = useState(10);
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState("answer"); // "answer" | "evidence" | "validation"

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    if (!question.trim() || isQuerying) return;

    try {
      const res = await onExecuteQuery({
        question: question.trim(),
        retrieval_mode: mode,
        top_k: topK,
      });
      setResult(res);
      setActiveTab("answer");
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="rag-playground-view">
      {/* Search Input Box */}
      <div className="glass-panel search-panel">
        <form onSubmit={handleSubmit}>
          <div className="search-bar-row">
            <div className="search-input-wrap">
              <Search className="search-icon" size={20} />
              <input 
                type="text" 
                className="query-input"
                placeholder="Ask a cybersecurity question (e.g. CVE-2026, CWE weaknesses, adversary techniques)..."
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
              />
            </div>
            <button 
              type="submit" 
              className="btn btn-primary search-submit-btn"
              disabled={isQuerying || !question.trim()}
            >
              <Zap size={16} />
              {isQuerying ? "Retrieving..." : "Analyze Threat"}
            </button>
          </div>

          {/* Preset Prompts */}
          <div className="preset-chips">
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', alignSelf: 'center' }}>Examples:</span>
            {PRESET_QUERIES.map((q, idx) => (
              <button 
                key={idx}
                type="button"
                className="chip-btn"
                onClick={() => setQuestion(q)}
              >
                {q}
              </button>
            ))}
          </div>

          {/* Controls Bar */}
          <div className="query-controls-bar">
            <div className="control-group">
              <span className="control-label">Retrieval Engine:</span>
              <div className="mode-toggle-group">
                <button
                  type="button"
                  className={`mode-btn ${mode === 'hybrid' ? 'active' : ''}`}
                  onClick={() => setMode('hybrid')}
                >
                  <Sparkles size={13} />
                  Hybrid (Graph + Semantic)
                </button>
                <button
                  type="button"
                  className={`mode-btn ${mode === 'graph' ? 'active' : ''}`}
                  onClick={() => setMode('graph')}
                >
                  <Cpu size={13} />
                  Graph-Only
                </button>
                <button
                  type="button"
                  className={`mode-btn ${mode === 'semantic' ? 'active' : ''}`}
                  onClick={() => setMode('semantic')}
                >
                  <Zap size={13} />
                  Semantic-Only
                </button>
              </div>
            </div>

            <div className="control-group">
              <span className="control-label">Top-K Evidence: <strong className="mono" style={{ color: 'var(--accent-cyan)' }}>{topK}</strong></span>
              <input 
                type="range" 
                min="3" 
                max="25" 
                value={topK} 
                onChange={(e) => setTopK(Number(e.target.value))}
                className="slider-range"
              />
            </div>
          </div>
        </form>
      </div>

      {/* Results View */}
      {result && (
        <div className="glass-panel results-panel">
          {/* Performance HUD */}
          <div className="perf-hud">
            <div className="perf-metric">
              <span className="perf-label"><Clock size={12} /> Total Latency</span>
              <span className="perf-val mono" style={{ color: 'var(--accent-cyan)' }}>{result.performance?.total_ms || 0} ms</span>
            </div>
            <div className="perf-metric">
              <span className="perf-label">Retrieval</span>
              <span className="perf-val mono">{result.performance?.retrieval_ms || 0} ms</span>
            </div>
            <div className="perf-metric">
              <span className="perf-label">Generation</span>
              <span className="perf-val mono">{result.performance?.generation_ms || 0} ms</span>
            </div>
            <div className="perf-metric">
              <span className="perf-label">Validation</span>
              <span className="perf-val mono">{result.performance?.validation_ms || 0} ms</span>
            </div>
            <div className="perf-metric">
              <span className="perf-label">Groundedness</span>
              <span className="perf-val mono" style={{ color: result.validation?.groundedness >= 0.8 ? '#00ff9d' : '#ffb700' }}>
                {Math.round((result.validation?.groundedness || 0) * 100)}%
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="result-subtabs">
            <button 
              className={`subtab-btn ${activeTab === 'answer' ? 'active' : ''}`}
              onClick={() => setActiveTab('answer')}
            >
              <BookOpen size={14} /> Threat Intelligence Synthesis
            </button>
            <button 
              className={`subtab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
              onClick={() => setActiveTab('evidence')}
            >
              <Tag size={14} /> Retrieved Evidence ({result.evidence?.length || 0})
            </button>
            <button 
              className={`subtab-btn ${activeTab === 'validation' ? 'active' : ''}`}
              onClick={() => setActiveTab('validation')}
            >
              <CheckCircle2 size={14} /> Claim Grounding Verification
            </button>
          </div>

          {/* Content Pane */}
          {activeTab === 'answer' && (
            <div className="answer-pane">
              <div className="answer-text">
                {result.answer.split('\n').map((line, idx) => {
                  if (line.startsWith('**') && line.endsWith('**')) {
                    return <h4 key={idx} style={{ color: 'var(--accent-cyan)', margin: '14px 0 6px' }}>{line.replace(/\*\*/g, '')}</h4>;
                  }
                  if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
                    return <li key={idx} style={{ marginLeft: '20px', color: '#e2e8f0', margin: '4px 0' }}>{line.replace(/^[-*]\s+/, '')}</li>;
                  }
                  return <p key={idx} style={{ margin: '8px 0', lineHeight: '1.65' }}>{line}</p>;
                })}
              </div>

              {result.citations && result.citations.length > 0 && (
                <div className="citations-tray">
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)', fontWeight: 600 }}>Citations:</span>
                  <div className="citations-list">
                    {result.citations.map((c, i) => (
                      <span key={i} className="citation-tag mono">{c}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="evidence-pane">
              <div className="evidence-grid">
                {result.evidence && result.evidence.map((ev, i) => (
                  <div key={i} className="evidence-card">
                    <div className="evidence-card-header">
                      <span className={`badge badge-${(ev.entity_type || 'cve').toLowerCase()}`}>
                        {ev.entity_type} {ev.id}
                      </span>
                      <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                        Score: {ev.relevance_score}
                      </span>
                    </div>
                    <p className="evidence-desc">{ev.description || "No detailed description recorded."}</p>
                    <div className="evidence-footer">
                      <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        Source: {ev.source} | Method: {ev.retrieval_method}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'validation' && (
            <div className="validation-pane">
              <div className="validation-summary-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {result.validation?.status === 'SUPPORTED' ? (
                    <CheckCircle2 color="#00ff9d" size={24} />
                  ) : (
                    <AlertTriangle color="#ffb700" size={24} />
                  )}
                  <div>
                    <h4 style={{ color: '#fff' }}>Validation Status: {result.validation?.status}</h4>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                      {result.validation?.supported_claims?.length || 0} of {result.validation?.total_claims || 0} claims directly grounded in retrieved knowledge.
                    </p>
                  </div>
                </div>
              </div>

              <div className="claims-columns">
                <div className="claims-col">
                  <h4 style={{ color: '#00ff9d', marginBottom: '10px', fontSize: '0.9rem' }}>Supported Claims:</h4>
                  {result.validation?.supported_claims?.map((c, i) => (
                    <div key={i} className="claim-box supported">
                      <CheckCircle2 size={14} color="#00ff9d" style={{ flexShrink: 0, marginTop: '2px' }} />
                      <span>{c}</span>
                    </div>
                  ))}
                  {(!result.validation?.supported_claims || result.validation.supported_claims.length === 0) && (
                    <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No grounded claims detected.</p>
                  )}
                </div>

                <div className="claims-col">
                  <h4 style={{ color: '#ff3366', marginBottom: '10px', fontSize: '0.9rem' }}>Unsupported / Ungrounded Claims:</h4>
                  {result.validation?.unsupported_claims?.map((c, i) => (
                    <div key={i} className="claim-box unsupported">
                      <AlertTriangle size={14} color="#ff3366" style={{ flexShrink: 0, marginTop: '2px' }} />
                      <span>{c}</span>
                    </div>
                  ))}
                  {(!result.validation?.unsupported_claims || result.validation.unsupported_claims.length === 0) && (
                    <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No ungrounded claims detected.</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

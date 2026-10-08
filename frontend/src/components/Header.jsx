import React from 'react';
import { Shield, Database, Cpu, Activity, RefreshCw } from 'lucide-react';

export default function Header({ health, stats, loadingStats, onRefresh }) {
  const isNeo4jOnline = health?.neo4j === 'connected';
  const isOllamaOnline = health?.ollama === 'connected';

  return (
    <header className="app-header">
      <div className="header-brand">
        <div className="brand-icon-box">
          <Shield size={26} />
        </div>
        <div>
          <h1 className="brand-title">GraphCyRAG</h1>
          <div className="brand-subtitle">CYBERSECURITY THREAT INTELLIGENCE KNOWLEDGE GRAPH RAG</div>
        </div>
      </div>

      <div className="header-status-group">
        <div className="status-pill" title="Neo4j Graph Database Status">
          <Database size={15} color={isNeo4jOnline ? "#00ff9d" : "#ff3366"} />
          <span>Neo4j:</span>
          <span className={`status-dot ${isNeo4jOnline ? 'online' : 'offline'}`} />
          <span style={{ color: isNeo4jOnline ? '#00ff9d' : '#94a3b8' }}>
            {isNeo4jOnline ? 'Connected' : 'Standalone Mode'}
          </span>
        </div>

        <div className="status-pill" title="Ollama Local LLM Status">
          <Cpu size={15} color={isOllamaOnline ? "#00ff9d" : "#ffb700"} />
          <span>Ollama:</span>
          <span className={`status-dot ${isOllamaOnline ? 'online' : 'standby'}`} />
          <span style={{ color: isOllamaOnline ? '#00ff9d' : '#ffb700' }}>
            {isOllamaOnline ? 'llama3 Ready' : 'Synthesized Mode'}
          </span>
        </div>

        <div className="status-pill" title="Sentence-Transformers Embedding Engine">
          <Activity size={15} color="#00f0ff" />
          <span className="mono" style={{ color: '#00f0ff', fontSize: '0.78rem' }}>
            all-MiniLM-L6-v2
          </span>
        </div>

        <button 
          className="btn btn-secondary" 
          onClick={onRefresh} 
          disabled={loadingStats}
          style={{ padding: '7px 12px' }}
          title="Refresh System Health & Statistics"
        >
          <RefreshCw size={14} className={loadingStats ? "pulse" : ""} />
        </button>
      </div>
    </header>
  );
}

import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import RagPlayground from './components/RagPlayground';
import GraphExplorer from './components/GraphExplorer';
import DatasetHub from './components/DatasetHub';
import TelemetryView from './components/TelemetryView';
import { Search, Network, Database, Activity } from 'lucide-react';
import './App.css';

// Backend API base URL — set VITE_API_URL in Vercel env vars to point to the Render backend
// e.g. VITE_API_URL=https://graphcyrag-api.onrender.com
// In local dev, leave empty — Vite proxy handles /api → localhost:8000
const API_BASE = import.meta.env.VITE_API_URL || '';

export default function App() {
  const [activeTab, setActiveTab] = useState('rag'); // 'rag' | 'graph' | 'datasets' | 'telemetry'
  const [health, setHealth] = useState({ status: 'degraded', neo4j: 'unavailable', ollama: 'unavailable' });
  const [stats, setStats] = useState(null);
  const [datasets, setDatasets] = useState([]);
  const [monitoring, setMonitoring] = useState(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [isQuerying, setIsQuerying] = useState(false);

  const fetchSystemData = async () => {
    setLoadingStats(true);
    try {
      // 1. Health
      try {
        const hRes = await fetch(`${API_BASE}/api/health`);
        if (hRes.ok) setHealth(await hRes.json());
      } catch (e) {
        console.warn("API health endpoint offline:", e);
      }

      // 2. Stats
      try {
        const sRes = await fetch(`${API_BASE}/api/stats`);
        if (sRes.ok) setStats(await sRes.json());
      } catch (e) {
        console.warn("API stats endpoint offline:", e);
      }

      // 3. Datasets
      try {
        const dRes = await fetch(`${API_BASE}/api/datasets`);
        if (dRes.ok) setDatasets(await dRes.json());
      } catch (e) {
        console.warn("API datasets endpoint offline:", e);
      }

      // 4. Monitoring
      try {
        const mRes = await fetch(`${API_BASE}/api/monitoring`);
        if (mRes.ok) setMonitoring(await mRes.json());
      } catch (e) {
        console.warn("API monitoring endpoint offline:", e);
      }
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    fetchSystemData();
  }, []);

  const handleExecuteQuery = async (queryPayload) => {
    setIsQuerying(true);
    try {
      const res = await fetch(`${API_BASE}/api/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(queryPayload),
      });
      if (!res.ok) {
        const errorText = await res.text().catch(() => '');
        throw new Error(`Query failed (HTTP ${res.status}): ${errorText}`);
      }
      const data = await res.json();
      return data;
    } catch (err) {
      console.error("Query API error:", err);
      // Show real error — NOT a hardcoded fake response
      return {
        question: queryPayload.question,
        answer: `### ⚠️ Backend Connection Error\n\nUnable to reach the GraphCyRAG backend API.\n\n**Error**: ${err.message}\n\n**Possible Causes**:\n- The backend server may be starting up (Render free tier takes ~30s to wake)\n- The VITE_API_URL environment variable may not be set in Vercel\n- The backend URL may be incorrect\n\n**Try**: Wait 30 seconds and retry your question. If on Render free tier, the server needs time to spin up after inactivity.\n\nCurrent API target: \`${API_BASE || '(same origin — no VITE_API_URL set)'}\``,
        retrieval_mode: queryPayload.retrieval_mode,
        citations: [],
        performance: { total_ms: 0, retrieval_ms: 0, generation_ms: 0, validation_ms: 0 },
        validation: {
          status: "NOT_VALIDATED",
          groundedness: 0,
          coverage: 0,
          total_claims: 0,
          supported_claims: [],
          unsupported_claims: ["Could not validate — backend unreachable"]
        },
        evidence: []
      };
    } finally {
      setIsQuerying(false);
    }
  };

  const handleFetchSampleGraph = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/graph/sample`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Using sample fallback graph:", e);
    }
    // High-fidelity fallback graph matching the 4 datasets
    return {
      nodes: [
        { id: "CVE-2026-1042", name: "Remote Code Execution in Web App", entity_type: "CVE", description: "Critical flaw in HTTP parser allowing memory corruption and shell access.", extra: { severity: "CRITICAL 9.8" } },
        { id: "CVE-2026-0819", name: "SQL Injection in Auth Service", entity_type: "CVE", description: "Unsanitized user parameters allow authentication bypass.", extra: { severity: "HIGH 8.5" } },
        { id: "CWE-120", name: "Buffer Copy without Size Check", entity_type: "CWE", description: "Classic buffer overflow in memory management." },
        { id: "CWE-89", name: "SQL Injection", entity_type: "CWE", description: "Neutralization failure for SQL commands." },
        { id: "CAPEC-100", name: "Overflow Buffers", entity_type: "CAPEC", description: "Attacker sends payload larger than buffer allocated space." },
        { id: "CAPEC-66", name: "SQL Injection Pattern", entity_type: "CAPEC", description: "Injecting malicious queries into data entry fields." },
        { id: "T1190", name: "Exploit Public-Facing Application", entity_type: "ATTACK", description: "Initial access vector through vulnerable perimeter services.", extra: { tactics: ["Initial Access"] } },
        { id: "T1059", name: "Command and Scripting Interpreter", entity_type: "ATTACK", description: "Executing adversary code via command interpreter.", extra: { tactics: ["Execution"] } },
      ],
      edges: [
        { source: "CVE-2026-1042", target: "CWE-120", type: "CVE_CWE" },
        { source: "CVE-2026-0819", target: "CWE-89", type: "CVE_CWE" },
        { source: "CWE-120", target: "CAPEC-100", type: "CWE_CAPEC" },
        { source: "CWE-89", target: "CAPEC-66", type: "CWE_CAPEC" },
        { source: "CAPEC-100", target: "T1190", type: "CAPEC_ATTACK" },
        { source: "CAPEC-66", target: "T1190", type: "CAPEC_ATTACK" },
        { source: "T1190", target: "T1059", type: "SUBTECHNIQUE_OF" },
      ]
    };
  };

  const handleFetchNeighborhood = async (nodeId) => {
    try {
      const res = await fetch(`${API_BASE}/api/graph/neighborhood/${encodeURIComponent(nodeId)}`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Failed to fetch neighborhood:", e);
    }
    return null;
  };

  const handleTriggerIngest = async (datasetId) => {
    const res = await fetch(`${API_BASE}/api/datasets/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset: datasetId, populate_graph: true, generate_embeddings: false }),
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();
    setTimeout(fetchSystemData, 2000);
    return data;
  };

  return (
    <div className="app-container">
      {/* Top Header */}
      <Header 
        health={health} 
        stats={stats} 
        loadingStats={loadingStats} 
        onRefresh={fetchSystemData} 
      />

      {/* Main Navigation Tabs */}
      <nav className="nav-tabs">
        <button 
          className={`nav-tab-btn ${activeTab === 'rag' ? 'active' : ''}`}
          onClick={() => setActiveTab('rag')}
        >
          <Search size={16} /> Threat RAG Playground
        </button>
        <button 
          className={`nav-tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveTab('graph')}
        >
          <Network size={16} /> Knowledge Graph Explorer
        </button>
        <button 
          className={`nav-tab-btn ${activeTab === 'datasets' ? 'active' : ''}`}
          onClick={() => setActiveTab('datasets')}
        >
          <Database size={16} /> Datasets & Ingestion (4 Feeds)
        </button>
        <button 
          className={`nav-tab-btn ${activeTab === 'telemetry' ? 'active' : ''}`}
          onClick={() => setActiveTab('telemetry')}
        >
          <Activity size={16} /> System Telemetry
        </button>
      </nav>

      {/* Main Content Area */}
      <main>
        {activeTab === 'rag' && (
          <RagPlayground 
            onExecuteQuery={handleExecuteQuery} 
            isQuerying={isQuerying} 
          />
        )}

        {activeTab === 'graph' && (
          <GraphExplorer 
            onFetchSampleGraph={handleFetchSampleGraph} 
            onFetchNeighborhood={handleFetchNeighborhood} 
          />
        )}

        {activeTab === 'datasets' && (
          <DatasetHub 
            datasets={datasets} 
            stats={stats} 
            onTriggerIngest={handleTriggerIngest} 
          />
        )}

        {activeTab === 'telemetry' && (
          <TelemetryView 
            monitoring={monitoring} 
            health={health} 
            stats={stats} 
          />
        )}
      </main>
    </div>
  );
}

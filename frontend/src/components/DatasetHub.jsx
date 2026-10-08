import React, { useState } from 'react';
import { Database, FileCheck, Layers, Play, CheckCircle, AlertTriangle, Clock, HardDrive, RefreshCw } from 'lucide-react';

export default function DatasetHub({ datasets, stats, onTriggerIngest }) {
  const [ingesting, setIngesting] = useState({});
  const [ingestMsg, setIngestMsg] = useState('');

  const handleIngest = async (datasetId) => {
    setIngesting(prev => ({ ...prev, [datasetId]: true }));
    setIngestMsg(`Starting ingestion pipeline for ${datasetId.toUpperCase()}...`);
    try {
      const res = await onTriggerIngest(datasetId);
      setIngestMsg(res?.message || `Ingestion job started successfully.`);
    } catch (err) {
      setIngestMsg(`Failed to trigger ingestion: ${err.message}`);
    } finally {
      setTimeout(() => {
        setIngesting(prev => ({ ...prev, [datasetId]: false }));
      }, 3000);
    }
  };

  const getEntityCount = (type) => {
    if (!stats) return 0;
    switch(type) {
      case 'CVE': return stats.cve_count || 0;
      case 'CWE': return stats.cwe_count || 0;
      case 'CAPEC': return stats.capec_count || 0;
      case 'ATTACK': return stats.attack_count || 0;
      default: return 0;
    }
  };

  return (
    <div className="dataset-hub-view">
      <div className="section-header-banner">
        <div>
          <h2 style={{ fontSize: '1.4rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Database color="#00f0ff" size={22} />
            Cybersecurity Knowledge Base Datasets
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginTop: '4px' }}>
            The GraphCyRAG pipeline processes 4 foundational cybersecurity feeds into an interconnected ontology graph.
          </p>
        </div>

        <button 
          className="btn btn-emerald"
          onClick={() => handleIngest('all')}
          disabled={ingesting['all']}
        >
          <Play size={15} />
          {ingesting['all'] ? 'Ingesting All Datasets...' : 'Run Full Pipeline (All 4 Datasets)'}
        </button>
      </div>

      {ingestMsg && (
        <div className="alert-box">
          <Clock size={16} color="#00f0ff" />
          <span>{ingestMsg}</span>
        </div>
      )}

      <div className="dataset-grid">
        {datasets && datasets.map((ds) => {
          const typeClass = `badge-${ds.type.toLowerCase()}`;
          const isBusy = ingesting[ds.id] || ingesting['all'];
          const recordCount = getEntityCount(ds.type);

          return (
            <div key={ds.id} className="glass-panel dataset-card">
              <div className="dataset-card-top">
                <span className={`badge ${typeClass}`}>
                  {ds.type}
                </span>
                <span className="badge badge-success">
                  <FileCheck size={12} />
                  {ds.file_present ? 'File Detected' : 'Missing'}
                </span>
              </div>

              <h3 className="dataset-title">{ds.name}</h3>
              <p className="dataset-desc">{ds.description}</p>

              <div className="dataset-specs">
                <div className="spec-row">
                  <span className="spec-label"><HardDrive size={13} /> Raw File:</span>
                  <span className="spec-val mono">{ds.filename}</span>
                </div>
                <div className="spec-row">
                  <span className="spec-label"><Layers size={13} /> Size on Disk:</span>
                  <span className="spec-val mono">{ds.size_mb} MB</span>
                </div>
                <div className="spec-row">
                  <span className="spec-label"><Clock size={13} /> Version / Release:</span>
                  <span className="spec-val mono">{ds.version}</span>
                </div>
                <div className="spec-row">
                  <span className="spec-label"><Database size={13} /> Graph Entities:</span>
                  <span className="spec-val mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                    {recordCount > 0 ? recordCount.toLocaleString() : 'Ready to Parse'}
                  </span>
                </div>
              </div>

              <div className="dataset-card-footer">
                <button
                  className="btn btn-secondary"
                  style={{ width: '100%' }}
                  onClick={() => handleIngest(ds.id)}
                  disabled={isBusy}
                >
                  <Play size={14} color="#00f0ff" />
                  {isBusy ? 'Processing...' : `Ingest ${ds.id.toUpperCase()}`}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <div className="glass-panel ontology-banner">
        <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Layers size={18} />
          Ontology Relationship Pipeline
        </h4>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.86rem', lineHeight: '1.6' }}>
          When parsed, each dataset is mapped across four standard relationship layers:
          <strong style={{ color: '#fff' }}> NVD CVE</strong> links to <strong style={{ color: '#ffb700' }}>CWE</strong> weaknesses (<code>CVE_CWE</code>), 
          which link to <strong style={{ color: '#a855f7' }}>CAPEC</strong> attack patterns (<code>CWE_CAPEC</code>), 
          which in turn link to <strong style={{ color: '#00f0ff' }}>MITRE ATT&CK</strong> enterprise techniques (<code>CAPEC_ATTACK</code>).
        </p>
      </div>
    </div>
  );
}

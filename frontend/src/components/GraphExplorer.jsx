import React, { useState, useEffect, useRef } from 'react';
import { Network, Search, Filter, Layers, Info, ExternalLink, RefreshCw } from 'lucide-react';

const ENTITY_CONFIG = {
  CVE: { color: '#ff3366', bg: 'rgba(255, 51, 102, 0.2)', label: 'Vulnerability' },
  CWE: { color: '#ffb700', bg: 'rgba(255, 183, 0, 0.2)', label: 'Weakness' },
  CAPEC: { color: '#a855f7', bg: 'rgba(168, 85, 247, 0.2)', label: 'Attack Pattern' },
  ATTACK: { color: '#00f0ff', bg: 'rgba(0, 240, 255, 0.2)', label: 'Adversary Technique' },
};

export default function GraphExplorer({ onFetchSampleGraph, onFetchNeighborhood }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchId, setSearchId] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [loading, setLoading] = useState(false);
  const svgRef = useRef(null);

  // Position nodes with a clean force-directed/hierarchical layout
  const loadGraph = async () => {
    setLoading(true);
    try {
      const data = await onFetchSampleGraph();
      if (data && data.nodes) {
        // Lay out nodes
        const layoutNodes = data.nodes.map((n, i) => {
          const type = (n.entity_type || n.label || 'CVE').toUpperCase();
          // Stratify somewhat by type: CVE top, CWE second, CAPEC third, ATTACK bottom
          let targetY = 160;
          if (type === 'CVE') targetY = 80;
          else if (type === 'CWE') targetY = 180;
          else if (type === 'CAPEC') targetY = 280;
          else if (type === 'ATTACK') targetY = 380;

          const totalForType = data.nodes.filter(x => (x.entity_type || x.label || '').toUpperCase() === type).length || 1;
          const indexInType = data.nodes.filter((x, idx) => idx <= i && (x.entity_type || x.label || '').toUpperCase() === type).length;
          const targetX = 120 + (indexInType / (totalForType + 1)) * 660;

          return {
            ...n,
            x: targetX + (Math.random() * 40 - 20),
            y: targetY + (Math.random() * 30 - 15),
            type: type in ENTITY_CONFIG ? type : 'CVE',
          };
        });
        setNodes(layoutNodes);
        setEdges(data.edges || []);
        if (layoutNodes.length > 0) {
          setSelectedNode(layoutNodes[0]);
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, []);

  const handleSearchNeighborhood = async (e) => {
    if (e) e.preventDefault();
    if (!searchId.trim()) return;
    setLoading(true);
    try {
      const res = await onFetchNeighborhood(searchId.trim());
      if (res && res.nodes) {
        const layoutNodes = res.nodes.map((n, i) => {
          const type = (n.entity_type || n.label || 'CVE').toUpperCase();
          const angle = (i / res.nodes.length) * 2 * Math.PI;
          const radius = i === 0 ? 0 : 160;
          return {
            ...n,
            x: 450 + Math.cos(angle) * radius,
            y: 240 + Math.sin(angle) * radius,
            type: type in ENTITY_CONFIG ? type : 'CVE',
          };
        });
        setNodes(layoutNodes);
        setEdges(res.edges || []);
        setSelectedNode(res.center_node || layoutNodes[0]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const filteredNodes = nodes.filter(n => filterType === 'ALL' || n.type === filterType);
  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = edges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));

  return (
    <div className="graph-explorer-view">
      {/* Top Toolbar */}
      <div className="glass-panel graph-toolbar">
        <form onSubmit={handleSearchNeighborhood} className="graph-search-form">
          <Search size={16} color="var(--text-dim)" />
          <input 
            type="text" 
            placeholder="Focus node neighborhood (e.g. CVE-..., CWE-89, CAPEC-66, T1059)..." 
            value={searchId}
            onChange={(e) => setSearchId(e.target.value)}
            className="graph-search-input"
          />
          <button type="submit" className="btn btn-secondary" style={{ padding: '6px 14px' }}>
            Inspect Node
          </button>
        </form>

        <div className="graph-filter-group">
          <Filter size={15} color="var(--text-dim)" />
          <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>Filter:</span>
          {['ALL', 'CVE', 'CWE', 'CAPEC', 'ATTACK'].map(type => (
            <button
              key={type}
              className={`chip-filter-btn ${filterType === type ? 'active' : ''}`}
              onClick={() => setFilterType(type)}
            >
              {type}
            </button>
          ))}
          <button className="btn btn-secondary" onClick={loadGraph} disabled={loading} style={{ padding: '6px 10px' }} title="Reset graph view">
            <RefreshCw size={13} className={loading ? "pulse" : ""} />
          </button>
        </div>
      </div>

      <div className="graph-main-split">
        {/* SVG Interactive Canvas */}
        <div className="glass-panel graph-canvas-wrap">
          <svg 
            ref={svgRef} 
            className="graph-svg" 
            viewBox="0 0 900 480"
          >
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
              </marker>
              <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Edges */}
            {filteredEdges.map((edge, i) => {
              const srcNode = nodes.find(n => n.id === edge.source);
              const tgtNode = nodes.find(n => n.id === edge.target);
              if (!srcNode || !tgtNode) return null;

              const midX = (srcNode.x + tgtNode.x) / 2;
              const midY = (srcNode.y + tgtNode.y) / 2;

              return (
                <g key={i}>
                  <line 
                    x1={srcNode.x} 
                    y1={srcNode.y} 
                    x2={tgtNode.x} 
                    y2={tgtNode.y} 
                    stroke="rgba(100, 116, 139, 0.45)"
                    strokeWidth="1.5"
                    strokeDasharray={edge.type?.includes('CHILD') ? '4,4' : 'none'}
                    markerEnd="url(#arrow)"
                  />
                  <text 
                    x={midX} 
                    y={midY - 4} 
                    fill="#64748b" 
                    fontSize="9" 
                    textAnchor="middle"
                    className="mono"
                  >
                    {edge.type || 'LINK'}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {filteredNodes.map((node) => {
              const conf = ENTITY_CONFIG[node.type] || ENTITY_CONFIG.CVE;
              const isSelected = selectedNode?.id === node.id;

              return (
                <g 
                  key={node.id} 
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNode(node)}
                  style={{ cursor: 'pointer' }}
                >
                  <circle 
                    r={isSelected ? 19 : 14} 
                    fill={conf.bg}
                    stroke={isSelected ? '#ffffff' : conf.color}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    filter={isSelected ? 'url(#glow-cyan)' : 'none'}
                  />
                  <circle 
                    r={isSelected ? 7 : 5} 
                    fill={conf.color}
                  />
                  <text 
                    y={28} 
                    fill="#cbd5e1" 
                    fontSize="10" 
                    textAnchor="middle"
                    className="mono"
                    fontWeight={isSelected ? 700 : 500}
                  >
                    {node.id}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Canvas Legend */}
          <div className="canvas-legend">
            {Object.entries(ENTITY_CONFIG).map(([k, v]) => (
              <div key={k} className="legend-item">
                <span className="legend-dot" style={{ background: v.color }} />
                <span>{k}: {v.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Node Inspector Sidebar */}
        <div className="glass-panel node-inspector">
          <div className="inspector-header">
            <h3 style={{ fontSize: '1rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Info size={16} color="var(--accent-cyan)" />
              Entity Inspector
            </h3>
            {selectedNode && (
              <span className={`badge badge-${selectedNode.type.toLowerCase()}`}>
                {selectedNode.type}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="inspector-body">
              <div className="inspector-field">
                <span className="field-label">Identifier</span>
                <span className="field-val mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                  {selectedNode.id}
                </span>
              </div>

              {selectedNode.name && (
                <div className="inspector-field">
                  <span className="field-label">Name / Title</span>
                  <span className="field-val" style={{ fontWeight: 600 }}>{selectedNode.name}</span>
                </div>
              )}

              <div className="inspector-field">
                <span className="field-label">Description</span>
                <p className="field-desc">
                  {selectedNode.description || "No description cataloged."}
                </p>
              </div>

              {selectedNode.extra?.severity && (
                <div className="inspector-field">
                  <span className="field-label">Severity</span>
                  <span className="badge badge-warning">{selectedNode.extra.severity}</span>
                </div>
              )}

              {selectedNode.extra?.tactics && (
                <div className="inspector-field">
                  <span className="field-label">MITRE Tactics</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
                    {selectedNode.extra.tactics.map((t, i) => (
                      <span key={i} className="citation-tag mono">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ marginTop: '16px' }}>
                <button 
                  className="btn btn-secondary" 
                  style={{ width: '100%', fontSize: '0.8rem' }}
                  onClick={() => {
                    setSearchId(selectedNode.id);
                    handleSearchNeighborhood();
                  }}
                >
                  <Network size={14} /> Expand 1-Hop Neighborhood
                </button>
              </div>
            </div>
          ) : (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
              Click on any graph node to inspect its cybersecurity attributes and relationships.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

import React, { useMemo, useState } from 'react';
import {
  ArrowRight,
  BrainCircuit,
  Check,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import { Badge, Button, Modal, RiskBadge, SpotlightCard, Toggle } from '../components/Primitives.jsx';
import { ToolIcon } from '../lib/icons.jsx';
import { TOOL_CATALOG, TOOL_CATEGORIES, TOOL_COUNTS } from '../data/tools.js';
import { riskTone } from '../lib/format.js';

export default function Tools({ settings, onSaveSettings, onNavigate, toast }) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const [risk, setRisk] = useState('all');
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return TOOL_CATALOG.filter((tool) => {
      if (category !== 'All' && tool.category !== category) return false;
      if (risk !== 'all' && tool.risk !== risk) return false;
      if (!needle) return true;
      return `${tool.name} ${tool.label} ${tool.description} ${tool.category}`.toLowerCase().includes(needle);
    });
  }, [category, query, risk]);

  const grouped = useMemo(() => {
    const groups = {};
    for (const tool of filtered) {
      groups[tool.category] = groups[tool.category] || [];
      groups[tool.category].push(tool);
    }
    return groups;
  }, [filtered]);

  return (
    <div className="page page-tools">
      <div className="section-toolbar">
        <div className="toolbar-copy">
          <span className="eyebrow">CAPABILITY CATALOG / {TOOL_CATALOG.length} TOOLS</span>
          <h2>Everything the agent can touch.</h2>
        </div>
        <div className="toolbar-actions">
          <Badge dot tone={settings.mcpFullControl ? 'amber' : 'mint'}>
            {settings.mcpFullControl ? 'FULL CONTROL ENABLED' : 'GUARDED MODE'}
          </Badge>
          <Button icon={BrainCircuit} onClick={() => onNavigate('agent')} variant="secondary">Open agent fabric</Button>
        </div>
      </div>

      <div className="tool-stats">
        <div><span className="stat-icon"><Terminal size={15} /></span><strong>{TOOL_CATALOG.length}</strong><span>total tools</span></div>
        <div><span className="stat-icon stat-icon-mint"><ShieldCheck size={15} /></span><strong>{TOOL_COUNTS.safe}</strong><span>read-only</span></div>
        <div><span className="stat-icon stat-icon-amber"><ShieldAlert size={15} /></span><strong>{TOOL_COUNTS.elevated}</strong><span>elevated</span></div>
        <div><span className="stat-icon stat-icon-danger"><ShieldAlert size={15} /></span><strong>{TOOL_COUNTS.critical}</strong><span>critical</span></div>
      </div>

      <div className="tool-policy-banner">
        <div className="tool-policy-icon"><SlidersHorizontal size={17} /></div>
        <div>
          <strong>Every invocation crosses the same policy gate.</strong>
          <span>Paths are checked against {settings.mcpAllowedRoots.length} root{settings.mcpAllowedRoots.length === 1 ? '' : 's'} and every call is appended to the audit stream.</span>
        </div>
        <div className="tool-policy-toggle">
          <span>Full control</span>
          <Toggle
            checked={settings.mcpFullControl}
            label="Full control"
            onChange={(value) => {
              onSaveSettings({ mcpFullControl: value });
              toast(
                value ? 'Full control enabled' : 'Guarded mode restored',
                value ? 'Shell, screen, input, clipboard, process, and delete tools are now reachable.' : 'Elevated and destructive tools are blocked.',
                value ? 'warning' : 'success',
              );
            }}
          />
        </div>
      </div>

      <div className="tool-filter-bar">
        <div className="tool-search">
          <Search size={16} />
          <input onChange={(event) => setQuery(event.target.value)} placeholder="Search tools, categories, or capabilities…" value={query} />
          {query ? <button aria-label="Clear search" onClick={() => setQuery('')} type="button"><X size={14} /></button> : null}
        </div>
        <div className="category-chips">
          <button className={category === 'All' ? 'is-selected' : ''} onClick={() => setCategory('All')} type="button">All <span>{TOOL_CATALOG.length}</span></button>
          {TOOL_CATEGORIES.map((item) => (
            <button className={category === item ? 'is-selected' : ''} key={item} onClick={() => setCategory(item)} type="button">
              {item}<span>{TOOL_CATALOG.filter((tool) => tool.category === item).length}</span>
            </button>
          ))}
        </div>
        <div className="risk-filter">
          <Filter size={13} />
          {['all', 'safe', 'elevated', 'critical'].map((item) => (
            <button className={risk === item ? 'is-selected' : ''} key={item} onClick={() => setRisk(item)} type="button">
              {item}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="tools-empty">
          <Search size={20} />
          <h3>No tools match that filter.</h3>
          <p>Try a broader search or reset the categories.</p>
          <Button onClick={() => { setCategory('All'); setRisk('all'); setQuery(''); }} variant="secondary">Reset filters</Button>
        </div>
      ) : (
        <div className="tool-categories">
          {Object.entries(grouped).map(([group, tools]) => (
            <section className="tool-category" key={group}>
              <div className="tool-category-head">
                <h3>{group}</h3>
                <span>{String(tools.length).padStart(2, '0')}</span>
              </div>
              <div className="tool-grid">
                {tools.map((tool) => (
                  <ToolCard key={tool.name} onOpen={() => setSelected(tool)} tool={tool} />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}

      <Modal
        eyebrow={selected ? selected.category.toUpperCase() : 'TOOL'}
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected?.label || ''}
        width="720px"
        footer={(
          <>
            <Button onClick={() => setSelected(null)} variant="ghost">Close</Button>
            <Button
              icon={BrainCircuit}
              onClick={() => {
                setSelected(null);
                onNavigate('agent');
              }}
              variant="primary"
            >
              Use in agent fabric
            </Button>
          </>
        )}
      >
        {selected ? (
          <div className="tool-detail">
            <div className="tool-detail-hero">
              <span className={`tool-card-icon tool-risk-${selected.risk}`}><ToolIcon name={selected.icon} size={24} /></span>
              <div>
                <code>{selected.name}</code>
                <p>{selected.description}</p>
              </div>
              <RiskBadge risk={selected.risk} />
            </div>
            <div className="tool-detail-grid">
              <div><span>Category</span><strong>{selected.category}</strong></div>
              <div><span>Access</span><strong>{selected.gated ? 'Requires full control' : selected.risk === 'elevated' ? 'Root-scoped write' : 'Read-only'}</strong></div>
              <div><span>Annotations</span><strong>{selected.gated ? 'gated · audited' : 'audited'}</strong></div>
              <div><span>Transport</span><strong>stdio / MCP</strong></div>
            </div>
            <div className="tool-detail-copy">
              <span className="eyebrow">WHAT IT DOES</span>
              <p>{selected.detail}</p>
            </div>
            <div className="tool-detail-args">
              <span className="eyebrow">INPUT SHAPE</span>
              {selected.args.length ? (
                <div className="arg-chips">{selected.args.map((arg) => <code key={arg}>{arg}</code>)}</div>
              ) : <span className="muted-copy">No arguments required.</span>}
            </div>
            <div className="tool-detail-note">
              <Sparkles size={14} />
              <span>Tool results are untrusted data. The agent is instructed to ignore instructions found inside files, clipboard text, or process output.</span>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}

function ToolCard({ tool, onOpen }) {
  return (
    <SpotlightCard className="tool-card">
      <div className="tool-card-top">
        <span className={`tool-card-icon tool-risk-${tool.risk}`}><ToolIcon name={tool.icon} size={18} /></span>
        <RiskBadge risk={tool.risk} />
      </div>
      <div className="tool-card-body">
        <code>{tool.name}</code>
        <h4>{tool.label}</h4>
        <p>{tool.description}</p>
      </div>
      <div className="tool-card-foot">
        {tool.gated ? <span className="tool-gate"><ShieldAlert size={12} /> full control</span> : <span className="tool-gate tool-gate-safe"><Check size={12} /> available</span>}
        <button onClick={onOpen} type="button">Details <ArrowRight size={12} /></button>
      </div>
    </SpotlightCard>
  );
}

import React, { useMemo, useState } from 'react';
import {
  Activity as ActivityIcon,
  BrainCircuit,
  CheckCircle2,
  Clock,
  Download,
  FileJson,
  KeyRound,
  Network,
  ShieldCheck,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react';
import { Badge, Button, CopyButton, EmptyState, SpotlightCard } from '../components/Primitives.jsx';
import { downloadJson, timeAgo } from '../lib/format.js';

const FILTERS = ['all', 'tunnel', 'mcp', 'agent', 'profile', 'system'];

const KIND_ICONS = {
  tunnel: Network,
  mcp: Terminal,
  agent: BrainCircuit,
  profile: KeyRound,
  system: ShieldCheck,
};

const KIND_TONE = {
  tunnel: 'mint',
  mcp: 'violet',
  agent: 'amber',
  profile: 'ice',
  system: 'neutral',
};

export default function Activity({ activity, onClear, mcp, toast }) {
  const [filter, setFilter] = useState('all');

  const filtered = useMemo(
    () => (filter === 'all' ? activity : activity.filter((entry) => entry.kind === filter)),
    [activity, filter],
  );

  const counts = useMemo(() => {
    const base = { all: activity.length };
    for (const item of FILTERS.slice(1)) base[item] = activity.filter((entry) => entry.kind === item).length;
    return base;
  }, [activity]);

  const clear = async () => {
    if (!activity.length) return;
    if (!window.confirm('Clear the local activity stream? Audit JSONL records on disk are not deleted.')) return;
    await onClear();
    toast('Activity cleared', 'The in-app timeline is empty; disk audit records remain.', 'success');
  };

  const exportActivity = () => {
    downloadJson(`praetor-activity-${new Date().toISOString().slice(0, 10)}.json`, {
      exportedAt: new Date().toISOString(),
      entries: activity,
    });
    toast('Activity exported', 'JSON snapshot downloaded.', 'success');
  };

  return (
    <div className="page page-activity">
      <div className="section-toolbar">
        <div className="toolbar-copy">
          <span className="eyebrow">AUDIT STREAM / LOCAL</span>
          <h2>Every move leaves a trace.</h2>
        </div>
        <div className="toolbar-actions">
          <Button icon={Download} onClick={exportActivity} variant="ghost">Export</Button>
          <Button icon={Trash2} onClick={clear} variant="ghost">Clear</Button>
        </div>
      </div>

      <div className="activity-stats">
        <div><span className="eyebrow">EVENTS</span><strong>{activity.length}</strong><span>in this session</span></div>
        <div><span className="eyebrow">TUNNEL</span><strong>{counts.tunnel}</strong><span>handshake events</span></div>
        <div><span className="eyebrow">AGENT</span><strong>{counts.agent + counts.mcp}</strong><span>runtime calls</span></div>
        <div><span className="eyebrow">AUDIT DISK</span><strong><FileJson size={18} /> JSONL</strong><span>{mcp?.auditPath ? 'stream attached' : 'awaiting runtime'}</span></div>
      </div>

      <div className="activity-layout">
        <SpotlightCard className="panel timeline-panel">
          <div className="timeline-toolbar">
            <div className="category-chips category-chips-small">
              {FILTERS.map((item) => (
                <button className={filter === item ? 'is-selected' : ''} key={item} onClick={() => setFilter(item)} type="button">
                  {item}<span>{counts[item]}</span>
                </button>
              ))}
            </div>
            <Badge tone="mint" dot>{filtered.length} visible</Badge>
          </div>
          {filtered.length ? (
            <div className="timeline">
              {filtered.map((entry) => {
                const Icon = KIND_ICONS[entry.kind] || ActivityIcon;
                return (
                  <div className="timeline-item" key={entry.id}>
                    <div className={`timeline-icon activity-${entry.kind}`}><Icon size={15} /></div>
                    <div className="timeline-line" />
                    <div className="timeline-copy">
                      <div className="timeline-title-row">
                        <strong>{entry.title}</strong>
                        <Badge tone={KIND_TONE[entry.kind] || 'neutral'}>{entry.kind}</Badge>
                      </div>
                      <p>{entry.detail}</p>
                      <span className="timeline-time"><Clock size={12} /> {timeAgo(entry.ts)} · {new Date(entry.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <EmptyState icon={ActivityIcon} title="No events in this slice">
              Run a handshake, diagnostic, or agent task and the trace will appear here.
            </EmptyState>
          )}
        </SpotlightCard>

        <div className="activity-side">
          <SpotlightCard className="panel audit-card">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">ON-DISK AUDIT</span>
                <h2>JSONL stream</h2>
              </div>
              <span className="audit-live"><span className="status-dot is-online is-pulsing" /> LIVE</span>
            </div>
            <p className="audit-copy">
              Every MCP invocation is appended with a timestamp, tool name, duration, redacted arguments, and result status.
            </p>
            <code className="audit-path">{mcp?.auditPath || 'Audit path is available after the MCP runtime is staged.'}</code>
            <div className="audit-actions">
              <CopyButton label="Copy path" value={mcp?.auditPath || ''} />
              <Badge tone="neutral">append-only</Badge>
            </div>
          </SpotlightCard>

          <SpotlightCard className="panel integrity-card">
            <div className="integrity-icon"><CheckCircle2 size={20} /></div>
            <span className="eyebrow">INTEGRITY CHECK</span>
            <h2>Local by default.</h2>
            <p>The bridge has no listening socket. MCP clients spawn it over stdio, and the audit file lives under the app’s userData folder.</p>
            <div className="integrity-list">
              <span><CheckCircle2 size={13} /> No remote control endpoint</span>
              <span><CheckCircle2 size={13} /> Root-scoped filesystem</span>
              <span><CheckCircle2 size={13} /> Full control is opt-in</span>
              <span><XCircle size={13} /> No hardware-backed key store yet</span>
            </div>
          </SpotlightCard>
        </div>
      </div>
    </div>
  );
}

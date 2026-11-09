import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Boxes,
  BrainCircuit,
  ChevronRight,
  Command,
  LayoutDashboard,
  Maximize2,
  Minimize2,
  Minus,
  Network,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Square,
  Terminal,
  Wrench,
  X,
} from 'lucide-react';
import { LogoMark } from './Atmosphere.jsx';
import { Badge } from './Primitives.jsx';
import { cx } from '../lib/format.js';

export const NAV_ITEMS = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard, hint: 'Command deck' },
  { id: 'tunnels', label: 'Tunnels', icon: Network, hint: 'Profiles & peers' },
  { id: 'agent', label: 'Agent fabric', icon: BrainCircuit, hint: 'MCP & operator' },
  { id: 'tools', label: 'Toolset', icon: Wrench, hint: '36 capabilities' },
  { id: 'activity', label: 'Activity', icon: Activity, hint: 'Audit stream' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, hint: 'System preferences' },
];

export const PAGE_META = {
  dashboard: { title: 'Overview', eyebrow: 'COMMAND DECK', subtitle: 'Signal, posture, and agent readiness at a glance.' },
  tunnels: { title: 'Tunnels', eyebrow: 'NETWORK PROFILES', subtitle: 'Shape peers, routes, and handshake policy.' },
  agent: { title: 'Agent fabric', eyebrow: 'MCP + OPERATOR', subtitle: 'A local computer-use surface for your agents.' },
  tools: { title: 'Toolset', eyebrow: 'CAPABILITY CATALOG', subtitle: 'Every audited action available to an MCP client.' },
  activity: { title: 'Activity', eyebrow: 'AUDIT STREAM', subtitle: 'A chronological record of control-plane events.' },
  settings: { title: 'Settings', eyebrow: 'SYSTEM PREFERENCES', subtitle: 'Tune the surface, runtime, and trust boundary.' },
};

export function StatusDot({ online, pulse = true }) {
  return <span className={cx('status-dot', online ? 'is-online' : '', pulse ? 'is-pulsing' : '')} />;
}

export function TitleBar({ page, mcpReady, windowState, onWindow }) {
  const meta = PAGE_META[page] || PAGE_META.dashboard;
  return (
    <header className="titlebar">
      <div className="titlebar-drag">
        <div className="titlebar-breadcrumb">
          <span className="breadcrumb-app">PRAETOR</span>
          <ChevronRight size={12} />
          <span>{meta.eyebrow}</span>
          <ChevronRight size={12} />
          <strong>{meta.title}</strong>
        </div>
      </div>
      <div className="titlebar-center">
        <span className="titlebar-signal"><StatusDot online={mcpReady} /> MCP {mcpReady ? 'READY' : 'STAGING'}</span>
        <span className="titlebar-separator" />
        <span className="titlebar-environment">LOCAL RUNTIME</span>
      </div>
      <div className="window-controls">
        <button aria-label="Minimize" className="window-button" onClick={() => onWindow('minimize')} type="button">
          <Minus size={14} />
        </button>
        <button aria-label={windowState?.maximized ? 'Restore' : 'Maximize'} className="window-button" onClick={() => onWindow('maximize')} type="button">
          {windowState?.maximized ? <Minimize2 size={13} /> : <Square size={12} />}
        </button>
        <button aria-label="Close" className="window-button window-button-close" onClick={() => onWindow('close')} type="button">
          <X size={14} />
        </button>
      </div>
    </header>
  );
}

export function Sidebar({ page, onNavigate, mcpReady, appInfo, onCommand, badgeImage }) {
  return (
    <aside className="sidebar">
      <button className="brand" onClick={() => onNavigate('dashboard')} type="button">
        {badgeImage ? (
          <span className="brand-image" style={{ backgroundImage: `url(${badgeImage})` }} />
        ) : (
          <LogoMark size={34} />
        )}
        <span className="brand-wordmark">
          <strong>PRAETOR</strong>
          <span>COMMAND</span>
        </span>
      </button>

      <div className="workspace-chip">
        <span className="workspace-avatar">{appInfo?.name?.slice(0, 1) || 'P'}</span>
        <div>
          <strong>Local workstation</strong>
          <span>Control plane 01</span>
        </div>
        <span className="workspace-state"><StatusDot online={mcpReady} /></span>
      </div>

      <button className="command-trigger" onClick={onCommand} type="button">
        <Search size={14} />
        <span>Jump to anywhere</span>
        <kbd>⌘ K</kbd>
      </button>

      <nav className="sidebar-nav" aria-label="Primary navigation">
        <span className="nav-label">SURFACE</span>
        {NAV_ITEMS.slice(0, 3).map((item) => (
          <SidebarItem key={item.id} item={item} active={page === item.id} onClick={() => onNavigate(item.id)} />
        ))}
        <span className="nav-label nav-label-spaced">CONTROL</span>
        {NAV_ITEMS.slice(3).map((item) => (
          <SidebarItem key={item.id} item={item} active={page === item.id} onClick={() => onNavigate(item.id)} />
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="runtime-card">
          <div className="runtime-card-header">
            <span className="runtime-icon"><Terminal size={14} /></span>
            <span>MCP runtime</span>
            <StatusDot online={mcpReady} />
          </div>
          <div className="runtime-meta">
            <span>{mcpReady ? '36 tools staged' : 'Runtime unavailable'}</span>
            <span className="runtime-version">v1.0.0</span>
          </div>
          <div className="runtime-line"><span style={{ width: mcpReady ? '100%' : '18%' }} /></div>
        </div>
        <div className="sidebar-footer">
          <span><ShieldCheck size={13} /> Local-first by design</span>
          <span className="sidebar-version">BUILD 1.0.0</span>
        </div>
      </div>
    </aside>
  );
}

function SidebarItem({ item, active, onClick }) {
  const Icon = item.icon;
  return (
    <button className={cx('sidebar-item', active && 'is-active')} onClick={onClick} type="button">
      <span className="sidebar-item-icon"><Icon size={17} /></span>
      <span className="sidebar-item-copy">
        <strong>{item.label}</strong>
        <span>{item.hint}</span>
      </span>
      {active ? <span className="sidebar-active-mark" /> : <ChevronRight className="sidebar-chevron" size={13} />}
    </button>
  );
}

export function ToolsetGlyph({ count = 36 }) {
  return (
    <div className="toolset-glyph">
      <Boxes size={16} />
      <span>{count}</span>
    </div>
  );
}

export function CommandPalette({ open, onClose, items }) {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setSelected(0);
    requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => `${item.label} ${item.hint || ''} ${item.section || ''}`.toLowerCase().includes(needle));
  }, [items, query]);

  useEffect(() => {
    setSelected(0);
  }, [query]);

  if (!open) return null;

  const run = (item) => {
    if (!item) return;
    item.action?.();
    onClose();
  };

  return (
    <div className="palette-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div aria-label="Command palette" aria-modal="true" className="palette" role="dialog">
        <div className="palette-search">
          <Search size={18} />
          <input
            aria-label="Search commands"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowDown') {
                event.preventDefault();
                setSelected((current) => Math.min(current + 1, filtered.length - 1));
              }
              if (event.key === 'ArrowUp') {
                event.preventDefault();
                setSelected((current) => Math.max(current - 1, 0));
              }
              if (event.key === 'Enter') {
                event.preventDefault();
                run(filtered[selected]);
              }
              if (event.key === 'Escape') onClose();
            }}
            placeholder="Search pages, actions, or tools…"
            ref={inputRef}
            value={query}
          />
          <kbd>ESC</kbd>
        </div>
        <div className="palette-results">
          {filtered.length === 0 ? <div className="palette-empty">No matches. Try “tunnel” or “agent”.</div> : null}
          {filtered.map((item, index) => {
            const Icon = item.icon || Command;
            return (
              <button
                className={cx('palette-item', index === selected && 'is-selected')}
                key={item.id}
                onMouseEnter={() => setSelected(index)}
                onClick={() => run(item)}
                type="button"
              >
                <span className="palette-icon"><Icon size={16} /></span>
                <span className="palette-copy">
                  <strong>{item.label}</strong>
                  <span>{item.hint || item.section}</span>
                </span>
                {item.section ? <span className="palette-section">{item.section}</span> : null}
                <ChevronRight size={14} className="palette-arrow" />
              </button>
            );
          })}
        </div>
        <div className="palette-footer">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> run</span>
          <span><kbd>ESC</kbd> close</span>
        </div>
      </div>
    </div>
  );
}

export function ToastStack({ toasts, onDismiss }) {
  return (
    <div aria-live="polite" className="toast-stack">
      {toasts.map((toast) => (
        <div className={cx('toast', `toast-${toast.tone || 'info'}`)} key={toast.id}>
          <span className="toast-mark" />
          <div>
            <strong>{toast.title}</strong>
            {toast.detail ? <span>{toast.detail}</span> : null}
          </div>
          <button aria-label="Dismiss notification" onClick={() => onDismiss(toast.id)} type="button">
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  );
}

export function PageHeader({ page, action = null, children }) {
  const meta = PAGE_META[page] || PAGE_META.dashboard;
  return (
    <div className="page-header">
      <div>
        <span className="eyebrow">{meta.eyebrow}</span>
        <h1>{meta.title}</h1>
        <p>{meta.subtitle}</p>
      </div>
      {action ? <div className="page-header-actions">{action}</div> : null}
      {children}
    </div>
  );
}

export function Kbd({ children }) {
  return <kbd className="inline-kbd">{children}</kbd>;
}

export function SectionTitle({ title, hint, action }) {
  return (
    <div className="section-title">
      <div>
        <h2>{title}</h2>
        {hint ? <span>{hint}</span> : null}
      </div>
      {action}
    </div>
  );
}

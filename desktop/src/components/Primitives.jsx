import React, { useEffect } from 'react';
import { Check, Copy, Loader2, X } from 'lucide-react';
import { copyText } from '../lib/format.js';

export function Badge({ children, tone = 'neutral', dot = false, className = '' }) {
  return (
    <span className={`badge badge-${tone} ${className}`}>
      {dot ? <span className="mini-dot" /> : null}
      {children}
    </span>
  );
}

export function Button({
  children,
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  loading = false,
  className = '',
  type = 'button',
  ...props
}) {
  return (
    <button className={`button button-${variant} button-${size} ${className}`} type={type} {...props}>
      {loading ? <Loader2 className="spin" size={15} /> : Icon ? <Icon size={15} /> : null}
      <span>{children}</span>
    </button>
  );
}

export function IconButton({ label, icon: Icon, className = '', ...props }) {
  return (
    <button aria-label={label} className={`icon-button ${className}`} title={label} type="button" {...props}>
      <Icon size={16} />
    </button>
  );
}

export function Toggle({ checked, onChange, disabled = false, label }) {
  return (
    <button
      aria-checked={checked}
      aria-label={label}
      className={`toggle ${checked ? 'is-on' : ''}`}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      role="switch"
      type="button"
    >
      <span className="toggle-thumb" />
    </button>
  );
}

export function SpotlightCard({ children, className = '', ...props }) {
  const handleMove = (event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty('--spot-x', `${event.clientX - rect.left}px`);
    event.currentTarget.style.setProperty('--spot-y', `${event.clientY - rect.top}px`);
  };
  return (
    <div className={`spotlight-card ${className}`} onPointerMove={handleMove} {...props}>
      {children}
    </div>
  );
}

export function Modal({ open, onClose, title, eyebrow, children, width = '620px', footer = null }) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div aria-modal="true" className="modal-panel" role="dialog" style={{ '--modal-width': width }}>
        <div className="modal-head">
          <div>
            {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
            <h2>{title}</h2>
          </div>
          <IconButton icon={X} label="Close dialog" onClick={onClose} />
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-footer">{footer}</div> : null}
      </div>
    </div>
  );
}

export function Stat({ label, value, hint, tone = 'mint', icon: Icon, children }) {
  return (
    <div className={`stat stat-${tone}`}>
      <div className="stat-top">
        <span className="eyebrow">{label}</span>
        {Icon ? <span className="stat-icon"><Icon size={15} /></span> : null}
      </div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="stat-hint">{hint}</div> : null}
      {children}
    </div>
  );
}

export function CopyButton({ value, label = 'Copy', onDone, className = '' }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      className={`copy-button ${copied ? 'is-copied' : ''} ${className}`}
      onClick={async () => {
        const ok = await copyText(value);
        if (ok) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
          onDone?.();
        }
      }}
      type="button"
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
      <span>{copied ? 'Copied' : label}</span>
    </button>
  );
}

export function EmptyState({ icon: Icon, title, children, action = null }) {
  return (
    <div className="empty-state">
      {Icon ? <div className="empty-icon"><Icon size={22} /></div> : null}
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function RiskBadge({ risk }) {
  return <Badge tone={risk === 'critical' ? 'danger' : risk === 'elevated' ? 'amber' : 'mint'}>{risk}</Badge>;
}

export function Progress({ value, tone = 'mint' }) {
  return (
    <div className={`progress progress-${tone}`}>
      <span style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ImagePlus, RefreshCw, Upload, X } from 'lucide-react';
import { readImage } from '../lib/format.js';

export function CursorAura({ enabled }) {
  useEffect(() => {
    if (!enabled) return undefined;
    let frame = null;
    let x = window.innerWidth / 2;
    let y = window.innerHeight / 2;
    const move = (event) => {
      x = event.clientX;
      y = event.clientY;
      if (frame) return;
      frame = requestAnimationFrame(() => {
        document.documentElement.style.setProperty('--cursor-x', `${x}px`);
        document.documentElement.style.setProperty('--cursor-y', `${y}px`);
        frame = null;
      });
    };
    const leave = () => {
      document.documentElement.style.setProperty('--cursor-active', '0');
    };
    const enter = () => {
      document.documentElement.style.setProperty('--cursor-active', '1');
    };
    window.addEventListener('pointermove', move, { passive: true });
    window.addEventListener('pointerleave', leave);
    window.addEventListener('pointerenter', enter);
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerleave', leave);
      window.removeEventListener('pointerenter', enter);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [enabled]);

  if (!enabled) return null;
  return (
    <div className="cursor-atmosphere" aria-hidden="true">
      <div className="cursor-aura" />
      <div className="cursor-ring" />
      <div className="cursor-crosshair" />
    </div>
  );
}

const PARTICLES = Array.from({ length: 26 }, (_, index) => ({
  id: index,
  left: `${(index * 37 + 11) % 100}%`,
  top: `${(index * 61 + 7) % 100}%`,
  size: `${1 + ((index * 7) % 3)}px`,
  delay: `${-((index * 0.83) % 12)}s`,
  duration: `${10 + ((index * 3) % 13)}s`,
  opacity: 0.18 + ((index * 5) % 30) / 100,
}));

export function ParticleField() {
  return (
    <div className="particle-field" aria-hidden="true">
      {PARTICLES.map((particle) => (
        <span
          key={particle.id}
          style={{
            left: particle.left,
            top: particle.top,
            width: particle.size,
            height: particle.size,
            animationDelay: particle.delay,
            animationDuration: particle.duration,
            opacity: particle.opacity,
          }}
        />
      ))}
    </div>
  );
}

export function LogoMark({ size = 34 }) {
  const id = React.useId().replace(/:/g, '');
  return (
    <svg
      aria-label="PRAETOR mark"
      className="logo-mark"
      height={size}
      viewBox="0 0 44 44"
      width={size}
    >
      <defs>
        <linearGradient id={`mark-${id}`} x1="4" x2="40" y1="4" y2="40" gradientUnits="userSpaceOnUse">
          <stop stopColor="#9dffd7" />
          <stop offset="0.55" stopColor="#5ce1b0" />
          <stop offset="1" stopColor="#2b9d8a" />
        </linearGradient>
      </defs>
      <rect fill="rgba(92,225,176,0.06)" height="42" rx="12" stroke="rgba(92,225,176,0.26)" width="42" x="1" y="1" />
      <path
        d="M13 31V13.5h8.1c5 0 8.2 2.7 8.2 7.1 0 3.1-1.7 5.4-4.5 6.4L31 31h-6.5l-5-3.9h-1.1V31H13Zm5.4-8.4h2.5c2.1 0 3.4-1 3.4-2.8 0-1.8-1.3-2.8-3.4-2.8h-2.5v5.6Z"
        fill={`url(#mark-${id})`}
      />
      <circle cx="32" cy="12" fill="#9dffd7" r="2" />
    </svg>
  );
}

export function HeaderArt({ image, onPick, onClear, caption, compact = false }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const id = React.useId();

  const accept = async (file) => {
    setError('');
    try {
      const dataUrl = await readImage(file);
      onPick(dataUrl);
    } catch (readError) {
      setError(readError.message);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0];
    if (file) accept(file);
  };

  return (
    <div
      className={`header-art ${compact ? 'header-art-compact' : ''} ${dragging ? 'is-dragging' : ''}`}
      onDragEnter={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      style={image ? { backgroundImage: `url(${image})` } : undefined}
    >
      {image ? (
        <div className="header-art-image-overlay" />
      ) : (
        <div className="header-art-default" aria-hidden="true">
          <div className="art-grid" />
          <div className="art-orbit art-orbit-one" />
          <div className="art-orbit art-orbit-two" />
          <div className="art-orbit art-orbit-three" />
          <div className="art-node art-node-one" />
          <div className="art-node art-node-two" />
          <div className="art-node art-node-three" />
          <div className="art-core">
            <span>P</span>
            <div className="art-core-ring" />
          </div>
          <div className="art-readout">
            <span>PQ HANDSHAKE</span>
            <strong>ACTIVE</strong>
          </div>
        </div>
      )}
      <div className="header-art-vignette" />
      <div className="header-art-caption">
        <span className="eyebrow">{caption || 'PRAETOR / VISUAL FIELD'}</span>
        <span className="header-art-slot-label">{image ? 'CUSTOM HEADER ART' : 'HEADER ART SLOT'}</span>
      </div>
      <div className="header-art-controls">
        <button className="art-control" onClick={() => inputRef.current?.click()} type="button">
          {image ? <Upload size={13} /> : <ImagePlus size={13} />}
          <span>{image ? 'Replace' : 'Add image'}</span>
        </button>
        {image ? (
          <button className="art-control art-control-quiet" onClick={onClear} type="button">
            <X size={13} />
            <span>Clear</span>
          </button>
        ) : null}
      </div>
      <input
        ref={inputRef}
        accept="image/png,image/jpeg,image/webp,image/gif,image/avif"
        className="visually-hidden"
        id={`header-upload-${id}`}
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) accept(file);
          event.target.value = '';
        }}
        type="file"
      />
      {error ? <div className="header-art-error">{error}</div> : null}
    </div>
  );
}

export function ConnectionOrb({ status, latency }) {
  const active = status === 'connected';
  const connecting = status === 'connecting';
  return (
    <div className={`connection-orb ${active ? 'is-online' : ''} ${connecting ? 'is-connecting' : ''}`}>
      <div className="orb-ring orb-ring-outer" />
      <div className="orb-ring orb-ring-mid" />
      <div className="orb-ring orb-ring-inner" />
      <div className="orb-glow" />
      <div className="orb-core">
        <span className="orb-status-mark">{active ? 'ON' : connecting ? '··' : '—'}</span>
        <span className="orb-latency">{active && latency ? `${latency} ms` : connecting ? 'SYNC' : 'OFFLINE'}</span>
      </div>
      <span className="orb-tick orb-tick-1" />
      <span className="orb-tick orb-tick-2" />
      <span className="orb-tick orb-tick-3" />
    </div>
  );
}

export function Sparkline({ values, tone = 'mint', height = 34 }) {
  const width = 120;
  const maximum = Math.max(...values, 1);
  const points = values
    .map((value, index) => `${(index / Math.max(1, values.length - 1)) * width},${height - (value / maximum) * (height - 5) - 2}`)
    .join(' ');
  return (
    <svg className={`sparkline sparkline-${tone}`} height={height} viewBox={`0 0 ${width} ${height}`} width="100%" aria-hidden="true">
      <polyline fill="none" points={points} stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}

function makeSeries(seed = 0) {
  return Array.from({ length: 30 }, (_, index) => 15 + Math.abs(Math.sin(index * 0.44 + seed) * 42) + (index % 5) * 3);
}

function seriesPath(values, width, height, padding = 4) {
  const maximum = Math.max(...values, 1);
  const step = width / Math.max(1, values.length - 1);
  const points = values.map((value, index) => [
    index * step,
    height - padding - (value / maximum) * (height - padding * 2),
  ]);
  const line = points.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const area = `${line} L${width},${height} L0,${height} Z`;
  return { line, area };
}

export function TrafficChart({ status }) {
  const [download, setDownload] = useState(() => makeSeries(0.4));
  const [upload, setUpload] = useState(() => makeSeries(2.1));

  useEffect(() => {
    if (status !== 'connected') return undefined;
    const timer = setInterval(() => {
      setDownload((current) => [...current.slice(1), 20 + Math.random() * 55 + (current.at(-1) || 0) * 0.15]);
      setUpload((current) => [...current.slice(1), 10 + Math.random() * 36 + (current.at(-1) || 0) * 0.1]);
    }, 1600);
    return () => clearInterval(timer);
  }, [status]);

  const width = 700;
  const height = 168;
  const down = seriesPath(download, width, height);
  const up = seriesPath(upload, width, height);

  return (
    <div className="traffic-chart">
      <div className="chart-head">
        <div>
          <span className="eyebrow">LIVE THROUGHPUT</span>
          <h3>Data plane</h3>
        </div>
        <div className="chart-legend">
          <span className="legend-item"><i className="legend-swatch swatch-mint" />RX</span>
          <span className="legend-item"><i className="legend-swatch swatch-violet" />TX</span>
          <span className={`chart-state ${status === 'connected' ? 'is-live' : ''}`}>
            <span className="mini-dot" />{status === 'connected' ? 'STREAMING' : 'IDLE'}
          </span>
        </div>
      </div>
      <div className="chart-stage">
        <div className="chart-y-labels">
          <span>100</span>
          <span>75</span>
          <span>50</span>
          <span>25</span>
          <span>0</span>
        </div>
        <svg className="chart-svg" preserveAspectRatio="none" viewBox={`0 0 ${width} ${height}`} aria-label="Tunnel throughput chart">
          <defs>
            <linearGradient id="downloadArea" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor="#5ce1b0" stopOpacity="0.26" />
              <stop offset="1" stopColor="#5ce1b0" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="uploadArea" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor="#a78bfa" stopOpacity="0.16" />
              <stop offset="1" stopColor="#a78bfa" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0, 1, 2, 3, 4].map((line) => (
            <line
              key={line}
              stroke="rgba(174, 211, 199, 0.11)"
              strokeDasharray="2 6"
              x1="0"
              x2={width}
              y1={(height / 4) * line}
              y2={(height / 4) * line}
            />
          ))}
          <path className="chart-area chart-area-upload" d={up.area} fill="url(#uploadArea)" />
          <path className="chart-area chart-area-download" d={down.area} fill="url(#downloadArea)" />
          <path className="chart-line chart-line-upload" d={up.line} />
          <path className="chart-line chart-line-download" d={down.line} />
        </svg>
        <div className="chart-x-labels">
          <span>−60s</span><span>−45s</span><span>−30s</span><span>−15s</span><span>now</span>
        </div>
      </div>
    </div>
  );
}

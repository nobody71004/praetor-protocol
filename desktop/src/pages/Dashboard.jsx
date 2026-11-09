import React from 'react';
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  BrainCircuit,
  Clock,
  Cpu,
  Gauge,
  KeyRound,
  MapPin,
  Network,
  Power,
  Radio,
  ShieldCheck,
  Sparkles,
  Wifi,
  Zap,
} from 'lucide-react';
import { HeaderArt, ConnectionOrb, TrafficChart } from '../components/Atmosphere.jsx';
import { Badge, Button, CopyButton, Stat, SpotlightCard } from '../components/Primitives.jsx';
import { formatBytes, formatDuration, statusLabel, timeAgo } from '../lib/format.js';
import { useNow } from '../lib/hooks.js';
import { TOOL_COUNT } from '../data/tools.js';
import {
  PRAETOR_HANDSHAKE,
  PRAETOR_PROTOCOL,
  cellWireSize,
  endpointPort,
  suiteMeta,
} from '../lib/praetor.js';

function activityIcon(kind) {
  if (kind === 'tunnel') return Network;
  if (kind === 'agent') return BrainCircuit;
  if (kind === 'mcp') return Cpu;
  if (kind === 'profile') return KeyRound;
  return Activity;
}

export default function Dashboard({
  profiles,
  tunnel,
  activeProfileId,
  settings,
  activity,
  mcp,
  onSelectProfile,
  onConnect,
  onDisconnect,
  onNavigate,
  heroImage,
  onPickHero,
  onClearHero,
  onEditProfile,
  onOpenNew,
}) {
  const now = useNow(1000);
  const active = profiles.find((profile) => profile.id === activeProfileId) || profiles[0] || null;
  const sessionActive = Boolean(active && tunnel.profileId === active.id);
  const connected = tunnel.status === 'connected' && sessionActive;
  const connecting = tunnel.status === 'connecting' && sessionActive;
  const started = tunnel.connectedAt || tunnel.startedAt;
  const uptime = started ? (now - started) / 1000 : 0;
  const recent = activity.slice(0, 4);
  const suite = suiteMeta(connected ? tunnel.suite : active?.suite);

  const connectPrimary = () => {
    if (connected || connecting) onDisconnect();
    else if (active) onConnect(active.id);
    else onOpenNew();
  };

  return (
    <div className="page page-dashboard">
      <section className="hero-grid">
        <div className="hero-copy">
          <div className="hero-topline">
            <span className="eyebrow">PRAETOR CONTROL / 01</span>
            <span className={`signal-pill ${connected ? 'is-live' : ''}`}>
              <span className="signal-bars"><i /><i /><i /><i /></span>
              {connected ? 'LINK ACTIVE' : connecting ? 'NEGOTIATING' : 'STANDBY'}
            </span>
          </div>
          <h1>{settings.heroTitle || 'Network control, without the friction.'}</h1>
          <p className="hero-description">
            A pinned PRAETOR control plane for hybrid post-quantum handshakes, selectable crypto suites, and an agent fabric that can actually reach your computer.
          </p>
          <ProfileSwitcher
            activeId={active?.id || null}
            onSelect={onSelectProfile}
            profiles={profiles}
            tunnel={tunnel}
          />
          <div className="hero-actions">
            <Button
              icon={connected || connecting ? Power : Zap}
              onClick={connectPrimary}
              size="lg"
              variant={connected || connecting ? 'danger' : 'primary'}
            >
              {connected ? 'Disconnect' : connecting ? 'Cancel handshake' : active ? `Connect ${active.name}` : 'Create a profile'}
            </Button>
            <Button icon={ArrowRight} onClick={() => onNavigate('tunnels')} size="lg" variant="ghost">
              Manage profiles
            </Button>
          </div>
          <div className="hero-trust-row">
            <span><ShieldCheck size={13} /> Hybrid X-Wing handshake</span>
            <span><Radio size={13} /> Fixed-cell framing</span>
            <span><BrainCircuit size={13} /> Agent accessible</span>
          </div>
          <div className="hero-footline">
            <span className="hero-pulse" />
            <span>{active ? `${active.name} · ${active.endpoint}` : 'No profile selected'}</span>
            <span className="hero-footline-divider" />
            <span>{connected ? `UP ${formatDuration(uptime)}` : 'TCP DATA PLANE SIMULATED'}</span>
          </div>
        </div>
        <HeaderArt
          caption={settings.headerCaption}
          image={heroImage}
          onClear={onClearHero}
          onPick={onPickHero}
        />
      </section>

      <section className="metric-grid">
        <Stat
          hint={connected ? `Session ${formatDuration(uptime)}` : 'No active session'}
          icon={Gauge}
          label="HANDSHAKE"
          tone="mint"
          value={tunnel.handshakeMs ? `${tunnel.handshakeMs} ms` : '—'}
        />
        <Stat
          hint={`RX ${formatBytes(tunnel.rx)} · TX ${formatBytes(tunnel.tx)}`}
          icon={Activity}
          label="TRANSFER"
          tone="violet"
          value={formatBytes(tunnel.rx + tunnel.tx)}
        />
        <Stat
          hint={connected ? 'Rolling jitter sample' : 'Awaiting link'}
          icon={Radio}
          label="LATENCY"
          tone={connected ? 'mint' : 'neutral'}
          value={tunnel.latency ? `${tunnel.latency} ms` : '—'}
        />
        <Stat
          hint={`${PRAETOR_PROTOCOL} · ${active?.cellSize || 1024} B cells`}
          icon={KeyRound}
          label="SUITE"
          tone="amber"
          value={active ? suite.label : '—'}
        />
      </section>

      <section className="dashboard-grid">
        <SpotlightCard className="panel traffic-panel">
          <TrafficChart status={tunnel.status} />
        </SpotlightCard>

        <SpotlightCard className="panel connection-panel">
          <div className="connection-head">
            <div>
              <span className="eyebrow">PRAETOR SESSION</span>
              <h2>{active?.name || 'No active profile'}</h2>
            </div>
            <Badge dot tone={connected ? 'mint' : connecting ? 'amber' : 'neutral'}>
              {statusLabel(sessionActive ? tunnel.status : 'disconnected')}
            </Badge>
          </div>
          <div className="connection-visual">
            <ConnectionOrb latency={tunnel.latency} status={connected || connecting ? tunnel.status : 'disconnected'} />
            <div className="connection-readout">
              <span className="readout-path"><MapPin size={13} /> {active?.location || 'No endpoint'}</span>
              <code>{active?.endpoint || '—'}</code>
              <span className="readout-meta">
                {connected ? `Online for ${formatDuration(uptime)}` : connecting ? 'Establishing PRAETOR handshake…' : 'Pinned identity loaded'}
              </span>
            </div>
          </div>
          <div className="connection-details">
            <div><span>Protocol</span><strong>{active?.protocol || PRAETOR_PROTOCOL}</strong></div>
            <div><span>Suite</span><strong>{suite.label}</strong></div>
            <div><span>Cells</span><strong>{active?.cellSize || 1024} B · {cellWireSize(active?.cellSize)} wire</strong></div>
            <div><span>Transport</span><strong>TCP / {endpointPort(active?.endpoint)}</strong></div>
          </div>
          <div className="connection-actions">
            <Button
              icon={connected || connecting ? Power : Zap}
              onClick={connectPrimary}
              variant={connected || connecting ? 'danger' : 'secondary'}
            >
              {connected ? 'Disconnect' : connecting ? 'Cancel' : 'Connect'}
            </Button>
            <Button icon={ArrowUpRight} onClick={() => active && onEditProfile(active)} variant="ghost">
              Edit profile
            </Button>
          </div>
        </SpotlightCard>

        <SpotlightCard className="panel agent-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">AGENT FABRIC</span>
              <h2>Computer use, wired in.</h2>
            </div>
            <span className="agent-glyph"><Sparkles size={17} /></span>
          </div>
          <div className="agent-status-line">
            <span className={`status-dot ${mcp?.ready ? 'is-online' : ''} is-pulsing`} />
            <strong>{mcp?.ready ? 'MCP runtime ready' : 'Runtime unavailable'}</strong>
            <Badge tone={settings.mcpFullControl ? 'amber' : 'mint'}>
              {settings.mcpFullControl ? 'FULL CONTROL' : 'GUARDED'}
            </Badge>
          </div>
          <p className="agent-description">
            {TOOL_COUNT} audited tools span the filesystem, PowerShell, screen, input, apps, and git. Any MCP client can connect over the local stdio bridge.
          </p>
          <div className="agent-mini-stats">
            <div><strong>{TOOL_COUNT}</strong><span>tools</span></div>
            <div><strong>7</strong><span>categories</span></div>
            <div><strong>{settings.mcpAllowedRoots.length}</strong><span>roots</span></div>
          </div>
          <div className="agent-actions">
            <Button icon={BrainCircuit} onClick={() => onNavigate('agent')} variant="secondary">Open agent fabric</Button>
            <Button icon={ArrowRight} onClick={() => onNavigate('tools')} variant="ghost">Browse tools</Button>
          </div>
        </SpotlightCard>

        <SpotlightCard className="panel posture-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">CRYPTO POSTURE</span>
              <h2>Pinned by default.</h2>
            </div>
            <ShieldCheck className="posture-shield" size={21} />
          </div>
          <div className="posture-list">
            <PostureRow label="Hybrid KEM handshake" active />
            <PostureRow label="Pinned server identity" active={Boolean(active?.serverPublicKey)} />
            <PostureRow label="Fixed-cell framing" active />
            <PostureRow label="Cover-traffic schedule" active={false} />
          </div>
          <div className="posture-note">
            <Clock size={13} />
            <span>{connected ? `${PRAETOR_HANDSHAKE}; policy sampled each handshake.` : 'The pin and suite are applied on the next handshake.'}</span>
          </div>
        </SpotlightCard>

        <SpotlightCard className="panel activity-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">RECENT SIGNAL</span>
              <h2>Activity</h2>
            </div>
            <button className="text-button" onClick={() => onNavigate('activity')} type="button">View all <ArrowRight size={13} /></button>
          </div>
          <div className="activity-list activity-list-compact">
            {recent.length ? recent.map((entry) => {
              const Icon = activityIcon(entry.kind);
              return (
                <div className="activity-row" key={entry.id}>
                  <span className={`activity-icon activity-${entry.kind}`}><Icon size={14} /></span>
                  <div>
                    <strong>{entry.title}</strong>
                    <span>{entry.detail}</span>
                  </div>
                  <time>{timeAgo(entry.ts)}</time>
                </div>
              );
            }) : <div className="activity-empty">No events yet.</div>}
          </div>
        </SpotlightCard>
      </section>

      <div className="dashboard-footnote">
        <Wifi size={14} />
        <span>
          PRAETOR profiles pin an X-Wing server key and select a record-protection suite. Live TCP packet flow requires the PRAETOR data-plane driver; MCP and agent execution are real.
        </span>
        <div className="footnote-actions">
          <CopyButton label="Copy endpoint" value={active?.endpoint || ''} />
        </div>
      </div>
    </div>
  );
}

function ProfileSwitcher({ profiles, activeId, tunnel, onSelect }) {
  if (!profiles.length) return null;
  return (
    <div className="profile-switcher">
      <div className="profile-switcher-head">
        <span className="eyebrow">ACTIVE CRYPTO PROFILE</span>
        <span className="profile-switcher-note">{PRAETOR_PROTOCOL} · switch re-handshakes</span>
      </div>
      <div aria-label="PRAETOR crypto profiles" className="profile-switcher-track" role="tablist">
        {profiles.map((profile) => {
          const selected = profile.id === activeId;
          const live = tunnel.profileId === profile.id && tunnel.status !== 'disconnected';
          return (
            <button
              aria-selected={selected}
              className={`profile-switcher-option ${selected ? 'is-active' : ''}`}
              key={profile.id}
              onClick={() => onSelect(profile.id)}
              role="tab"
              type="button"
            >
              <span className="profile-switcher-suite">{suiteMeta(profile.suite).label}</span>
              <span className="profile-switcher-copy">
                <strong>{profile.name}</strong>
                <small>{profile.cellSize} B cells</small>
              </span>
              {live ? <span className={`profile-switcher-live ${tunnel.status === 'connecting' ? 'is-busy' : ''}`} /> : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function PostureRow({ label, active, invert = false }) {
  const good = invert ? !active : active;
  return (
    <div className="posture-row">
      <span className={`posture-dot ${good ? 'is-good' : ''}`} />
      <span>{label}</span>
      <strong className={good ? 'is-good' : ''}>{active ? 'ON' : 'OFF'}</strong>
    </div>
  );
}

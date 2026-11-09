import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowUpRight,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  MapPin,
  Network,
  Pencil,
  Plus,
  Power,
  ShieldCheck,
  Trash2,
  Upload,
  Wifi,
  Zap,
} from 'lucide-react';
import { ConnectionOrb } from '../components/Atmosphere.jsx';
import { Badge, Button, CopyButton, EmptyState, IconButton, SpotlightCard } from '../components/Primitives.jsx';
import { formatDuration, statusLabel } from '../lib/format.js';
import { useNow } from '../lib/hooks.js';
import {
  PRAETOR_HANDSHAKE,
  PRAETOR_PROTOCOL,
  PRAETOR_SERVER_KEY_BYTES,
  cellWireSize,
  endpointPort,
  suiteMeta,
} from '../lib/praetor.js';

function KeyRow({ label, value, shown, onToggle }) {
  return (
    <div className="key-row">
      <span><KeyRound size={13} />{label}</span>
      <code>{shown ? value : `${value?.slice(0, 6) || '—'}••••••••${value?.slice(-6) || ''}`}</code>
      <button aria-label={`Toggle ${label} visibility`} onClick={onToggle} type="button">
        {shown ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
      <CopyButton label="" value={value} />
    </div>
  );
}

export default function Tunnels({
  profiles,
  tunnel,
  activeProfileId,
  onConnect,
  onDisconnect,
  onNewProfile,
  onEditProfile,
  onDeleteProfile,
  onImport,
  onExport,
}) {
  const now = useNow(1000);
  const [selectedId, setSelectedId] = useState(activeProfileId || tunnel.profileId || profiles[0]?.id || null);
  const [showKeys, setShowKeys] = useState(false);
  const fileRef = useRef(null);

  useEffect(() => {
    const preferred = activeProfileId || tunnel.profileId;
    if (preferred) setSelectedId(preferred);
  }, [activeProfileId, tunnel.profileId]);

  useEffect(() => {
    if (selectedId && profiles.some((profile) => profile.id === selectedId)) return;
    setSelectedId(profiles[0]?.id || null);
  }, [profiles, selectedId]);

  const selected = profiles.find((profile) => profile.id === selectedId) || profiles[0] || null;
  const connected = tunnel.status === 'connected' && tunnel.profileId === selected?.id;
  const connecting = tunnel.status === 'connecting' && tunnel.profileId === selected?.id;
  const selectedSuite = suiteMeta(connected ? tunnel.suite : selected?.suite);
  const activeAny = tunnel.status !== 'disconnected';
  const uptime = tunnel.connectedAt ? (now - tunnel.connectedAt) / 1000 : 0;

  return (
    <div className="page page-tunnels">
      <div className="section-toolbar">
        <div className="toolbar-copy">
          <span className="eyebrow">CRYPTO PROFILES / {String(profiles.length).padStart(2, '0')}</span>
          <h2>Choose the encrypted path.</h2>
        </div>
        <div className="toolbar-actions">
          <input
            accept="application/json,.json"
            className="visually-hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) onImport(file);
              event.target.value = '';
            }}
            ref={fileRef}
            type="file"
          />
          <Button icon={Upload} onClick={() => fileRef.current?.click()} variant="ghost">Import</Button>
          <Button icon={Download} onClick={() => onExport(profiles)} variant="ghost">Export</Button>
          <Button icon={Plus} onClick={onNewProfile} variant="primary">New profile</Button>
        </div>
      </div>

      <div className="tunnel-layout">
        <div className="tunnel-list">
          <div className="tunnel-list-head">
            <span className="eyebrow">PRAETOR/1 PROFILES</span>
            <span className="count-chip">{profiles.length}</span>
          </div>
          {profiles.map((profile) => {
            const isActive = profile.id === selected?.id;
            const isConnected = tunnel.status !== 'disconnected' && tunnel.profileId === profile.id;
            const isEnabled = profile.id === activeProfileId;
            return (
              <button
                className={`tunnel-list-item ${isActive ? 'is-selected' : ''}`}
                key={profile.id}
                onClick={() => setSelectedId(profile.id)}
                type="button"
              >
                <span className={`profile-avatar profile-avatar-${profile.color || 'mint'}`}>
                  <Network size={16} />
                </span>
                <span className="tunnel-list-copy">
                  <span className="tunnel-list-name">
                    <strong>{profile.name}</strong>
                    {isConnected ? (
                      <span className="mini-link is-live"><i />{tunnel.status === 'connecting' ? 'SYNC' : 'ON'}</span>
                    ) : isEnabled ? (
                      <span className="mini-link"><i />ACTIVE</span>
                    ) : null}
                  </span>
                  <span>{isConnected ? tunnel.suite : profile.suite} · {profile.endpoint}</span>
                  <span className="tunnel-tags">
                    {profile.tags?.slice(0, 3).map((tag) => <em key={tag}>{tag}</em>)}
                  </span>
                </span>
                <ArrowUpRight size={14} className="tunnel-list-arrow" />
              </button>
            );
          })}
          {profiles.length === 0 ? (
            <EmptyState icon={Network} title="No crypto profiles yet">
              Create a PRAETOR/1 profile to pin a server and select a suite.
            </EmptyState>
          ) : null}
          <button className="tunnel-add-card" onClick={onNewProfile} type="button">
            <Plus size={15} />
            <span>Add another crypto profile</span>
          </button>
        </div>

        {selected ? (
          <div className="tunnel-detail">
            <SpotlightCard className="panel tunnel-detail-hero">
              <div className="tunnel-detail-head">
                <div className="tunnel-detail-title">
                  <span className={`profile-avatar profile-avatar-${selected.color || 'mint'} profile-avatar-lg`}>
                    <Network size={21} />
                  </span>
                  <div>
                    <div className="tunnel-detail-name-row">
                      <h2>{selected.name}</h2>
                      <Badge tone="neutral">{selected.protocol || PRAETOR_PROTOCOL}</Badge>
                      <Badge tone={selected.color || 'mint'}>{selectedSuite.label}</Badge>
                    </div>
                    <p>{selected.description || 'No description yet.'}</p>
                    <div className="tunnel-meta-row">
                      <span><MapPin size={13} /> {selected.location || 'Unassigned'}</span>
                      <span><ShieldCheck size={13} /> {PRAETOR_HANDSHAKE}</span>
                      <span><KeyRound size={13} /> {selected.cellSize} B cells</span>
                      {selected.autoConnect ? <span><Zap size={13} /> auto-connect</span> : null}
                    </div>
                  </div>
                </div>
                <div className="tunnel-detail-actions">
                  <IconButton icon={Pencil} label="Edit profile" onClick={() => onEditProfile(selected)} />
                  <IconButton icon={Trash2} label="Delete profile" onClick={() => onDeleteProfile(selected)} />
                </div>
              </div>

              <div className="tunnel-connection-strip">
                <div className="tunnel-orb-wrap">
                  <ConnectionOrb latency={tunnel.profileId === selected.id ? tunnel.latency : null} status={tunnel.profileId === selected.id ? tunnel.status : 'disconnected'} />
                </div>
                <div className="tunnel-connection-copy">
                  <span className="eyebrow">CURRENT LINK</span>
                  <h3>{tunnel.profileId === selected.id ? statusLabel(tunnel.status) : 'Not active'}</h3>
                  <code>{selected.endpoint}</code>
                  {tunnel.profileId === selected.id && tunnel.status === 'connected' ? (
                    <span className="link-meta"><Wifi size={13} /> up {formatDuration(uptime)} · {tunnel.latency} ms · {selectedSuite.label} suite</span>
                  ) : (
                    <span className="link-meta"><Zap size={13} /> Ready for a PRAETOR handshake</span>
                  )}
                </div>
                <Button
                  icon={connected || connecting ? Power : Zap}
                  onClick={() => (connected || connecting ? onDisconnect() : onConnect(selected.id))}
                  variant={connected || connecting ? 'danger' : 'primary'}
                >
                  {connected ? 'Disconnect' : connecting ? 'Cancel' : 'Connect'}
                </Button>
              </div>
            </SpotlightCard>

            <div className="tunnel-detail-grid">
              <SpotlightCard className="panel detail-card">
                <div className="panel-heading">
                  <div>
                    <span className="eyebrow">WIRE FORMAT</span>
                    <h2>PRAETOR framing</h2>
                  </div>
                  <Badge tone="neutral">{selected.transport?.toUpperCase() || 'TCP'}</Badge>
                </div>
                <div className="detail-grid">
                  <Detail label="Endpoint" value={selected.endpoint} mono />
                  <Detail label="Protocol" value={selected.protocol || PRAETOR_PROTOCOL} mono />
                  <Detail label="Suite" value={selectedSuite.label} />
                  <Detail label="Transport" value={`TCP / ${endpointPort(selected.endpoint)}`} mono />
                  <Detail label="Cell size" value={`${selected.cellSize} B`} />
                  <Detail label="Wire cell" value={`${cellWireSize(selected.cellSize)} B`} />
                </div>
              </SpotlightCard>

              <SpotlightCard className="panel detail-card">
                <div className="panel-heading">
                  <div>
                    <span className="eyebrow">PINNED IDENTITY</span>
                    <h2>Server key</h2>
                  </div>
                  <button className="text-button" onClick={() => setShowKeys((value) => !value)} type="button">
                    {showKeys ? <EyeOff size={13} /> : <Eye size={13} />} {showKeys ? 'Hide' : 'Reveal'}
                  </button>
                </div>
                <div className="key-stack">
                  <KeyRow label="X-Wing server" onToggle={() => setShowKeys((value) => !value)} shown={showKeys} value={selected.serverPublicKey} />
                </div>
                <p className="detail-note"><KeyRound size={13} /> {PRAETOR_SERVER_KEY_BYTES}-byte public key. Client keys are generated per handshake and never stored in the profile.</p>
              </SpotlightCard>

              <SpotlightCard className="panel detail-card detail-card-wide">
                <div className="panel-heading">
                  <div>
                    <span className="eyebrow">ADVANCED</span>
                    <h2>Handshake policy</h2>
                  </div>
                  <Badge tone={selected.autoConnect ? 'mint' : 'neutral'}>{selected.autoConnect ? 'AUTO-CONNECT' : 'MANUAL'}</Badge>
                </div>
                <div className="policy-row-grid">
                  <div className="policy-tile"><span>Handshake</span><strong>Hybrid X-Wing</strong><small>{PRAETOR_HANDSHAKE}</small></div>
                  <div className="policy-tile"><span>Record protection</span><strong>{selectedSuite.label}</strong><small>{selectedSuite.description}</small></div>
                  <div className="policy-tile"><span>Framing</span><strong>{selected.cellSize} B cells</strong><small>{cellWireSize(selected.cellSize)} B on wire</small></div>
                  <div className="policy-tile"><span>Transport</span><strong>TCP / {endpointPort(selected.endpoint)}</strong><small>Pinned server, no TLS layer</small></div>
                </div>
              </SpotlightCard>
            </div>
          </div>
        ) : (
          <SpotlightCard className="panel tunnel-detail tunnel-detail-empty">
            <EmptyState
              action={<Button icon={Plus} onClick={onNewProfile} variant="primary">Create profile</Button>}
              icon={Network}
              title="Select a crypto profile"
            >
              Profiles appear here with pinned server identity, suite, framing, and handshake policy.
            </EmptyState>
          </SpotlightCard>
        )}
      </div>

      <div className="tunnel-footnote">
        <span className={`status-dot ${activeAny ? 'is-online' : ''}`} />
        <span>{activeAny ? `${tunnel.profileName || 'A profile'} is ${tunnel.status}.` : 'No active PRAETOR session. Connect a profile to route browser traffic through the Dallas egress.'}</span>
        <span className="tunnel-footnote-separator" />
        <span>Imports and exports use portable JSON.</span>
      </div>
    </div>
  );
}

function Detail({ label, value, mono = false, className = '' }) {
  return (
    <div className={`detail-item ${className}`}>
      <span>{label}</span>
      <strong className={mono ? 'is-mono' : ''}>{value || '—'}</strong>
    </div>
  );
}

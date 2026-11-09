import React, { useEffect, useState } from 'react';
import { KeyRound, Save, ShieldCheck } from 'lucide-react';
import { Modal, Button, Toggle, Badge } from './Primitives.jsx';
import {
  DEMO_ENDPOINT,
  DEMO_SERVER_PUBLIC_KEY,
  PRAETOR_CELL_SIZES,
  PRAETOR_HANDSHAKE,
  PRAETOR_PROTOCOL,
  PRAETOR_SERVER_KEY_BYTES,
  PRAETOR_SUITES,
  base64ByteLength,
  cellWireSize,
  suiteMeta,
} from '../lib/praetor.js';

const COLORS = [
  { id: 'mint', label: 'Mint' },
  { id: 'violet', label: 'Violet' },
  { id: 'amber', label: 'Amber' },
  { id: 'ice', label: 'Ice' },
];

const BLANK = {
  name: '',
  description: '',
  location: '',
  endpoint: DEMO_ENDPOINT,
  protocol: PRAETOR_PROTOCOL,
  suite: 'PSEAL',
  transport: 'tcp',
  cellSize: 1024,
  serverPublicKey: '',
  autoConnect: false,
  tags: '',
  color: 'mint',
};

export default function ProfileEditor({ open, profile, onClose, onSave }) {
  const [draft, setDraft] = useState(BLANK);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!open) return;
    setError('');
    if (profile) {
      setDraft({
        ...BLANK,
        ...profile,
        suite: suiteMeta(profile.suite).id,
        cellSize: Number(profile.cellSize) || 1024,
        tags: Array.isArray(profile.tags) ? profile.tags.join(', ') : profile.tags || '',
      });
    } else {
      setDraft({ ...BLANK });
    }
  }, [open, profile]);

  const update = (key, value) => setDraft((current) => ({ ...current, [key]: value }));
  const keyLength = base64ByteLength(draft.serverPublicKey);

  const submit = (event) => {
    event.preventDefault();
    if (!draft.name.trim()) {
      setError('Give the crypto profile a name.');
      return;
    }

    const endpoint = draft.endpoint.trim();
    if (endpoint.includes('://')) {
      setError('Enter a host and port only, for example 104.251.218.227:9443.');
      return;
    }
    const endpointMatch = endpoint.match(/^(.+):(\d{1,5})$/);
    if (!endpointMatch) {
      setError('The endpoint must be host:port, for example 104.251.218.227:9443.');
      return;
    }
    const host = endpointMatch[1].trim();
    const port = Number(endpointMatch[2]);
    if (!host || /\s/.test(host) || port < 1 || port > 65535) {
      setError('The endpoint needs a valid host and a port between 1 and 65535.');
      return;
    }

    const serverPublicKey = draft.serverPublicKey.replace(/\s+/g, '');
    const pinBytes = base64ByteLength(serverPublicKey);
    if (pinBytes !== PRAETOR_SERVER_KEY_BYTES) {
      setError(`The pinned X-Wing public key must decode to ${PRAETOR_SERVER_KEY_BYTES} bytes (got ${pinBytes || 0}).`);
      return;
    }

    const cellSize = Number(draft.cellSize);
    if (!PRAETOR_CELL_SIZES.includes(cellSize)) {
      setError('Choose a supported fixed cell size.');
      return;
    }

    const suite = suiteMeta(draft.suite).id;
    const tags = String(draft.tags || '')
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean)
      .slice(0, 8);

    onSave({
      id: profile?.id,
      name: draft.name.trim(),
      description: draft.description.trim(),
      location: draft.location.trim() || 'Local',
      endpoint,
      protocol: PRAETOR_PROTOCOL,
      suite,
      transport: 'tcp',
      cellSize,
      serverPublicKey,
      autoConnect: Boolean(draft.autoConnect),
      tags,
      color: draft.color,
    });
  };

  return (
    <Modal
      eyebrow={profile ? 'EDIT CRYPTO PROFILE' : 'NEW CRYPTO PROFILE'}
      footer={(
        <>
          <Button onClick={onClose} variant="ghost">Cancel</Button>
          <Button icon={Save} onClick={submit} variant="primary">{profile ? 'Save changes' : 'Create profile'}</Button>
        </>
      )}
      onClose={onClose}
      open={open}
      title={profile ? 'Refine PRAETOR profile' : 'Shape a PRAETOR profile'}
      width="790px"
    >
      <form className="profile-form" onSubmit={submit}>
        <div className="form-section">
          <div className="form-section-heading">
            <span className="eyebrow">IDENTITY</span>
            <h3>Profile</h3>
          </div>
          <div className="form-grid form-grid-two">
            <label className="field">
              <span>Name</span>
              <input autoFocus onChange={(event) => update('name', event.target.value)} placeholder="Nexus PSEAL" value={draft.name} />
            </label>
            <label className="field">
              <span>Location</span>
              <input onChange={(event) => update('location', event.target.value)} placeholder="Nexus VPS" value={draft.location} />
            </label>
            <label className="field form-span-two">
              <span>Description</span>
              <input onChange={(event) => update('description', event.target.value)} placeholder="What this crypto profile is for…" value={draft.description} />
            </label>
            <label className="field">
              <span>Tags <em>comma separated</em></span>
              <input onChange={(event) => update('tags', event.target.value)} placeholder="pq, siv, default" value={draft.tags} />
            </label>
            <div className="field">
              <span>Accent</span>
              <div className="color-picker">
                {COLORS.map((color) => (
                  <button
                    aria-label={color.label}
                    className={`color-swatch swatch-${color.id} ${draft.color === color.id ? 'is-selected' : ''}`}
                    key={color.id}
                    onClick={() => update('color', color.id)}
                    type="button"
                  >
                    <span />
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="form-section">
          <div className="form-section-heading">
            <span className="eyebrow">TRANSPORT</span>
            <h3>Endpoint and suite</h3>
          </div>
          <div className="form-grid form-grid-two">
            <label className="field form-span-two">
              <span>Endpoint <em>host:port</em></span>
              <input onChange={(event) => update('endpoint', event.target.value)} placeholder="104.251.218.227:9443" value={draft.endpoint} />
            </label>
            <label className="field">
              <span>Crypto suite</span>
              <select onChange={(event) => update('suite', event.target.value)} value={draft.suite}>
                {PRAETOR_SUITES.map((suite) => (
                  <option key={suite.id} value={suite.id}>{suite.label} · {suite.primitive}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Fixed cell size</span>
              <select onChange={(event) => update('cellSize', Number(event.target.value))} value={draft.cellSize}>
                {PRAETOR_CELL_SIZES.map((size) => (
                  <option key={size} value={size}>{size} B · {cellWireSize(size)} B on wire</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Protocol</span>
              <input readOnly value={PRAETOR_PROTOCOL} />
            </label>
            <label className="field">
              <span>Transport</span>
              <input readOnly value="TCP" />
            </label>
            <label className="field form-span-two">
              <span>Pinned server key <em>X-Wing public key · {PRAETOR_SERVER_KEY_BYTES} bytes</em></span>
              <textarea
                className="key-textarea"
                onChange={(event) => update('serverPublicKey', event.target.value)}
                placeholder="Paste the base64 X-Wing public key from the PRAETOR server"
                rows={3}
                spellCheck={false}
                value={draft.serverPublicKey}
              />
            </label>
            <div className="field-actions form-span-two">
              <Button icon={KeyRound} onClick={() => update('serverPublicKey', DEMO_SERVER_PUBLIC_KEY)} size="sm" variant="ghost">
                Use demo pin
              </Button>
              <span>{keyLength === PRAETOR_SERVER_KEY_BYTES ? `${keyLength} bytes decoded` : keyLength ? `${keyLength} bytes decoded · expected ${PRAETOR_SERVER_KEY_BYTES}` : 'Awaiting the server pin'}</span>
            </div>
          </div>
          <p className="form-note">
            <ShieldCheck size={13} />
            PRAETOR pins the server's X-Wing key. Client keypairs are ephemeral for each handshake and are never stored in this profile.
          </p>
          <div className="form-toggle-row">
            <div>
              <strong>Hybrid post-quantum handshake</strong>
              <span>{PRAETOR_HANDSHAKE} · PRAETOR/1</span>
            </div>
            <Badge tone="mint">REQUIRED</Badge>
          </div>
          <div className="form-toggle-row">
            <div>
              <strong>Auto-connect at launch</strong>
              <span>Start this profile's PRAETOR handshake when the control plane opens.</span>
            </div>
            <Toggle checked={draft.autoConnect} label="Auto-connect at launch" onChange={(value) => update('autoConnect', value)} />
          </div>
        </div>

        {error ? <div className="form-error">{error}</div> : null}
      </form>
    </Modal>
  );
}

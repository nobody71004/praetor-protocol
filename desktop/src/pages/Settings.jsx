import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Cpu,
  FolderPlus,
  ImagePlus,
  Info,
  KeyRound,
  Monitor,
  Plus,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { Badge, Button, CopyButton, Toggle } from '../components/Primitives.jsx';
import { api } from '../lib/bridge.js';
import { readImage } from '../lib/format.js';

const ACCENTS = [
  { id: 'mint', label: 'Mint', color: '#5ce1b0' },
  { id: 'violet', label: 'Violet', color: '#b79cff' },
  { id: 'amber', label: 'Amber', color: '#ffc46b' },
  { id: 'ice', label: 'Ice', color: '#83c7ff' },
];

function SettingsSection({ eyebrow, title, description, icon: Icon, children, tone = 'mint' }) {
  return (
    <section className="settings-section">
      <div className="settings-section-aside">
        <span className={`settings-icon settings-icon-${tone}`}><Icon size={18} /></span>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      <div className="settings-section-body">{children}</div>
    </section>
  );
}

function SettingsRow({ title, description, children, tone = '' }) {
  return (
    <div className={`settings-row ${tone ? `settings-row-${tone}` : ''}`}>
      <div>
        <strong>{title}</strong>
        {description ? <span>{description}</span> : null}
      </div>
      {children}
    </div>
  );
}

function ImageSlot({ image, label, hint, onPick, onClear }) {
  const ref = useRef(null);
  const [error, setError] = useState('');
  const choose = async (file) => {
    setError('');
    try {
      const dataUrl = await readImage(file);
      onPick(dataUrl);
    } catch (readError) {
      setError(readError.message);
    }
  };
  return (
    <div className="settings-image-slot">
      <div className={`image-slot-preview ${image ? 'has-image' : ''}`} style={image ? { backgroundImage: `url(${image})` } : undefined}>
        {!image ? <ImagePlus size={22} /> : null}
        <div className="image-slot-overlay">
          <button onClick={() => ref.current?.click()} type="button"><Upload size={13} /> {image ? 'Replace' : 'Upload'}</button>
          {image ? <button onClick={onClear} type="button"><X size={13} /> Remove</button> : null}
        </div>
      </div>
      <div className="image-slot-copy">
        <strong>{label}</strong>
        <span>{hint}</span>
        {error ? <em>{error}</em> : null}
      </div>
      <input
        accept="image/png,image/jpeg,image/webp,image/gif,image/avif"
        className="visually-hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) choose(file);
          event.target.value = '';
        }}
        ref={ref}
        type="file"
      />
    </div>
  );
}

export default function Settings({
  settings,
  onSave,
  appInfo,
  heroImage,
  badgeImage,
  onPickHero,
  onPickBadge,
  onClearHero,
  onClearBadge,
  toast,
}) {
  const [title, setTitle] = useState(settings.heroTitle || '');
  const [caption, setCaption] = useState(settings.headerCaption || '');
  const [modelInput, setModelInput] = useState(settings.agentModel || '');
  const [baseInput, setBaseInput] = useState(settings.agentBaseUrl || '');
  const [rootInput, setRootInput] = useState('');

  useEffect(() => {
    setTitle(settings.heroTitle || '');
    setCaption(settings.headerCaption || '');
    setModelInput(settings.agentModel || '');
    setBaseInput(settings.agentBaseUrl || '');
  }, [settings.heroTitle, settings.headerCaption, settings.agentModel, settings.agentBaseUrl]);

  const save = (patch) => onSave(patch);
  const addRoot = () => {
    const value = rootInput.trim();
    if (!value) return;
    if (settings.mcpAllowedRoots.includes(value)) {
      toast('Root already listed', value, 'warning');
      return;
    }
    save({ mcpAllowedRoots: [...settings.mcpAllowedRoots, value] });
    setRootInput('');
  };
  const removeRoot = (root) => {
    if (settings.mcpAllowedRoots.length <= 1) {
      toast('Keep one root', 'At least one allowlisted root is required.', 'warning');
      return;
    }
    save({ mcpAllowedRoots: settings.mcpAllowedRoots.filter((entry) => entry !== root) });
  };
  const copyConfig = async () => {
    const result = await api.mcp.copyConfig();
    if (result?.ok) toast('MCP config copied', 'Paste it into your MCP client.', 'success');
    else toast('Copy failed', result?.error || 'Config unavailable.', 'error');
  };

  return (
    <div className="page page-settings">
      <div className="settings-intro">
        <span className="eyebrow">SYSTEM PREFERENCES / 01</span>
        <h1>Make the surface yours.</h1>
        <p>Appearance and trust settings apply immediately. Changes to the MCP runtime are staged into the next spawned server.</p>
      </div>

      <SettingsSection
        description="The accent propagates through the whole command surface. Motion controls the ambient animations, including the cursor field."
        eyebrow="01 / APPEARANCE"
        icon={Sparkles}
        title="Surface"
      >
        <SettingsRow title="Accent" description="Command color and signal highlights.">
          <div className="accent-options">
            {ACCENTS.map((accent) => (
              <button
                aria-label={accent.label}
                className={`accent-option ${settings.accent === accent.id ? 'is-selected' : ''}`}
                key={accent.id}
                onClick={() => save({ accent: accent.id })}
                style={{ '--swatch': accent.color }}
                type="button"
              >
                <span />
                {accent.label}
                {settings.accent === accent.id ? <Check size={12} /> : null}
              </button>
            ))}
          </div>
        </SettingsRow>
        <SettingsRow title="Ambient motion" description="Particles, orb pulses, and chart transitions.">
          <Toggle checked={settings.animations} label="Ambient motion" onChange={(value) => save({ animations: value })} />
        </SettingsRow>
        <SettingsRow title="Cursor field" description="A soft light and crosshair that follow the pointer.">
          <Toggle checked={settings.cursorEffects} label="Cursor field" onChange={(value) => save({ cursorEffects: value })} />
        </SettingsRow>
        <SettingsRow title="Glass density" description="Opacity of the command panels.">
          <div className="range-control">
            <input max="100" min="20" onChange={(event) => save({ glass: Number(event.target.value) })} type="range" value={settings.glass} />
            <span>{settings.glass}%</span>
          </div>
        </SettingsRow>
      </SettingsSection>

      <SettingsSection
        description="Drop in artwork for the overview hero and the command badge. Images stay in local storage on this machine."
        eyebrow="02 / HEADER ART"
        icon={ImagePlus}
        title="Image slots"
        tone="violet"
      >
        <div className="image-slot-grid">
          <ImageSlot
            hint="Wide artwork for the overview hero. PNG, JPEG, WebP, AVIF, or GIF under 4 MB."
            image={heroImage}
            label="Command header"
            onClear={onClearHero}
            onPick={onPickHero}
          />
          <ImageSlot
            hint="Square mark for the sidebar. Falls back to the PRAETOR glyph."
            image={badgeImage}
            label="Workspace badge"
            onClear={onClearBadge}
            onPick={onPickBadge}
          />
        </div>
        <div className="settings-inline-fields">
          <label className="field">
            <span>Hero headline</span>
            <input
              maxLength={180}
              onBlur={() => save({ heroTitle: title.trim() || 'Network control, without the friction.' })}
              onChange={(event) => setTitle(event.target.value)}
              value={title}
            />
          </label>
          <label className="field">
            <span>Header caption</span>
            <input
              maxLength={80}
              onBlur={() => save({ headerCaption: caption.trim() })}
              onChange={(event) => setCaption(event.target.value)}
              value={caption}
            />
          </label>
        </div>
      </SettingsSection>

      <SettingsSection
        description="These preferences shape the control plane and the defaults applied when a profile does not override them."
        eyebrow="03 / NETWORK DEFAULTS"
        icon={Monitor}
        title="Connection"
        tone="amber"
      >
        <SettingsRow title="Auto-connect" description="Start the preferred profile when the app opens.">
          <Toggle checked={settings.autoConnect} label="Auto-connect" onChange={(value) => save({ autoConnect: value })} />
        </SettingsRow>
        <SettingsRow title="Launch at login" description="Open the command surface with Windows.">
          <Toggle checked={settings.launchAtLogin} label="Launch at login" onChange={(value) => save({ launchAtLogin: value })} />
        </SettingsRow>
        <div className="settings-hint">
          <Info size={13} /> PRAETOR handshake policy lives in each crypto profile: pinned server key, suite, framing, and endpoint.
        </div>
      </SettingsSection>

      <SettingsSection
        description="The MCP server is local-only and speaks stdio. Full control unlocks shell, screen, input, clipboard, process, and delete capabilities."
        eyebrow="04 / MCP RUNTIME"
        icon={Terminal}
        title="Agent trust boundary"
        tone="amber"
      >
        <SettingsRow
          description="When off, guarded tools are rejected before execution."
          title="Full computer control"
          tone={settings.mcpFullControl ? 'warning' : ''}
        >
          <div className="settings-toggle-with-state">
            <span className={`state-label ${settings.mcpFullControl ? 'is-warning' : ''}`}>{settings.mcpFullControl ? 'FULL CONTROL' : 'GUARDED'}</span>
            <Toggle
              checked={settings.mcpFullControl}
              label="Full computer control"
              onChange={(value) => {
                save({ mcpFullControl: value });
                toast(
                  value ? 'Full control enabled' : 'Guarded mode restored',
                  value ? 'Any connected MCP client can now use shell, screen, input, clipboard, process, and delete tools.' : 'Elevated and destructive tools are rejected at the policy gate.',
                  value ? 'warning' : 'success',
                );
              }}
            />
          </div>
        </SettingsRow>
        {settings.mcpFullControl ? (
          <div className="settings-warning">
            <ShieldAlert size={15} />
            <span>Full control is a real trust boundary. Use it only with clients and models you trust. Every call is audited, but auditing is not prevention.</span>
          </div>
        ) : null}

        <div className="settings-subsection">
          <div className="settings-subheading">
            <div><strong>Allowlisted roots</strong><span>Filesystem tools resolve every path against these directories.</span></div>
            <Badge tone="neutral">{settings.mcpAllowedRoots.length} roots</Badge>
          </div>
          <div className="root-list">
            {settings.mcpAllowedRoots.map((root) => (
              <div className="root-row" key={root}>
                <FolderPlus size={14} />
                <code>{root}</code>
                <button aria-label={`Remove ${root}`} disabled={settings.mcpAllowedRoots.length <= 1} onClick={() => removeRoot(root)} type="button">
                  <X size={13} />
                </button>
              </div>
            ))}
          </div>
          <div className="root-add-row">
            <input
              onChange={(event) => setRootInput(event.target.value)}
              onKeyDown={(event) => event.key === 'Enter' && addRoot()}
              placeholder="C:\Users\you\Projects"
              value={rootInput}
            />
            <Button icon={Plus} onClick={addRoot} size="sm" variant="secondary">Add root</Button>
          </div>
        </div>

        <div className="settings-config-row">
          <div>
            <strong>Client config</strong>
            <span>Copy the stdio server definition or reveal it in Explorer.</span>
          </div>
          <div className="settings-config-actions">
            <Button icon={Copy} onClick={copyConfig} size="sm" variant="secondary">Copy config</Button>
            <CopyButton label="Copy server path" value={appInfo?.mcp?.serverPath || ''} />
          </div>
        </div>
        <div className="settings-path">
          <span>SERVER</span><code>{appInfo?.mcp?.serverPath || 'runtime pending'}</code>
        </div>
      </SettingsSection>

      <SettingsSection
        description="The operator loop is OpenAI-compatible. The key is entered per run and is never written to disk."
        eyebrow="05 / AGENT MODEL"
        icon={KeyRound}
        title="Model endpoint"
        tone="violet"
      >
        <div className="settings-inline-fields">
          <label className="field">
            <span>Default model</span>
            <input onBlur={() => save({ agentModel: modelInput.trim() || 'gpt-4o-mini' })} onChange={(event) => setModelInput(event.target.value)} placeholder="gpt-4o-mini" value={modelInput} />
          </label>
          <label className="field">
            <span>Base URL</span>
            <input onBlur={() => save({ agentBaseUrl: baseInput.trim() || 'https://api.openai.com/v1' })} onChange={(event) => setBaseInput(event.target.value)} placeholder="https://api.openai.com/v1" value={baseInput} />
          </label>
        </div>
        <p className="settings-hint"><Info size={13} /> These defaults are used when the Agent Fabric page opens; the page can override them for an individual run.</p>
      </SettingsSection>

      <SettingsSection
        description="PRAETOR Command runs a real PRAETOR/1 egress session to the Dallas exit. The MCP and agent paths are local to this machine."
        eyebrow="06 / ABOUT"
        icon={Info}
        title="Build"
      >
        <div className="about-grid">
          <div><span>App</span><strong>{appInfo?.name || 'PRAETOR Command'}</strong></div>
          <div><span>Version</span><strong>{appInfo?.version || '1.0.0'}</strong></div>
          <div><span>Electron</span><strong>{appInfo?.electron || '—'}</strong></div>
          <div><span>Chromium</span><strong>{appInfo?.chrome || '—'}</strong></div>
          <div><span>Runtime</span><strong>{appInfo?.packaged ? 'Packaged EXE' : 'Development'}</strong></div>
          <div><span>Transport</span><strong>{appInfo?.dataPlane === 'praetor-egress' ? 'PRAETOR/1 egress' : appInfo?.dataPlane || '—'}</strong></div>
        </div>
        <div className="about-note">
          <ShieldCheck size={14} />
          <span>Local-first. No telemetry. No remote listening control endpoint. Audit records stay under userData.</span>
        </div>
      </SettingsSection>
    </div>
  );
}

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { BrainCircuit, Command, Network, Plus, Power, Settings as SettingsIcon, ShieldCheck, Sparkles, Terminal, Wrench, Zap } from 'lucide-react';
import { api, isElectron } from './lib/bridge.js';
import { DEMO_SETTINGS } from './lib/demo.js';
import { downloadJson } from './lib/format.js';
import { CursorAura, LogoMark, ParticleField } from './components/Atmosphere.jsx';
import { CommandPalette, NAV_ITEMS, Sidebar, TitleBar, ToastStack, StatusDot } from './components/Chrome.jsx';
import ProfileEditor from './components/ProfileEditor.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Tunnels from './pages/Tunnels.jsx';
import Agent from './pages/Agent.jsx';
import Tools from './pages/Tools.jsx';
import Activity from './pages/Activity.jsx';
import Settings from './pages/Settings.jsx';
import { useLocalStorage } from './lib/hooks.js';

const FALLBACK_SETTINGS = {
  ...DEMO_SETTINGS,
  mcpAllowedRoots: [],
};

const EMPTY_TUNNEL = {
  status: 'disconnected',
  profileId: null,
  profileName: null,
  endpoint: null,
  location: null,
  protocol: null,
  suite: null,
  requestedSuite: null,
  cellSize: null,
  startedAt: null,
  connectedAt: null,
  handshakeMs: null,
  latency: null,
  rx: 0,
  tx: 0,
  quality: 'idle',
};

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [profiles, setProfiles] = useState([]);
  const [settings, setSettings] = useState(FALLBACK_SETTINGS);
  const [tunnel, setTunnel] = useState(EMPTY_TUNNEL);
  const [activeProfileId, setActiveProfileId] = useState(null);
  const [activity, setActivity] = useState([]);
  const [mcp, setMcp] = useState(null);
  const [appInfo, setAppInfo] = useState(null);
  const [windowState, setWindowState] = useState({ maximized: false, focused: true });
  const [toasts, setToasts] = useState([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [editor, setEditor] = useState({ open: false, profile: null });
  const [booted, setBooted] = useState(false);
  const [bootError, setBootError] = useState('');
  const [heroImage, setHeroImage] = useLocalStorage('praetor.heroImage', null);
  const [badgeImage, setBadgeImage] = useLocalStorage('praetor.badgeImage', null);
  const toastTimers = useRef(new Map());

  const toast = (title, detail = '', tone = 'info') => {
    const id = crypto.randomUUID();
    setToasts((current) => [...current.slice(-3), { id, title, detail, tone }]);
    const timer = setTimeout(() => {
      setToasts((current) => current.filter((item) => item.id !== id));
      toastTimers.current.delete(id);
    }, 4200);
    toastTimers.current.set(id, timer);
  };

  useEffect(() => () => {
    for (const timer of toastTimers.current.values()) clearTimeout(timer);
    toastTimers.current.clear();
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [nextSettings, nextProfiles, nextTunnel, nextActivity, info, mcpStatus] = await Promise.all([
          api.settings.get(),
          api.profiles.list(),
          api.tunnel.status(),
          api.activity.list(),
          api.app.info(),
          api.mcp.status(),
        ]);
        if (cancelled) return;
        setSettings(nextSettings);
        setProfiles(nextProfiles);
        setTunnel(nextTunnel);
        setActiveProfileId(
          nextTunnel.profileId
          || nextProfiles.find((profile) => profile.autoConnect)?.id
          || nextProfiles[0]?.id
          || null,
        );
        setActivity(nextActivity);
        setAppInfo(info);
        setMcp(mcpStatus);
        setBooted(true);
        if (nextSettings.autoConnect) {
          const preferred = nextProfiles.find((profile) => profile.autoConnect) || nextProfiles[0];
          if (preferred) {
            try {
              const status = await api.tunnel.connect(preferred.id);
              if (!cancelled) setTunnel(status);
            } catch {
              // Auto-connect is best-effort.
            }
          }
        }
      } catch (error) {
        if (!cancelled) {
          setBootError(error.message);
          setBooted(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const cleanups = [];
    cleanups.push(api.tunnel.onStatus((status) => {
      setTunnel(status);
      if (status.profileId) setActiveProfileId(status.profileId);
    }));
    cleanups.push(api.activity.onNew((entry) => setActivity((current) => [entry, ...current].slice(0, 300))));
    cleanups.push(api.settings.onChanged((next) => setSettings(next)));
    cleanups.push(api.window.onState((state) => setWindowState(state)));
    return () => cleanups.forEach((cleanup) => cleanup?.());
  }, []);

  useEffect(() => {
    if (!profiles.length) {
      setActiveProfileId(null);
      return;
    }
    if (!profiles.some((profile) => profile.id === activeProfileId)) {
      setActiveProfileId(profiles.find((profile) => profile.autoConnect)?.id || profiles[0].id);
    }
  }, [profiles, activeProfileId]);

  useEffect(() => {
    document.documentElement.dataset.accent = settings.accent || 'mint';
    document.documentElement.dataset.motion = settings.animations === false ? 'off' : 'on';
    document.documentElement.style.setProperty('--glass-amount', `${(settings.glass ?? 72) / 100}`);
  }, [settings.accent, settings.animations, settings.glass]);

  useEffect(() => {
    const onKey = (event) => {
      const modifier = event.ctrlKey || event.metaKey;
      if (modifier && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
      if (event.key === 'Escape') setPaletteOpen(false);
      if (event.altKey && /^[1-6]$/.test(event.key)) {
        event.preventDefault();
        onNavigate(NAV_ITEMS[Number(event.key) - 1].id);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const onNavigate = (nextPage) => {
    setPage(nextPage);
    setPaletteOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const refreshMcp = async () => {
    try {
      const status = await api.mcp.status();
      setMcp(status);
      setAppInfo((current) => current ? { ...current, mcp: { ...current.mcp, ready: status.ready, path: status.runtimePath, serverPath: status.serverPath } } : current);
    } catch {
      // Status refresh is non-critical.
    }
  };

  const saveSettings = async (patch) => {
    setSettings((current) => ({ ...current, ...patch }));
    try {
      const next = await api.settings.save(patch);
      setSettings(next);
      refreshMcp();
      return next;
    } catch (error) {
      toast('Settings not saved', error.message, 'error');
      return settings;
    }
  };

  const connect = async (profileId = activeProfileId) => {
    const targetId = profileId || profiles.find((item) => item.autoConnect)?.id || profiles[0]?.id;
    if (!targetId) {
      toast('No profile selected', 'Create a PRAETOR crypto profile first.', 'warning');
      return;
    }
    const profile = profiles.find((item) => item.id === targetId);
    setActiveProfileId(targetId);
    try {
      const status = await api.tunnel.connect(targetId);
      setTunnel(status);
      const actualSuite = status.suite || profile?.suite;
      if (status.status === 'connected') {
        toast(
          'PRAETOR session online',
          profile
            ? `${profile.name} · ${actualSuite}${profile.suite !== actualSuite ? ` (${profile.suite} profile)` : ''} → ${profile.endpoint}`
            : 'Pinned PRAETOR transport is online.',
          'success',
        );
      } else {
        toast('PRAETOR session failed', 'Check Activity for the handshake error.', 'error');
      }
    } catch (error) {
      toast('Connection failed', error.message, 'error');
    }
  };

  const selectProfile = async (profileId) => {
    const profile = profiles.find((item) => item.id === profileId);
    if (!profile) return;
    setActiveProfileId(profileId);
    if (tunnel.profileId === profileId) return;
    if (tunnel.status !== 'connected' && tunnel.status !== 'connecting') return;
    try {
      const status = await api.tunnel.connect(profileId);
      setTunnel(status);
      const actualSuite = status.suite || profile.suite;
      toast(
        status.status === 'connected' ? 'Crypto profile switched' : 'Profile switch failed',
        `${profile.name} · ${actualSuite}${status.status === 'connected' ? ' is online.' : ' did not connect.'}`,
        status.status === 'connected' ? 'success' : 'error',
      );
    } catch (error) {
      toast('Profile switch failed', error.message, 'error');
    }
  };

  const disconnect = async () => {
    try {
      const status = await api.tunnel.disconnect();
      setTunnel(status);
      toast('PRAETOR session offline', 'The control plane is back in standby.', 'info');
    } catch (error) {
      toast('Disconnect failed', error.message, 'error');
    }
  };

  const saveProfile = async (profile) => {
    try {
      const saved = await api.profiles.save(profile);
      setProfiles((current) => {
        const exists = current.some((entry) => entry.id === saved.id);
        return exists ? current.map((entry) => (entry.id === saved.id ? saved : entry)) : [saved, ...current];
      });
      setEditor({ open: false, profile: null });
      if (!profile.id) setActiveProfileId(saved.id);
      toast(profile.id ? 'Crypto profile updated' : 'Crypto profile created', `${saved.name} · ${saved.suite} is ready.`, 'success');
    } catch (error) {
      toast('Profile not saved', error.message, 'error');
    }
  };

  const deleteProfile = async (profile) => {
    if (!profile) return;
    if (!window.confirm(`Delete “${profile.name}”? This removes the local profile.`)) return;
    try {
      await api.profiles.remove(profile.id);
      setProfiles((current) => current.filter((entry) => entry.id !== profile.id));
      toast('Crypto profile removed', `${profile.name} was deleted.`, 'success');
    } catch (error) {
      toast('Delete failed', error.message, 'error');
    }
  };

  const importProfiles = async (file) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const entries = Array.isArray(parsed) ? parsed : parsed.profiles;
      if (!Array.isArray(entries) || entries.length === 0) throw new Error('No profiles found in that JSON.');
      const saved = [];
      for (const entry of entries.slice(0, 50)) {
        saved.push(await api.profiles.save({ ...entry, id: undefined }));
      }
      setProfiles((current) => [...saved, ...current]);
      toast('Profiles imported', `${saved.length} PRAETOR profile${saved.length === 1 ? '' : 's'} added.`, 'success');
    } catch (error) {
      toast('Import failed', error.message, 'error');
    }
  };

  const exportProfiles = (entries) => {
    downloadJson(`praetor-crypto-profiles-${new Date().toISOString().slice(0, 10)}.json`, {
      exportedAt: new Date().toISOString(),
      profiles: entries,
    });
    toast('Profiles exported', 'Portable PRAETOR profile JSON downloaded.', 'success');
  };

  const runDiagnostic = async () => {
    const result = await api.mcp.runDiagnostic();
    if (result?.ok) refreshMcp();
    return result;
  };

  const runAgent = async (payload) => {
    const result = await api.mcp.runAgent(payload);
    if (result?.ok) refreshMcp();
    return result;
  };

  const onWindow = async (action) => {
    try {
      if (action === 'minimize') await api.window.minimize();
      if (action === 'maximize') {
        const maximized = await api.window.maximize();
        setWindowState((current) => ({ ...current, maximized: Boolean(maximized) }));
      }
      if (action === 'close') await api.window.close();
    } catch {
      // Window management is optional in the browser preview.
    }
  };

  const commandItems = useMemo(() => {
    const activeProfile = profiles.find((profile) => profile.id === activeProfileId) || profiles[0] || null;
    const items = NAV_ITEMS.map((item) => ({
      id: `nav-${item.id}`,
      label: item.label,
      hint: item.hint,
      section: 'Navigate',
      icon: item.icon,
      action: () => onNavigate(item.id),
    }));
    items.push(
      { id: 'new-tunnel', label: 'Create a new crypto profile', hint: 'Open the PRAETOR profile editor', section: 'Actions', icon: Plus, action: () => setEditor({ open: true, profile: null }) },
      { id: 'connect', label: 'Connect active profile', hint: activeProfile?.name || 'No profile', section: 'Actions', icon: Zap, action: () => activeProfile && connect(activeProfile.id) },
      { id: 'disconnect', label: 'Disconnect tunnel', hint: 'Return to standby', section: 'Actions', icon: Power, action: disconnect },
      { id: 'diagnostic', label: 'Run MCP diagnostic', hint: 'End-to-end stdio pipeline', section: 'Actions', icon: Terminal, action: async () => { onNavigate('agent'); toast('Opening pipeline', 'Run the diagnostic from the Agent Fabric page.', 'info'); } },
      { id: 'settings', label: 'Open settings', hint: 'Appearance and trust', section: 'Navigate', icon: SettingsIcon, action: () => onNavigate('settings') },
      { id: 'agent', label: 'Open agent fabric', hint: 'MCP, tools, and operator', section: 'Navigate', icon: BrainCircuit, action: () => onNavigate('agent') },
    );
    return items;
  }, [profiles, activeProfileId]);

  if (!booted) {
    return (
      <div className="boot-screen">
        <div className="boot-aurora" />
        <ParticleField />
        <LogoMark size={58} />
        <span className="eyebrow">PRAETOR COMMAND</span>
        <h1>Bringing the surface online.</h1>
        <div className="boot-progress"><span /></div>
        <div className="boot-meta"><span>LOCAL RUNTIME</span><span>{isElectron ? 'ELECTRON BRIDGE' : 'BROWSER PREVIEW'}</span></div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <CursorAura enabled={settings.cursorEffects && settings.animations} />
      <ParticleField />
      <div className="ambient-grid" aria-hidden="true" />
      <div className="ambient-orb ambient-orb-one" aria-hidden="true" />
      <div className="ambient-orb ambient-orb-two" aria-hidden="true" />
      <TitleBar mcpReady={Boolean(mcp?.ready)} onWindow={onWindow} page={page} windowState={windowState} />
      <div className="app-body">
        <Sidebar
          appInfo={appInfo}
          badgeImage={badgeImage}
          mcpReady={Boolean(mcp?.ready)}
          onCommand={() => setPaletteOpen(true)}
          onNavigate={onNavigate}
          page={page}
        />
        <main className="main-surface">
          <div className="page-scroll" key={page}>
            {page === 'dashboard' ? (
              <Dashboard
                activity={activity}
                activeProfileId={activeProfileId}
                heroImage={heroImage}
                mcp={mcp}
                onClearHero={() => setHeroImage(null)}
                onConnect={connect}
                onDisconnect={disconnect}
                onEditProfile={(profile) => setEditor({ open: true, profile })}
                onNavigate={onNavigate}
                onOpenNew={() => setEditor({ open: true, profile: null })}
                onPickHero={(dataUrl) => { setHeroImage(dataUrl); toast('Header art updated', 'Your image is now part of the command surface.', 'success'); }}
                onSelectProfile={selectProfile}
                profiles={profiles}
                settings={settings}
                tunnel={tunnel}
              />
            ) : null}
            {page === 'tunnels' ? (
              <Tunnels
                activeProfileId={activeProfileId}
                onConnect={connect}
                onDeleteProfile={deleteProfile}
                onDisconnect={disconnect}
                onEditProfile={(profile) => setEditor({ open: true, profile })}
                onExport={exportProfiles}
                onImport={importProfiles}
                onNewProfile={() => setEditor({ open: true, profile: null })}
                profiles={profiles}
                tunnel={tunnel}
              />
            ) : null}
            {page === 'agent' ? (
              <Agent
                mcp={mcp}
                onNavigate={onNavigate}
                onRunAgent={runAgent}
                onRunDiagnostic={runDiagnostic}
                onSaveSettings={saveSettings}
                settings={settings}
                toast={toast}
              />
            ) : null}
            {page === 'tools' ? (
              <Tools onNavigate={onNavigate} onSaveSettings={saveSettings} settings={settings} toast={toast} />
            ) : null}
            {page === 'activity' ? (
              <Activity
                activity={activity}
                mcp={mcp}
                onClear={async () => {
                  await api.activity.clear();
                  setActivity([]);
                }}
                toast={toast}
              />
            ) : null}
            {page === 'settings' ? (
              <Settings
                appInfo={appInfo}
                badgeImage={badgeImage}
                heroImage={heroImage}
                onClearBadge={() => setBadgeImage(null)}
                onClearHero={() => setHeroImage(null)}
                onPickBadge={(dataUrl) => { setBadgeImage(dataUrl); toast('Workspace badge updated', 'Image stored locally on this workstation.', 'success'); }}
                onPickHero={(dataUrl) => { setHeroImage(dataUrl); toast('Command header updated', 'Image stored locally on this workstation.', 'success'); }}
                onSave={saveSettings}
                settings={settings}
                toast={toast}
              />
            ) : null}
          </div>
          <footer className="status-rail">
            <span className={`status-rail-item ${tunnel.status === 'connected' ? 'is-live' : ''}`}>
              <StatusDot online={tunnel.status === 'connected'} pulse={tunnel.status === 'connected'} />
              {tunnel.status === 'connected' ? `${tunnel.profileName} · ${tunnel.suite || 'PRAETOR'} protected` : tunnel.status === 'connecting' ? 'negotiating PRAETOR handshake' : 'data plane standby'}
            </span>
            <span className="status-rail-divider" />
            <span className="status-rail-item"><Terminal size={12} /> MCP {mcp?.ready ? 'READY' : 'OFFLINE'}</span>
            <span className="status-rail-item"><Wrench size={12} /> {mcp?.toolCount || 36} tools</span>
            <span className="status-rail-item"><ShieldCheck size={12} /> LOCAL-FIRST</span>
            <span className="status-rail-spacer" />
            <span className="status-rail-item status-rail-muted">{bootError ? `BOOT WARNING: ${bootError}` : isElectron ? 'ELECTRON BRIDGE' : 'BROWSER PREVIEW'}</span>
          </footer>
        </main>
      </div>

      <CommandPalette items={commandItems} onClose={() => setPaletteOpen(false)} open={paletteOpen} />
      <ProfileEditor
        onClose={() => setEditor({ open: false, profile: null })}
        onSave={saveProfile}
        open={editor.open}
        profile={editor.profile}
      />
      <ToastStack onDismiss={(id) => setToasts((current) => current.filter((item) => item.id !== id))} toasts={toasts} />
    </div>
  );
}

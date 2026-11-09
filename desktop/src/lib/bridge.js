import { TOOL_CATALOG } from '../data/tools.js';
import { copyText } from './format.js';
import {
  DEMO_ACTIVITY,
  DEMO_APP_INFO,
  DEMO_PROFILES,
  DEMO_SETTINGS,
  buildDemoConfig,
} from './demo.js';
import {
  DEMO_ENDPOINT,
  DEMO_SERVER_PUBLIC_KEY,
  PRAETOR_CELL_SIZES,
  PRAETOR_PROTOCOL,
  PRAETOR_SUITES,
} from './praetor.js';

export const isElectron = Boolean(
  typeof window !== 'undefined' && window.praetor && window.praetor.app,
);

const STORAGE_KEY = 'praetor-command-browser-preview-v2';
const clone = (value) => JSON.parse(JSON.stringify(value));
const listeners = { tunnel: new Set(), activity: new Set(), settings: new Set() };
let browserTunnel = {
  status: 'disconnected',
  profileId: null,
  profileName: null,
  endpoint: null,
  location: null,
  protocol: null,
  suite: null,
  cellSize: null,
  startedAt: null,
  connectedAt: null,
  handshakeMs: null,
  latency: null,
  rx: 0,
  tx: 0,
  quality: 'idle',
};
let browserTimer = null;
let browserConnectTimer = null;
let browserState = loadState();

function loadState() {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return {
        profiles: Array.isArray(parsed.profiles) && parsed.profiles.length ? parsed.profiles : clone(DEMO_PROFILES),
        settings: { ...DEMO_SETTINGS, ...(parsed.settings || {}) },
        activity: Array.isArray(parsed.activity) ? parsed.activity : clone(DEMO_ACTIVITY),
      };
    }
  } catch {
    // Fall through to seed data.
  }
  return {
    profiles: clone(DEMO_PROFILES),
    settings: clone(DEMO_SETTINGS),
    activity: clone(DEMO_ACTIVITY),
  };
}

function saveState() {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(browserState));
  } catch {
    // Preview remains in-memory when storage is unavailable.
  }
}

function emitTunnel() {
  for (const listener of listeners.tunnel) listener(clone(browserTunnel));
}

function emitActivity(entry) {
  for (const listener of listeners.activity) listener(clone(entry));
}

function logActivity(kind, title, detail = '', meta = {}) {
  const entry = {
    id: crypto.randomUUID(),
    kind,
    title,
    detail,
    meta,
    ts: Date.now(),
  };
  browserState.activity.unshift(entry);
  browserState.activity = browserState.activity.slice(0, 300);
  saveState();
  emitActivity(entry);
  return clone(entry);
}

function stopBrowserTunnel(reason = 'Disconnected') {
  if (browserConnectTimer) clearTimeout(browserConnectTimer);
  if (browserTimer) clearInterval(browserTimer);
  browserConnectTimer = null;
  browserTimer = null;
  const previous = browserTunnel.profileName;
  browserTunnel = {
    ...browserTunnel,
    status: 'disconnected',
    profileId: null,
    profileName: null,
    endpoint: null,
    location: null,
    protocol: null,
    suite: null,
    cellSize: null,
    startedAt: null,
    connectedAt: null,
    handshakeMs: null,
    latency: null,
    quality: 'idle',
  };
  emitTunnel();
  if (previous) logActivity('tunnel', 'PRAETOR session disconnected', `${previous} · ${reason}`);
  return clone(browserTunnel);
}

const mockApi = {
  platform: 'win32',
  versions: { electron: 'browser-preview', chrome: navigator.userAgent, node: 'n/a' },
  app: {
    info: async () => clone(DEMO_APP_INFO),
  },
  window: {
    minimize: async () => false,
    maximize: async () => false,
    close: async () => false,
    state: async () => ({ maximized: false, focused: true }),
    onState: () => () => {},
  },
  profiles: {
    list: async () => clone(browserState.profiles),
    save: async (input) => {
      const existing = input?.id ? browserState.profiles.find((profile) => profile.id === input.id) : null;
      const tags = Array.isArray(input.tags)
        ? [...new Set(input.tags.map((tag) => String(tag).trim()).filter(Boolean))].slice(0, 8)
        : existing?.tags || [];
      const saved = {
        id: existing?.id || crypto.randomUUID(),
        name: String(input.name || existing?.name || 'New PRAETOR profile').slice(0, 80),
        description: String(input.description || existing?.description || 'A pinned PRAETOR/1 crypto profile.').slice(0, 300),
        location: String(input.location || existing?.location || 'Local').slice(0, 80),
        endpoint: String(input.endpoint || existing?.endpoint || DEMO_ENDPOINT).trim(),
        protocol: PRAETOR_PROTOCOL,
        suite: PRAETOR_SUITES.some((suite) => suite.id === input.suite) ? input.suite : existing?.suite || 'PSEAL',
        transport: 'tcp',
        cellSize: PRAETOR_CELL_SIZES.includes(Number(input.cellSize)) ? Number(input.cellSize) : existing?.cellSize || 1024,
        serverPublicKey: String(input.serverPublicKey || existing?.serverPublicKey || DEMO_SERVER_PUBLIC_KEY).replace(/\s+/g, ''),
        autoConnect: Boolean(input.autoConnect ?? existing?.autoConnect),
        tags,
        color: input.color || existing?.color || 'mint',
        createdAt: existing?.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      browserState.profiles = existing
        ? browserState.profiles.map((profile) => (profile.id === saved.id ? saved : profile))
        : [saved, ...browserState.profiles];
      saveState();
      logActivity('profile', existing ? 'Crypto profile updated' : 'Crypto profile created', `${saved.name} · ${saved.suite}`);
      return clone(saved);
    },
    remove: async (id) => {
      const profile = browserState.profiles.find((entry) => entry.id === id);
      browserState.profiles = browserState.profiles.filter((entry) => entry.id !== id);
      if (browserTunnel.profileId === id) stopBrowserTunnel('Profile deleted');
      saveState();
      if (profile) logActivity('profile', 'Crypto profile removed', `${profile.name} · ${profile.suite}`);
      return Boolean(profile);
    },
  },
  tunnel: {
    status: async () => clone(browserTunnel),
    connect: async (id) => {
      const profile = browserState.profiles.find((entry) => entry.id === id);
      if (!profile) throw new Error('PRAETOR profile not found.');
      stopBrowserTunnel('Switched profile');
      browserTunnel = {
        status: 'connecting',
        profileId: profile.id,
        profileName: profile.name,
        endpoint: profile.endpoint,
        location: profile.location,
        protocol: profile.protocol,
        suite: profile.suite,
        cellSize: profile.cellSize,
        startedAt: Date.now(),
        connectedAt: null,
        handshakeMs: null,
        latency: null,
        rx: 0,
        tx: 0,
        quality: 'negotiating',
      };
      emitTunnel();
      logActivity('tunnel', 'PRAETOR handshake started', `${profile.name} · ${profile.suite} → ${profile.endpoint}`);
      browserConnectTimer = setTimeout(() => {
        browserConnectTimer = null;
        browserTunnel = {
          ...browserTunnel,
          status: 'connected',
          connectedAt: Date.now(),
          handshakeMs: Math.round((2.4 + Math.random() * 2.6) * 10) / 10,
          latency: Math.round(18 + Math.random() * 22),
          quality: 'excellent',
        };
        emitTunnel();
        logActivity('tunnel', 'PRAETOR session online', `${profile.name} · ${profile.suite} · handshake ${browserTunnel.handshakeMs} ms`);
        browserTimer = setInterval(() => {
          browserTunnel = {
            ...browserTunnel,
            rx: browserTunnel.rx + Math.floor(35_000 + Math.random() * 290_000),
            tx: browserTunnel.tx + Math.floor(8_000 + Math.random() * 80_000),
            latency: Math.max(9, Math.round(18 + Math.random() * 22)),
            quality: 'excellent',
          };
          emitTunnel();
        }, 1000);
      }, 900);
      return clone(browserTunnel);
    },
    disconnect: async () => stopBrowserTunnel('User requested'),
    onStatus: (callback) => {
      listeners.tunnel.add(callback);
      return () => listeners.tunnel.delete(callback);
    },
  },
  settings: {
    get: async () => clone(browserState.settings),
    save: async (patch) => {
      browserState.settings = { ...browserState.settings, ...patch };
      saveState();
      for (const listener of listeners.settings) listener(clone(browserState.settings));
      return clone(browserState.settings);
    },
    onChanged: (callback) => {
      listeners.settings.add(callback);
      return () => listeners.settings.delete(callback);
    },
  },
  activity: {
    list: async () => clone(browserState.activity),
    clear: async () => {
      browserState.activity = [];
      saveState();
      return [];
    },
    onNew: (callback) => {
      listeners.activity.add(callback);
      return () => listeners.activity.delete(callback);
    },
  },
  mcp: {
    status: async () => {
      const config = buildDemoConfig(browserState.settings.mcpAllowedRoots, browserState.settings.mcpFullControl);
      return {
        ready: true,
        error: null,
        runtimePath: 'C:\\Users\\mattb\\AppData\\Roaming\\praetor-command\\mcp',
        serverPath: 'C:\\Users\\mattb\\AppData\\Roaming\\praetor-command\\mcp\\server.mjs',
        configPath: 'C:\\Users\\mattb\\AppData\\Roaming\\praetor-command\\mcp-config.json',
        config,
        fullControl: browserState.settings.mcpFullControl,
        roots: browserState.settings.mcpAllowedRoots,
        auditPath: 'C:\\Users\\mattb\\AppData\\Roaming\\praetor-command\\audit.jsonl',
        toolCount: TOOL_CATALOG.length,
      };
    },
    config: async () => ({
      ok: true,
      config: buildDemoConfig(browserState.settings.mcpAllowedRoots, browserState.settings.mcpFullControl),
      json: JSON.stringify(
        buildDemoConfig(browserState.settings.mcpAllowedRoots, browserState.settings.mcpFullControl),
        null,
        2,
      ),
    }),
    copyConfig: async () => {
      const config = buildDemoConfig(browserState.settings.mcpAllowedRoots, browserState.settings.mcpFullControl);
      await copyText(JSON.stringify(config, null, 2));
      return { ok: true, configPath: 'C:\\Users\\mattb\\AppData\\Roaming\\praetor-command\\mcp-config.json' };
    },
    openConfig: async () => ({ ok: true, configPath: 'Browser preview' }),
    runDiagnostic: async () => {
      await new Promise((resolve) => setTimeout(resolve, 1400));
      const steps = [
        'policy_info',
        'system_info',
        'workspace_info',
        'fs_list',
        'git_status',
        'screen_size',
        'audit_tail',
      ].map((tool, index) => ({
        tool,
        ok: true,
        chars: 300 + index * 80,
        summary: { source: 'browser preview' },
      }));
      const data = {
        ok: true,
        pipeline: 'praetor-mcp-diagnostic',
        toolCount: TOOL_CATALOG.length,
        tools: TOOL_CATALOG.map((tool) => tool.name),
        capabilities: {
          filesystemRead: true,
          filesystemWrite: true,
          shell: browserState.settings.mcpFullControl,
          fullControl: browserState.settings.mcpFullControl,
          screen: browserState.settings.mcpFullControl,
          mouseKeyboard: browserState.settings.mcpFullControl,
          clipboard: browserState.settings.mcpFullControl,
          processControl: browserState.settings.mcpFullControl,
        },
        steps,
        durationMs: 1400,
      };
      logActivity('mcp', 'MCP diagnostic completed', `${data.toolCount} tools · ${steps.length} calls · preview`);
      return { ok: true, code: 0, timedOut: false, durationMs: 1400, data, stdout: JSON.stringify(data), stderr: '' };
    },
    runAgent: async (payload) => {
      if (!payload?.apiKey) return { ok: false, error: 'Enter an API key for the model endpoint.' };
      await new Promise((resolve) => setTimeout(resolve, 1800));
      const data = {
        ok: true,
        agent: 'praetor-llm-agent',
        model: payload.model || browserState.settings.agentModel,
        task: payload.task,
        answer: `Preview response for: “${payload.task}”. The packaged app runs this loop against your configured model endpoint and the live MCP server.`,
        toolTrace: [
          { tool: 'workspace_info', ok: true, text: 'Workspace inspected.' },
          { tool: 'git_status', ok: true, text: 'Working tree clean.' },
        ],
        exposedTools: TOOL_CATALOG.length,
        fullControl: browserState.settings.mcpFullControl,
        browserPreview: true,
      };
      logActivity('agent', 'Agent run completed', `${data.model} · ${data.toolTrace.length} tool calls`);
      return { ok: true, code: 0, timedOut: false, durationMs: 1800, data, stdout: JSON.stringify(data), stderr: '' };
    },
  },
  shell: {
    openExternal: async (url) => {
      window.open(url, '_blank', 'noopener,noreferrer');
      return true;
    },
  },
};

export const api = isElectron ? window.praetor : mockApi;

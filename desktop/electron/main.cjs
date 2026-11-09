const {
  app,
  BrowserWindow,
  clipboard,
  ipcMain,
  nativeTheme,
  session,
  shell,
} = require('electron');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawn, spawnSync } = require('node:child_process');
const { Store } = require('./store.cjs');

app.setName('PRAETOR Command');
app.setAppUserModelId('io.praetor.command');

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();

let store = null;
let mainWindow = null;
let mcpRuntime = null;
let tunnelTimer = null;
let connectTimer = null;
let statsTimer = null;
let tunnelToken = 0;
let activeProxy = null;
let savedProxyState = null;
let proxyModule = null;
let nodeRuntimeCache;

const tunnel = {
  status: 'disconnected',
  profileId: null,
  profileName: null,
  endpoint: null,
  proxyPort: null,
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function broadcast(channel, payload) {
  for (const window of BrowserWindow.getAllWindows()) {
    if (!window.isDestroyed()) window.webContents.send(channel, payload);
  }
}

function logActivity(kind, title, detail, meta = {}) {
  if (!store) return null;
  const entry = store.logActivity(kind, title, detail, meta);
  broadcast('activity:new', entry);
  return entry;
}

function mcpSourcePath() {
  if (app.isPackaged) return path.join(process.resourcesPath, 'mcp');
  return path.join(__dirname, '..', 'mcp-dist');
}

function stageMcpRuntime() {
  const source = mcpSourcePath();
  const serverSource = path.join(source, 'server.mjs');
  if (!fs.existsSync(serverSource)) {
    mcpRuntime = {
      ready: false,
      source,
      error: 'MCP runtime is not built. Run "npm run build:mcp" before launching.',
    };
    return mcpRuntime;
  }
  const target = path.join(app.getPath('userData'), 'mcp');
  const marker = path.join(target, '.runtime-version');
  const version = `${app.getVersion()}-${Math.round(fs.statSync(serverSource).mtimeMs)}`;
  let current = '';
  try {
    current = fs.readFileSync(marker, 'utf8').trim();
  } catch {
    current = '';
  }
  if (current !== version) {
    fs.rmSync(target, { recursive: true, force: true });
    fs.mkdirSync(target, { recursive: true });
    fs.cpSync(source, target, { recursive: true });
    fs.writeFileSync(marker, version, 'utf8');
  }
  mcpRuntime = {
    ready: true,
    source,
    path: target,
    serverPath: path.join(target, 'server.mjs'),
    pipelinePath: path.join(target, 'agent-pipeline.mjs'),
    agentPath: path.join(target, 'llm-agent.mjs'),
    version,
  };
  return mcpRuntime;
}

function mcpEnv() {
  const settings = store.getSettings();
  const roots = settings.mcpAllowedRoots.length
    ? settings.mcpAllowedRoots
    : [app.getPath('home')];
  const audit = path.join(app.getPath('userData'), 'audit.jsonl');
  return {
    ...process.env,
    ELECTRON_RUN_AS_NODE: '1',
    PRAETOR_MCP_ROOTS: roots.join(';'),
    PRAETOR_MCP_AUDIT: audit,
    PRAETOR_MCP_ALLOW_WRITES: '1',
    PRAETOR_MCP_ALLOW_SHELL: settings.mcpFullControl ? '1' : '0',
    PRAETOR_MCP_ALLOW_FULL: settings.mcpFullControl ? '1' : '0',
    PRAETOR_MCP_SERVER: mcpRuntime?.serverPath || '',
  };
}

function findNodeRuntime() {
  if (nodeRuntimeCache !== undefined) return nodeRuntimeCache;
  const candidates = [];
  if (process.env.PRAETOR_MCP_NODE) candidates.push(process.env.PRAETOR_MCP_NODE);
  const executable = process.platform === 'win32' ? 'node.exe' : 'node';
  for (const entry of String(process.env.PATH || '').split(path.delimiter)) {
    const directory = entry.trim().replace(/^"(.*)"$/, '$1');
    if (directory) candidates.push(path.join(directory, executable));
  }
  if (process.platform === 'win32') {
    candidates.push(
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'nodejs', executable),
      path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'nodejs', executable),
      path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Programs', 'nodejs', executable),
      path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Volta', 'bin', executable),
    );
  } else {
    candidates.push('/usr/local/bin/node', '/usr/bin/node', '/opt/homebrew/bin/node');
  }
  const seen = new Set();
  for (const candidate of candidates) {
    if (!candidate) continue;
    const resolved = path.resolve(candidate);
    const key = process.platform === 'win32' ? resolved.toLowerCase() : resolved;
    if (seen.has(key) || key === process.execPath.toLowerCase()) continue;
    seen.add(key);
    try {
      if (!fs.statSync(resolved).isFile()) continue;
      const probe = spawnSync(resolved, ['--version'], {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 3000,
      });
      const version = String(probe.stdout || '').trim();
      if (probe.status === 0 && /^v\d+\./.test(version)) {
        nodeRuntimeCache = { path: resolved, version };
        return nodeRuntimeCache;
      }
    } catch {
      // Try the next runtime.
    }
  }
  nodeRuntimeCache = null;
  return null;
}

function writeMcpConfig() {
  if (!mcpRuntime?.ready) {
    return { ok: false, error: mcpRuntime?.error || 'MCP runtime is not ready.' };
  }
  const settings = store.getSettings();
  const nodeRuntime = findNodeRuntime();
  const env = {
    PRAETOR_MCP_ROOTS: settings.mcpAllowedRoots.join(';'),
    PRAETOR_MCP_AUDIT: path.join(app.getPath('userData'), 'audit.jsonl'),
    PRAETOR_MCP_ALLOW_WRITES: '1',
    PRAETOR_MCP_ALLOW_SHELL: settings.mcpFullControl ? '1' : '0',
    PRAETOR_MCP_ALLOW_FULL: settings.mcpFullControl ? '1' : '0',
  };
  if (!nodeRuntime) env.ELECTRON_RUN_AS_NODE = '1';
  const config = {
    mcpServers: {
      'praetor-computer-use': {
        command: nodeRuntime?.path || process.execPath,
        args: [mcpRuntime.serverPath],
        env,
      },
    },
  };
  const configPath = path.join(app.getPath('userData'), 'mcp-config.json');
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  return {
    ok: true,
    config,
    json: `${JSON.stringify(config, null, 2)}\n`,
    configPath,
    serverPath: mcpRuntime.serverPath,
    auditPath: path.join(app.getPath('userData'), 'audit.jsonl'),
    runtime: nodeRuntime ? 'node' : 'electron',
    runtimeVersion: nodeRuntime?.version || process.versions.electron,
    warning: nodeRuntime ? null : 'Node.js was not found. External MCP config uses the current app executable, which is not stable for portable builds.',
  };
}

function runNodeScript(scriptPath, args = [], options = {}) {
  const { timeoutMs = 120_000, env = {}, cwd = app.getPath('home') } = options;
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd,
      env,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
          windowsHide: true,
          stdio: 'ignore',
        });
      } catch {
        child.kill();
      }
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
      if (stdout.length > 2_000_000) stdout = stdout.slice(-2_000_000);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
      if (stderr.length > 500_000) stderr = stderr.slice(-500_000);
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        code: null,
        stdout,
        stderr: `${stderr}\n${error.message}`.trim(),
        timedOut,
        durationMs: Date.now() - started,
        data: null,
      });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      let data = null;
      try {
        data = JSON.parse(stdout.trim());
      } catch {
        data = null;
      }
      resolve({
        ok: code === 0 && !timedOut,
        code,
        stdout: stdout.slice(0, 200_000),
        stderr: stderr.slice(0, 30_000),
        timedOut,
        durationMs: Date.now() - started,
        data,
      });
    });
  });
}

function statusPayload() {
  return clone(tunnel);
}

function sendTunnel() {
  broadcast('tunnel:status', statusPayload());
}

function loadProxyModule() {
  if (!proxyModule) proxyModule = require('./praetor-tunnel.cjs');
  if (typeof proxyModule.startSocksProxy !== 'function') {
    throw new Error('PRAETOR proxy bundle is missing startSocksProxy.');
  }
  return proxyModule.startSocksProxy;
}

async function openProxy(options) {
  const startProxy = loadProxyModule();
  try {
    return await startProxy({ ...options, proxyPort: PRAETOR_PROXY_PORT });
  } catch (error) {
    const inUse = error?.code === 'EADDRINUSE' || String(error?.message || '').includes('EADDRINUSE');
    if (!inUse) throw error;
    return startProxy({ ...options, proxyPort: 0 });
  }
}

const IE_SETTINGS = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const PRAETOR_PROXY_PORT = 17890;
const PRAETOR_PROXY_MARKER = 'PRAETORProxyManaged';
const PROXY_BACKUP_FILE = 'system-proxy-backup.json';

function readIeSetting(name) {
  if (process.platform !== 'win32') return null;
  try {
    const output = execFileSync('reg', ['query', IE_SETTINGS, '/v', name], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const match = output.match(new RegExp(`^\\s*${name}\\s+REG_(\\w+)\\s+(.*)$`, 'm'));
    if (!match) return null;
    return { type: `REG_${match[1]}`, value: match[2].trim() };
  } catch {
    return null;
  }
}

function writeIeSetting(name, type, value) {
  execFileSync('reg', ['add', IE_SETTINGS, '/v', name, '/t', type, '/d', value, '/f'], {
    windowsHide: true,
    stdio: 'ignore',
  });
}

function deleteIeSetting(name) {
  try {
    execFileSync('reg', ['delete', IE_SETTINGS, '/v', name, '/f'], {
      windowsHide: true,
      stdio: 'ignore',
    });
  } catch {
    // The value was already absent.
  }
}

function notifyProxyChange() {
  if (process.platform !== 'win32') return;
  const script = [
    "$sig = '[DllImport(\"wininet.dll\")] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'",
    '$w = Add-Type -MemberDefinition $sig -Name PraetorWinInet -Namespace Praetor -PassThru',
    '[void]$w::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)',
    '[void]$w::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)',
  ].join('; ');
  try {
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      stdio: 'ignore',
      timeout: 5000,
    });
  } catch {
    // Registry writes still apply; the notification is best effort.
  }
}

function proxyBackupPath() {
  return path.join(app.getPath('userData'), PROXY_BACKUP_FILE);
}

function readProxyBackup() {
  try {
    const saved = JSON.parse(fs.readFileSync(proxyBackupPath(), 'utf8'));
    if (!saved || typeof saved !== 'object') return null;
    return {
      enable: saved.enable || null,
      server: saved.server || null,
      override: saved.override || null,
    };
  } catch {
    return null;
  }
}

function writeProxyBackup(saved) {
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    fs.writeFileSync(proxyBackupPath(), `${JSON.stringify(saved, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch {
    // The registry still works if the backup cannot be written.
  }
}

function removeProxyBackup() {
  try {
    fs.rmSync(proxyBackupPath(), { force: true });
  } catch {
    // Best effort.
  }
}

function proxyMarkerPresent() {
  const marker = readIeSetting(PRAETOR_PROXY_MARKER);
  const value = String(marker?.value || '').trim().toLowerCase();
  return value === '1' || value === '0x1';
}

function restoreSystemProxy(saved) {
  for (const [name, value] of [
    ['ProxyEnable', saved?.enable],
    ['ProxyServer', saved?.server],
    ['ProxyOverride', saved?.override],
  ]) {
    try {
      if (value && typeof value.type === 'string' && typeof value.value === 'string') {
        writeIeSetting(name, value.type, value.value);
      } else {
        deleteIeSetting(name);
      }
    } catch {
      deleteIeSetting(name);
    }
  }
}

function setSystemProxy(proxyPort) {
  if (process.platform !== 'win32') return;
  if (!savedProxyState) {
    savedProxyState = readProxyBackup() || {
      enable: readIeSetting('ProxyEnable'),
      server: readIeSetting('ProxyServer'),
      override: readIeSetting('ProxyOverride'),
    };
    writeProxyBackup(savedProxyState);
  }
  writeIeSetting(PRAETOR_PROXY_MARKER, 'REG_DWORD', '1');
  const override = String(savedProxyState.override?.value || '');
  const entries = override.split(';').map((value) => value.trim()).filter(Boolean);
  if (!entries.some((value) => value.toLowerCase() === '<local>')) entries.push('<local>');
  writeIeSetting('ProxyOverride', 'REG_SZ', entries.join(';'));
  writeIeSetting('ProxyServer', 'REG_SZ', `socks=127.0.0.1:${proxyPort}`);
  writeIeSetting('ProxyEnable', 'REG_DWORD', '1');
  notifyProxyChange();
}

function clearSystemProxy() {
  if (process.platform !== 'win32') return;
  const saved = savedProxyState || readProxyBackup();
  if (!saved && !proxyMarkerPresent()) return;
  savedProxyState = null;
  restoreSystemProxy(saved);
  deleteIeSetting(PRAETOR_PROXY_MARKER);
  removeProxyBackup();
  notifyProxyChange();
}

// A crash can leave WinINET pointed at a loopback port that no longer exists.
// Restore the user's pre-PRAETOR settings before the window opens.
function recoverStaleSystemProxy() {
  if (process.platform !== 'win32' || !proxyMarkerPresent()) return false;
  const server = readIeSetting('ProxyServer');
  if (server && !/^socks=127\.0\.0\.1:\d{1,5}$/.test(server.value)) {
    deleteIeSetting(PRAETOR_PROXY_MARKER);
    removeProxyBackup();
    return false;
  }
  const saved = readProxyBackup();
  restoreSystemProxy(saved);
  deleteIeSetting(PRAETOR_PROXY_MARKER);
  removeProxyBackup();
  notifyProxyChange();
  return true;
}

function parseEndpoint(endpoint) {
  const text = String(endpoint || '');
  const split = text.lastIndexOf(':');
  if (split <= 0 || split === text.length - 1) {
    throw new Error(`PRAETOR endpoint must be host:port, got ${text || '(empty)'}`);
  }
  const host = text.slice(0, split).replace(/^\[|\]$/g, '');
  const port = Number(text.slice(split + 1));
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`PRAETOR endpoint must be host:port, got ${text}`);
  }
  return { host, port };
}

function resetTunnelState() {
  tunnel.status = 'disconnected';
  tunnel.profileId = null;
  tunnel.profileName = null;
  tunnel.endpoint = null;
  tunnel.proxyPort = null;
  tunnel.location = null;
  tunnel.protocol = null;
  tunnel.suite = null;
  tunnel.requestedSuite = null;
  tunnel.cellSize = null;
  tunnel.connectedAt = null;
  tunnel.startedAt = null;
  tunnel.handshakeMs = null;
  tunnel.latency = null;
  tunnel.quality = 'idle';
}

function disconnectTunnel(reason = 'Disconnected') {
  tunnelToken += 1;
  if (connectTimer) clearTimeout(connectTimer);
  if (tunnelTimer) clearInterval(tunnelTimer);
  if (statsTimer) clearInterval(statsTimer);
  connectTimer = null;
  tunnelTimer = null;
  statsTimer = null;
  if (activeProxy) {
    try {
      activeProxy.close();
    } catch {
      // The session already closed.
    }
    activeProxy = null;
  }
  clearSystemProxy();
  const previous = tunnel.profileName;
  resetTunnelState();
  sendTunnel();
  if (previous) logActivity('tunnel', 'PRAETOR session disconnected', `${previous} · ${reason}`, { profile: previous });
  return statusPayload();
}

async function connectTunnel(profileId) {
  const profile = store.getProfile(profileId);
  if (!profile) throw new Error('PRAETOR profile not found.');
  disconnectTunnel('Switched profile');
  const token = ++tunnelToken;
  tunnel.status = 'connecting';
  tunnel.profileId = profile.id;
  tunnel.profileName = profile.name;
  tunnel.endpoint = profile.endpoint;
  tunnel.proxyPort = null;
  tunnel.location = profile.location;
  tunnel.protocol = profile.protocol;
  tunnel.suite = profile.suite;
  tunnel.requestedSuite = profile.suite;
  tunnel.cellSize = profile.cellSize;
  tunnel.startedAt = Date.now();
  tunnel.connectedAt = null;
  tunnel.handshakeMs = null;
  tunnel.latency = null;
  tunnel.rx = 0;
  tunnel.tx = 0;
  tunnel.quality = 'negotiating';
  sendTunnel();
  logActivity('tunnel', 'PRAETOR handshake started', `${profile.name} · ${profile.suite} → ${profile.endpoint}`, {
    profile: profile.name,
    endpoint: profile.endpoint,
    protocol: profile.protocol,
    suite: profile.suite,
    cellSize: profile.cellSize,
  });

  try {
    const target = parseEndpoint(profile.endpoint);
    const serverPublicKey = Buffer.from(profile.serverPublicKey || '', 'base64');
    if (serverPublicKey.length !== 1216) {
      throw new Error(`Pinned PRAETOR server key is ${serverPublicKey.length} bytes, expected 1216.`);
    }
    const proxy = await openProxy({
      serverPublicKey,
      host: target.host,
      port: target.port,
      cellSize: profile.cellSize,
      proxyHost: '127.0.0.1',
      onTraffic: (direction, bytes) => {
        if (direction === 'rx') tunnel.rx += bytes;
        else tunnel.tx += bytes;
      },
      onError: (error) => {
        if (token !== tunnelToken || tunnel.status === 'disconnected') return;
        logActivity('tunnel', 'PRAETOR data plane error', error.message, { ok: false });
        disconnectTunnel('Transport error');
      },
      onLog: (message) => {
        if (!app.isPackaged) console.log(`[praetor] ${message}`);
      },
    });
    if (token !== tunnelToken) {
      proxy.close();
      return statusPayload();
    }
    activeProxy = proxy;
    tunnel.suite = 'PSEAL';
    tunnel.status = 'connected';
    tunnel.connectedAt = Date.now();
    tunnel.handshakeMs = proxy.handshakeMs;
    tunnel.latency = null;
    tunnel.quality = 'good';
    tunnel.proxyPort = proxy.port;
    setSystemProxy(proxy.port);
    sendTunnel();
    const fallback = profile.suite !== 'PSEAL';
    logActivity(
      'tunnel',
      'PRAETOR session online',
      `${profile.name} · PSEAL${fallback ? ` (${profile.suite} profile)` : ''} · ${profile.endpoint} · ${proxy.handshakeMs} ms · SOCKS ${proxy.port}`,
      {
        profile: profile.name,
        suite: 'PSEAL',
        requestedSuite: profile.suite,
        fallback,
        handshakeMs: proxy.handshakeMs,
        proxyPort: proxy.port,
        real: true,
      },
    );
    statsTimer = setInterval(() => {
      if (tunnel.status === 'connected') sendTunnel();
    }, 1000);
  } catch (error) {
    if (token !== tunnelToken) return statusPayload();
    clearSystemProxy();
    resetTunnelState();
    sendTunnel();
    logActivity('tunnel', 'PRAETOR session failed', error.message, { ok: false });
  }
  return statusPayload();
}

function registerIpc() {
  ipcMain.handle('app:info', () => ({
    name: 'PRAETOR Command',
    version: app.getVersion(),
    electron: process.versions.electron,
    node: process.versions.node,
    chrome: process.versions.chrome,
    platform: process.platform,
    arch: process.arch,
    packaged: app.isPackaged,
    userData: app.getPath('userData'),
    home: app.getPath('home'),
    mcp: {
      ready: Boolean(mcpRuntime?.ready),
      path: mcpRuntime?.path || null,
      serverPath: mcpRuntime?.serverPath || null,
      error: mcpRuntime?.error || null,
    },
    dataPlane: 'praetor-egress',
  }));

  ipcMain.handle('window:minimize', () => {
    mainWindow?.minimize();
    return true;
  });
  ipcMain.handle('window:maximize', () => {
    if (!mainWindow) return false;
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
    return mainWindow.isMaximized();
  });
  ipcMain.handle('window:close', () => {
    mainWindow?.close();
    return true;
  });
  ipcMain.handle('window:state', () => ({
    maximized: Boolean(mainWindow?.isMaximized()),
    focused: Boolean(mainWindow?.isFocused()),
  }));

  ipcMain.handle('profiles:list', () => store.listProfiles());
  ipcMain.handle('profiles:save', (_event, profile) => {
    const saved = store.saveProfile(profile);
    logActivity('profile', profile?.id ? 'Crypto profile updated' : 'Crypto profile created', `${saved.name} · ${saved.suite}`, {
      profile: saved.name,
      suite: saved.suite,
    });
    return saved;
  });
  ipcMain.handle('profiles:delete', (_event, id) => {
    const profile = store.getProfile(id);
    if (tunnel.profileId === id) disconnectTunnel('Profile deleted');
    const removed = store.deleteProfile(id);
    if (removed && profile) logActivity('profile', 'Crypto profile removed', `${profile.name} · ${profile.suite}`);
    return removed;
  });

  ipcMain.handle('tunnel:status', () => statusPayload());
  ipcMain.handle('tunnel:connect', (_event, id) => connectTunnel(id));
  ipcMain.handle('tunnel:disconnect', () => disconnectTunnel('User requested'));

  ipcMain.handle('settings:get', () => store.getSettings());
  ipcMain.handle('settings:save', (_event, patch) => {
    const settings = store.saveSettings(patch);
    if (Object.prototype.hasOwnProperty.call(patch || {}, 'launchAtLogin')) {
      try {
        app.setLoginItemSettings({
          openAtLogin: Boolean(settings.launchAtLogin),
          path: process.execPath,
          args: app.isPackaged ? [] : [app.getAppPath()],
        });
      } catch (error) {
        logActivity('system', 'Launch-at-login update failed', error.message);
      }
    }
    broadcast('settings:changed', settings);
    return settings;
  });

  ipcMain.handle('activity:list', () => store.listActivity());
  ipcMain.handle('activity:clear', () => {
    store.clearActivity();
    return [];
  });

  ipcMain.handle('mcp:status', () => {
    const config = writeMcpConfig();
    return {
      ready: Boolean(mcpRuntime?.ready),
      error: mcpRuntime?.error || config.error || null,
      runtimePath: mcpRuntime?.path || null,
      serverPath: mcpRuntime?.serverPath || null,
      configPath: config.configPath || null,
      config: config.config || null,
      externalRuntime: config.runtime || null,
      externalRuntimeVersion: config.runtimeVersion || null,
      configWarning: config.warning || null,
      fullControl: store.getSettings().mcpFullControl,
      roots: store.getSettings().mcpAllowedRoots,
      auditPath: config.auditPath || path.join(app.getPath('userData'), 'audit.jsonl'),
      toolCount: 36,
    };
  });

  ipcMain.handle('mcp:config', () => writeMcpConfig());
  ipcMain.handle('mcp:copy-config', async () => {
    const config = writeMcpConfig();
    if (!config.ok) return config;
    clipboard.writeText(config.json);
    return { ok: true, configPath: config.configPath };
  });
  ipcMain.handle('mcp:open-config', async () => {
    const config = writeMcpConfig();
    if (!config.ok) return config;
    shell.showItemInFolder(config.configPath);
    return { ok: true, configPath: config.configPath };
  });

  ipcMain.handle('mcp:run-diagnostic', async () => {
    if (!mcpRuntime?.ready) {
      return { ok: false, error: mcpRuntime?.error || 'MCP runtime is not ready.' };
    }
    const settings = store.getSettings();
    const env = mcpEnv();
    const result = await runNodeScript(mcpRuntime.pipelinePath, [], {
      env,
      cwd: settings.mcpAllowedRoots[0] || app.getPath('home'),
      timeoutMs: 90_000,
    });
    if (result.data?.ok) {
      logActivity(
        'mcp',
        'MCP diagnostic completed',
        `${result.data.toolCount} tools · ${result.data.steps?.length || 0} calls · ${result.durationMs} ms`,
        { toolCount: result.data.toolCount, ok: true },
      );
    } else {
      logActivity('mcp', 'MCP diagnostic failed', result.stderr?.slice(-500) || 'Unknown error', { ok: false });
    }
    return {
      ok: Boolean(result.ok && result.data?.ok),
      code: result.code,
      timedOut: result.timedOut,
      durationMs: result.durationMs,
      data: result.data,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  });

  ipcMain.handle('mcp:run-agent', async (_event, payload = {}) => {
    if (!mcpRuntime?.ready) {
      return { ok: false, error: mcpRuntime?.error || 'MCP runtime is not ready.' };
    }
    const task = String(payload.task || '').trim();
    const apiKey = String(payload.apiKey || '').trim();
    if (!task) return { ok: false, error: 'Describe a task for the agent.' };
    if (!apiKey) return { ok: false, error: 'Enter an API key for the model endpoint (kept in memory only).' };
    if (task.length > 6_000) return { ok: false, error: 'Task is too long (6,000 character limit).' };
    const settings = store.getSettings();
    const env = {
      ...mcpEnv(),
      OPENAI_API_KEY: apiKey,
      OPENAI_BASE_URL: String(payload.baseUrl || settings.agentBaseUrl || 'https://api.openai.com/v1').replace(/\/+$/, ''),
      OPENAI_MODEL: String(payload.model || settings.agentModel || 'gpt-4o-mini'),
      PRAETOR_AGENT_ALLOW_FULL: settings.mcpFullControl ? '1' : '0',
      PRAETOR_MCP_CWD: settings.mcpAllowedRoots[0] || app.getPath('home'),
    };
    const result = await runNodeScript(mcpRuntime.agentPath, [task], {
      env,
      cwd: settings.mcpAllowedRoots[0] || app.getPath('home'),
      timeoutMs: 240_000,
    });
    if (result.data?.ok) {
      logActivity('agent', 'Agent run completed', `${result.data.model} · ${result.data.toolTrace?.length || 0} tool calls`, {
        model: result.data.model,
        tools: result.data.toolTrace?.length || 0,
      });
    } else {
      logActivity('agent', 'Agent run failed', result.stderr?.slice(-700) || 'Unknown error', { ok: false });
    }
    return {
      ok: Boolean(result.ok && result.data?.ok),
      code: result.code,
      timedOut: result.timedOut,
      durationMs: result.durationMs,
      data: result.data,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  });

  ipcMain.handle('shell:open-external', async (_event, url) => {
    if (!/^https?:\/\//i.test(String(url || ''))) return false;
    await shell.openExternal(url);
    return true;
  });
}

function createWindow() {
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 940,
    minWidth: 1100,
    minHeight: 720,
    show: false,
    frame: false,
    backgroundColor: '#070b0e',
    title: 'PRAETOR Command',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      spellcheck: false,
      devTools: !app.isPackaged,
    },
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (devUrl && url.startsWith(devUrl)) return;
    if (!devUrl && url.startsWith('file://')) return;
    event.preventDefault();
  });

  const emitState = () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.webContents.send('window:state', {
      maximized: mainWindow.isMaximized(),
      focused: mainWindow.isFocused(),
    });
  };
  mainWindow.on('maximize', emitState);
  mainWindow.on('unmaximize', emitState);
  mainWindow.on('focus', emitState);
  mainWindow.on('blur', emitState);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    sendTunnel();
  });

  if (devUrl) mainWindow.loadURL(devUrl);
  else mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

if (gotLock) {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    nativeTheme.themeSource = 'dark';
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
      callback(false);
    });
    store = new Store(app.getPath('userData'));
    recoverStaleSystemProxy();
    stageMcpRuntime();
    registerIpc();
    createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  app.on('before-quit', () => {
    if (connectTimer) clearTimeout(connectTimer);
    if (tunnelTimer) clearInterval(tunnelTimer);
    if (statsTimer) clearInterval(statsTimer);
    if (activeProxy) {
      try {
        activeProxy.close();
      } catch {
        // The session already closed.
      }
      activeProxy = null;
    }
    clearSystemProxy();
  });
}

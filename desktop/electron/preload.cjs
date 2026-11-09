const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld('praetor', {
  platform: process.platform,
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
  },
  app: {
    info: () => ipcRenderer.invoke('app:info'),
  },
  window: {
    minimize: () => ipcRenderer.invoke('window:minimize'),
    maximize: () => ipcRenderer.invoke('window:maximize'),
    close: () => ipcRenderer.invoke('window:close'),
    state: () => ipcRenderer.invoke('window:state'),
    onState: (callback) => subscribe('window:state', callback),
  },
  profiles: {
    list: () => ipcRenderer.invoke('profiles:list'),
    save: (profile) => ipcRenderer.invoke('profiles:save', profile),
    remove: (id) => ipcRenderer.invoke('profiles:delete', id),
  },
  tunnel: {
    status: () => ipcRenderer.invoke('tunnel:status'),
    connect: (id) => ipcRenderer.invoke('tunnel:connect', id),
    disconnect: () => ipcRenderer.invoke('tunnel:disconnect'),
    onStatus: (callback) => subscribe('tunnel:status', callback),
  },
  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    save: (patch) => ipcRenderer.invoke('settings:save', patch),
    onChanged: (callback) => subscribe('settings:changed', callback),
  },
  activity: {
    list: () => ipcRenderer.invoke('activity:list'),
    clear: () => ipcRenderer.invoke('activity:clear'),
    onNew: (callback) => subscribe('activity:new', callback),
  },
  mcp: {
    status: () => ipcRenderer.invoke('mcp:status'),
    config: () => ipcRenderer.invoke('mcp:config'),
    copyConfig: () => ipcRenderer.invoke('mcp:copy-config'),
    openConfig: () => ipcRenderer.invoke('mcp:open-config'),
    runDiagnostic: () => ipcRenderer.invoke('mcp:run-diagnostic'),
    runAgent: (payload) => ipcRenderer.invoke('mcp:run-agent', payload),
  },
  shell: {
    openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),
  },
});

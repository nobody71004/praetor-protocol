import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import {
  POLICY,
  PolicyError,
  resolveInside,
  requireShell,
  requireFullControl,
  requireWrites,
  audit,
  summarizeArgs,
  policySnapshot,
  readAuditTail,
  clip,
} from './policy.mjs';
import { runPowerShell, runCommand, powerShellJson } from './shell.mjs';

const HEAVY_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'release',
  'target',
  '.next',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
]);

function textResult(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text: clip(text) }] };
}

function rel(root, target) {
  const value = path.relative(root, target) || '.';
  return value.split(path.sep).join('/');
}

function register(server, name, config, handler) {
  server.registerTool(name, config, async (args = {}, extra) => {
    const started = Date.now();
    try {
      const result = await handler(args ?? {}, extra);
      await audit({
        tool: name,
        ok: !result?.isError,
        durationMs: Date.now() - started,
        args: summarizeArgs(args),
      });
      return result;
    } catch (error) {
      await audit({
        tool: name,
        ok: false,
        durationMs: Date.now() - started,
        args: summarizeArgs(args),
        error: error.message,
      });
      const label = error instanceof PolicyError ? 'Blocked by policy' : 'Tool error';
      return {
        content: [{ type: 'text', text: `${label}: ${error.message}` }],
        isError: true,
      };
    }
  });
}

async function safeStat(target) {
  try {
    return await fsp.lstat(target);
  } catch {
    return null;
  }
}

function looksBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  return sample.includes(0);
}

function assertRegularFile(stat, target) {
  if (!stat) throw new Error(`Not found: ${target}`);
  if (!stat.isFile()) throw new Error(`Not a regular file: ${target}`);
}

function sendKeysFromCombo(combo) {
  const aliases = {
    CTRL: '^',
    CONTROL: '^',
    SHIFT: '+',
    ALT: '%',
    ENTER: '{ENTER}',
    RETURN: '{ENTER}',
    TAB: '{TAB}',
    ESC: '{ESC}',
    ESCAPE: '{ESC}',
    SPACE: ' ',
    BACKSPACE: '{BACKSPACE}',
    DELETE: '{DELETE}',
    DEL: '{DELETE}',
    INSERT: '{INSERT}',
    INS: '{INSERT}',
    HOME: '{HOME}',
    END: '{END}',
    PAGEUP: '{PGUP}',
    PAGEDOWN: '{PGDN}',
    UP: '{UP}',
    DOWN: '{DOWN}',
    LEFT: '{LEFT}',
    RIGHT: '{RIGHT}',
    WIN: '^{ESC}',
  };
  return String(combo)
    .split('+')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const upper = part.toUpperCase();
      if (aliases[upper]) return aliases[upper];
      if (/^F([1-9]|1[0-9]|2[0-4])$/.test(upper)) return `{${upper}}`;
      if (/^[A-Z0-9]$/.test(upper)) return upper.toLowerCase();
      return `{${upper}}`;
    })
    .join('');
}

async function collectEntries(root, maxDepth, limit) {
  const entries = [];
  let truncated = false;

  async function visit(directory, depth) {
    if (entries.length >= limit) {
      truncated = true;
      return;
    }
    let dirents;
    try {
      dirents = await fsp.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    dirents.sort((a, b) => {
      if (a.isDirectory() !== b.isDirectory()) return a.isDirectory() ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const dirent of dirents) {
      if (entries.length >= limit) {
        truncated = true;
        return;
      }
      const target = path.join(directory, dirent.name);
      const stat = await safeStat(target);
      entries.push({
        path: rel(root, target),
        name: dirent.name,
        type: dirent.isSymbolicLink()
          ? 'symlink'
          : dirent.isDirectory()
            ? 'directory'
            : dirent.isFile()
              ? 'file'
              : 'other',
        size: stat?.isFile() ? stat.size : null,
        modified: stat?.mtime?.toISOString?.() ?? null,
      });
      if (dirent.isDirectory() && depth + 1 < maxDepth) {
        await visit(target, depth + 1);
      }
    }
  }

  await visit(root, 0);
  return { entries, truncated };
}

async function searchFiles(root, { query, regex, maxResults, extensions }) {
  const matcher = regex
    ? new RegExp(query, 'i')
    : null;
  const needle = query.toLowerCase();
  const allowedExtensions = extensions
    ? new Set(
        extensions
          .split(',')
          .map((item) => item.trim().toLowerCase())
          .filter(Boolean)
          .map((item) => (item.startsWith('.') ? item : `.${item}`)),
      )
    : null;
  const matches = [];
  let scanned = 0;
  let skipped = 0;

  async function visit(directory) {
    if (matches.length >= maxResults) return;
    let dirents;
    try {
      dirents = await fsp.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const dirent of dirents) {
      if (matches.length >= maxResults) return;
      if (dirent.isDirectory()) {
        if (HEAVY_DIRS.has(dirent.name)) {
          skipped += 1;
          continue;
        }
        await visit(path.join(directory, dirent.name));
        continue;
      }
      if (!dirent.isFile()) continue;
      const ext = path.extname(dirent.name).toLowerCase();
      if (allowedExtensions && !allowedExtensions.has(ext)) continue;
      const target = path.join(directory, dirent.name);
      const stat = await safeStat(target);
      if (!stat || stat.size > 1_500_000) {
        skipped += 1;
        continue;
      }
      scanned += 1;
      let buffer;
      try {
        buffer = await fsp.readFile(target);
      } catch {
        skipped += 1;
        continue;
      }
      if (looksBinary(buffer)) {
        skipped += 1;
        continue;
      }
      const lines = buffer.toString('utf8').split(/\r?\n/);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        let hit = false;
        try {
          hit = matcher ? matcher.test(line) : line.toLowerCase().includes(needle);
        } catch (error) {
          throw new Error(`Invalid regular expression: ${error.message}`);
        }
        if (hit) {
          matches.push({
            path: rel(root, target),
            line: index + 1,
            text: clip(line.trim(), 400),
          });
          if (matches.length >= maxResults) return;
        }
      }
    }
  }

  await visit(root);
  return { matches, scannedFiles: scanned, skippedFiles: skipped };
}

export function registerTools(server) {
  // ---------------------------------------------------------------------------
  // System
  // ---------------------------------------------------------------------------

  register(
    server,
    'system_info',
    {
      title: 'System information',
      description:
        'Return host, OS, CPU, memory, uptime, Node/Electron versions, and MCP policy roots. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      const cpus = os.cpus();
      return textResult({
        hostname: os.hostname(),
        platform: process.platform,
        arch: process.arch,
        osType: os.type(),
        osRelease: os.release(),
        osVersion: os.version(),
        uptimeSeconds: Math.round(os.uptime()),
        user: os.userInfo().username,
        home: os.homedir(),
        cpu: {
          model: cpus[0]?.model ?? 'unknown',
          cores: cpus.length,
          speedMHz: cpus[0]?.speed ?? null,
        },
        memory: {
          totalBytes: os.totalmem(),
          freeBytes: os.freemem(),
          usedPercent: Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 1000) / 10,
        },
        versions: {
          node: process.versions.node,
          electron: process.versions.electron ?? null,
          chrome: process.versions.chrome ?? null,
        },
        now: new Date().toISOString(),
        roots: POLICY.roots,
      });
    },
  );

  register(
    server,
    'system_processes',
    {
      title: 'List processes',
      description: 'List running processes with PID, name, CPU, memory, and responsiveness. Read-only.',
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional().describe('Maximum rows (default 30).'),
        sortBy: z.enum(['cpu', 'memory', 'name']).optional().describe('Sort order.'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ limit = 30, sortBy = 'cpu' }) => {
      const sortExpression =
        sortBy === 'memory'
          ? 'WorkingSet64'
          : sortBy === 'name'
            ? 'ProcessName'
            : 'CPU';
      const data = await powerShellJson(
        `Get-Process -ErrorAction SilentlyContinue |
          Select-Object Id, ProcessName, CPU, WorkingSet64, Responding, StartTime |
          Sort-Object ${sortExpression} -Descending |
          Select-Object -First $env:PRAETOR_ARG_LIMIT |
          ConvertTo-Json -Depth 3`,
        { env: { PRAETOR_ARG_LIMIT: String(limit) } },
      );
      return textResult({ count: Array.isArray(data) ? data.length : data ? 1 : 0, processes: data ?? [] });
    },
  );

  register(
    server,
    'system_windows',
    {
      title: 'List application windows',
      description: 'List visible top-level windows with process, PID, title, and responsiveness. Read-only.',
      inputSchema: {
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ limit = 40 }) => {
      const data = await powerShellJson(
        `Get-Process -ErrorAction SilentlyContinue |
          Where-Object { $_.MainWindowTitle -and $_.MainWindowTitle.Trim() -ne '' } |
          Select-Object Id, ProcessName, MainWindowTitle, Responding, StartTime |
          Sort-Object ProcessName |
          Select-Object -First $env:PRAETOR_ARG_LIMIT |
          ConvertTo-Json -Depth 3`,
        { env: { PRAETOR_ARG_LIMIT: String(limit) } },
      );
      return textResult({ windows: data ?? [] });
    },
  );

  register(
    server,
    'system_ports',
    {
      title: 'Listening ports',
      description: 'List TCP listeners and owning PIDs using Get-NetTCPConnection. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      const data = await powerShellJson(
        `Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
          Select-Object LocalAddress, LocalPort, OwningProcess |
          Sort-Object LocalPort |
          ConvertTo-Json -Depth 3`,
      );
      return textResult({ listeners: data ?? [] });
    },
  );

  register(
    server,
    'system_env',
    {
      title: 'Environment variables (redacted)',
      description:
        'Return environment variable names and non-secret values. Names matching token, secret, key, password, or credential are redacted. Read-only.',
      inputSchema: {
        filter: z.string().optional().describe('Case-insensitive substring filter on variable names.'),
        includeValues: z.boolean().optional().describe('Include non-secret values (default true).'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ filter, includeValues = true }) => {
      const entries = Object.entries(process.env)
        .filter(([key]) => !filter || key.toLowerCase().includes(filter.toLowerCase()))
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => ({
          name: key,
          value: includeValues
            ? /token|secret|password|passwd|api[_-]?key|authorization|credential/i.test(key)
              ? '[redacted]'
              : clip(value ?? '', 500)
            : undefined,
        }));
      return textResult({ count: entries.length, variables: entries });
    },
  );

  register(
    server,
    'system_displays',
    {
      title: 'List displays',
      description: 'Report monitors, bounds, primary display, and DPI-independent coordinates. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      const data = await powerShellJson(
        `Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
          [pscustomobject]@{
            device = $_.DeviceName
            primary = $_.Primary
            x = $_.Bounds.X
            y = $_.Bounds.Y
            width = $_.Bounds.Width
            height = $_.Bounds.Height
          }
        } | ConvertTo-Json -Depth 3`,
      );
      return textResult({ displays: data ?? [] });
    },
  );

  register(
    server,
    'screen_size',
    {
      title: 'Primary screen size',
      description: 'Return the primary screen bounds without capturing pixels. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      const data = await powerShellJson(
        `Add-Type -AssemblyName System.Windows.Forms
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        [pscustomobject]@{
          x = $b.X
          y = $b.Y
          width = $b.Width
          height = $b.Height
          device = [System.Windows.Forms.Screen]::PrimaryScreen.DeviceName
        } | ConvertTo-Json`,
      );
      return textResult(data ?? {});
    },
  );

  register(
    server,
    'screen_capture',
    {
      title: 'Capture primary screen',
      description:
        'Capture the primary screen as a PNG image. Requires MCP full control; the image is also written to a temporary path.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      requireFullControl('Screen capture');
      const target = path.join(
        os.tmpdir(),
        `praetor-screen-${Date.now()}-${Math.random().toString(16).slice(2)}.png`,
      );
      const result = await powerShellJson(
        `Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen($b.X, $b.Y, 0, 0, $bmp.Size)
        $bmp.Save($env:PRAETOR_ARG_PATH, [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bmp.Dispose()
        [pscustomobject]@{ path = $env:PRAETOR_ARG_PATH; width = $b.Width; height = $b.Height } | ConvertTo-Json`,
        { env: { PRAETOR_ARG_PATH: target }, timeoutMs: 30_000 },
      );
      const image = await fsp.readFile(target);
      if (image.length > 16 * 1024 * 1024) {
        throw new Error('Captured image is larger than 16 MiB; refusing to send it.');
      }
      return {
        content: [
          { type: 'image', data: image.toString('base64'), mimeType: 'image/png' },
          { type: 'text', text: JSON.stringify(result ?? { path: target }, null, 2) },
        ],
      };
    },
  );

  register(
    server,
    'system_process_kill',
    {
      title: 'Terminate process',
      description:
        'Terminate a process by PID. Requires MCP full control and is audited. Use with explicit intent.',
      inputSchema: {
        pid: z.number().int().positive().describe('Windows process ID.'),
        force: z.boolean().optional().describe('Force termination (default true).'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    async ({ pid, force = true }) => {
      requireFullControl('Process control');
      if (pid === process.pid) throw new Error('Refusing to terminate the MCP server process.');
      const result = await runPowerShell(
        `Stop-Process -Id $env:PRAETOR_ARG_PID ${force ? '-Force' : ''} -ErrorAction Stop
        Write-Output "terminated $env:PRAETOR_ARG_PID"`,
        { env: { PRAETOR_ARG_PID: String(pid) } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Stop-Process failed.');
      return textResult({ pid, terminated: true, output: result.stdout.trim() });
    },
  );

  // ---------------------------------------------------------------------------
  // Computer input
  // ---------------------------------------------------------------------------

  register(
    server,
    'input_move',
    {
      title: 'Move mouse',
      description: 'Move the mouse cursor to absolute screen coordinates. Requires MCP full control.',
      inputSchema: {
        x: z.number().int().describe('Screen X coordinate.'),
        y: z.number().int().describe('Screen Y coordinate.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ x, y }) => {
      requireFullControl('Mouse control');
      const result = await runPowerShell(
        `Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PraetorNativeMove {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
}
"@
        if (-not [PraetorNativeMove]::SetCursorPos([int]$env:PRAETOR_ARG_X, [int]$env:PRAETOR_ARG_Y)) {
          throw "SetCursorPos failed"
        }
        Write-Output "moved $env:PRAETOR_ARG_X,$env:PRAETOR_ARG_Y"`,
        { env: { PRAETOR_ARG_X: String(x), PRAETOR_ARG_Y: String(y) } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Mouse move failed.');
      return textResult({ x, y, moved: true });
    },
  );

  register(
    server,
    'input_click',
    {
      title: 'Click mouse',
      description:
        'Click at the current cursor position or at absolute coordinates. Requires MCP full control.',
      inputSchema: {
        x: z.number().int().optional(),
        y: z.number().int().optional(),
        button: z.enum(['left', 'right', 'middle']).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ x, y, button = 'left' }) => {
      requireFullControl('Mouse control');
      const down = button === 'right' ? '8' : button === 'middle' ? '32' : '2';
      const up = button === 'right' ? '16' : button === 'middle' ? '64' : '4';
      const move =
        Number.isInteger(x) && Number.isInteger(y)
          ? '[PraetorNativeClick]::SetCursorPos([int]$env:PRAETOR_ARG_X, [int]$env:PRAETOR_ARG_Y) | Out-Null'
          : '';
      const result = await runPowerShell(
        `Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PraetorNativeClick {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);
}
"@
        ${move}
        [PraetorNativeClick]::mouse_event(${down}, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 40
        [PraetorNativeClick]::mouse_event(${up}, 0, 0, 0, [UIntPtr]::Zero)
        Write-Output "clicked ${button}"`,
        {
          env: {
            PRAETOR_ARG_X: String(Number.isInteger(x) ? x : 0),
            PRAETOR_ARG_Y: String(Number.isInteger(y) ? y : 0),
          },
        },
      );
      if (!result.ok) throw new Error(result.stderr || 'Mouse click failed.');
      return textResult({ clicked: true, button, x: x ?? null, y: y ?? null });
    },
  );

  register(
    server,
    'input_type',
    {
      title: 'Type text',
      description:
        'Paste text into the focused application using the clipboard and Ctrl+V. Requires MCP full control.',
      inputSchema: {
        text: z.string().min(1).max(50_000).describe('Text to insert.'),
        submit: z.boolean().optional().describe('Press Enter after pasting.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ text, submit = false }) => {
      requireFullControl('Keyboard control');
      const result = await runPowerShell(
        `Set-Clipboard -Value $env:PRAETOR_ARG_TEXT
        Start-Sleep -Milliseconds 80
        $shell = New-Object -ComObject WScript.Shell
        $shell.SendKeys('^v')
        ${submit ? "Start-Sleep -Milliseconds 120\n        $shell.SendKeys('{ENTER}')" : ''}
        Write-Output "typed $($env:PRAETOR_ARG_TEXT.Length) chars"`,
        { env: { PRAETOR_ARG_TEXT: text }, timeoutMs: 30_000 },
      );
      if (!result.ok) throw new Error(result.stderr || 'Typing failed.');
      return textResult({ typed: text.length, submitted: submit });
    },
  );

  register(
    server,
    'input_key',
    {
      title: 'Press key combination',
      description:
        'Send a key combination such as CTRL+S, ALT+TAB, CTRL+SHIFT+ESC, or F5 to the focused window. Requires MCP full control.',
      inputSchema: {
        combo: z.string().min(1).max(100).describe('Plus-separated key combination.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ combo }) => {
      requireFullControl('Keyboard control');
      const sendKeys = sendKeysFromCombo(combo);
      const result = await runPowerShell(
        `$shell = New-Object -ComObject WScript.Shell
        $shell.SendKeys($env:PRAETOR_ARG_KEYS)
        Write-Output "sent $env:PRAETOR_ARG_COMBO"`,
        { env: { PRAETOR_ARG_KEYS: sendKeys, PRAETOR_ARG_COMBO: combo } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Key press failed.');
      return textResult({ combo, sent: true });
    },
  );

  register(
    server,
    'input_scroll',
    {
      title: 'Scroll mouse wheel',
      description:
        'Scroll the mouse wheel at the current cursor position. Positive clicks scroll up. Requires MCP full control.',
      inputSchema: {
        clicks: z.number().int().min(-50).max(50).describe('Wheel clicks, positive is up.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ clicks }) => {
      requireFullControl('Mouse control');
      const result = await runPowerShell(
        `Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PraetorNativeScroll {
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);
}
"@
        $delta = [int]$env:PRAETOR_ARG_CLICKS * 120
        [PraetorNativeScroll]::mouse_event(0x0800, 0, 0, [uint32]$delta, [UIntPtr]::Zero)
        Write-Output "scrolled $env:PRAETOR_ARG_CLICKS"`,
        { env: { PRAETOR_ARG_CLICKS: String(clicks) } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Scroll failed.');
      return textResult({ clicks, scrolled: true });
    },
  );

  register(
    server,
    'clipboard_read',
    {
      title: 'Read clipboard',
      description: 'Read text from the Windows clipboard. Requires MCP full control.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => {
      requireFullControl('Clipboard access');
      const result = await runPowerShell('Get-Clipboard -Raw -ErrorAction SilentlyContinue');
      if (!result.ok) throw new Error(result.stderr || 'Clipboard read failed.');
      return textResult({ text: result.stdout.replace(/\r?\n$/, '') });
    },
  );

  register(
    server,
    'clipboard_write',
    {
      title: 'Write clipboard',
      description: 'Replace Windows clipboard text. Requires MCP full control.',
      inputSchema: {
        text: z.string().max(200_000),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ text }) => {
      requireFullControl('Clipboard access');
      const result = await runPowerShell(
        'Set-Clipboard -Value $env:PRAETOR_ARG_TEXT; Write-Output "clipboard updated"',
        { env: { PRAETOR_ARG_TEXT: text } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Clipboard write failed.');
      return textResult({ written: text.length });
    },
  );

  // ---------------------------------------------------------------------------
  // Applications
  // ---------------------------------------------------------------------------

  register(
    server,
    'app_list',
    {
      title: 'List installed applications',
      description: 'List Start-menu applications and currently running windowed apps. Read-only.',
      inputSchema: {
        limit: z.number().int().min(1).max(200).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ limit = 80 }) => {
      const installed = await powerShellJson(
        `$apps = @()
        if (Get-Command Get-StartApps -ErrorAction SilentlyContinue) {
          $apps = Get-StartApps | Select-Object Name, AppID | Sort-Object Name | Select-Object -First $env:PRAETOR_ARG_LIMIT
        }
        $apps | ConvertTo-Json -Depth 3`,
        { env: { PRAETOR_ARG_LIMIT: String(limit) } },
      );
      const running = await powerShellJson(
        `Get-Process -ErrorAction SilentlyContinue |
          Where-Object { $_.MainWindowTitle } |
          Select-Object Id, ProcessName, MainWindowTitle |
          Sort-Object ProcessName |
          ConvertTo-Json -Depth 3`,
      );
      return textResult({
        installed: installed ?? [],
        running: running ?? [],
      });
    },
  );

  register(
    server,
    'app_launch',
    {
      title: 'Launch application or URL',
      description:
        'Launch an executable, document, folder, or URL with Start-Process. Requires MCP full control.',
      inputSchema: {
        target: z.string().min(1).max(2000).describe('Executable path, document, folder, or URL.'),
        args: z.string().max(4000).optional().describe('Optional argument string.'),
        cwd: z.string().optional().describe('Optional working directory inside an MCP root.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async ({ target, args, cwd }) => {
      requireFullControl('Application launch');
      const workingDirectory = cwd ? resolveInside(cwd, { field: 'cwd' }) : '';
      const result = await runPowerShell(
        `$params = @{ FilePath = $env:PRAETOR_ARG_TARGET }
        if ($env:PRAETOR_ARG_ARGS) { $params.ArgumentList = $env:PRAETOR_ARG_ARGS }
        if ($env:PRAETOR_ARG_CWD) { $params.WorkingDirectory = $env:PRAETOR_ARG_CWD }
        Start-Process @params
        Write-Output "launched $env:PRAETOR_ARG_TARGET"`,
        {
          env: {
            PRAETOR_ARG_TARGET: target,
            PRAETOR_ARG_ARGS: args ?? '',
            PRAETOR_ARG_CWD: workingDirectory,
          },
        },
      );
      if (!result.ok) throw new Error(result.stderr || 'Launch failed.');
      return textResult({ launched: target, args: args ?? null });
    },
  );

  register(
    server,
    'app_focus',
    {
      title: 'Focus application window',
      description: 'Activate a window by title substring. Requires MCP full control.',
      inputSchema: {
        title: z.string().min(1).max(500),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ title }) => {
      requireFullControl('Window control');
      const result = await runPowerShell(
        `$shell = New-Object -ComObject WScript.Shell
        $activated = $shell.AppActivate($env:PRAETOR_ARG_TITLE)
        if (-not $activated) { throw "No window matched: $env:PRAETOR_ARG_TITLE" }
        Write-Output "focused"`,
        { env: { PRAETOR_ARG_TITLE: title } },
      );
      if (!result.ok) throw new Error(result.stderr || 'Focus failed.');
      return textResult({ focused: title });
    },
  );

  // ---------------------------------------------------------------------------
  // Filesystem
  // ---------------------------------------------------------------------------

  register(
    server,
    'fs_list',
    {
      title: 'List directory',
      description:
        'List a directory tree within an allowlisted root, with names, types, sizes, and timestamps. Read-only.',
      inputSchema: {
        path: z.string().optional().describe('Directory, relative to the first root or absolute inside a root.'),
        depth: z.number().int().min(1).max(4).optional().describe('Directory levels to traverse (default 1).'),
        limit: z.number().int().min(1).max(2000).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath = '.', depth = 1, limit = 500 }) => {
      const root = resolveInside(inputPath);
      const stat = await safeStat(root);
      if (!stat?.isDirectory()) throw new Error(`Not a directory: ${root}`);
      const result = await collectEntries(root, depth, limit);
      return textResult({ root, depth, ...result, count: result.entries.length });
    },
  );

  register(
    server,
    'fs_read',
    {
      title: 'Read file',
      description:
        'Read a UTF-8 text file inside an allowlisted root. Binary files are rejected. Read-only.',
      inputSchema: {
        path: z.string(),
        maxBytes: z.number().int().min(1).max(2_000_000).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath, maxBytes = 500_000 }) => {
      const target = resolveInside(inputPath);
      const stat = await safeStat(target);
      assertRegularFile(stat, target);
      if (stat.size > maxBytes) {
        throw new Error(`File is ${stat.size} bytes; maxBytes is ${maxBytes}.`);
      }
      const buffer = await fsp.readFile(target);
      if (looksBinary(buffer)) throw new Error('File appears to be binary.');
      return textResult({
        path: target,
        bytes: buffer.length,
        modified: stat.mtime.toISOString(),
        content: buffer.toString('utf8'),
      });
    },
  );

  register(
    server,
    'fs_stat',
    {
      title: 'File metadata',
      description: 'Return metadata for a path inside an allowlisted root. Read-only.',
      inputSchema: { path: z.string() },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath }) => {
      const target = resolveInside(inputPath);
      const stat = await safeStat(target);
      if (!stat) throw new Error(`Not found: ${target}`);
      return textResult({
        path: target,
        type: stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'symlink' : 'other',
        size: stat.size,
        mode: stat.mode.toString(8),
        created: stat.birthtime.toISOString(),
        modified: stat.mtime.toISOString(),
        accessed: stat.atime.toISOString(),
      });
    },
  );

  register(
    server,
    'fs_search',
    {
      title: 'Search files',
      description:
        'Search text across files under an allowlisted root. Skips dependency/build directories and binary files. Read-only.',
      inputSchema: {
        path: z.string().optional(),
        query: z.string().min(1).max(500),
        regex: z.boolean().optional().describe('Treat query as a case-insensitive regular expression.'),
        extensions: z.string().optional().describe('Comma-separated extensions, e.g. ts,tsx,md.'),
        maxResults: z.number().int().min(1).max(300).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath = '.', query, regex = false, extensions, maxResults = 80 }) => {
      const root = resolveInside(inputPath);
      const stat = await safeStat(root);
      if (!stat) throw new Error(`Not found: ${root}`);
      if (!stat.isDirectory()) throw new Error(`Not a directory: ${root}`);
      const result = await searchFiles(root, { query, regex, maxResults, extensions });
      return textResult({ root, query, regex, ...result });
    },
  );

  register(
    server,
    'fs_write',
    {
      title: 'Write file',
      description:
        'Write or append UTF-8 text to a file inside an allowlisted root. Creates parent directories by default.',
      inputSchema: {
        path: z.string(),
        content: z.string().max(2_000_000),
        append: z.boolean().optional(),
        createDirs: z.boolean().optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath, content, append = false, createDirs = true }) => {
      requireWrites();
      const target = resolveInside(inputPath);
      if (createDirs) await fsp.mkdir(path.dirname(target), { recursive: true });
      await fsp.writeFile(target, content, { encoding: 'utf8', flag: append ? 'a' : 'w' });
      const stat = await fsp.stat(target);
      return textResult({
        path: target,
        bytes: stat.size,
        written: Buffer.byteLength(content, 'utf8'),
        mode: append ? 'append' : 'overwrite',
      });
    },
  );

  register(
    server,
    'fs_mkdir',
    {
      title: 'Create directory',
      description: 'Create a directory inside an allowlisted root. Parent directories are created.',
      inputSchema: {
        path: z.string(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath }) => {
      requireWrites();
      const target = resolveInside(inputPath);
      await fsp.mkdir(target, { recursive: true });
      return textResult({ path: target, created: true });
    },
  );

  register(
    server,
    'fs_copy',
    {
      title: 'Copy file or directory',
      description: 'Copy a file or directory inside an allowlisted root. Requires filesystem writes.',
      inputSchema: {
        from: z.string(),
        to: z.string(),
        overwrite: z.boolean().optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ from, to, overwrite = false }) => {
      requireWrites();
      const source = resolveInside(from, { field: 'from' });
      const destination = resolveInside(to, { field: 'to' });
      if (!overwrite && fs.existsSync(destination)) {
        throw new Error(`Destination exists: ${destination}`);
      }
      await fsp.cp(source, destination, {
        recursive: true,
        force: overwrite,
        errorOnExist: !overwrite,
      });
      return textResult({ from: source, to: destination, copied: true });
    },
  );

  register(
    server,
    'fs_move',
    {
      title: 'Move or rename',
      description: 'Move or rename a file or directory inside an allowlisted root. Requires filesystem writes.',
      inputSchema: {
        from: z.string(),
        to: z.string(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ from, to }) => {
      requireWrites();
      const source = resolveInside(from, { field: 'from' });
      const destination = resolveInside(to, { field: 'to' });
      if (fs.existsSync(destination)) throw new Error(`Destination exists: ${destination}`);
      await fsp.mkdir(path.dirname(destination), { recursive: true });
      await fsp.rename(source, destination);
      return textResult({ from: source, to: destination, moved: true });
    },
  );

  register(
    server,
    'fs_delete',
    {
      title: 'Delete path',
      description:
        'Delete a file or directory inside an allowlisted root. Requires MCP full control and confirm="DELETE". Audited.',
      inputSchema: {
        path: z.string(),
        recursive: z.boolean().optional(),
        confirm: z.literal('DELETE').describe('Must be the exact string DELETE.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    async ({ path: inputPath, recursive = false }) => {
      requireFullControl('Filesystem deletion');
      const target = resolveInside(inputPath);
      if (POLICY.roots.some((root) => path.resolve(root) === target)) {
        throw new Error('Refusing to delete an allowlisted root.');
      }
      const stat = await safeStat(target);
      if (!stat) throw new Error(`Not found: ${target}`);
      if (stat.isDirectory() && !recursive) {
        throw new Error('Directory deletion requires recursive=true.');
      }
      await fsp.rm(target, { recursive, force: false });
      return textResult({ path: target, deleted: true, recursive });
    },
  );

  // ---------------------------------------------------------------------------
  // Shell
  // ---------------------------------------------------------------------------

  register(
    server,
    'shell_exec',
    {
      title: 'Execute PowerShell',
      description:
        'Execute an arbitrary PowerShell script with a timeout. Requires MCP full control and is audited. This is unrestricted command execution.',
      inputSchema: {
        command: z.string().min(1).max(100_000),
        cwd: z.string().optional(),
        timeoutMs: z.number().int().min(1_000).max(300_000).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async ({ command, cwd, timeoutMs = 30_000 }) => {
      requireShell();
      const workingDirectory = cwd ? resolveInside(cwd, { field: 'cwd' }) : POLICY.roots[0];
      const result = await runPowerShell(command, { cwd: workingDirectory, timeoutMs });
      return textResult({
        cwd: workingDirectory,
        code: result.code,
        timedOut: result.timedOut,
        stdout: result.stdout,
        stderr: result.stderr,
        durationMs: result.durationMs,
      });
    },
  );

  // ---------------------------------------------------------------------------
  // Developer tools
  // ---------------------------------------------------------------------------

  register(
    server,
    'workspace_info',
    {
      title: 'Workspace overview',
      description:
        'Summarize the top-level workspace, package.json, and git branch/status. Read-only.',
      inputSchema: {
        path: z.string().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath = '.' }) => {
      const root = resolveInside(inputPath);
      const stat = await safeStat(root);
      if (!stat?.isDirectory()) throw new Error(`Not a directory: ${root}`);
      const top = await fsp.readdir(root, { withFileTypes: true });
      const packagePath = path.join(root, 'package.json');
      let packageInfo = null;
      if (fs.existsSync(packagePath)) {
        try {
          const pkg = JSON.parse(await fsp.readFile(packagePath, 'utf8'));
          packageInfo = {
            name: pkg.name ?? null,
            version: pkg.version ?? null,
            scripts: pkg.scripts ?? {},
            packageManager: pkg.packageManager ?? null,
          };
        } catch (error) {
          packageInfo = { error: error.message };
        }
      }
      const git = await runCommand('git', ['-C', root, 'rev-parse', '--abbrev-ref', 'HEAD'], {
        cwd: root,
        timeoutMs: 8_000,
      });
      return textResult({
        root,
        entries: top
          .sort((a, b) => (a.isDirectory() === b.isDirectory() ? a.name.localeCompare(b.name) : a.isDirectory() ? -1 : 1))
          .slice(0, 80)
          .map((entry) => ({ name: entry.name, type: entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : 'other' })),
        package: packageInfo,
        gitBranch: git.ok ? git.stdout.trim() : null,
        gitAvailable: git.ok,
      });
    },
  );

  register(
    server,
    'package_info',
    {
      title: 'Package manifest',
      description: 'Read package.json name, version, scripts, and dependency counts. Read-only.',
      inputSchema: {
        path: z.string().optional().describe('Directory containing package.json.'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ path: inputPath = '.' }) => {
      const directory = resolveInside(inputPath);
      const manifestPath = path.join(directory, 'package.json');
      const stat = await safeStat(manifestPath);
      if (!stat) throw new Error(`No package.json in ${directory}`);
      assertRegularFile(stat, manifestPath);
      const pkg = JSON.parse(await fsp.readFile(manifestPath, 'utf8'));
      return textResult({
        path: manifestPath,
        name: pkg.name,
        version: pkg.version,
        description: pkg.description,
        type: pkg.type,
        main: pkg.main,
        scripts: pkg.scripts ?? {},
        dependencies: Object.keys(pkg.dependencies ?? {}),
        devDependencies: Object.keys(pkg.devDependencies ?? {}),
      });
    },
  );

  register(
    server,
    'git_status',
    {
      title: 'Git status',
      description: 'Show branch and working-tree status for a repository inside an allowlisted root. Read-only.',
      inputSchema: {
        cwd: z.string().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ cwd }) => {
      const directory = resolveInside(cwd || '.', { field: 'cwd' });
      const result = await runCommand('git', ['-C', directory, 'status', '--short', '--branch'], {
        cwd: directory,
        timeoutMs: 15_000,
      });
      return textResult({
        cwd: directory,
        ok: result.ok,
        code: result.code,
        stdout: result.stdout,
        stderr: result.stderr,
      });
    },
  );

  register(
    server,
    'git_diff',
    {
      title: 'Git diff',
      description: 'Show working-tree or staged diff. Read-only.',
      inputSchema: {
        cwd: z.string().optional(),
        staged: z.boolean().optional(),
        path: z.string().optional().describe('Optional path filter inside the root.'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ cwd, staged = false, path: filter }) => {
      const directory = resolveInside(cwd || '.', { field: 'cwd' });
      const args = ['-C', directory, 'diff', '--no-ext-diff'];
      if (staged) args.push('--cached');
      if (filter) args.push('--', rel(directory, resolveInside(filter, { field: 'path' })));
      const result = await runCommand('git', args, { cwd: directory, timeoutMs: 30_000 });
      return textResult({
        cwd: directory,
        staged,
        ok: result.ok,
        code: result.code,
        diff: result.stdout,
        stderr: result.stderr,
      });
    },
  );

  register(
    server,
    'git_log',
    {
      title: 'Git log',
      description: 'Show recent commit history. Read-only.',
      inputSchema: {
        cwd: z.string().optional(),
        count: z.number().int().min(1).max(50).optional(),
        oneline: z.boolean().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ cwd, count = 12, oneline = true }) => {
      const directory = resolveInside(cwd || '.', { field: 'cwd' });
      const args = ['-C', directory, 'log', `-n${count}`];
      if (oneline) args.push('--oneline', '--decorate');
      else args.push('--date=iso', '--pretty=format:%h %ad %an%n%s%n');
      const result = await runCommand('git', args, { cwd: directory, timeoutMs: 15_000 });
      return textResult({
        cwd: directory,
        ok: result.ok,
        code: result.code,
        log: result.stdout,
        stderr: result.stderr,
      });
    },
  );

  // ---------------------------------------------------------------------------
  // Policy & audit
  // ---------------------------------------------------------------------------

  register(
    server,
    'policy_info',
    {
      title: 'MCP policy',
      description: 'Report roots, capability flags, audit path, platform, and server version. Read-only.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => textResult(policySnapshot()),
  );

  register(
    server,
    'audit_tail',
    {
      title: 'Audit log tail',
      description: 'Read the most recent MCP tool invocation audit records. Read-only.',
      inputSchema: {
        limit: z.number().int().min(1).max(200).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async ({ limit = 40 }) => textResult({ auditFile: POLICY.auditFile, entries: await readAuditTail(limit) }),
  );
}

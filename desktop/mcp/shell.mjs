import { spawn } from 'node:child_process';
import path from 'node:path';
import { POLICY, clip } from './policy.mjs';

const MAX_CAPTURE = 1_048_576;

function collect(stream, state) {
  stream.on('data', (chunk) => {
    state.bytes += chunk.length;
    if (state.text.length < MAX_CAPTURE) {
      state.text += chunk.toString('utf8');
    }
  });
}

function killTree(child) {
  if (!child || child.killed) return;
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
      });
    } else {
      child.kill('SIGTERM');
    }
  } catch {
    try {
      child.kill();
    } catch {
      // Process may already be gone.
    }
  }
}

/**
 * Run a PowerShell script over stdin. Values that originate from an MCP caller
 * should be passed through `env` and read as $env:... rather than interpolated
 * into the script text.
 */
export function runPowerShell(script, options = {}) {
  const {
    cwd = POLICY.roots[0],
    timeoutMs = 20_000,
    env = {},
    maxOutputChars = POLICY.maxOutputChars,
  } = options;

  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(
      process.env.PRAETOR_POWERSHELL ||
        (process.platform === 'win32' ? 'powershell.exe' : 'pwsh'),
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        '-',
      ],
      {
        cwd,
        env: { ...process.env, ...env },
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    const stdout = { text: '', bytes: 0 };
    const stderr = { text: '', bytes: 0 };
    collect(child.stdout, stdout);
    collect(child.stderr, stderr);

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, Math.max(1_000, Math.min(Number(timeoutMs) || 20_000, 300_000)));

    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        code: null,
        signal: null,
        stdout: '',
        stderr: error.message,
        durationMs: Date.now() - started,
        timedOut,
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        ok: code === 0 && !timedOut,
        code,
        signal,
        stdout: clip(stdout.text, maxOutputChars),
        stderr: clip(stderr.text, maxOutputChars),
        stdoutBytes: stdout.bytes,
        stderrBytes: stderr.bytes,
        durationMs: Date.now() - started,
        timedOut,
      });
    });

    child.stdin.on('error', () => {});
    child.stdin.end(script, 'utf8');
  });
}

export function runCommand(file, args, options = {}) {
  const {
    cwd = POLICY.roots[0],
    timeoutMs = 20_000,
    env = {},
    maxOutputChars = POLICY.maxOutputChars,
  } = options;

  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(file, args, {
      cwd,
      env: { ...process.env, ...env },
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = { text: '', bytes: 0 };
    const stderr = { text: '', bytes: 0 };
    collect(child.stdout, stdout);
    collect(child.stderr, stderr);

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, Math.max(1_000, Math.min(Number(timeoutMs) || 20_000, 300_000)));

    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        code: null,
        stdout: '',
        stderr: error.message,
        durationMs: Date.now() - started,
        timedOut,
      });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        ok: code === 0 && !timedOut,
        code,
        stdout: clip(stdout.text, maxOutputChars),
        stderr: clip(stderr.text, maxOutputChars),
        durationMs: Date.now() - started,
        timedOut,
      });
    });
  });
}

export async function powerShellJson(script, options = {}) {
  const result = await runPowerShell(script, options);
  if (!result.ok) {
    const detail = result.timedOut
      ? 'PowerShell command timed out.'
      : result.stderr || `PowerShell exited with code ${result.code}.`;
    throw new Error(detail.trim());
  }
  const text = result.stdout.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Expected JSON from PowerShell, received: ${text.slice(0, 300)}`);
  }
}

export function resolveCwd(input, fallback = POLICY.roots[0]) {
  const candidate = input ? path.resolve(input) : fallback;
  return candidate;
}

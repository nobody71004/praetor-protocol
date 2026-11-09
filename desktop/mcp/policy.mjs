import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const SERVER_NAME = 'praetor-computer-use';
export const SERVER_VERSION = '1.0.0';

export class PolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PolicyError';
  }
}

function normalizeRoots() {
  const raw = process.env.PRAETOR_MCP_ROOTS || process.cwd();
  const roots = raw
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const resolved = path.resolve(entry);
      try {
        return fs.realpathSync.native(resolved);
      } catch {
        return resolved;
      }
    });
  return [...new Set(roots)];
}

const roots = normalizeRoots();
const auditFile =
  process.env.PRAETOR_MCP_AUDIT ||
  path.join(os.homedir(), '.praetor-mcp', 'audit.jsonl');

export const POLICY = Object.freeze({
  roots,
  auditFile,
  platform: process.platform,
  allowShell: process.env.PRAETOR_MCP_ALLOW_SHELL === '1',
  allowFullControl: process.env.PRAETOR_MCP_ALLOW_FULL === '1',
  allowWrites: process.env.PRAETOR_MCP_ALLOW_WRITES !== '0',
  maxReadBytes: Number(process.env.PRAETOR_MCP_MAX_READ_BYTES || 1_048_576),
  maxOutputChars: 200_000,
});

function comparable(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value;
}

export function isInsideRoots(candidate) {
  const target = comparable(path.resolve(candidate));
  return roots.some((root) => {
    const base = comparable(path.resolve(root));
    return target === base || target.startsWith(base.endsWith(path.sep) ? base : `${base}${path.sep}`);
  });
}

function assertRealPathInside(candidate) {
  let probe = path.resolve(candidate);
  while (!fs.existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  let real = probe;
  try {
    real = fs.realpathSync.native(probe);
  } catch {
    // If the existing ancestor cannot be resolved, fall back to the lexical check.
  }
  if (!isInsideRoots(real)) {
    throw new PolicyError(
      `Path escapes the configured MCP roots after symlink resolution: ${candidate}`,
    );
  }
}

/**
 * Resolve a user-supplied path and require it to be inside one of the
 * allowlisted roots. Relative paths are anchored to the first root.
 */
export function resolveInside(input, { field = 'path' } = {}) {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new PolicyError(`"${field}" is required.`);
  }
  const candidate = path.isAbsolute(input)
    ? path.resolve(input)
    : path.resolve(roots[0], input);
  if (!isInsideRoots(candidate)) {
    throw new PolicyError(
      `"${field}" must be inside an allowlisted root. Allowed roots: ${roots.join('; ')}`,
    );
  }
  assertRealPathInside(candidate);
  return candidate;
}

export function requireShell() {
  if (!POLICY.allowShell) {
    throw new PolicyError(
      'shell_exec is disabled. Enable "MCP full control" in PRAETOR Command, or set PRAETOR_MCP_ALLOW_SHELL=1.',
    );
  }
}

export function requireFullControl(capability = 'This tool') {
  if (!POLICY.allowFullControl) {
    throw new PolicyError(
      `${capability} is disabled. Enable "MCP full control" in PRAETOR Command, or set PRAETOR_MCP_ALLOW_FULL=1.`,
    );
  }
}

export function requireWrites() {
  if (!POLICY.allowWrites) {
    throw new PolicyError('Filesystem writes are disabled by PRAETOR_MCP_ALLOW_WRITES=0.');
  }
}

export function clip(text, max = POLICY.maxOutputChars) {
  const value = typeof text === 'string' ? text : String(text ?? '');
  if (value.length <= max) return value;
  return `${value.slice(0, max)}\n… truncated ${value.length - max} chars …`;
}

function redactValue(key, value) {
  if (/token|secret|password|passwd|api[_-]?key|authorization|credential/i.test(key)) {
    return '[redacted]';
  }
  if (typeof value === 'string') {
    return value.length > 240 ? `${value.slice(0, 240)}…` : value;
  }
  return value;
}

export function summarizeArgs(args) {
  if (!args || typeof args !== 'object') return {};
  return Object.fromEntries(
    Object.entries(args)
      .slice(0, 30)
      .map(([key, value]) => [
        key,
        key === 'content' && typeof value === 'string'
          ? `[${value.length} chars]`
          : redactValue(key, value),
      ]),
  );
}

export async function audit(event) {
  const line = `${JSON.stringify({
    ts: new Date().toISOString(),
    pid: process.pid,
    server: SERVER_NAME,
    version: SERVER_VERSION,
    ...event,
  })}\n`;
  try {
    await fs.promises.mkdir(path.dirname(auditFile), { recursive: true });
    await fs.promises.appendFile(auditFile, line, 'utf8');
  } catch (error) {
    console.error(`[audit] ${error.message}`);
  }
}

export async function readAuditTail(limit = 40) {
  const count = Math.max(1, Math.min(Number(limit) || 40, 200));
  try {
    const raw = await fs.promises.readFile(auditFile, 'utf8');
    const lines = raw.trim().split(/\r?\n/).filter(Boolean);
    return lines.slice(-count).map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

export function policySnapshot() {
  return {
    server: { name: SERVER_NAME, version: SERVER_VERSION },
    platform: POLICY.platform,
    arch: process.arch,
    node: process.versions.node,
    roots: POLICY.roots,
    auditFile: POLICY.auditFile,
    capabilities: {
      filesystemRead: true,
      filesystemWrite: POLICY.allowWrites,
      shell: POLICY.allowShell,
      fullControl: POLICY.allowFullControl,
      screen: POLICY.allowFullControl,
      mouseKeyboard: POLICY.allowFullControl,
      clipboard: POLICY.allowFullControl,
      processControl: POLICY.allowFullControl,
    },
    note: 'Computer-use capabilities are gated by explicit environment flags and every call is audited.',
  };
}

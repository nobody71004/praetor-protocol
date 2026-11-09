#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = process.env.PRAETOR_MCP_SERVER || path.join(here, 'server.mjs');
const cwd = process.env.PRAETOR_MCP_CWD || process.cwd();
const started = Date.now();
const steps = [];
const logs = [];

function log(message) {
  logs.push(message);
  console.error(`[pipeline] ${message}`);
}

function contentText(result) {
  return (result?.content ?? [])
    .filter((item) => item.type === 'text')
    .map((item) => item.text)
    .join('\n');
}

function summarize(name, result) {
  const text = contentText(result);
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    // Non-JSON output is summarized as text.
  }
  return {
    tool: name,
    ok: !result?.isError,
    chars: text.length,
    summary: parsed
      ? Object.fromEntries(
          Object.entries(parsed)
            .filter(([key]) => !['entries', 'matches', 'processes', 'listeners', 'windows'].includes(key))
            .slice(0, 10)
            .map(([key, value]) => [
              key,
              typeof value === 'string' ? value.slice(0, 180) : value,
            ]),
        )
      : text.slice(0, 250),
  };
}

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  cwd,
  env: {
    ...process.env,
    ELECTRON_RUN_AS_NODE: '1',
    PRAETOR_MCP_ROOTS: process.env.PRAETOR_MCP_ROOTS || cwd,
  },
  stderr: 'pipe',
});

const stderr = transport.stderr;
if (stderr) {
  stderr.on('data', (chunk) => {
    const line = chunk.toString('utf8').trim();
    if (line) log(`server: ${line}`);
  });
}

const client = new Client(
  { name: 'praetor-agent-pipeline', version: '1.0.0' },
  { capabilities: {} },
);

async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  steps.push(summarize(name, result));
  log(`${name} ${result?.isError ? 'failed' : 'ok'}`);
  return result;
}

async function main() {
  log(`connecting to ${serverPath}`);
  await client.connect(transport);
  const listed = await client.listTools();
  log(`${listed.tools.length} tools discovered`);

  const policyResult = await call('policy_info');
  let policy = null;
  try {
    policy = JSON.parse(contentText(policyResult));
  } catch {
    policy = null;
  }

  await call('system_info');
  await call('workspace_info', { path: '.' });
  await call('fs_list', { path: '.', depth: 1, limit: 30 });
  await call('git_status', { cwd: '.' });
  await call('screen_size');
  await call('audit_tail', { limit: 5 });

  if (policy?.capabilities?.shell) {
    await call('shell_exec', {
      command: "Write-Output ('PRAETOR_MCP_OK ' + $PID)",
      cwd: '.',
      timeoutMs: 10_000,
    });
  }

  await client.close();
  console.log(
    JSON.stringify(
      {
        ok: steps.every((step) => step.ok),
        pipeline: 'praetor-mcp-diagnostic',
        toolCount: listed.tools.length,
        tools: listed.tools.map((tool) => tool.name),
        capabilities: policy?.capabilities ?? null,
        roots: policy?.roots ?? null,
        steps,
        durationMs: Date.now() - started,
        logs,
      },
      null,
      2,
    ),
  );
}

main().catch(async (error) => {
  try {
    await client.close();
  } catch {
    // Connection may never have been established.
  }
  console.error(`[pipeline] fatal: ${error.stack || error.message}`);
  process.exitCode = 1;
});

import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  Check,
  ChevronRight,
  Circle,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  ExternalLink,
  Folder,
  KeyRound,
  Loader2,
  MousePointer2,
  Play,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Wifi,
  Wrench,
  XCircle,
} from 'lucide-react';
import { Badge, Button, CopyButton, SpotlightCard } from '../components/Primitives.jsx';
import { TOOL_CATALOG, TOOL_COUNT } from '../data/tools.js';
import { api } from '../lib/bridge.js';
import { copyText } from '../lib/format.js';

const QUICK_TASKS = [
  { label: 'Inspect workspace', task: 'Inspect the workspace, summarize the project structure, and report git status. Do not modify files.' },
  { label: 'Find a file', task: 'Search the allowlisted workspace for TODO comments and summarize the five most relevant matches.' },
  { label: 'Screen check', task: 'Report the display topology and primary screen size. Do not capture or interact with the screen.' },
];

function initialPipelineLines() {
  return [
    { kind: 'muted', text: 'PRAETOR MCP diagnostic v1.0.0' },
    { kind: 'muted', text: 'Runtime bridge armed · stdio transport · JSONL audit' },
    { kind: 'muted', text: 'Waiting for a pipeline run…' },
  ];
}

function stepTone(step) {
  return step.ok ? 'ok' : 'error';
}

export default function Agent({ mcp, settings, onSaveSettings, onRunDiagnostic, onRunAgent, toast, onNavigate }) {
  const [diagnostic, setDiagnostic] = useState(null);
  const [diagnosticError, setDiagnosticError] = useState('');
  const [diagnosticRunning, setDiagnosticRunning] = useState(false);
  const [task, setTask] = useState(QUICK_TASKS[0].task);
  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [model, setModel] = useState(settings.agentModel || 'gpt-4o-mini');
  const [baseUrl, setBaseUrl] = useState(settings.agentBaseUrl || 'https://api.openai.com/v1');
  const [agentRunning, setAgentRunning] = useState(false);
  const [agentResult, setAgentResult] = useState(null);
  const [agentError, setAgentError] = useState('');
  const [showTrace, setShowTrace] = useState(true);
  const [config, setConfig] = useState(null);

  useEffect(() => {
    setModel(settings.agentModel || 'gpt-4o-mini');
    setBaseUrl(settings.agentBaseUrl || 'https://api.openai.com/v1');
  }, [settings.agentModel, settings.agentBaseUrl]);

  useEffect(() => {
    api.mcp.config().then((result) => {
      if (result?.config) setConfig(result);
    }).catch(() => {});
  }, [settings.mcpFullControl, settings.mcpAllowedRoots]);

  const toolsByCategory = useMemo(() => {
    const groups = {};
    for (const tool of TOOL_CATALOG) {
      groups[tool.category] = (groups[tool.category] || 0) + 1;
    }
    return groups;
  }, []);

  const runDiagnostic = async () => {
    setDiagnosticRunning(true);
    setDiagnosticError('');
    try {
      const result = await onRunDiagnostic();
      if (result?.ok && result.data) setDiagnostic(result);
      else setDiagnosticError(result?.error || result?.stderr || 'Pipeline returned an error.');
    } catch (error) {
      setDiagnosticError(error.message);
    } finally {
      setDiagnosticRunning(false);
    }
  };

  const runAgent = async () => {
    if (!task.trim()) {
      setAgentError('Describe a task first.');
      return;
    }
    if (!apiKey.trim()) {
      setAgentError('Enter an API key for the configured model endpoint.');
      return;
    }
    setAgentRunning(true);
    setAgentError('');
    setAgentResult(null);
    onSaveSettings({ agentModel: model, agentBaseUrl: baseUrl });
    try {
      const result = await onRunAgent({ task: task.trim(), apiKey: apiKey.trim(), model, baseUrl });
      if (result?.ok && result.data) setAgentResult(result);
      else setAgentError(result?.error || result?.stderr || 'The agent run returned an error.');
    } catch (error) {
      setAgentError(error.message);
    } finally {
      setAgentRunning(false);
    }
  };

  const copyConfig = async () => {
    const result = await api.mcp.copyConfig();
    if (result?.ok) toast('MCP config copied', 'mcpServers JSON is on your clipboard.', 'success');
    else toast('Copy failed', result?.error || 'Could not copy the config.', 'error');
  };

  const openConfig = async () => {
    const result = await api.mcp.openConfig();
    if (!result?.ok) toast('Config unavailable', result?.error || 'Could not open the config.', 'error');
  };

  const steps = diagnostic?.data?.steps || [];
  const toolNames = diagnostic?.data?.tools || TOOL_CATALOG.map((tool) => tool.name);

  return (
    <div className="page page-agent">
      <div className="section-toolbar">
        <div className="toolbar-copy">
          <span className="eyebrow">AGENT FABRIC / LOCAL</span>
          <h2>Give an agent a way in.</h2>
        </div>
        <div className="toolbar-actions">
          <Badge dot tone={mcp?.ready ? 'mint' : 'danger'}>{mcp?.ready ? 'MCP ONLINE' : 'MCP OFFLINE'}</Badge>
          <Badge tone={settings.mcpFullControl ? 'amber' : 'mint'}>
            {settings.mcpFullControl ? 'FULL CONTROL' : 'GUARDED MODE'}
          </Badge>
        </div>
      </div>

      <div className="agent-top-grid">
        <SpotlightCard className="panel agent-overview-card">
          <div className="agent-card-icon"><Server size={20} /></div>
          <div>
            <span className="eyebrow">TRANSPORT</span>
            <h2>Local stdio bridge</h2>
            <p>No listening port. The MCP client spawns the server with Electron’s Node runtime and speaks JSON-RPC over stdin/stdout.</p>
          </div>
          <div className="agent-overview-meta">
            <span><span className="status-dot is-online is-pulsing" /> Ready</span>
            <code>{mcp?.serverPath ? 'server.mjs · staged' : 'runtime pending'}</code>
          </div>
        </SpotlightCard>

        <SpotlightCard className="panel agent-overview-card">
          <div className="agent-card-icon agent-card-icon-violet"><Wrench size={20} /></div>
          <div>
            <span className="eyebrow">SURFACE</span>
            <h2>{TOOL_COUNT} audited tools</h2>
            <p>System, screen, input, apps, filesystem, PowerShell, developer workflows, and policy introspection.</p>
          </div>
          <div className="agent-overview-meta">
            <span><Sparkles size={13} /> {Object.keys(toolsByCategory).length} categories</span>
            <code>{settings.mcpFullControl ? 'full capability' : 'guarded capability'}</code>
          </div>
        </SpotlightCard>

        <SpotlightCard className="panel agent-overview-card">
          <div className="agent-card-icon agent-card-icon-amber"><Folder size={20} /></div>
          <div>
            <span className="eyebrow">TRUST BOUNDARY</span>
            <h2>{settings.mcpAllowedRoots.length} allowlisted roots</h2>
            <p>Filesystem calls are resolved against real paths and rejected when they escape a configured root.</p>
          </div>
          <div className="agent-overview-meta">
            <span><ShieldCheck size={13} /> Path containment</span>
            <code>{settings.killSwitch ? 'kill switch armed' : 'kill switch off'}</code>
          </div>
        </SpotlightCard>
      </div>

      <div className="agent-main-grid">
        <SpotlightCard className="panel console-panel">
          <div className="panel-heading panel-heading-console">
            <div>
              <span className="eyebrow">PIPELINE / DIAGNOSTIC</span>
              <h2>End-to-end handshake</h2>
            </div>
            <Button
              icon={diagnosticRunning ? Loader2 : Play}
              loading={diagnosticRunning}
              onClick={runDiagnostic}
              size="sm"
              variant="primary"
            >
              {diagnosticRunning ? 'Running' : 'Run diagnostic'}
            </Button>
          </div>
          <div className="console-frame">
            <div className="console-bar">
              <span className="console-dots"><i /><i /><i /></span>
              <span className="console-path">praetor://agent-pipeline</span>
              <span className="console-state">{diagnostic ? 'COMPLETE' : diagnosticRunning ? 'STREAMING' : 'IDLE'}</span>
            </div>
            <div className="console-body">
              {!diagnostic && !diagnosticError
                ? initialPipelineLines().map((line, index) => (
                  <div className={`console-line console-${line.kind}`} key={`${line.text}-${index}`}>
                    <span className="console-gutter">{String(index + 1).padStart(2, '0')}</span>
                    <span>{line.text}</span>
                  </div>
                )) : null}
              {diagnostic ? (
                <>
                  <div className="console-line console-ok">
                    <span className="console-gutter">01</span>
                    <span><span className="console-prompt">$</span> connect stdio → {diagnostic.data?.tools?.length || TOOL_COUNT} tools discovered</span>
                  </div>
                  <div className="console-line console-ok">
                    <span className="console-gutter">02</span>
                    <span><span className="console-prompt">$</span> policy_info · roots and capabilities enumerated</span>
                  </div>
                  {steps.map((step, index) => (
                    <div className={`console-line console-${stepTone(step)}`} key={`${step.tool}-${index}`}>
                      <span className="console-gutter">{String(index + 3).padStart(2, '0')}</span>
                      <span>
                        <span className="console-prompt">{step.ok ? '✓' : '×'}</span> {step.tool}
                        <span className="console-dim"> · {step.chars ?? 0} chars</span>
                      </span>
                    </div>
                  ))}
                  <div className="console-line console-ok">
                    <span className="console-gutter">{String(steps.length + 3).padStart(2, '0')}</span>
                    <span><span className="console-prompt">✓</span> pipeline complete in {diagnostic.durationMs} ms · audit appended</span>
                  </div>
                </>
              ) : null}
              {diagnosticError ? (
                <div className="console-line console-error">
                  <span className="console-gutter">!!</span>
                  <span><span className="console-prompt">×</span> {diagnosticError}</span>
                </div>
              ) : null}
              {diagnosticRunning ? (
                <div className="console-line console-running">
                  <span className="console-gutter">··</span>
                  <span><span className="console-prompt">›</span> spawning runtime, negotiating tool registry…</span>
                  <span className="console-cursor" />
                </div>
              ) : null}
            </div>
            <div className="console-foot">
              <span><Circle size={8} /> {diagnostic ? `${steps.length} tool calls` : 'stdio transport'}</span>
              <span><ShieldCheck size={12} /> every call audited</span>
              <span>{diagnostic ? `${diagnostic.data?.capabilities?.shell ? 'shell enabled' : 'shell gated'}` : 'guarded by default'}</span>
            </div>
          </div>

          {diagnostic ? (
            <div className="pipeline-summary">
              <div><span className="eyebrow">TOOL REGISTRY</span><strong>{diagnostic.data?.tools?.length || toolNames.length} discovered</strong></div>
              <div><span className="eyebrow">AUDIT</span><strong>{diagnostic.data?.steps?.length || 0} records</strong></div>
              <div><span className="eyebrow">DURATION</span><strong>{diagnostic.durationMs} ms</strong></div>
            </div>
          ) : null}
        </SpotlightCard>

        <SpotlightCard className="panel operator-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">OPERATOR / MODEL LOOP</span>
              <h2>Delegate the next move.</h2>
            </div>
            <span className="agent-glyph agent-glyph-violet"><BrainCircuit size={17} /></span>
          </div>
          <p className="operator-intro">
            The agent plans, calls MCP tools, observes results, and summarizes. Your model key stays in this process and is sent only to the endpoint you configure.
          </p>
          <div className="quick-task-row">
            {QUICK_TASKS.map((quick) => (
              <button key={quick.label} onClick={() => setTask(quick.task)} type="button">{quick.label}</button>
            ))}
          </div>
          <label className="field">
            <span>Task <em>plain language</em></span>
            <textarea
              className="agent-task-input"
              onChange={(event) => setTask(event.target.value)}
              placeholder="Inspect this workspace, find the relevant tests, and summarize what is failing…"
              rows={4}
              value={task}
            />
          </label>
          <div className="operator-meta-grid">
            <label className="field">
              <span>Model key <em>memory only</em></span>
              <div className="secret-input">
                <KeyRound size={14} />
                <input
                  autoComplete="off"
                  onChange={(event) => setApiKey(event.target.value)}
                  placeholder="sk-…"
                  type={showKey ? 'text' : 'password'}
                  value={apiKey}
                />
                <button aria-label={showKey ? 'Hide key' : 'Show key'} onClick={() => setShowKey((value) => !value)} type="button">
                  {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </label>
            <label className="field">
              <span>Model</span>
              <input onChange={(event) => setModel(event.target.value)} placeholder="gpt-4o-mini" value={model} />
            </label>
          </div>
          <label className="field">
            <span>Base URL <em>OpenAI-compatible</em></span>
            <input onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://api.openai.com/v1" value={baseUrl} />
          </label>
          <div className="operator-run-row">
            <Button icon={BrainCircuit} loading={agentRunning} onClick={runAgent} variant="primary">
              {agentRunning ? 'Agent thinking' : 'Run operator'}
            </Button>
            <span className="operator-note"><ShieldAlert size={13} /> keys are never persisted</span>
          </div>
          {agentError ? (
            <div className="operator-error"><AlertTriangle size={14} /> {agentError}</div>
          ) : null}
        </SpotlightCard>
      </div>

      <div className="agent-lower-grid">
        <SpotlightCard className="panel agent-result-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">OPERATOR OUTPUT</span>
              <h2>What the agent found</h2>
            </div>
            {agentResult ? <Badge dot tone="mint">TRACE {agentResult.data?.toolTrace?.length || 0}</Badge> : null}
          </div>
          {agentResult ? (
            <div className="agent-result">
              <div className="agent-answer">{agentResult.data?.answer}</div>
              <div className="agent-result-meta">
                <span><Cpu size={13} /> {agentResult.data?.model}</span>
                <span><Wifi size={13} /> {agentResult.data?.exposedTools} tools exposed</span>
                <span><ScanLine size={13} /> {agentResult.durationMs} ms</span>
                {agentResult.data?.browserPreview ? <Badge tone="amber">BROWSER PREVIEW</Badge> : null}
              </div>
              <button className="trace-toggle" onClick={() => setShowTrace((value) => !value)} type="button">
                <ChevronRight className={showTrace ? 'is-open' : ''} size={14} /> Tool trace
              </button>
              {showTrace && agentResult.data?.toolTrace?.length ? (
                <div className="tool-trace">
                  {agentResult.data.toolTrace.map((trace, index) => (
                    <div className="trace-row" key={`${trace.tool}-${index}`}>
                      <span className="trace-index">{String(index + 1).padStart(2, '0')}</span>
                      <span className={`trace-status ${trace.isError || trace.ok === false ? 'is-error' : ''}`}>{trace.isError || trace.ok === false ? <XCircle size={13} /> : <Check size={13} />}</span>
                      <strong>{trace.tool}</strong>
                      <span className="trace-text">{trace.text || JSON.stringify(trace.args || {})}</span>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          ) : (
            <div className="agent-empty">
              <BrainCircuit size={22} />
              <h3>No operator run yet</h3>
              <p>Run the diagnostic to prove the bridge, then give the operator a task that spans tools.</p>
              <div className="agent-empty-tags"><span><Terminal size={12} /> inspect</span><span><Folder size={12} /> read</span><span><ScanLine size={12} /> observe</span><span><MousePointer2 size={12} /> act</span></div>
            </div>
          )}
        </SpotlightCard>

        <SpotlightCard className="panel config-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">MCP CLIENT CONFIG</span>
              <h2>Copy. Connect. Go.</h2>
            </div>
            <CopyButton value={config?.json || ''} label="Copy JSON" />
          </div>
          <pre className="config-code">{config?.json || '{\n  "mcpServers": {}\n}'}</pre>
          <div className="config-actions">
            <Button icon={Copy} onClick={copyConfig} size="sm" variant="secondary">Copy config</Button>
            <Button icon={ExternalLink} onClick={openConfig} size="sm" variant="ghost">Open folder</Button>
          </div>
          <p className="config-note">
            Point any stdio-capable MCP client at this config. The packaged app stages the server into <code>userData/mcp</code> so paths stay stable.
          </p>
        </SpotlightCard>
      </div>

      <div className="security-band">
        <div className="security-band-icon"><ShieldAlert size={18} /></div>
        <div>
          <strong>Full control is a trust boundary.</strong>
          <span>
            With {settings.mcpFullControl ? 'full control enabled' : 'guarded mode active'}, shell, screen, input, clipboard, process, and delete tools are {settings.mcpFullControl ? 'available to any connected MCP client.' : 'blocked before they execute.'} Only connect clients you trust.
          </span>
        </div>
        <button className="text-button" onClick={() => onNavigate('settings')} type="button">Review policy <ArrowRight size={13} /></button>
      </div>
    </div>
  );
}

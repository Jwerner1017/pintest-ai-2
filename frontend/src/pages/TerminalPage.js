import { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { Send } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card } from '../components/ui/card';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

const HELP_TEXT = `Available commands:
  help                          Show this help
  clear                         Clear the terminal
  whoami                        Show current user
  scans                         List recent scans (id · target · status)
  scan <target> [preset]        Run recon scan (preset: fast|thorough|stealth, default fast)
  vuln <target> [preset]        Run vulnerability scan
  netscan <cidr> [preset]       Run network sweep
  cancel <scan_id_prefix>       Cancel a running scan (first 8 chars ok)
  summary <scan_id_prefix>      Generate AI executive summary
  xml <scan_id_prefix>          Download raw nmap XML
  ai <query>                    Ask the Claude AI assistant`;

const PRESETS = new Set(['fast', 'thorough', 'stealth']);

// Compact single-scan renderer used by scan/vuln/netscan output.
function formatScanResults(scan) {
    const r = scan.results || {};
    const lines = [];
    if (r.ports && r.ports.length) {
        lines.push('  Open ports:');
        r.ports.slice(0, 20).forEach(p => lines.push(`    ${String(p.port).padEnd(6)} ${p.service}  [${p.state}]`));
    }
    if (r.vulnerabilities && r.vulnerabilities.length) {
        lines.push(`  Vulnerabilities (${r.vulnerabilities.length}):`);
        r.vulnerabilities.slice(0, 10).forEach(v => lines.push(`    [${(v.severity || '?').toUpperCase()}] ${v.id} — ${(v.description || '').slice(0, 80)}`));
    }
    if (r.alive_hosts && r.alive_hosts.length) {
        lines.push(`  Live hosts (${r.alive_hosts.length}):`);
        r.alive_hosts.slice(0, 15).forEach(h => lines.push(`    ${h.ip}${h.hostname && h.hostname !== h.ip ? ' (' + h.hostname + ')' : ''}  ports=${(h.ports || []).length}`));
    }
    if (r.risk_score !== undefined) lines.push(`  Risk score: ${r.risk_score}/10`);
    if (r.error) lines.push(`  ERROR: ${r.error}`);
    return lines.length ? lines.join('\n') : '  (no notable findings)';
}

export default function TerminalPage() {
    const [input, setInput] = useState('');
    const [history, setHistory] = useState([
        { type: 'system', content: 'PentestAI Terminal v1.9 — hands-free scanning' },
        { type: 'system', content: 'Type "help" for available commands.' },
    ]);
    const [loading, setLoading] = useState(false);
    const [cmdHistory, setCmdHistory] = useState([]);
    const [histIdx, setHistIdx] = useState(-1);
    const scrollAreaRef = useRef(null);

    const push = (type, content) => setHistory(prev => [...prev, { type, content }]);

    useEffect(() => {
        const el = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
        if (el) el.scrollTop = el.scrollHeight;
    }, [history]);

    // ---- Scan dispatch helper ----
    const runScan = async (scanType, target, preset) => {
        if (!target) { push('error', `usage: ${scanType === 'network' ? 'netscan <cidr>' : `${scanType === 'vuln' ? 'vuln' : 'scan'} <target>`} [preset]`); return; }
        const effectivePreset = PRESETS.has(preset) ? preset : 'fast';
        push('output', `→ Starting ${scanType} scan on ${target} (preset=${effectivePreset})...`);
        try {
            const res = await axios.post(`${API_URL}/api/scans`, { scan_type: scanType, target, options: { preset: effectivePreset } });
            const scanId = res.data.id;
            push('output', `  scan_id=${scanId}`);
            // Poll every 2s up to ~5min.
            let lastStage = '';
            for (let i = 0; i < 150; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const { data: scan } = await axios.get(`${API_URL}/api/scans/${scanId}`);
                if (scan.stage && scan.stage !== lastStage) {
                    push('output', `  [${scan.progress || 0}%] ${scan.stage}`);
                    lastStage = scan.stage;
                }
                if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
                    push(scan.status === 'completed' ? 'output' : 'error', `✓ Scan ${scan.status}`);
                    if (scan.status === 'completed') push('output', formatScanResults(scan));
                    return;
                }
            }
            push('error', 'Poll timeout — check GUI for status');
        } catch (e) {
            push('error', `Scan failed: ${e.response?.data?.detail || e.message}`);
        }
    };

    // Resolve `scan_id_prefix` to a full id from the user's history (case-insensitive prefix match).
    const resolveScanId = async (prefix) => {
        if (!prefix) return null;
        try {
            const { data: list } = await axios.get(`${API_URL}/api/scans`);
            const hit = list.find(s => s.id.toLowerCase().startsWith(prefix.toLowerCase()));
            return hit ? hit.id : null;
        } catch {
            return null;
        }
    };

    // ---- Command router ----
    const handleCommand = async (raw) => {
        const cmd = raw.trim();
        if (!cmd) return;
        push('input', `$ ${cmd}`);
        setCmdHistory(prev => [...prev, cmd].slice(-50));
        setHistIdx(-1);

        const [head, ...rest] = cmd.split(/\s+/);
        const verb = head.toLowerCase();

        if (verb === 'help') { push('output', HELP_TEXT); return; }
        if (verb === 'clear') { setHistory([{ type: 'system', content: 'Terminal cleared.' }]); return; }
        if (verb === 'whoami') {
            try {
                const { data } = await axios.get(`${API_URL}/api/auth/me`);
                push('output', `  ${data.username} <${data.email}>  role=${data.role}`);
            } catch (e) { push('error', 'Not authenticated'); }
            return;
        }
        if (verb === 'scans') {
            try {
                const { data } = await axios.get(`${API_URL}/api/scans`);
                if (!data.length) { push('output', '  (no scans yet)'); return; }
                push('output', '  ID        TYPE      TARGET                       STATUS');
                data.slice(0, 15).forEach(s => {
                    push('output', `  ${s.id.slice(0, 8)}  ${s.scan_type.padEnd(8)}  ${(s.target || '').padEnd(28).slice(0, 28)}  ${s.status}`);
                });
            } catch (e) { push('error', 'Failed to fetch scans'); }
            return;
        }
        if (verb === 'scan' || verb === 'vuln' || verb === 'netscan') {
            const scanType = verb === 'scan' ? 'recon' : verb === 'vuln' ? 'vuln' : 'network';
            setLoading(true);
            try { await runScan(scanType, rest[0], rest[1]); } finally { setLoading(false); }
            return;
        }
        if (verb === 'cancel') {
            const id = await resolveScanId(rest[0]);
            if (!id) { push('error', `No scan matching '${rest[0] || ''}'`); return; }
            try {
                await axios.post(`${API_URL}/api/scans/${id}/cancel`);
                push('output', `✓ Cancelled ${id.slice(0, 8)}`);
            } catch (e) { push('error', `Cancel failed: ${e.response?.data?.detail || e.message}`); }
            return;
        }
        if (verb === 'summary') {
            const id = await resolveScanId(rest[0]);
            if (!id) { push('error', `No scan matching '${rest[0] || ''}'`); return; }
            push('output', '  Generating AI executive summary...');
            setLoading(true);
            try {
                const { data } = await axios.post(`${API_URL}/api/scans/${id}/summary`);
                push('ai', data.summary);
                push('output', `  (model=${data.model}, cached=${data.cached})`);
            } catch (e) { push('error', `Summary failed: ${e.response?.data?.detail || e.message}`); } finally { setLoading(false); }
            return;
        }
        if (verb === 'xml') {
            const id = await resolveScanId(rest[0]);
            if (!id) { push('error', `No scan matching '${rest[0] || ''}'`); return; }
            try {
                const res = await axios.get(`${API_URL}/api/scans/${id}/nmap-xml`, { responseType: 'blob' });
                const url = URL.createObjectURL(res.data);
                const a = document.createElement('a');
                a.href = url;
                a.download = `pentestai-${id.slice(0, 8)}.xml`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                push('output', `✓ Downloaded pentestai-${id.slice(0, 8)}.xml`);
            } catch (e) {
                push('error', e.response?.status === 404 ? 'No XML artifact for that scan' : 'Download failed');
            }
            return;
        }
        if (verb === 'ai') {
            const query = rest.join(' ');
            if (!query) { push('error', 'usage: ai <query>'); return; }
            setLoading(true);
            try {
                const { data } = await axios.post(`${API_URL}/api/chat`, { message: query });
                push('ai', data.response);
            } catch (e) { push('error', 'AI Error: ' + e.message); } finally { setLoading(false); }
            return;
        }
        push('error', `Command not found: ${verb}. Type 'help'.`);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!input.trim() || loading) return;
        handleCommand(input);
        setInput('');
    };

    const handleKeyDown = (e) => {
        if (e.key === 'ArrowUp' && cmdHistory.length) {
            e.preventDefault();
            const next = histIdx === -1 ? cmdHistory.length - 1 : Math.max(0, histIdx - 1);
            setHistIdx(next);
            setInput(cmdHistory[next] || '');
        } else if (e.key === 'ArrowDown' && histIdx !== -1) {
            e.preventDefault();
            const next = histIdx + 1;
            if (next >= cmdHistory.length) { setHistIdx(-1); setInput(''); }
            else { setHistIdx(next); setInput(cmdHistory[next]); }
        }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="terminal-page">
            <Header title="Terminal" subtitle="Hands-free CLI wired to live scan endpoints" />
            <div className="flex-1 p-6">
                <Card className="h-full border-border/40 bg-black flex flex-col overflow-hidden" data-testid="terminal-container">
                    <div className="flex items-center gap-2 px-4 py-3 border-b border-border/20 bg-zinc-950">
                        <div className="flex gap-1.5">
                            <div className="w-3 h-3 rounded-full bg-red-500" />
                            <div className="w-3 h-3 rounded-full bg-yellow-500" />
                            <div className="w-3 h-3 rounded-full bg-green-500" />
                        </div>
                        <span className="text-sm text-muted-foreground font-mono ml-2">pentestai@localhost</span>
                    </div>
                    <ScrollArea ref={scrollAreaRef} className="flex-1 p-4 font-mono text-sm" data-testid="terminal-output">
                        <div className="space-y-1">
                            {history.map((line, i) => (
                                <div
                                    key={i}
                                    className={`whitespace-pre-wrap ${line.type === 'system' ? 'text-blue-400' : line.type === 'input' ? 'text-white' : line.type === 'output' ? 'text-green-400' : line.type === 'error' ? 'text-red-400' : line.type === 'ai' ? 'text-purple-400' : 'text-foreground'}`}
                                    data-testid={`terminal-line-${line.type}`}
                                >
                                    {line.content}
                                </div>
                            ))}
                            {loading && <div className="text-muted-foreground animate-pulse">Working...</div>}
                        </div>
                    </ScrollArea>
                    <form onSubmit={handleSubmit} className="flex items-center gap-2 p-4 border-t border-border/20 bg-zinc-950">
                        <span className="text-primary font-mono">$</span>
                        <Input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder="e.g. scan 127.0.0.1 fast   |   ai list common ssh CVEs"
                            className="flex-1 bg-transparent border-none focus-visible:ring-0 font-mono text-sm text-white"
                            disabled={loading}
                            data-testid="terminal-input"
                            autoFocus
                        />
                        <Button type="submit" size="sm" disabled={loading || !input.trim()} data-testid="terminal-submit">
                            <Send className="w-4 h-4" />
                        </Button>
                    </form>
                </Card>
            </div>
        </div>
    );
}

import { useState, useRef, useEffect } from 'react';
import { Header } from '../components/layout/Header.jsx';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { ScrollArea } from '../components/ui/scroll-area';
import { Terminal as TerminalIcon, Send, Loader2, Lightbulb, X } from 'lucide-react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function TerminalPage() {
    const [input, setInput] = useState('');
    const [history, setHistory] = useState([
        { type: 'system', content: 'PentestAI Terminal v1.0.0' },
        { type: 'system', content: 'Type a command or ask AI for suggestions. Use "help" for available commands.' },
        { type: 'prompt', content: '' }
    ]);
    const [loading, setLoading] = useState(false);
    const [suggestions, setSuggestions] = useState([]);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const inputRef = useRef(null);
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [history]);

    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    const handleCommand = async (cmd) => {
        const command = cmd.trim().toLowerCase();
        
        // Add command to history
        setHistory(prev => [
            ...prev.slice(0, -1),
            { type: 'input', content: `$ ${cmd}` }
        ]);

        // Handle built-in commands
        if (command === 'help') {
            setHistory(prev => [
                ...prev,
                { type: 'output', content: `
Available Commands:
  help          - Show this help message
  clear         - Clear terminal screen
  scan <target> - Run reconnaissance scan
  vuln <target> - Run vulnerability scan
  net <target>  - Run network analysis
  ai <query>    - Ask AI for assistance
  history       - Show command history

Examples:
  scan example.com
  vuln 192.168.1.1
  ai How do I detect open ports?
                `.trim() },
                { type: 'prompt', content: '' }
            ]);
            return;
        }

        if (command === 'clear') {
            setHistory([
                { type: 'system', content: 'Terminal cleared.' },
                { type: 'prompt', content: '' }
            ]);
            return;
        }

        if (command.startsWith('scan ') || command.startsWith('vuln ') || command.startsWith('net ')) {
            const [scanType, ...targetParts] = command.split(' ');
            const target = targetParts.join(' ');
            
            if (!target) {
                setHistory(prev => [
                    ...prev,
                    { type: 'error', content: 'Error: Target required. Usage: scan <target>' },
                    { type: 'prompt', content: '' }
                ]);
                return;
            }

            setLoading(true);
            try {
                const typeMap = { scan: 'recon', vuln: 'vuln', net: 'network' };
                const response = await axios.post(`${API_URL}/api/scans`, {
                    scan_type: typeMap[scanType],
                    target,
                    options: {}
                });

                const results = response.data.results;
                let output = `Scan completed for ${target}\n\n`;
                
                if (results.ports) {
                    output += 'Open Ports:\n';
                    results.ports.forEach(p => {
                        output += `  ${p.port}/${p.service} - ${p.state}\n`;
                    });
                }
                
                if (results.vulnerabilities?.length) {
                    output += '\nVulnerabilities Found:\n';
                    results.vulnerabilities.forEach(v => {
                        output += `  [${v.severity.toUpperCase()}] ${v.id}: ${v.description}\n`;
                    });
                }

                setHistory(prev => [
                    ...prev,
                    { type: 'output', content: output },
                    { type: 'prompt', content: '' }
                ]);
            } catch (error) {
                setHistory(prev => [
                    ...prev,
                    { type: 'error', content: `Error: ${error.message}` },
                    { type: 'prompt', content: '' }
                ]);
            } finally {
                setLoading(false);
            }
            return;
        }

        if (command.startsWith('ai ')) {
            const query = command.slice(3);
            setLoading(true);
            try {
                const response = await axios.post(`${API_URL}/api/chat`, {
                    message: query
                });
                setHistory(prev => [
                    ...prev,
                    { type: 'ai', content: response.data.response },
                    { type: 'prompt', content: '' }
                ]);
            } catch (error) {
                setHistory(prev => [
                    ...prev,
                    { type: 'error', content: `AI Error: ${error.message}` },
                    { type: 'prompt', content: '' }
                ]);
            } finally {
                setLoading(false);
            }
            return;
        }

        // Unknown command - suggest AI
        setHistory(prev => [
            ...prev,
            { type: 'error', content: `Command not found: ${command}. Try "ai ${command}" to ask AI.` },
            { type: 'prompt', content: '' }
        ]);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!input.trim() || loading) return;
        handleCommand(input);
        setInput('');
        setShowSuggestions(false);
    };

    const getAISuggestions = async () => {
        if (!input.trim()) return;
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/chat`, {
                message: `Suggest 3 pentesting commands related to: "${input}". Format as a simple list.`
            });
            // Parse suggestions from response
            const lines = response.data.response.split('\n').filter(l => l.trim());
            setSuggestions(lines.slice(0, 3));
            setShowSuggestions(true);
        } catch (error) {
            console.error('Failed to get suggestions:', error);
        } finally {
            setLoading(false);
        }
    };

    const getLineColor = (type) => {
        switch(type) {
            case 'system': return 'text-blue-400';
            case 'input': return 'text-white';
            case 'output': return 'text-green-400';
            case 'error': return 'text-red-400';
            case 'ai': return 'text-purple-400';
            case 'prompt': return 'text-primary';
            default: return 'text-foreground';
        }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="terminal-page">
            <Header title="Terminal" subtitle="Command-line interface with AI assistance" />
            
            <div className="flex-1 p-6">
                <Card className="h-full border-border/40 bg-[#050505] flex flex-col overflow-hidden" data-testid="terminal-container">
                    {/* Terminal Header */}
                    <div className="flex items-center gap-2 px-4 py-3 border-b border-border/20 bg-[#0a0a0a]">
                        <div className="flex gap-1.5">
                            <div className="w-3 h-3 rounded-full bg-red-500" />
                            <div className="w-3 h-3 rounded-full bg-yellow-500" />
                            <div className="w-3 h-3 rounded-full bg-green-500" />
                        </div>
                        <span className="text-sm text-muted-foreground font-mono ml-2">pentestai@localhost</span>
                    </div>

                    {/* Terminal Content */}
                    <ScrollArea className="flex-1 p-4 font-mono text-sm" ref={scrollRef}>
                        <div className="space-y-1">
                            {history.map((line, i) => (
                                <div key={i} className={`${getLineColor(line.type)} whitespace-pre-wrap`}>
                                    {line.type === 'prompt' ? (
                                        <span className="text-primary">$ </span>
                                    ) : line.content}
                                </div>
                            ))}
                            {loading && (
                                <div className="flex items-center gap-2 text-muted-foreground">
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    <span>Processing...</span>
                                </div>
                            )}
                        </div>
                    </ScrollArea>

                    {/* AI Suggestions */}
                    {showSuggestions && suggestions.length > 0 && (
                        <div className="px-4 py-2 border-t border-border/20 bg-[#0a0a0a]">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-xs text-muted-foreground flex items-center gap-1">
                                    <Lightbulb className="w-3 h-3" />
                                    AI Suggestions
                                </span>
                                <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => setShowSuggestions(false)}>
                                    <X className="w-3 h-3" />
                                </Button>
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {suggestions.map((s, i) => (
                                    <Button
                                        key={i}
                                        variant="outline"
                                        size="sm"
                                        className="text-xs font-mono"
                                        onClick={() => { setInput(s); setShowSuggestions(false); }}
                                    >
                                        {s}
                                    </Button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Input Area */}
                    <form onSubmit={handleSubmit} className="flex items-center gap-2 p-4 border-t border-border/20 bg-[#0a0a0a]">
                        <span className="text-primary font-mono">$</span>
                        <Input
                            ref={inputRef}
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Enter command..."
                            className="flex-1 bg-transparent border-none focus-visible:ring-0 font-mono text-sm"
                            disabled={loading}
                            data-testid="terminal-input"
                        />
                        <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={getAISuggestions}
                            disabled={loading || !input.trim()}
                            className="text-xs"
                            data-testid="ai-suggest-button"
                        >
                            <Lightbulb className="w-4 h-4 mr-1" />
                            AI Suggest
                        </Button>
                        <Button type="submit" size="sm" disabled={loading || !input.trim()} data-testid="terminal-submit">
                            <Send className="w-4 h-4" />
                        </Button>
                    </form>
                </Card>
            </div>
        </div>
    );
}

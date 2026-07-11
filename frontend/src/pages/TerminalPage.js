import { useState } from 'react';
import axios from 'axios';
import { Send } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card } from '../components/ui/card';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function TerminalPage() {
    const [input, setInput] = useState('');
    const [history, setHistory] = useState([
        { type: 'system', content: 'PentestAI Terminal v1.0.0' },
        { type: 'system', content: 'Type "help" for available commands.' }
    ]);
    const [loading, setLoading] = useState(false);

    const handleCommand = async (cmd) => {
        const command = cmd.trim().toLowerCase();
        setHistory(prev => [...prev, { type: 'input', content: `$ ${cmd}` }]);

        if (command === 'help') {
            setHistory(prev => [...prev, { type: 'output', content: 'Commands: help, clear, scan <target>, vuln <target>, ai <query>' }]);
            return;
        }
        if (command === 'clear') {
            setHistory([{ type: 'system', content: 'Terminal cleared.' }]);
            return;
        }
        if (command.startsWith('ai ')) {
            const query = command.slice(3);
            setLoading(true);
            try {
                const response = await axios.post(`${API_URL}/api/chat`, { message: query });
                setHistory(prev => [...prev, { type: 'ai', content: response.data.response }]);
            } catch (error) {
                setHistory(prev => [...prev, { type: 'error', content: 'AI Error: ' + error.message }]);
            } finally { setLoading(false); }
            return;
        }
        setHistory(prev => [...prev, { type: 'error', content: `Command not found: ${command}` }]);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!input.trim() || loading) return;
        handleCommand(input);
        setInput('');
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="terminal-page">
            <Header title="Terminal" subtitle="Command-line interface with AI assistance" />
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
                    <ScrollArea className="flex-1 p-4 font-mono text-sm">
                        <div className="space-y-1">
                            {history.map((line, i) => (
                                <div key={i} className={`whitespace-pre-wrap ${line.type === 'system' ? 'text-blue-400' : line.type === 'input' ? 'text-white' : line.type === 'output' ? 'text-green-400' : line.type === 'error' ? 'text-red-400' : line.type === 'ai' ? 'text-purple-400' : 'text-foreground'}`}>
                                    {line.content}
                                </div>
                            ))}
                            {loading && <div className="text-muted-foreground">Processing...</div>}
                        </div>
                    </ScrollArea>
                    <form onSubmit={handleSubmit} className="flex items-center gap-2 p-4 border-t border-border/20 bg-zinc-950">
                        <span className="text-primary font-mono">$</span>
                        <Input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Enter command..." className="flex-1 bg-transparent border-none focus-visible:ring-0 font-mono text-sm text-white" disabled={loading} data-testid="terminal-input" />
                        <Button type="submit" size="sm" disabled={loading || !input.trim()} data-testid="terminal-submit"><Send className="w-4 h-4" /></Button>
                    </form>
                </Card>
            </div>
        </div>
    );
}

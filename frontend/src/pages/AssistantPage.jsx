import { useState, useRef, useEffect } from 'react';
import { Header } from '../components/layout/Header';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { ScrollArea } from '../components/ui/scroll-area';
import { Send, Bot, User, Loader2, Sparkles, Copy, Check } from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function AssistantPage() {
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            content: `Welcome to PentestAI! I'm your AI-powered penetration testing assistant. I can help you with:

• **Reconnaissance**: Suggest tools and interpret scan results (Nmap, Shodan, whois)
• **Vulnerability Assessment**: Identify potential vulnerabilities and exploitation paths
• **Network Analysis**: Analyze traffic patterns and detect anomalies
• **Exploitation Guidance**: Provide ethical guidance on security frameworks
• **Reporting**: Help generate professional security reports

How can I assist you today? Remember, I only support **authorized security testing**.`
        }
    ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [sessionId, setSessionId] = useState(null);
    const [copiedIndex, setCopiedIndex] = useState(null);
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages]);

    const handleSend = async () => {
        if (!input.trim() || loading) return;

        const userMessage = input.trim();
        setInput('');
        setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
        setLoading(true);

        try {
            const response = await axios.post(`${API_URL}/api/chat`, {
                message: userMessage,
                session_id: sessionId
            });

            setMessages(prev => [...prev, { role: 'assistant', content: response.data.response }]);
            setSessionId(response.data.session_id);
        } catch (error) {
            console.error('Chat error:', error);
            toast.error('Failed to get response. Please try again.');
            setMessages(prev => [...prev, { 
                role: 'assistant', 
                content: 'Sorry, I encountered an error. Please try again.' 
            }]);
        } finally {
            setLoading(false);
        }
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const copyToClipboard = (text, index) => {
        navigator.clipboard.writeText(text);
        setCopiedIndex(index);
        setTimeout(() => setCopiedIndex(null), 2000);
        toast.success('Copied to clipboard');
    };

    const suggestedPrompts = [
        "How do I perform a basic Nmap scan?",
        "Explain SQL injection vulnerabilities",
        "Generate a whois lookup command",
        "What ports should I check first?"
    ];

    return (
        <div className="flex-1 flex flex-col" data-testid="assistant-page">
            <Header title="AI Assistant" subtitle="Your intelligent pentesting companion" />
            
            <div className="flex-1 p-6 flex flex-col">
                <Card className="flex-1 border-border/40 bg-card/20 flex flex-col overflow-hidden">
                    {/* Chat Messages */}
                    <ScrollArea className="flex-1 p-4" ref={scrollRef}>
                        <div className="space-y-4 max-w-4xl mx-auto">
                            {messages.map((message, index) => (
                                <div
                                    key={index}
                                    className={`flex gap-3 animate-fade-in ${
                                        message.role === 'user' ? 'justify-end' : 'justify-start'
                                    }`}
                                    data-testid={`message-${index}`}
                                >
                                    {message.role === 'assistant' && (
                                        <div className="w-8 h-8 bg-primary/20 flex items-center justify-center flex-shrink-0">
                                            <Bot className="w-4 h-4 text-primary" />
                                        </div>
                                    )}
                                    
                                    <div className={`max-w-[80%] relative group ${
                                        message.role === 'user' 
                                            ? 'message-user p-4' 
                                            : 'message-ai p-4'
                                    }`}>
                                        <div className="prose prose-invert prose-sm max-w-none">
                                            {message.content.split('\n').map((line, i) => {
                                                // Handle code blocks
                                                if (line.startsWith('```')) {
                                                    return null;
                                                }
                                                // Handle headers
                                                if (line.startsWith('##')) {
                                                    return <h3 key={i} className="text-base font-semibold mt-2 mb-1">{line.replace(/^#+\s*/, '')}</h3>;
                                                }
                                                // Handle bullet points
                                                if (line.startsWith('•') || line.startsWith('-') || line.startsWith('*')) {
                                                    return <p key={i} className="ml-2 text-sm">{line}</p>;
                                                }
                                                // Handle bold
                                                if (line.includes('**')) {
                                                    const parts = line.split(/\*\*(.*?)\*\*/g);
                                                    return (
                                                        <p key={i} className="text-sm">
                                                            {parts.map((part, j) => 
                                                                j % 2 === 1 ? <strong key={j}>{part}</strong> : part
                                                            )}
                                                        </p>
                                                    );
                                                }
                                                // Handle inline code
                                                if (line.includes('`')) {
                                                    const parts = line.split(/`(.*?)`/g);
                                                    return (
                                                        <p key={i} className="text-sm">
                                                            {parts.map((part, j) => 
                                                                j % 2 === 1 ? <code key={j} className="bg-background/50 px-1 py-0.5 text-xs font-mono text-primary">{part}</code> : part
                                                            )}
                                                        </p>
                                                    );
                                                }
                                                // Regular text
                                                return line ? <p key={i} className="text-sm">{line}</p> : <br key={i} />;
                                            })}
                                        </div>
                                        
                                        {message.role === 'assistant' && (
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="absolute -right-10 top-2 opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8"
                                                onClick={() => copyToClipboard(message.content, index)}
                                                data-testid={`copy-message-${index}`}
                                            >
                                                {copiedIndex === index ? (
                                                    <Check className="w-4 h-4 text-green-500" />
                                                ) : (
                                                    <Copy className="w-4 h-4" />
                                                )}
                                            </Button>
                                        )}
                                    </div>
                                    
                                    {message.role === 'user' && (
                                        <div className="w-8 h-8 bg-secondary/20 flex items-center justify-center flex-shrink-0">
                                            <User className="w-4 h-4 text-secondary" />
                                        </div>
                                    )}
                                </div>
                            ))}
                            
                            {loading && (
                                <div className="flex gap-3 animate-fade-in" data-testid="loading-indicator">
                                    <div className="w-8 h-8 bg-primary/20 flex items-center justify-center flex-shrink-0">
                                        <Bot className="w-4 h-4 text-primary" />
                                    </div>
                                    <div className="message-ai p-4 flex items-center gap-2">
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        <span className="text-sm text-muted-foreground">Analyzing...</span>
                                    </div>
                                </div>
                            )}
                        </div>
                    </ScrollArea>

                    {/* Suggested Prompts */}
                    {messages.length === 1 && (
                        <div className="px-4 pb-4">
                            <div className="max-w-4xl mx-auto">
                                <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                                    <Sparkles className="w-3 h-3" />
                                    Suggested prompts
                                </p>
                                <div className="flex flex-wrap gap-2">
                                    {suggestedPrompts.map((prompt, index) => (
                                        <Button
                                            key={index}
                                            variant="outline"
                                            size="sm"
                                            className="text-xs"
                                            onClick={() => setInput(prompt)}
                                            data-testid={`suggested-prompt-${index}`}
                                        >
                                            {prompt}
                                        </Button>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Input Area */}
                    <div className="border-t border-border/40 p-4">
                        <div className="max-w-4xl mx-auto flex gap-2">
                            <Input
                                placeholder="Ask about reconnaissance, vulnerabilities, exploits..."
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={handleKeyDown}
                                disabled={loading}
                                className="flex-1 bg-background"
                                data-testid="chat-input"
                            />
                            <Button 
                                onClick={handleSend} 
                                disabled={!input.trim() || loading}
                                data-testid="send-button"
                            >
                                {loading ? (
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                ) : (
                                    <Send className="w-4 h-4" />
                                )}
                            </Button>
                        </div>
                        <p className="text-xs text-muted-foreground text-center mt-2">
                            PentestAI may produce inaccurate information. Always verify commands before execution.
                        </p>
                    </div>
                </Card>
            </div>
        </div>
    );
}

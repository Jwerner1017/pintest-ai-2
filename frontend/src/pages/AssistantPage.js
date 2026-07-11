import { useState } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Send, Bot, User, Loader2 } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card } from '../components/ui/card';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function AssistantPage() {
    const [messages, setMessages] = useState([
        { role: 'assistant', content: 'Welcome to PentestAI! I can help you with reconnaissance, vulnerability assessment, network analysis, and more. How can I assist you today?' }
    ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [sessionId, setSessionId] = useState(null);

    const handleSend = async () => {
        if (!input.trim() || loading) return;
        const userMessage = input.trim();
        setInput('');
        setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/chat`, { message: userMessage, session_id: sessionId });
            setMessages(prev => [...prev, { role: 'assistant', content: response.data.response }]);
            setSessionId(response.data.session_id);
        } catch (error) {
            toast.error('Failed to get response');
            setMessages(prev => [...prev, { role: 'assistant', content: 'Sorry, I encountered an error. Please try again.' }]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="assistant-page">
            <Header title="AI Assistant" subtitle="Your intelligent pentesting companion" />
            <div className="flex-1 p-6 flex flex-col">
                <Card className="flex-1 border-border/40 bg-card/20 flex flex-col overflow-hidden">
                    <ScrollArea className="flex-1 p-4">
                        <div className="space-y-4 max-w-4xl mx-auto">
                            {messages.map((message, index) => (
                                <div key={index} className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`} data-testid={`message-${index}`}>
                                    {message.role === 'assistant' && (
                                        <div className="w-8 h-8 bg-primary/20 flex items-center justify-center flex-shrink-0">
                                            <Bot className="w-4 h-4 text-primary" />
                                        </div>
                                    )}
                                    <div className={`max-w-[80%] p-4 ${message.role === 'user' ? 'bg-primary/20 border border-primary/30' : 'bg-card border border-border/40'}`}>
                                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                                    </div>
                                    {message.role === 'user' && (
                                        <div className="w-8 h-8 bg-secondary/20 flex items-center justify-center flex-shrink-0">
                                            <User className="w-4 h-4 text-secondary" />
                                        </div>
                                    )}
                                </div>
                            ))}
                            {loading && (
                                <div className="flex gap-3" data-testid="loading-indicator">
                                    <div className="w-8 h-8 bg-primary/20 flex items-center justify-center flex-shrink-0">
                                        <Bot className="w-4 h-4 text-primary" />
                                    </div>
                                    <div className="bg-card border border-border/40 p-4 flex items-center gap-2">
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        <span className="text-sm text-muted-foreground">Analyzing...</span>
                                    </div>
                                </div>
                            )}
                        </div>
                    </ScrollArea>
                    <div className="border-t border-border/40 p-4">
                        <div className="max-w-4xl mx-auto flex gap-2">
                            <Input
                                placeholder="Ask about reconnaissance, vulnerabilities, exploits..."
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
                                disabled={loading}
                                className="flex-1 bg-background"
                                data-testid="chat-input"
                            />
                            <Button onClick={handleSend} disabled={!input.trim() || loading} data-testid="send-button">
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                            </Button>
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
}

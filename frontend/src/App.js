import { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation, useNavigate } from 'react-router-dom';
import { Toaster, toast } from 'sonner';
import axios from 'axios';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { ScrollArea } from './components/ui/scroll-area';
import { Switch } from './components/ui/switch';
import { Separator } from './components/ui/separator';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Progress } from './components/ui/progress';
import { Checkbox } from './components/ui/checkbox';
import { 
    Shield, LayoutDashboard, Search, Bug, Network, MessageSquare, 
    FileText, Settings, Terminal, LogOut, ChevronLeft, ChevronRight,
    Sun, Moon, Bell, AlertCircle, AlertTriangle, Target, Activity, ArrowUpRight, Clock,
    Send, Bot, User, Loader2, Sparkles, Copy, Check, Globe, Server, Wifi,
    Play, FileWarning, CheckCircle, XCircle, Download, Calendar, Lightbulb, X,
    Palette, Key
} from 'lucide-react';
import './App.css';

const API_URL = process.env.REACT_APP_BACKEND_URL;

// Auth Context
const AuthContext = createContext(null);

function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('token'));
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (token) {
            axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
            fetchUser();
        } else {
            setLoading(false);
        }
    }, [token]);

    const fetchUser = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/auth/me`);
            setUser(response.data);
        } catch (error) {
            logout();
        } finally {
            setLoading(false);
        }
    };

    const login = async (email, password) => {
        const response = await axios.post(`${API_URL}/api/auth/login`, { email, password });
        const { access_token, user: userData } = response.data;
        localStorage.setItem('token', access_token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        setToken(access_token);
        setUser(userData);
        return userData;
    };

    const register = async (email, password, username) => {
        const response = await axios.post(`${API_URL}/api/auth/register`, { email, password, username });
        const { access_token, user: userData } = response.data;
        localStorage.setItem('token', access_token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        setToken(access_token);
        setUser(userData);
        return userData;
    };

    const logout = () => {
        localStorage.removeItem('token');
        delete axios.defaults.headers.common['Authorization'];
        setToken(null);
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, token, loading, login, register, logout, isAuthenticated: !!user }}>
            {children}
        </AuthContext.Provider>
    );
}

function useAuth() {
    return useContext(AuthContext);
}

// Sidebar Component
const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/recon', label: 'Reconnaissance', icon: Search },
    { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { path: '/network', label: 'Network', icon: Network },
    { path: '/assistant', label: 'AI Assistant', icon: MessageSquare },
    { path: '/terminal', label: 'Terminal', icon: Terminal },
    { path: '/reports', label: 'Reports', icon: FileText },
    { path: '/settings', label: 'Settings', icon: Settings },
];

function Sidebar() {
    const location = useLocation();
    const { user, logout } = useAuth();
    const [collapsed, setCollapsed] = useState(false);

    return (
        <aside className={`h-screen sticky top-0 border-r border-border/40 bg-card/30 backdrop-blur-sm flex flex-col transition-all duration-200 ${collapsed ? 'w-16' : 'w-64'}`} data-testid="sidebar">
            <div className="p-4 border-b border-border/40 flex items-center justify-between">
                {!collapsed && (
                    <Link to="/dashboard" className="flex items-center gap-2" data-testid="sidebar-logo">
                        <Shield className="w-6 h-6 text-primary" />
                        <span className="font-bold text-lg">PentestAI</span>
                    </Link>
                )}
                {collapsed && (
                    <Link to="/dashboard" className="mx-auto" data-testid="sidebar-logo-collapsed">
                        <Shield className="w-6 h-6 text-primary" />
                    </Link>
                )}
                <Button variant="ghost" size="icon" onClick={() => setCollapsed(!collapsed)} className={`h-8 w-8 ${collapsed ? 'mx-auto' : ''}`} data-testid="sidebar-toggle">
                    {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
                </Button>
            </div>

            <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
                {navItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = location.pathname === item.path;
                    return (
                        <Link
                            key={item.path}
                            to={item.path}
                            className={`flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors ${isActive ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'} ${collapsed ? 'justify-center' : ''}`}
                            data-testid={`nav-${item.path.slice(1)}`}
                            title={collapsed ? item.label : undefined}
                        >
                            <Icon className="w-5 h-5 flex-shrink-0" />
                            {!collapsed && <span>{item.label}</span>}
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-border/40">
                {!collapsed ? (
                    <div className="space-y-3">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 bg-primary/20 flex items-center justify-center text-primary font-medium text-sm">
                                {user?.username?.charAt(0).toUpperCase() || 'U'}
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate">{user?.username}</p>
                                <p className="text-xs text-muted-foreground truncate">{user?.role}</p>
                            </div>
                        </div>
                        <Button variant="outline" size="sm" className="w-full justify-start gap-2" onClick={logout} data-testid="logout-button">
                            <LogOut className="w-4 h-4" />
                            Logout
                        </Button>
                    </div>
                ) : (
                    <Button variant="ghost" size="icon" className="w-full" onClick={logout} data-testid="logout-button-collapsed" title="Logout">
                        <LogOut className="w-5 h-5" />
                    </Button>
                )}
            </div>
        </aside>
    );
}

// Header Component
function Header({ title, subtitle }) {
    const [theme, setTheme] = useState('dark');

    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        setTheme(savedTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(savedTheme);
    }, []);

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(newTheme);
    };

    return (
        <header className="bg-background/80 backdrop-blur-md border-b border-border/40 sticky top-0 z-50 px-6 py-4 flex items-center justify-between" data-testid="header">
            <div>
                <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
                {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
            </div>
            <div className="flex items-center gap-4">
                <div className="relative hidden md:block">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input placeholder="Search targets, scans..." className="pl-9 w-64 bg-background" data-testid="header-search" />
                </div>
                <Button variant="ghost" size="icon" className="relative" data-testid="notifications-button">
                    <Bell className="w-5 h-5" />
                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full" />
                </Button>
                <Button variant="ghost" size="icon" onClick={toggleTheme} data-testid="theme-toggle">
                    {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                </Button>
            </div>
        </header>
    );
}

// Login Page
function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { login } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await login(email, password);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.detail || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4" style={{ backgroundImage: 'linear-gradient(to right, rgba(128, 128, 128, 0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(128, 128, 128, 0.07) 1px, transparent 1px)', backgroundSize: '24px 24px' }}>
            <div className="w-full max-w-md space-y-8">
                <div className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 bg-primary/10 border border-primary/20">
                            <Shield className="w-10 h-10 text-primary" />
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight">PentestAI</h1>
                    <p className="text-muted-foreground mt-2">AI-Enhanced Penetration Testing Platform</p>
                </div>
                <Card className="border-border/40 bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                        <CardTitle className="text-xl">Sign In</CardTitle>
                        <CardDescription>Enter your credentials to access the platform</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            {error && (
                                <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-sm" data-testid="login-error">
                                    <AlertCircle className="w-4 h-4" />
                                    {error}
                                </div>
                            )}
                            <div className="space-y-2">
                                <Label htmlFor="email">Email</Label>
                                <Input id="email" type="email" placeholder="admin@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-background" data-testid="login-email-input" />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input id="password" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required className="bg-background" data-testid="login-password-input" />
                            </div>
                            <Button type="submit" className="w-full" disabled={loading} data-testid="login-submit-button">
                                {loading ? 'Signing in...' : 'Sign In'}
                            </Button>
                        </form>
                        <div className="mt-6 text-center text-sm">
                            <span className="text-muted-foreground">Don't have an account? </span>
                            <Link to="/register" className="text-primary hover:underline" data-testid="register-link">Create one</Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

// Register Page
function RegisterPage() {
    const [email, setEmail] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { register } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        if (password.length < 6) {
            setError('Password must be at least 6 characters');
            return;
        }
        setLoading(true);
        try {
            await register(email, password, username);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.detail || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4" style={{ backgroundImage: 'linear-gradient(to right, rgba(128, 128, 128, 0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(128, 128, 128, 0.07) 1px, transparent 1px)', backgroundSize: '24px 24px' }}>
            <div className="w-full max-w-md space-y-8">
                <div className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 bg-primary/10 border border-primary/20">
                            <Shield className="w-10 h-10 text-primary" />
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight">PentestAI</h1>
                    <p className="text-muted-foreground mt-2">Create your account</p>
                </div>
                <Card className="border-border/40 bg-card/50 backdrop-blur-sm">
                    <CardHeader>
                        <CardTitle className="text-xl">Register</CardTitle>
                        <CardDescription>Start your journey in ethical hacking</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            {error && (
                                <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-sm" data-testid="register-error">
                                    <AlertCircle className="w-4 h-4" />
                                    {error}
                                </div>
                            )}
                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input id="username" type="text" placeholder="hackerman" value={username} onChange={(e) => setUsername(e.target.value)} required className="bg-background" data-testid="register-username-input" />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="email">Email</Label>
                                <Input id="email" type="email" placeholder="admin@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-background" data-testid="register-email-input" />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input id="password" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required className="bg-background" data-testid="register-password-input" />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="confirmPassword">Confirm Password</Label>
                                <Input id="confirmPassword" type="password" placeholder="••••••••" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required className="bg-background" data-testid="register-confirm-password-input" />
                            </div>
                            <Button type="submit" className="w-full" disabled={loading} data-testid="register-submit-button">
                                {loading ? 'Creating account...' : 'Create Account'}
                            </Button>
                        </form>
                        <div className="mt-6 text-center text-sm">
                            <span className="text-muted-foreground">Already have an account? </span>
                            <Link to="/login" className="text-primary hover:underline" data-testid="login-link">Sign in</Link>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

// Dashboard Page
function DashboardPage() {
    const [stats, setStats] = useState({ total_scans: 0, active_scans: 0, vulnerabilities_found: 0, critical_alerts: 0, recent_activity: [] });
    const [trends, setTrends] = useState([]);

    useEffect(() => {
        fetchDashboardData();
    }, []);

    const fetchDashboardData = async () => {
        try {
            const [statsRes, trendsRes] = await Promise.all([
                axios.get(`${API_URL}/api/dashboard/stats`),
                axios.get(`${API_URL}/api/dashboard/vulnerability-trends`)
            ]);
            setStats(statsRes.data);
            setTrends(trendsRes.data.trends);
        } catch (error) {
            console.error('Failed to fetch dashboard data:', error);
        }
    };

    const metricCards = [
        { title: 'Total Scans', value: stats.total_scans, icon: Target, color: 'text-blue-400', bgColor: 'bg-blue-400/10', borderColor: 'border-l-blue-400' },
        { title: 'Active Scans', value: stats.active_scans, icon: Activity, color: 'text-green-400', bgColor: 'bg-green-400/10', borderColor: 'border-l-green-400' },
        { title: 'Vulnerabilities', value: stats.vulnerabilities_found, icon: Bug, color: 'text-yellow-400', bgColor: 'bg-yellow-400/10', borderColor: 'border-l-yellow-400' },
        { title: 'Critical Alerts', value: stats.critical_alerts, icon: AlertTriangle, color: 'text-red-400', bgColor: 'bg-red-400/10', borderColor: 'border-l-red-400' },
    ];

    return (
        <div className="flex-1 flex flex-col" data-testid="dashboard-page">
            <Header title="Dashboard" subtitle="Security Operations Overview" />
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {metricCards.map((metric, index) => {
                        const Icon = metric.icon;
                        return (
                            <Card key={index} className={`border-l-2 ${metric.borderColor} bg-card/20 hover:bg-card/40 transition-colors`} data-testid={`metric-${metric.title.toLowerCase().replace(' ', '-')}`}>
                                <CardContent className="p-6">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm text-muted-foreground">{metric.title}</p>
                                            <p className="text-3xl font-bold mt-1">{metric.value}</p>
                                        </div>
                                        <div className={`p-3 ${metric.bgColor}`}>
                                            <Icon className={`w-6 h-6 ${metric.color}`} />
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        );
                    })}
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <Card className="border-border/40 bg-card/20" data-testid="quick-actions">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Quick Actions</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/recon"><Target className="w-4 h-4" />New Reconnaissance Scan</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/vulnerabilities"><Bug className="w-4 h-4" />Vulnerability Assessment</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/assistant"><Shield className="w-4 h-4" />Ask AI Assistant</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/reports"><Activity className="w-4 h-4" />Generate Report</Link>
                            </Button>
                        </CardContent>
                    </Card>
                    <Card className="lg:col-span-2 border-border/40 bg-card/20" data-testid="recent-activity">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Recent Activity</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                {stats.recent_activity.length > 0 ? stats.recent_activity.map((activity, index) => (
                                    <div key={index} className="flex items-center gap-4 p-3 bg-background/50 border border-border/20">
                                        <div className="p-2 bg-primary/10"><Activity className="w-4 h-4 text-primary" /></div>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium truncate">{activity.action}</p>
                                            <p className="text-xs text-muted-foreground">{activity.target}</p>
                                        </div>
                                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                            <Clock className="w-3 h-3" />{new Date(activity.created_at).toLocaleTimeString()}
                                        </div>
                                    </div>
                                )) : (
                                    <div className="text-center py-8 text-muted-foreground">
                                        <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                        <p>No recent activity</p>
                                        <p className="text-sm">Start a scan to see activity here</p>
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

// AI Assistant Page
function AssistantPage() {
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

// Recon Page
function ReconPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);

    useEffect(() => { fetchScans(); }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'recon'));
        } catch (error) { console.error('Failed to fetch scans:', error); }
    };

    const startScan = async () => {
        if (!target.trim()) { toast.error('Please enter a target'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, { scan_type: 'recon', target: target.trim(), options: {} });
            toast.success('Scan completed successfully');
            setScans(prev => [response.data, ...prev]);
            setSelectedScan(response.data);
            setTarget('');
        } catch (error) { toast.error('Scan failed'); } 
        finally { setLoading(false); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="recon-page">
            <Header title="Reconnaissance" subtitle="Target discovery and information gathering" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                <div className="space-y-4">
                    <Card className="border-border/40 bg-card/20" data-testid="new-scan-card">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Search className="w-5 h-5 text-primary" />New Scan</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input placeholder="example.com or 192.168.1.1" value={target} onChange={(e) => setTarget(e.target.value)} className="bg-background" data-testid="scan-target-input" />
                            </div>
                            <Button className="w-full" onClick={startScan} disabled={loading || !target.trim()} data-testid="start-scan-button">
                                {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : <><Play className="w-4 h-4 mr-2" />Start Scan</>}
                            </Button>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="scan-history">
                        <CardHeader><CardTitle className="text-lg">Scan History</CardTitle></CardHeader>
                        <CardContent className="p-0">
                            <ScrollArea className="h-64">
                                <div className="p-4 space-y-2">
                                    {scans.length > 0 ? scans.map((scan) => (
                                        <button key={scan.id} onClick={() => setSelectedScan(scan)} className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${selectedScan?.id === scan.id ? 'bg-accent' : ''}`} data-testid={`scan-item-${scan.id}`}>
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-2"><Globe className="w-4 h-4 text-muted-foreground" /><span className="font-medium text-sm truncate max-w-32">{scan.target}</span></div>
                                                <ChevronRight className="w-4 h-4 text-muted-foreground" />
                                            </div>
                                            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground"><Clock className="w-3 h-3" />{new Date(scan.created_at).toLocaleString()}</div>
                                        </button>
                                    )) : <div className="text-center py-8 text-muted-foreground"><Search className="w-8 h-8 mx-auto mb-2 opacity-50" /><p className="text-sm">No scans yet</p></div>}
                                </div>
                            </ScrollArea>
                        </CardContent>
                    </Card>
                </div>
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="scan-results">
                        <CardHeader><CardTitle className="text-lg">{selectedScan ? `Results: ${selectedScan.target}` : 'Scan Results'}</CardTitle></CardHeader>
                        <CardContent className="flex-1 overflow-auto">
                            {selectedScan?.results ? (
                                <div className="space-y-6">
                                    {selectedScan.results.ports && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Server className="w-4 h-4 text-primary" />Open Ports</h3>
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                {selectedScan.results.ports.map((port, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20 flex items-center justify-between">
                                                        <div><span className="font-mono text-sm text-primary">{port.port}</span><span className="text-muted-foreground text-sm ml-2">/ {port.service}</span></div>
                                                        <Badge variant="outline" className={port.state === 'open' ? 'border-green-500/30 text-green-400' : 'border-yellow-500/30 text-yellow-400'}>{port.state}</Badge>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    {selectedScan.results.vulnerabilities && selectedScan.results.vulnerabilities.length > 0 && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-500" />Vulnerabilities</h3>
                                            <div className="space-y-2">
                                                {selectedScan.results.vulnerabilities.map((vuln, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-mono text-sm text-primary">{vuln.id}</span>
                                                            <Badge className={`bg-${vuln.severity === 'critical' ? 'red' : vuln.severity === 'high' ? 'orange' : 'yellow'}-500/20 text-${vuln.severity === 'critical' ? 'red' : vuln.severity === 'high' ? 'orange' : 'yellow'}-400`}>{vuln.severity?.toUpperCase()}</Badge>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ) : <div className="h-full flex items-center justify-center text-muted-foreground"><div className="text-center"><Search className="w-12 h-12 mx-auto mb-4 opacity-30" /><p>Select a scan or start a new one</p></div></div>}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

// Vulnerabilities Page
function VulnerabilitiesPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);

    useEffect(() => { fetchScans(); }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'vuln'));
        } catch (error) { console.error('Failed to fetch scans:', error); }
    };

    const startScan = async () => {
        if (!target.trim()) { toast.error('Please enter a target'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, { scan_type: 'vuln', target: target.trim(), options: {} });
            toast.success('Vulnerability scan completed');
            setScans(prev => [response.data, ...prev]);
            setSelectedScan(response.data);
            setTarget('');
        } catch (error) { toast.error('Scan failed'); } 
        finally { setLoading(false); }
    };

    const vulnerabilities = selectedScan?.results?.vulnerabilities || [];

    return (
        <div className="flex-1 flex flex-col" data-testid="vulnerabilities-page">
            <Header title="Vulnerability Assessment" subtitle="Identify and analyze security vulnerabilities" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                <div className="space-y-4">
                    <Card className="border-border/40 bg-card/20" data-testid="vuln-scan-card">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Bug className="w-5 h-5 text-primary" />Vulnerability Scan</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input placeholder="example.com or IP" value={target} onChange={(e) => setTarget(e.target.value)} className="bg-background" data-testid="vuln-target-input" />
                            </div>
                            <Button className="w-full" onClick={startScan} disabled={loading || !target.trim()} data-testid="start-vuln-scan-button">
                                {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : <><Play className="w-4 h-4 mr-2" />Start Assessment</>}
                            </Button>
                        </CardContent>
                    </Card>
                </div>
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="vuln-results">
                        <CardHeader><CardTitle className="text-lg">{selectedScan ? `Vulnerabilities: ${selectedScan.target}` : 'Assessment Results'}</CardTitle></CardHeader>
                        <CardContent className="flex-1 overflow-auto">
                            {vulnerabilities.length > 0 ? (
                                <div className="space-y-3">
                                    {vulnerabilities.map((vuln, i) => (
                                        <div key={i} className="p-4 bg-background/50 border border-border/20 space-y-3" data-testid={`vulnerability-${i}`}>
                                            <div className="flex items-start justify-between">
                                                <span className="font-mono text-sm font-medium">{vuln.id}</span>
                                                <Badge>{vuln.severity?.toUpperCase()}</Badge>
                                            </div>
                                            <p className="text-sm">{vuln.description}</p>
                                            {vuln.remediation && <div className="p-2 bg-green-500/10 border border-green-500/20 text-sm"><span className="text-green-400 font-medium">Remediation: </span>{vuln.remediation}</div>}
                                        </div>
                                    ))}
                                </div>
                            ) : <div className="h-full flex items-center justify-center text-muted-foreground"><Bug className="w-12 h-12 mx-auto mb-4 opacity-30" /><p>Start a vulnerability assessment</p></div>}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

// Network Page
function NetworkPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);

    useEffect(() => { fetchScans(); }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'network'));
        } catch (error) { console.error('Failed to fetch scans:', error); }
    };

    const startScan = async () => {
        if (!target.trim()) { toast.error('Please enter a target'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, { scan_type: 'network', target: target.trim(), options: {} });
            toast.success('Network analysis completed');
            setScans(prev => [response.data, ...prev]);
            setSelectedScan(response.data);
            setTarget('');
        } catch (error) { toast.error('Analysis failed'); } 
        finally { setLoading(false); }
    };

    const results = selectedScan?.results;

    return (
        <div className="flex-1 flex flex-col" data-testid="network-page">
            <Header title="Network Analysis" subtitle="Traffic inspection and anomaly detection" />
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                <Card className="border-border/40 bg-card/20" data-testid="network-scan-card">
                    <CardContent className="p-6">
                        <div className="flex flex-col md:flex-row gap-4">
                            <div className="flex-1 space-y-2">
                                <Label>Network/IP Range</Label>
                                <Input placeholder="192.168.1.0/24" value={target} onChange={(e) => setTarget(e.target.value)} className="bg-background" data-testid="network-target-input" />
                            </div>
                            <div className="flex items-end">
                                <Button onClick={startScan} disabled={loading || !target.trim()} data-testid="start-network-scan-button">
                                    {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing...</> : <><Play className="w-4 h-4 mr-2" />Start Analysis</>}
                                </Button>
                            </div>
                        </div>
                    </CardContent>
                </Card>
                {results && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <Card className="border-border/40 bg-card/20" data-testid="traffic-summary">
                            <CardHeader><CardTitle className="text-lg">Traffic Summary</CardTitle></CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    <div className="p-3 bg-background/50 border border-border/20">
                                        <p className="text-sm text-muted-foreground">Total Packets</p>
                                        <p className="text-2xl font-bold">{results.traffic_summary?.total_packets?.toLocaleString()}</p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                        <Card className="border-border/40 bg-card/20" data-testid="anomalies-card">
                            <CardHeader><CardTitle className="text-lg">Anomalies Detected</CardTitle></CardHeader>
                            <CardContent>
                                {results.anomalies?.length > 0 ? (
                                    <div className="space-y-2">
                                        {results.anomalies.map((anomaly, i) => (
                                            <div key={i} className="p-3 bg-background/50 border border-border/20">
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="text-sm font-medium">{anomaly.type}</span>
                                                    <Badge>{anomaly.severity}</Badge>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ) : <p className="text-muted-foreground text-sm">No anomalies detected</p>}
                            </CardContent>
                        </Card>
                    </div>
                )}
            </div>
        </div>
    );
}

// Terminal Page
function TerminalPage() {
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

// Reports Page
function ReportsPage() {
    const [scans, setScans] = useState([]);
    const [selectedScans, setSelectedScans] = useState([]);
    const [reports, setReports] = useState([]);
    const [generatingReport, setGeneratingReport] = useState(false);

    useEffect(() => { fetchData(); }, []);

    const fetchData = async () => {
        try {
            const [scansRes, reportsRes] = await Promise.all([axios.get(`${API_URL}/api/scans`), axios.get(`${API_URL}/api/reports`)]);
            setScans(scansRes.data);
            setReports(reportsRes.data.reports || []);
        } catch (error) { console.error('Failed to fetch data:', error); }
    };

    const toggleScanSelection = (scanId) => {
        setSelectedScans(prev => prev.includes(scanId) ? prev.filter(id => id !== scanId) : [...prev, scanId]);
    };

    const generateReport = async () => {
        if (selectedScans.length === 0) { toast.error('Please select at least one scan'); return; }
        setGeneratingReport(true);
        try {
            const response = await axios.post(`${API_URL}/api/reports/generate`, selectedScans);
            toast.success('Report generated successfully');
            setReports(prev => [response.data, ...prev]);
            setSelectedScans([]);
        } catch (error) { toast.error('Failed to generate report'); } 
        finally { setGeneratingReport(false); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="reports-page">
            <Header title="Reports" subtitle="Generate and manage security reports" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="scans-selection">
                    <CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-lg">Select Scans</CardTitle><Badge variant="outline">{selectedScans.length} selected</Badge></CardHeader>
                    <CardContent className="flex-1 overflow-hidden flex flex-col">
                        <ScrollArea className="flex-1">
                            <div className="space-y-2 pr-4">
                                {scans.map((scan) => (
                                    <div key={scan.id} className={`p-4 border border-border/40 cursor-pointer transition-colors ${selectedScans.includes(scan.id) ? 'bg-accent border-primary/50' : 'hover:bg-accent/50'}`} onClick={() => toggleScanSelection(scan.id)} data-testid={`scan-select-${scan.id}`}>
                                        <div className="flex items-start gap-3">
                                            <Checkbox checked={selectedScans.includes(scan.id)} />
                                            <div className="flex-1"><span className="font-medium text-sm">{scan.target}</span><p className="text-xs text-muted-foreground">{scan.scan_type} - {new Date(scan.created_at).toLocaleDateString()}</p></div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </ScrollArea>
                        <div className="pt-4 border-t border-border/40 mt-4">
                            <Button className="w-full" onClick={generateReport} disabled={selectedScans.length === 0 || generatingReport} data-testid="generate-report-button">
                                {generatingReport ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Generating...</> : <><FileText className="w-4 h-4 mr-2" />Generate Report</>}
                            </Button>
                        </div>
                    </CardContent>
                </Card>
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="reports-list">
                    <CardHeader><CardTitle className="text-lg">Generated Reports</CardTitle></CardHeader>
                    <CardContent className="flex-1 overflow-hidden">
                        <ScrollArea className="h-full">
                            <div className="space-y-4 pr-4">
                                {reports.map((report) => (
                                    <Card key={report.id} className="border-border/40 bg-background/50" data-testid={`report-${report.id}`}>
                                        <CardContent className="p-4">
                                            <h3 className="font-medium text-sm">{report.title}</h3>
                                            <p className="text-xs text-muted-foreground">{new Date(report.created_at).toLocaleString()}</p>
                                            <div className="grid grid-cols-4 gap-2 mt-3">
                                                <div className="p-2 bg-red-500/10 text-center"><p className="text-lg font-bold text-red-400">{report.summary?.critical || 0}</p><p className="text-xs">Critical</p></div>
                                                <div className="p-2 bg-orange-500/10 text-center"><p className="text-lg font-bold text-orange-400">{report.summary?.high || 0}</p><p className="text-xs">High</p></div>
                                                <div className="p-2 bg-yellow-500/10 text-center"><p className="text-lg font-bold text-yellow-400">{report.summary?.medium || 0}</p><p className="text-xs">Medium</p></div>
                                                <div className="p-2 bg-green-500/10 text-center"><p className="text-lg font-bold text-green-400">{report.summary?.low || 0}</p><p className="text-xs">Low</p></div>
                                            </div>
                                        </CardContent>
                                    </Card>
                                ))}
                            </div>
                        </ScrollArea>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

// Settings Page
function SettingsPage() {
    const { user } = useAuth();
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(newTheme);
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="settings-page">
            <Header title="Settings" subtitle="Manage your preferences and account" />
            <div className="flex-1 p-6 overflow-auto">
                <div className="max-w-3xl mx-auto space-y-6">
                    <Card className="border-border/40 bg-card/20" data-testid="appearance-settings">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Palette className="w-5 h-5 text-primary" />Appearance</CardTitle></CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div><Label>Theme</Label><p className="text-sm text-muted-foreground">Switch between dark and light mode</p></div>
                                <div className="flex items-center gap-2">
                                    <Sun className="w-4 h-4 text-muted-foreground" />
                                    <Switch checked={theme === 'dark'} onCheckedChange={toggleTheme} data-testid="theme-switch" />
                                    <Moon className="w-4 h-4 text-muted-foreground" />
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="account-settings">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Shield className="w-5 h-5 text-primary" />Account</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2"><Label>Username</Label><Input value={user?.username || ''} disabled className="bg-background" /></div>
                                <div className="space-y-2"><Label>Email</Label><Input value={user?.email || ''} disabled className="bg-background" /></div>
                            </div>
                            <div className="space-y-2"><Label>Role</Label><Input value={user?.role || 'tester'} disabled className="bg-background capitalize" /></div>
                        </CardContent>
                    </Card>
                    <div className="flex justify-end"><Button onClick={() => toast.success('Settings saved')} data-testid="save-settings-button">Save Settings</Button></div>
                </div>
            </div>
        </div>
    );
}

// Protected Route
function ProtectedRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    if (loading) return <div className="min-h-screen flex items-center justify-center bg-background"><div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
    return isAuthenticated ? children : <Navigate to="/login" replace />;
}

// Public Route
function PublicRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    if (loading) return null;
    return isAuthenticated ? <Navigate to="/dashboard" replace /> : children;
}

// Main Layout
function MainLayout({ children }) {
    return (
        <div className="flex min-h-screen bg-background" data-testid="main-layout">
            <Sidebar />
            <main className="flex-1 flex flex-col overflow-hidden">{children}</main>
        </div>
    );
}

// App Routes
function AppRoutes() {
    return (
        <Routes>
            <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
            <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
            <Route path="/dashboard" element={<ProtectedRoute><MainLayout><DashboardPage /></MainLayout></ProtectedRoute>} />
            <Route path="/recon" element={<ProtectedRoute><MainLayout><ReconPage /></MainLayout></ProtectedRoute>} />
            <Route path="/vulnerabilities" element={<ProtectedRoute><MainLayout><VulnerabilitiesPage /></MainLayout></ProtectedRoute>} />
            <Route path="/network" element={<ProtectedRoute><MainLayout><NetworkPage /></MainLayout></ProtectedRoute>} />
            <Route path="/assistant" element={<ProtectedRoute><MainLayout><AssistantPage /></MainLayout></ProtectedRoute>} />
            <Route path="/terminal" element={<ProtectedRoute><MainLayout><TerminalPage /></MainLayout></ProtectedRoute>} />
            <Route path="/reports" element={<ProtectedRoute><MainLayout><ReportsPage /></MainLayout></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><MainLayout><SettingsPage /></MainLayout></ProtectedRoute>} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
    );
}

// App Component
function App() {
    return (
        <BrowserRouter>
            <AuthProvider>
                <AppRoutes />
                <Toaster position="bottom-right" richColors />
            </AuthProvider>
        </BrowserRouter>
    );
}

export default App;

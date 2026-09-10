import { useState, useEffect, useCallback, useRef } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate } from 'react-router-dom';
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
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from './components/ui/dialog';
import { Textarea } from './components/ui/textarea';
import { 
    Shield, Search, Bug, Network, MessageSquare, FileText, Terminal, 
    AlertCircle, AlertTriangle, Target, Activity, ArrowUpRight, Clock,
    Send, Bot, User, Loader2, Sparkles, Copy, Check, Globe, Server, Wifi,
    Play, FileWarning, CheckCircle, XCircle, Download, Calendar, Lightbulb, X,
    Palette, Key, Layers, Timer, ExternalLink, Info, Trash2, RefreshCw, Plus, FileDown
} from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { MainLayout, Header } from './components/layout';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { API_URL } from './lib/api';
import './App.css';

// Protected Route wrapper
function ProtectedRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    if (loading) return <div className="min-h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
    return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function PublicRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    if (loading) return <div className="min-h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
    return !isAuthenticated ? children : <Navigate to="/dashboard" replace />;
}

// Dashboard Page
function DashboardPage() {
    const [stats, setStats] = useState({ total_scans: 0, active_scans: 0, vulnerabilities_found: 0, critical_alerts: 0, recent_activity: [] });

    useEffect(() => { fetchDashboardData(); }, []);

    const fetchDashboardData = async () => {
        try {
            const statsRes = await axios.get(`${API_URL}/api/dashboard/stats`);
            setStats(statsRes.data);
        } catch (error) { console.error('Failed to fetch dashboard data:', error); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="dashboard-page">
            <Header title="Dashboard" subtitle="Security Operations Overview" />
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <Card className="border-border/40 bg-card/20" data-testid="stat-total-scans">
                        <CardContent className="p-4"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Total Scans</p><p className="text-2xl font-bold">{stats.total_scans}</p></div><Target className="w-8 h-8 text-primary/50" /></div></CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="stat-active-scans">
                        <CardContent className="p-4"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Active Scans</p><p className="text-2xl font-bold">{stats.active_scans}</p></div><Activity className="w-8 h-8 text-green-500/50" /></div></CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="stat-vulnerabilities">
                        <CardContent className="p-4"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Vulnerabilities</p><p className="text-2xl font-bold">{stats.vulnerabilities_found}</p></div><Bug className="w-8 h-8 text-yellow-500/50" /></div></CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="stat-critical">
                        <CardContent className="p-4"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Critical Alerts</p><p className="text-2xl font-bold text-red-500">{stats.critical_alerts}</p></div><AlertTriangle className="w-8 h-8 text-red-500/50" /></div></CardContent>
                    </Card>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <Card className="lg:col-span-2 border-border/40 bg-card/20">
                        <CardHeader><CardTitle>Quick Actions</CardTitle></CardHeader>
                        <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <Link to="/recon"><Button variant="outline" className="w-full h-20 flex-col gap-2"><Search className="w-6 h-6" /><span>New Recon</span></Button></Link>
                            <Link to="/bulk-scan"><Button variant="outline" className="w-full h-20 flex-col gap-2"><Layers className="w-6 h-6" /><span>Bulk Scan</span></Button></Link>
                            <Link to="/assistant"><Button variant="outline" className="w-full h-20 flex-col gap-2"><MessageSquare className="w-6 h-6" /><span>AI Assistant</span></Button></Link>
                            <Link to="/reports"><Button variant="outline" className="w-full h-20 flex-col gap-2"><FileText className="w-6 h-6" /><span>Reports</span></Button></Link>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20">
                        <CardHeader><CardTitle>Recent Activity</CardTitle></CardHeader>
                        <CardContent className="space-y-3">
                            {stats.recent_activity?.slice(0, 5).map((activity, i) => (
                                <div key={i} className="flex items-start gap-3 p-2 bg-background/30 border border-border/20">
                                    <Activity className="w-4 h-4 text-primary mt-0.5" />
                                    <div className="flex-1 min-w-0"><p className="text-sm truncate">{activity.action}</p><p className="text-xs text-muted-foreground">{activity.target}</p></div>
                                </div>
                            ))}
                            {!stats.recent_activity?.length && <p className="text-sm text-muted-foreground text-center py-4">No recent activity</p>}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

// Recon Page with Export
function ReconPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);
    const [cveModalOpen, setCveModalOpen] = useState(false);
    const [selectedCve, setSelectedCve] = useState(null);
    const [cveLoading, setCveLoading] = useState(false);
    const [cveData, setCveData] = useState(null);

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

    const fetchCveDetails = async (cveId) => {
        if (!cveId.startsWith('CVE-')) return;
        setSelectedCve(cveId);
        setCveModalOpen(true);
        setCveLoading(true);
        setCveData(null);
        try {
            const response = await axios.get(`${API_URL}/api/cve/${cveId}`);
            setCveData(response.data);
        } catch (error) {
            toast.error('Failed to fetch CVE details');
            setCveData({ error: error.response?.data?.detail || 'Failed to fetch CVE details' });
        } finally { setCveLoading(false); }
    };

    const exportScan = async (scanId, format) => {
        try {
            const response = await axios.get(`${API_URL}/api/scans/${scanId}/export?format=${format}`, {
                responseType: 'blob'
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `scan_${scanId.slice(0, 8)}.${format}`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
            toast.success(`Exported as ${format.toUpperCase()}`);
        } catch (error) { toast.error('Export failed'); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="recon-page">
            <Header title="Reconnaissance" subtitle="Network discovery and enumeration" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                <div className="space-y-4">
                    <Card className="border-border/40 bg-card/20">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Target className="w-5 h-5 text-primary" />New Scan</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input placeholder="example.com or 192.168.1.1" value={target} onChange={(e) => setTarget(e.target.value)} className="bg-background" data-testid="recon-target-input" />
                            </div>
                            <Button className="w-full" onClick={startScan} disabled={loading} data-testid="start-scan-button">
                                {loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : <><Play className="w-4 h-4 mr-2" />Start Scan</>}
                            </Button>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20">
                        <CardHeader><CardTitle className="text-lg">Scan History</CardTitle></CardHeader>
                        <CardContent className="p-0"><ScrollArea className="h-64">
                            <div className="p-4 space-y-2">
                                {scans.map((scan) => (
                                    <button key={scan.id} onClick={() => setSelectedScan(scan)} className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${selectedScan?.id === scan.id ? 'bg-accent' : ''}`} data-testid={`scan-item-${scan.id}`}>
                                        <div className="flex items-center justify-between"><span className="font-medium text-sm truncate">{scan.target}</span><Badge variant="outline" className="border-green-500/30 text-green-400">{scan.status}</Badge></div>
                                        <p className="text-xs text-muted-foreground mt-1">{new Date(scan.created_at).toLocaleString()}</p>
                                    </button>
                                ))}
                            </div>
                        </ScrollArea></CardContent>
                    </Card>
                </div>

                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="scan-results">
                        <CardHeader className="flex flex-row items-center justify-between">
                            <CardTitle className="text-lg">{selectedScan ? `Results: ${selectedScan.target}` : 'Scan Results'}</CardTitle>
                            {selectedScan && (
                                <div className="flex gap-2">
                                    <Button variant="outline" size="sm" onClick={() => exportScan(selectedScan.id, 'csv')} data-testid="export-csv"><FileDown className="w-4 h-4 mr-1" />CSV</Button>
                                    <Button variant="outline" size="sm" onClick={() => exportScan(selectedScan.id, 'json')} data-testid="export-json"><FileDown className="w-4 h-4 mr-1" />JSON</Button>
                                </div>
                            )}
                        </CardHeader>
                        <CardContent className="flex-1 overflow-auto" data-testid="scan-results-content">
                            {selectedScan?.results ? (
                                <div className="space-y-6">
                                    {/* Target Info */}
                                    {(selectedScan.results.ip_address || selectedScan.results.os_detection) && (
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            {selectedScan.results.ip_address && (
                                                <div className="p-3 bg-background/50 border border-border/20">
                                                    <p className="text-xs text-muted-foreground uppercase mb-1">IP Address</p>
                                                    <p className="font-mono text-sm text-primary">{selectedScan.results.ip_address}</p>
                                                </div>
                                            )}
                                            {selectedScan.results.os_detection && (
                                                <div className="p-3 bg-background/50 border border-border/20">
                                                    <p className="text-xs text-muted-foreground uppercase mb-1">OS Detection</p>
                                                    <p className="text-sm">{selectedScan.results.os_detection}</p>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Open Ports */}
                                    {selectedScan.results.ports && selectedScan.results.ports.length > 0 && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Server className="w-4 h-4 text-primary" />Open Ports ({selectedScan.results.ports.length})</h3>
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

                                    {/* Shodan Intelligence */}
                                    {selectedScan.results.shodan && !selectedScan.results.shodan.error && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Wifi className="w-4 h-4 text-cyan-400" />Shodan Intelligence<Badge variant="outline" className="ml-2 border-cyan-500/30 text-cyan-400 text-xs">OSINT</Badge></h3>
                                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 mb-4">
                                                {selectedScan.results.shodan.organization && <div className="p-3 bg-cyan-500/5 border border-cyan-500/20"><p className="text-xs text-muted-foreground mb-1">Organization</p><p className="text-sm font-medium">{selectedScan.results.shodan.organization}</p></div>}
                                                {selectedScan.results.shodan.isp && <div className="p-3 bg-cyan-500/5 border border-cyan-500/20"><p className="text-xs text-muted-foreground mb-1">ISP</p><p className="text-sm">{selectedScan.results.shodan.isp}</p></div>}
                                                {selectedScan.results.shodan.asn && <div className="p-3 bg-cyan-500/5 border border-cyan-500/20"><p className="text-xs text-muted-foreground mb-1">ASN</p><p className="text-sm font-mono">{selectedScan.results.shodan.asn}</p></div>}
                                                {selectedScan.results.shodan.country && <div className="p-3 bg-cyan-500/5 border border-cyan-500/20"><p className="text-xs text-muted-foreground mb-1">Location</p><p className="text-sm">{selectedScan.results.shodan.city ? `${selectedScan.results.shodan.city}, ` : ''}{selectedScan.results.shodan.country}</p></div>}
                                            </div>
                                        </div>
                                    )}

                                    {/* Vulnerabilities */}
                                    {selectedScan.results.vulnerabilities && selectedScan.results.vulnerabilities.length > 0 && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-500" />Vulnerabilities ({selectedScan.results.vulnerabilities.length})</h3>
                                            <div className="space-y-2">
                                                {selectedScan.results.vulnerabilities.slice(0, 20).map((vuln, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20 hover:bg-background/70 transition-colors">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <div className="flex items-center gap-2">
                                                                {vuln.id.startsWith('CVE-') ? (
                                                                    <button onClick={() => fetchCveDetails(vuln.id)} className="font-mono text-sm text-primary hover:underline flex items-center gap-1" data-testid={`cve-link-${vuln.id}`}>{vuln.id}<Info className="w-3 h-3" /></button>
                                                                ) : (<span className="font-mono text-sm text-primary">{vuln.id}</span>)}
                                                                {vuln.source === 'shodan' && <Badge variant="outline" className="text-xs border-cyan-500/30 text-cyan-400">Shodan</Badge>}
                                                            </div>
                                                            <div className="flex items-center gap-2">
                                                                {vuln.cvss && <span className="text-xs text-muted-foreground">CVSS: {vuln.cvss}</span>}
                                                                <Badge className={vuln.severity === 'critical' ? 'bg-red-500/20 text-red-400' : vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-400' : vuln.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'}>{vuln.severity?.toUpperCase()}</Badge>
                                                            </div>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                                        {vuln.remediation && <p className="text-xs text-green-400 mt-2">Fix: {vuln.remediation}</p>}
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

            {/* CVE Details Modal */}
            <Dialog open={cveModalOpen} onOpenChange={setCveModalOpen}>
                <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2"><Bug className="w-5 h-5 text-red-500" />{selectedCve}</DialogTitle>
                        <DialogDescription>Vulnerability details from National Vulnerability Database</DialogDescription>
                    </DialogHeader>
                    {cveLoading ? (
                        <div className="flex items-center justify-center py-8"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>
                    ) : cveData?.error ? (
                        <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400">{cveData.error}</div>
                    ) : cveData ? (
                        <div className="space-y-4">
                            <div className="flex items-center gap-4">
                                <Badge className={cveData.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 text-lg px-3 py-1' : cveData.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 text-lg px-3 py-1' : cveData.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 text-lg px-3 py-1' : 'bg-green-500/20 text-green-400 text-lg px-3 py-1'}>{cveData.severity}</Badge>
                                {cveData.score && <span className="text-2xl font-bold">{cveData.score}</span>}
                            </div>
                            <div><h4 className="text-sm font-semibold mb-2">Description</h4><p className="text-sm text-muted-foreground">{cveData.description}</p></div>
                            {cveData.affected_products && cveData.affected_products.length > 0 && (
                                <div><h4 className="text-sm font-semibold mb-2">Affected Products ({cveData.affected_products.length})</h4>
                                    <div className="space-y-1 max-h-32 overflow-y-auto">
                                        {cveData.affected_products.slice(0, 10).map((product, i) => (
                                            <div key={i} className="text-xs p-2 bg-background/50 border border-border/20"><span className="font-medium">{product.vendor}</span> / <span>{product.product}</span></div>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {cveData.references && cveData.references.length > 0 && (
                                <div><h4 className="text-sm font-semibold mb-2">References</h4>
                                    <div className="space-y-1 max-h-32 overflow-y-auto">
                                        {cveData.references.slice(0, 5).map((ref, i) => (
                                            <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex items-center gap-1 truncate"><ExternalLink className="w-3 h-3 flex-shrink-0" />{ref.url}</a>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : null}
                </DialogContent>
            </Dialog>
        </div>
    );
}

// Bulk Scan Page
function BulkScanPage() {
    const [targets, setTargets] = useState('');
    const [cidr, setCidr] = useState('');
    const [scanType, setScanType] = useState('recon');
    const [loading, setLoading] = useState(false);
    const [bulkScans, setBulkScans] = useState([]);
    const [selectedBulkScan, setSelectedBulkScan] = useState(null);
    const [wsConnected, setWsConnected] = useState(false);
    const wsRef = useRef(null);

    useEffect(() => { fetchBulkScans(); return () => { if (wsRef.current) wsRef.current.close(); }; }, []);

    const connectWebSocket = useCallback((scanId) => {
        if (wsRef.current) wsRef.current.close();
        const wsUrl = API_URL.replace('https://', 'wss://').replace('http://', 'ws://');
        const ws = new WebSocket(`${wsUrl}/api/ws/scan/${scanId}`);
        ws.onopen = () => { setWsConnected(true); };
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'progress' || data.type === 'completed' || data.type === 'started') {
                setBulkScans(prev => prev.map(s => s.id === scanId ? { ...s, completed: data.completed, failed: data.failed, status: data.status, results: data.type === 'progress' && s.results ? [...s.results.filter(r => r.target !== data.result?.target), data.result].filter(Boolean) : s.results } : s));
                setSelectedBulkScan(prev => prev?.id === scanId ? { ...prev, completed: data.completed, failed: data.failed, status: data.status, results: data.type === 'progress' && prev.results ? [...prev.results.filter(r => r.target !== data.result?.target), data.result].filter(Boolean) : prev.results } : prev);
                if (data.type === 'completed') { toast.success('Bulk scan completed'); fetchBulkScans(); }
            }
        };
        ws.onclose = () => { setWsConnected(false); };
        wsRef.current = ws;
    }, []);

    const fetchBulkScans = async () => {
        try { const response = await axios.get(`${API_URL}/api/bulk-scans`); setBulkScans(response.data.bulk_scans || []); } catch (error) { console.error('Failed:', error); }
    };

    const startBulkScan = async () => {
        const targetList = targets.split('\n').map(t => t.trim()).filter(t => t);
        if (!targetList.length && !cidr.trim()) { toast.error('Please enter targets or CIDR range'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/bulk-scans`, { scan_type: scanType, targets: targetList, cidr: cidr.trim() || null });
            toast.success(`Bulk scan started for ${response.data.total_targets} targets`);
            const newScan = { ...response.data, results: [] };
            setBulkScans(prev => [newScan, ...prev]);
            setSelectedBulkScan(newScan);
            setTargets(''); setCidr('');
            connectWebSocket(response.data.id);
        } catch (error) { toast.error(error.response?.data?.detail || 'Failed to start bulk scan'); } finally { setLoading(false); }
    };

    const refreshBulkScan = async (id) => {
        try { const response = await axios.get(`${API_URL}/api/bulk-scans/${id}`); setBulkScans(prev => prev.map(s => s.id === id ? response.data : s)); if (selectedBulkScan?.id === id) setSelectedBulkScan(response.data); } catch (error) { console.error('Failed:', error); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="bulk-scan-page">
            <Header title="Bulk Scan" subtitle="Scan multiple targets or CIDR ranges at once" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                <div className="space-y-4">
                    <Card className="border-border/40 bg-card/20" data-testid="bulk-scan-form">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Layers className="w-5 h-5 text-primary" />New Bulk Scan</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2"><Label>Targets (one per line)</Label><Textarea placeholder="example.com&#10;192.168.1.1&#10;target.org" value={targets} onChange={(e) => setTargets(e.target.value)} className="bg-background min-h-24 font-mono text-sm" data-testid="bulk-targets-input" /></div>
                            <div className="space-y-2"><Label>Or CIDR Range</Label><Input placeholder="192.168.1.0/24" value={cidr} onChange={(e) => setCidr(e.target.value)} className="bg-background font-mono" data-testid="cidr-input" /><p className="text-xs text-muted-foreground">Max /24 (256 hosts)</p></div>
                            <div className="space-y-2"><Label>Scan Type</Label><Select value={scanType} onValueChange={setScanType}><SelectTrigger className="bg-background" data-testid="scan-type-select"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="recon">Reconnaissance</SelectItem><SelectItem value="vuln">Vulnerability</SelectItem></SelectContent></Select></div>
                            <Button className="w-full" onClick={startBulkScan} disabled={loading} data-testid="start-bulk-scan-button">{loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Starting...</> : <><Play className="w-4 h-4 mr-2" />Start Bulk Scan</>}</Button>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="bulk-scan-history">
                        <CardHeader><CardTitle className="text-lg">Bulk Scan History</CardTitle></CardHeader>
                        <CardContent className="p-0"><ScrollArea className="h-48"><div className="p-4 space-y-2">
                            {bulkScans.length > 0 ? bulkScans.map((scan) => (
                                <button key={scan.id} onClick={() => { setSelectedBulkScan(scan); refreshBulkScan(scan.id); }} className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${selectedBulkScan?.id === scan.id ? 'bg-accent' : ''}`} data-testid={`bulk-scan-${scan.id}`}>
                                    <div className="flex items-center justify-between"><span className="font-medium text-sm">{scan.total_targets} targets</span><Badge variant="outline" className={scan.status === 'completed' ? 'border-green-500/30 text-green-400' : scan.status === 'running' ? 'border-blue-500/30 text-blue-400' : 'border-yellow-500/30 text-yellow-400'}>{scan.status}</Badge></div>
                                    <div className="text-xs text-muted-foreground mt-1">{scan.scan_type} • {new Date(scan.created_at).toLocaleString()}</div>
                                    {scan.status === 'running' && <Progress value={(scan.completed / scan.total_targets) * 100} className="mt-2 h-1" />}
                                </button>
                            )) : <div className="text-center py-4 text-muted-foreground text-sm">No bulk scans yet</div>}
                        </div></ScrollArea></CardContent>
                    </Card>
                </div>
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="bulk-scan-results">
                        <CardHeader className="flex flex-row items-center justify-between">
                            <div className="flex items-center gap-3"><CardTitle className="text-lg">{selectedBulkScan ? `Results: ${selectedBulkScan.completed || 0}/${selectedBulkScan.total_targets} completed` : 'Bulk Scan Results'}</CardTitle>{wsConnected && selectedBulkScan?.status === 'running' && <Badge variant="outline" className="border-green-500/30 text-green-400 animate-pulse"><Wifi className="w-3 h-3 mr-1" /> Live</Badge>}</div>
                            {selectedBulkScan && <Button variant="outline" size="sm" onClick={() => refreshBulkScan(selectedBulkScan.id)} data-testid="refresh-bulk-scan"><RefreshCw className="w-4 h-4" /></Button>}
                        </CardHeader>
                        {selectedBulkScan?.status === 'running' && <div className="px-6 pb-2"><Progress value={(selectedBulkScan.completed / selectedBulkScan.total_targets) * 100} className="h-2" /><p className="text-xs text-muted-foreground mt-1 text-center">{Math.round((selectedBulkScan.completed / selectedBulkScan.total_targets) * 100)}% complete{selectedBulkScan.failed > 0 && ` • ${selectedBulkScan.failed} failed`}</p></div>}
                        <CardContent className="flex-1 overflow-auto">
                            {selectedBulkScan?.results && selectedBulkScan.results.length > 0 ? (
                                <div className="space-y-2">{selectedBulkScan.results.map((result, i) => (<div key={i} className="p-3 bg-background/50 border border-border/20 flex items-center justify-between animate-in fade-in duration-300"><div><span className="font-mono text-sm">{result.target}</span>{result.vulnerabilities_count > 0 && <Badge variant="outline" className="ml-2 text-xs">{result.vulnerabilities_count} vulns</Badge>}</div><Badge className={result.status === 'completed' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>{result.status}</Badge></div>))}</div>
                            ) : selectedBulkScan?.status === 'running' ? (<div className="h-full flex flex-col items-center justify-center text-muted-foreground"><Loader2 className="w-12 h-12 animate-spin mb-4 text-primary" /><p>Scanning in progress...</p><p className="text-sm">{selectedBulkScan.completed} of {selectedBulkScan.total_targets} completed</p></div>
                            ) : (<div className="h-full flex items-center justify-center text-muted-foreground"><div className="text-center"><Layers className="w-12 h-12 mx-auto mb-4 opacity-30" /><p>Select a bulk scan to view results</p></div></div>)}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

// Scheduled Scans Page
function ScheduledScansPage() {
    const [scheduledScans, setScheduledScans] = useState([]);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [formData, setFormData] = useState({ name: '', scan_type: 'recon', targets: '', schedule_type: 'daily', schedule_time: '09:00', schedule_day: 0 });
    const [loading, setLoading] = useState(false);

    useEffect(() => { fetchScheduledScans(); }, []);

    const fetchScheduledScans = async () => { try { const response = await axios.get(`${API_URL}/api/scheduled-scans`); setScheduledScans(response.data.scheduled_scans || []); } catch (error) { console.error('Failed:', error); } };

    const createScheduledScan = async () => {
        const targetList = formData.targets.split('\n').map(t => t.trim()).filter(t => t);
        if (!formData.name.trim() || !targetList.length) { toast.error('Please fill in name and targets'); return; }
        setLoading(true);
        try {
            await axios.post(`${API_URL}/api/scheduled-scans`, { name: formData.name.trim(), scan_type: formData.scan_type, targets: targetList, schedule_type: formData.schedule_type, schedule_time: formData.schedule_time, schedule_day: formData.schedule_type !== 'daily' ? parseInt(formData.schedule_day) : null });
            toast.success('Scheduled scan created'); setShowCreateModal(false); setFormData({ name: '', scan_type: 'recon', targets: '', schedule_type: 'daily', schedule_time: '09:00', schedule_day: 0 }); fetchScheduledScans();
        } catch (error) { toast.error(error.response?.data?.detail || 'Failed'); } finally { setLoading(false); }
    };

    const toggleSchedule = async (id, enabled) => { try { await axios.patch(`${API_URL}/api/scheduled-scans/${id}?enabled=${!enabled}`); fetchScheduledScans(); toast.success(enabled ? 'Schedule disabled' : 'Schedule enabled'); } catch (error) { toast.error('Failed'); } };
    const deleteSchedule = async (id) => { try { await axios.delete(`${API_URL}/api/scheduled-scans/${id}`); fetchScheduledScans(); toast.success('Schedule deleted'); } catch (error) { toast.error('Failed'); } };
    const runNow = async (id) => { try { await axios.post(`${API_URL}/api/scheduled-scans/${id}/run`); toast.success('Scan started'); } catch (error) { toast.error('Failed'); } };

    const dayNames = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

    return (
        <div className="flex-1 flex flex-col" data-testid="scheduled-scans-page">
            <Header title="Scheduled Scans" subtitle="Automate recurring security scans" />
            <div className="flex-1 p-6 overflow-auto">
                <div className="max-w-4xl mx-auto space-y-6">
                    <div className="flex justify-between items-center"><div><h2 className="text-xl font-semibold">Your Schedules</h2><p className="text-sm text-muted-foreground">{scheduledScans.length} scheduled scan{scheduledScans.length !== 1 ? 's' : ''}</p></div><Button onClick={() => setShowCreateModal(true)} data-testid="create-schedule-button"><Plus className="w-4 h-4 mr-2" />New Schedule</Button></div>
                    <div className="space-y-4">
                        {scheduledScans.length > 0 ? scheduledScans.map((schedule) => (
                            <Card key={schedule.id} className="border-border/40 bg-card/20" data-testid={`schedule-${schedule.id}`}>
                                <CardContent className="p-4">
                                    <div className="flex items-start justify-between">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2"><h3 className="font-semibold">{schedule.name}</h3><Badge variant="outline">{schedule.scan_type}</Badge><Badge className={schedule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}>{schedule.enabled ? 'Active' : 'Paused'}</Badge></div>
                                            <div className="text-sm text-muted-foreground space-y-1">
                                                <div className="flex items-center gap-2"><Timer className="w-4 h-4" />{schedule.schedule_type === 'daily' && `Daily at ${schedule.schedule_time}`}{schedule.schedule_type === 'weekly' && `Weekly on ${dayNames[schedule.schedule_day]} at ${schedule.schedule_time}`}{schedule.schedule_type === 'monthly' && `Monthly on day ${schedule.schedule_day} at ${schedule.schedule_time}`}</div>
                                                <div className="flex items-center gap-2"><Target className="w-4 h-4" />{schedule.targets.length} target{schedule.targets.length !== 1 ? 's' : ''}: {schedule.targets.slice(0, 3).join(', ')}{schedule.targets.length > 3 ? '...' : ''}</div>
                                                {schedule.next_run && schedule.enabled && <div className="flex items-center gap-2"><Clock className="w-4 h-4" />Next run: {new Date(schedule.next_run).toLocaleString()}</div>}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <Button variant="outline" size="sm" onClick={() => runNow(schedule.id)} data-testid={`run-now-${schedule.id}`}><Play className="w-4 h-4" /></Button>
                                            <Switch checked={schedule.enabled} onCheckedChange={() => toggleSchedule(schedule.id, schedule.enabled)} data-testid={`toggle-${schedule.id}`} />
                                            <Button variant="ghost" size="sm" onClick={() => deleteSchedule(schedule.id)} className="text-red-400 hover:text-red-300" data-testid={`delete-${schedule.id}`}><Trash2 className="w-4 h-4" /></Button>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        )) : <Card className="border-border/40 bg-card/20"><CardContent className="p-8 text-center"><Timer className="w-12 h-12 mx-auto mb-4 text-muted-foreground opacity-30" /><p className="text-muted-foreground">No scheduled scans yet</p></CardContent></Card>}
                    </div>
                </div>
            </div>

            <Dialog open={showCreateModal} onOpenChange={setShowCreateModal}>
                <DialogContent className="max-w-md">
                    <DialogHeader><DialogTitle>Create Scheduled Scan</DialogTitle><DialogDescription>Set up automatic recurring scans</DialogDescription></DialogHeader>
                    <div className="space-y-4">
                        <div className="space-y-2"><Label>Schedule Name</Label><Input placeholder="Weekly Security Audit" value={formData.name} onChange={(e) => setFormData({...formData, name: e.target.value})} className="bg-background" data-testid="schedule-name-input" /></div>
                        <div className="space-y-2"><Label>Targets (one per line)</Label><Textarea placeholder="example.com&#10;192.168.1.1" value={formData.targets} onChange={(e) => setFormData({...formData, targets: e.target.value})} className="bg-background min-h-20 font-mono text-sm" data-testid="schedule-targets-input" /></div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2"><Label>Scan Type</Label><Select value={formData.scan_type} onValueChange={(v) => setFormData({...formData, scan_type: v})}><SelectTrigger className="bg-background"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="recon">Reconnaissance</SelectItem><SelectItem value="vuln">Vulnerability</SelectItem></SelectContent></Select></div>
                            <div className="space-y-2"><Label>Frequency</Label><Select value={formData.schedule_type} onValueChange={(v) => setFormData({...formData, schedule_type: v})}><SelectTrigger className="bg-background"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="daily">Daily</SelectItem><SelectItem value="weekly">Weekly</SelectItem><SelectItem value="monthly">Monthly</SelectItem></SelectContent></Select></div>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2"><Label>Time (UTC)</Label><Input type="time" value={formData.schedule_time} onChange={(e) => setFormData({...formData, schedule_time: e.target.value})} className="bg-background" /></div>
                            {formData.schedule_type === 'weekly' && <div className="space-y-2"><Label>Day of Week</Label><Select value={formData.schedule_day.toString()} onValueChange={(v) => setFormData({...formData, schedule_day: parseInt(v)})}><SelectTrigger className="bg-background"><SelectValue /></SelectTrigger><SelectContent>{dayNames.map((day, i) => <SelectItem key={i} value={i.toString()}>{day}</SelectItem>)}</SelectContent></Select></div>}
                            {formData.schedule_type === 'monthly' && <div className="space-y-2"><Label>Day of Month</Label><Input type="number" min="1" max="28" value={formData.schedule_day || 1} onChange={(e) => setFormData({...formData, schedule_day: parseInt(e.target.value)})} className="bg-background" /></div>}
                        </div>
                        <Button className="w-full" onClick={createScheduledScan} disabled={loading} data-testid="save-schedule-button">{loading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Creating...</> : 'Create Schedule'}</Button>
                    </div>
                </DialogContent>
            </Dialog>
        </div>
    );
}

// Vulnerabilities Page
function VulnerabilitiesPage() {
    const [scans, setScans] = useState([]);
    useEffect(() => { const fetchScans = async () => { try { const response = await axios.get(`${API_URL}/api/scans`); setScans(response.data.filter(s => s.scan_type === 'vuln')); } catch (error) { console.error('Failed:', error); } }; fetchScans(); }, []);
    return (
        <div className="flex-1 flex flex-col" data-testid="vulnerabilities-page">
            <Header title="Vulnerabilities" subtitle="Security vulnerability assessment" />
            <div className="flex-1 p-6 overflow-auto">
                <Card className="border-border/40 bg-card/20"><CardHeader><CardTitle>Vulnerability Scans</CardTitle></CardHeader><CardContent>
                    {scans.length > 0 ? scans.map((scan) => (<div key={scan.id} className="p-3 mb-2 border border-border/40"><div className="flex items-center justify-between"><span className="font-medium">{scan.target}</span><Badge>{scan.status}</Badge></div><p className="text-sm text-muted-foreground">{scan.results?.vulnerabilities?.length || 0} vulnerabilities found</p></div>)) : <p className="text-muted-foreground text-center py-8">No vulnerability scans yet. Start one from the Recon page.</p>}
                </CardContent></Card>
            </div>
        </div>
    );
}

// Network Page
function NetworkPage() {
    return (
        <div className="flex-1 flex flex-col" data-testid="network-page">
            <Header title="Network Analysis" subtitle="Traffic monitoring and analysis" />
            <div className="flex-1 p-6 overflow-auto">
                <Card className="border-border/40 bg-card/20"><CardContent className="p-8 text-center"><Network className="w-12 h-12 mx-auto mb-4 text-muted-foreground opacity-30" /><p className="text-muted-foreground">Network analysis requires elevated privileges</p><p className="text-sm text-muted-foreground">Use Wireshark or tcpdump with proper authorization</p></CardContent></Card>
            </div>
        </div>
    );
}

// AI Assistant Page
function AssistantPage() {
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [sessionId, setSessionId] = useState(null);

    const sendMessage = async () => {
        if (!input.trim() || loading) return;
        const userMessage = { role: 'user', content: input };
        setMessages(prev => [...prev, userMessage]);
        setInput(''); setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/ai/chat`, { message: input, session_id: sessionId });
            setMessages(prev => [...prev, { role: 'assistant', content: response.data.response }]);
            if (response.data.session_id) setSessionId(response.data.session_id);
        } catch (error) { toast.error('Failed to send message'); setMessages(prev => prev.slice(0, -1)); }
        finally { setLoading(false); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="assistant-page">
            <Header title="AI Assistant" subtitle="Claude-powered security assistant" />
            <div className="flex-1 flex flex-col p-6 overflow-hidden">
                <Card className="flex-1 flex flex-col border-border/40 bg-card/20 overflow-hidden">
                    <CardContent className="flex-1 overflow-auto p-4">
                        {messages.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center text-muted-foreground"><Bot className="w-16 h-16 mb-4 opacity-30" /><p className="text-lg font-medium">How can I help you today?</p><p className="text-sm">Ask about reconnaissance, vulnerabilities, or security best practices</p></div>
                        ) : (
                            <div className="space-y-4">{messages.map((msg, i) => (<div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}><div className={`max-w-[80%] p-3 ${msg.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}><p className="text-sm whitespace-pre-wrap">{msg.content}</p></div></div>))}{loading && <div className="flex gap-3"><div className="p-3 bg-muted"><Loader2 className="w-4 h-4 animate-spin" /></div></div>}</div>
                        )}
                    </CardContent>
                    <div className="p-4 border-t border-border/40">
                        <div className="flex gap-2"><Input placeholder="Ask about security, vulnerabilities, tools..." value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()} className="bg-background" data-testid="chat-input" /><Button onClick={sendMessage} disabled={loading} data-testid="send-message"><Send className="w-4 h-4" /></Button></div>
                    </div>
                </Card>
            </div>
        </div>
    );
}

// Terminal Page
function TerminalPage() {
    const [command, setCommand] = useState('');
    const [history, setHistory] = useState([{ type: 'output', content: 'PentestAI Terminal v1.0\nType "help" for available commands or "ai <query>" for AI assistance.\n' }]);
    const [loading, setLoading] = useState(false);

    const executeCommand = async () => {
        if (!command.trim()) return;
        setHistory(prev => [...prev, { type: 'input', content: `$ ${command}` }]);
        const cmd = command.trim(); setCommand(''); setLoading(true);
        try {
            if (cmd.startsWith('ai ')) {
                const response = await axios.post(`${API_URL}/api/ai/chat`, { message: cmd.slice(3) });
                setHistory(prev => [...prev, { type: 'output', content: response.data.response }]);
            } else if (cmd === 'help') {
                setHistory(prev => [...prev, { type: 'output', content: 'Available commands:\n  ai <query> - Ask AI assistant\n  clear - Clear terminal\n  help - Show this help' }]);
            } else if (cmd === 'clear') { setHistory([{ type: 'output', content: 'Terminal cleared.\n' }]); }
            else { setHistory(prev => [...prev, { type: 'output', content: `Command not found: ${cmd}\nType "help" for available commands.` }]); }
        } catch (error) { setHistory(prev => [...prev, { type: 'error', content: 'Error executing command' }]); }
        finally { setLoading(false); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="terminal-page">
            <Header title="Terminal" subtitle="Command-line interface" />
            <div className="flex-1 p-6">
                <Card className="h-full border-border/40 bg-black/50 font-mono text-sm flex flex-col">
                    <CardContent className="flex-1 overflow-auto p-4">
                        {history.map((item, i) => (<div key={i} className={item.type === 'error' ? 'text-red-400' : item.type === 'input' ? 'text-green-400' : 'text-gray-300'}><pre className="whitespace-pre-wrap">{item.content}</pre></div>))}
                        {loading && <div className="text-yellow-400"><Loader2 className="w-4 h-4 animate-spin inline mr-2" />Processing...</div>}
                    </CardContent>
                    <div className="p-4 border-t border-border/40 flex items-center gap-2">
                        <span className="text-green-400">$</span>
                        <Input value={command} onChange={(e) => setCommand(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && executeCommand()} className="bg-transparent border-none focus-visible:ring-0 text-gray-300" placeholder="Enter command..." data-testid="terminal-input" />
                    </div>
                </Card>
            </div>
        </div>
    );
}

// Reports Page with PDF Download
function ReportsPage() {
    const [scans, setScans] = useState([]);
    const [selectedScans, setSelectedScans] = useState([]);
    const [reports, setReports] = useState([]);
    const [generatingReport, setGeneratingReport] = useState(false);
    const [downloadingPdf, setDownloadingPdf] = useState(null);

    useEffect(() => { fetchData(); }, []);

    const fetchData = async () => {
        try { const [scansRes, reportsRes] = await Promise.all([axios.get(`${API_URL}/api/scans`), axios.get(`${API_URL}/api/reports`)]); setScans(scansRes.data); setReports(reportsRes.data.reports || []); } catch (error) { console.error('Failed:', error); }
    };

    const toggleScanSelection = (scanId) => { setSelectedScans(prev => prev.includes(scanId) ? prev.filter(id => id !== scanId) : [...prev, scanId]); };

    const generateReport = async () => {
        if (selectedScans.length === 0) { toast.error('Please select at least one scan'); return; }
        setGeneratingReport(true);
        try { const response = await axios.post(`${API_URL}/api/reports/generate`, selectedScans); toast.success('Report generated'); setReports(prev => [response.data, ...prev]); setSelectedScans([]); } catch (error) { toast.error('Failed'); } finally { setGeneratingReport(false); }
    };

    const downloadPdf = async (reportId) => {
        setDownloadingPdf(reportId);
        try {
            const response = await axios.get(`${API_URL}/api/reports/${reportId}/pdf`, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a'); link.href = url; link.setAttribute('download', `security_report_${reportId.slice(0, 8)}.pdf`);
            document.body.appendChild(link); link.click(); link.remove(); window.URL.revokeObjectURL(url);
            toast.success('PDF downloaded');
        } catch (error) { toast.error('Failed'); } finally { setDownloadingPdf(null); }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="reports-page">
            <Header title="Reports" subtitle="Generate and export security reports" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
                <Card className="border-border/40 bg-card/20 flex flex-col">
                    <CardHeader><CardTitle>Select Scans</CardTitle><CardDescription>Choose scans to include in report</CardDescription></CardHeader>
                    <CardContent className="flex-1 overflow-auto"><div className="space-y-2">
                        {scans.map((scan) => (<label key={scan.id} className="flex items-center gap-3 p-3 border border-border/40 hover:bg-accent cursor-pointer"><Checkbox checked={selectedScans.includes(scan.id)} onCheckedChange={() => toggleScanSelection(scan.id)} /><div className="flex-1"><p className="font-medium text-sm">{scan.target}</p><p className="text-xs text-muted-foreground">{scan.scan_type} • {new Date(scan.created_at).toLocaleDateString()}</p></div></label>))}
                    </div></CardContent>
                    <div className="p-4 border-t border-border/40"><Button className="w-full" onClick={generateReport} disabled={generatingReport || selectedScans.length === 0}>{generatingReport ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Generating...</> : 'Generate Report'}</Button></div>
                </Card>
                <Card className="border-border/40 bg-card/20 flex flex-col">
                    <CardHeader><CardTitle>Generated Reports</CardTitle></CardHeader>
                    <CardContent className="flex-1 overflow-auto"><div className="space-y-4">
                        {reports.length > 0 ? reports.map((report) => (
                            <Card key={report.id} className="border-border/40 bg-background/50" data-testid={`report-${report.id}`}>
                                <CardContent className="p-4">
                                    <div className="flex items-start justify-between mb-2">
                                        <div><h3 className="font-medium text-sm">{report.title}</h3><p className="text-xs text-muted-foreground">{new Date(report.created_at).toLocaleString()}</p></div>
                                        <Button variant="outline" size="sm" onClick={() => downloadPdf(report.id)} disabled={downloadingPdf === report.id} data-testid={`download-pdf-${report.id}`}>{downloadingPdf === report.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Download className="w-4 h-4 mr-1" />PDF</>}</Button>
                                    </div>
                                    <div className="grid grid-cols-4 gap-2 mt-3">
                                        <div className="p-2 bg-red-500/10 text-center"><p className="text-lg font-bold text-red-400">{report.summary?.critical || 0}</p><p className="text-xs">Critical</p></div>
                                        <div className="p-2 bg-orange-500/10 text-center"><p className="text-lg font-bold text-orange-400">{report.summary?.high || 0}</p><p className="text-xs">High</p></div>
                                        <div className="p-2 bg-yellow-500/10 text-center"><p className="text-lg font-bold text-yellow-400">{report.summary?.medium || 0}</p><p className="text-xs">Medium</p></div>
                                        <div className="p-2 bg-green-500/10 text-center"><p className="text-lg font-bold text-green-400">{report.summary?.low || 0}</p><p className="text-xs">Low</p></div>
                                    </div>
                                </CardContent>
                            </Card>
                        )) : <p className="text-center text-muted-foreground py-8">No reports generated yet</p>}
                    </div></CardContent>
                </Card>
            </div>
        </div>
    );
}

// Settings Page
function SettingsPage() {
    const [theme, setTheme] = useState('dark');
    useEffect(() => { setTheme(localStorage.getItem('theme') || 'dark'); }, []);
    const toggleTheme = () => { const newTheme = theme === 'dark' ? 'light' : 'dark'; setTheme(newTheme); localStorage.setItem('theme', newTheme); document.documentElement.classList.remove('light', 'dark'); document.documentElement.classList.add(newTheme); };

    return (
        <div className="flex-1 flex flex-col" data-testid="settings-page">
            <Header title="Settings" subtitle="Configure your preferences" />
            <div className="flex-1 p-6 overflow-auto">
                <div className="max-w-2xl space-y-6">
                    <Card className="border-border/40 bg-card/20"><CardHeader><CardTitle>Appearance</CardTitle></CardHeader><CardContent>
                        <div className="flex items-center justify-between"><div className="flex items-center gap-3"><Palette className="w-5 h-5" /><div><p className="font-medium">Theme</p><p className="text-sm text-muted-foreground">{theme === 'dark' ? 'Dark mode' : 'Light mode'}</p></div></div><Switch checked={theme === 'dark'} onCheckedChange={toggleTheme} data-testid="theme-switch" /></div>
                    </CardContent></Card>
                    <Card className="border-border/40 bg-card/20"><CardHeader><CardTitle>API Keys</CardTitle></CardHeader><CardContent><div className="flex items-center gap-3"><Key className="w-5 h-5 text-muted-foreground" /><div><p className="font-medium">Shodan API Key</p><p className="text-sm text-muted-foreground">Configured in backend</p></div></div></CardContent></Card>
                </div>
            </div>
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
            <Route path="/bulk-scan" element={<ProtectedRoute><MainLayout><BulkScanPage /></MainLayout></ProtectedRoute>} />
            <Route path="/scheduled" element={<ProtectedRoute><MainLayout><ScheduledScansPage /></MainLayout></ProtectedRoute>} />
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

// Main App
function App() {
    return (
        <BrowserRouter>
            <AuthProvider>
                <Toaster position="top-right" richColors />
                <AppRoutes />
            </AuthProvider>
        </BrowserRouter>
    );
}

export default App;

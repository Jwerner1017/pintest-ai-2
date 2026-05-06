import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Search, Play, Loader2, Globe, Clock, ChevronRight, Server, AlertTriangle, Satellite } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function ReconPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);
    const [shodanTarget, setShodanTarget] = useState('');
    const [shodanLoading, setShodanLoading] = useState(false);
    const [shodanResult, setShodanResult] = useState(null);
    const [shodanConfigured, setShodanConfigured] = useState(true);

    useEffect(() => {
        fetchScans();
        axios.get(`${API_URL}/api/shodan/status`).then(r => setShodanConfigured(r.data.configured)).catch(() => {});
    }, []);

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

    const runShodanLookup = async () => {
        if (!shodanTarget.trim()) { toast.error('Enter an IP address'); return; }
        setShodanLoading(true);
        setShodanResult(null);
        try {
            const res = await axios.post(`${API_URL}/api/shodan/lookup`, { target: shodanTarget.trim() });
            setShodanResult(res.data);
            if (res.data.error) toast.error(res.data.error);
            else if (!res.data.configured) toast.warning('Shodan not configured');
            else toast.success('Shodan data retrieved');
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Shodan lookup failed');
        } finally {
            setShodanLoading(false);
        }
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
                    <Card className="border-border/40 bg-card/20" data-testid="shodan-card">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Satellite className="w-5 h-5 text-primary" />Shodan Intel</CardTitle></CardHeader>
                        <CardContent className="space-y-3">
                            {!shodanConfigured && (
                                <div className="text-xs p-2 bg-yellow-500/10 border border-yellow-500/20 text-yellow-400" data-testid="shodan-not-configured">
                                    SHODAN_API_KEY not set on backend. Add it to enable live host intel.
                                </div>
                            )}
                            <div className="space-y-1">
                                <Label className="text-xs">IP address</Label>
                                <Input
                                    placeholder="8.8.8.8"
                                    value={shodanTarget}
                                    onChange={(e) => setShodanTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="shodan-target-input"
                                />
                            </div>
                            <Button
                                size="sm"
                                className="w-full"
                                onClick={runShodanLookup}
                                disabled={shodanLoading || !shodanTarget.trim()}
                                data-testid="shodan-lookup-button"
                            >
                                {shodanLoading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Querying...</> : 'Lookup Host'}
                            </Button>
                            {shodanResult && shodanResult.configured && !shodanResult.error && (
                                <div className="text-xs space-y-1 pt-2 border-t border-border/40" data-testid="shodan-result">
                                    <p><span className="text-muted-foreground">Org:</span> {shodanResult.org || 'n/a'}</p>
                                    <p><span className="text-muted-foreground">ISP:</span> {shodanResult.isp || 'n/a'}</p>
                                    <p><span className="text-muted-foreground">Country:</span> {shodanResult.country || 'n/a'}</p>
                                    <p><span className="text-muted-foreground">OS:</span> {shodanResult.os || 'n/a'}</p>
                                    <p><span className="text-muted-foreground">Open ports:</span> {(shodanResult.ports || []).join(', ') || 'none'}</p>
                                    {(shodanResult.vulns || []).length > 0 && (
                                        <p><span className="text-muted-foreground">Known CVEs:</span> {shodanResult.vulns.slice(0, 5).join(', ')}{shodanResult.vulns.length > 5 ? '…' : ''}</p>
                                    )}
                                </div>
                            )}
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
                                                {selectedScan.results.vulnerabilities.map((vuln, i) => {
                                                    const sev = (vuln.severity || '').toLowerCase();
                                                    const sevClass = sev === 'critical' ? 'bg-red-500/20 text-red-400'
                                                        : sev === 'high' ? 'bg-orange-500/20 text-orange-400'
                                                        : sev === 'medium' ? 'bg-yellow-500/20 text-yellow-400'
                                                        : 'bg-green-500/20 text-green-400';
                                                    return (
                                                        <div key={i} className="p-3 bg-background/50 border border-border/20">
                                                            <div className="flex items-center justify-between mb-2">
                                                                <span className="font-mono text-sm text-primary">{vuln.id}</span>
                                                                <Badge className={sevClass}>{vuln.severity?.toUpperCase()}</Badge>
                                                            </div>
                                                            <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                                        </div>
                                                    );
                                                })}
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

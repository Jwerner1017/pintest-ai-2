import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Play, Loader2, Network as NetworkIcon, AlertTriangle, Server } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { ScanProgress } from '../components/scans/ScanProgress';
import { useScanPolling } from '../hooks/useScanPolling';
import { API_URL } from '../lib/api';

const SEV_CLASS = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
    info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

export default function NetworkPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);
    const [activeScanId, setActiveScanId] = useState(null);

    useEffect(() => { fetchScans(); }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            const networkScans = response.data.filter(s => s.scan_type === 'network');
            setScans(networkScans);
            if (networkScans.length && !selectedScan) setSelectedScan(networkScans[0]);
        } catch (error) { console.error('Failed to fetch scans:', error); }
    };

    const { scan: liveScan, polling } = useScanPolling(activeScanId, {
        intervalMs: 2500,
        onComplete: (final) => {
            setActiveScanId(null);
            setLoading(false);
            setSelectedScan(final);
            setScans(prev => [final, ...prev.filter(s => s.id !== final.id)]);
            if (final.status === 'completed') toast.success('Network analysis completed');
            else toast.error('Analysis failed');
        },
    });

    const startScan = async () => {
        if (!target.trim()) { toast.error('Please enter a target'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, { scan_type: 'network', target: target.trim(), options: {} });
            setActiveScanId(response.data.id);
            setTarget('');
        } catch (error) {
            toast.error('Failed to queue scan');
            setLoading(false);
        }
    };

    const results = selectedScan?.results || {};
    const aliveHosts = results.alive_hosts || [];
    const anomalies = results.anomalies || [];
    const summary = results.traffic_summary || {};

    return (
        <div className="flex-1 flex flex-col" data-testid="network-page">
            <Header title="Network Analysis" subtitle="Live host discovery & service mapping (nmap)" />
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                <Card className="border-border/40 bg-card/20" data-testid="network-scan-card">
                    <CardContent className="p-6">
                        <div className="flex flex-col md:flex-row gap-4 items-end">
                            <div className="flex-1 space-y-2">
                                <Label>Network / IP Range</Label>
                                <Input
                                    placeholder="192.168.1.0/24 or single host"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="network-target-input"
                                />
                            </div>
                            <Button onClick={startScan} disabled={loading || polling || !target.trim()} data-testid="start-network-scan-button">
                                {loading || polling ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing...</> : <><Play className="w-4 h-4 mr-2" />Start Analysis</>}
                            </Button>
                        </div>
                        {liveScan && liveScan.status !== 'completed' && (
                            <div className="mt-4">
                                <ScanProgress scan={liveScan} />
                            </div>
                        )}
                    </CardContent>
                </Card>

                {selectedScan?.results && (
                    <>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3" data-testid="network-summary">
                            <SummaryCard label="Hosts Alive" value={summary.hosts_alive || 0} />
                            <SummaryCard label="Hosts Mapped" value={summary.hosts_scanned_for_services || 0} />
                            <SummaryCard label="Open Ports" value={summary.total_open_ports || 0} />
                            <SummaryCard label="Anomalies" value={anomalies.length} accent={anomalies.length > 0 ? 'text-yellow-400' : ''} />
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <Card className="border-border/40 bg-card/20" data-testid="alive-hosts-card">
                                <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Server className="w-5 h-5 text-primary" />Discovered Hosts</CardTitle></CardHeader>
                                <CardContent className="p-0">
                                    <ScrollArea className="h-96">
                                        <div className="p-4 space-y-3">
                                            {aliveHosts.length > 0 ? aliveHosts.map((host, i) => (
                                                <div key={i} className="p-3 bg-background/50 border border-border/20" data-testid={`host-${host.ip}`}>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <span className="font-mono text-sm">{host.ip}</span>
                                                        {host.hostname && host.hostname !== host.ip && (
                                                            <span className="text-xs text-muted-foreground truncate ml-2">{host.hostname}</span>
                                                        )}
                                                    </div>
                                                    <div className="flex flex-wrap gap-1">
                                                        {(host.ports || []).map((p, j) => (
                                                            <Badge key={j} variant="outline" className="text-xs font-mono">
                                                                {p.port}/{p.service}
                                                            </Badge>
                                                        ))}
                                                        {(host.ports || []).length === 0 && (
                                                            <span className="text-xs text-muted-foreground">no open ports detected</span>
                                                        )}
                                                    </div>
                                                </div>
                                            )) : (
                                                <p className="text-sm text-muted-foreground text-center py-8">No live hosts found</p>
                                            )}
                                        </div>
                                    </ScrollArea>
                                </CardContent>
                            </Card>

                            <Card className="border-border/40 bg-card/20" data-testid="anomalies-card">
                                <CardHeader><CardTitle className="text-lg flex items-center gap-2"><AlertTriangle className="w-5 h-5 text-primary" />Anomalies</CardTitle></CardHeader>
                                <CardContent className="p-0">
                                    <ScrollArea className="h-96">
                                        <div className="p-4 space-y-2">
                                            {anomalies.length > 0 ? anomalies.map((a, i) => (
                                                <div key={i} className="p-3 bg-background/50 border border-border/20 space-y-1" data-testid={`anomaly-${i}`}>
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-sm font-medium">{a.type}</span>
                                                        <Badge className={SEV_CLASS[a.severity?.toLowerCase()] || SEV_CLASS.info}>{a.severity?.toUpperCase()}</Badge>
                                                    </div>
                                                    {a.host && <p className="text-xs font-mono text-muted-foreground">{a.host}{a.port ? `:${a.port}` : ''}</p>}
                                                    {a.description && <p className="text-xs">{a.description}</p>}
                                                </div>
                                            )) : (
                                                <p className="text-sm text-muted-foreground text-center py-8">No anomalies detected</p>
                                            )}
                                        </div>
                                    </ScrollArea>
                                </CardContent>
                            </Card>
                        </div>
                    </>
                )}

                {!selectedScan && !liveScan && (
                    <div className="text-center py-12 text-muted-foreground">
                        <NetworkIcon className="w-12 h-12 mx-auto mb-4 opacity-30" />
                        <p>Run an analysis on a CIDR range or single host to see live discovery results.</p>
                    </div>
                )}
            </div>
        </div>
    );
}

function SummaryCard({ label, value, accent = '' }) {
    return (
        <div className="p-4 bg-card/30 border border-border/40">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className={`text-2xl font-bold mt-1 ${accent}`}>{value}</p>
        </div>
    );
}

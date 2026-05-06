import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Bug, Play, Loader2, ChevronRight, Clock } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Header } from '../components/layout/Header';
import { ScanProgress } from '../components/scans/ScanProgress';
import { AIScanSummary } from '../components/scans/AIScanSummary';
import { useScanPolling } from '../hooks/useScanPolling';
import { API_URL } from '../lib/api';

const SEV_CLASS = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
    info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

export default function VulnerabilitiesPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);
    const [activeScanId, setActiveScanId] = useState(null);

    useEffect(() => { fetchScans(); }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'vuln'));
        } catch (error) { console.error('Failed to fetch scans:', error); }
    };

    const { scan: liveScan, polling } = useScanPolling(activeScanId, {
        intervalMs: 2500,
        onComplete: (final) => {
            setActiveScanId(null);
            setLoading(false);
            setSelectedScan(final);
            setScans(prev => [final, ...prev.filter(s => s.id !== final.id)]);
            if (final.status === 'completed') toast.success('Vulnerability scan completed');
            else if (final.status === 'cancelled') toast.info('Scan cancelled');
            else toast.error('Scan failed');
        },
    });

    const cancelActiveScan = async () => {
        if (!activeScanId) return;
        try {
            await axios.post(`${API_URL}/api/scans/${activeScanId}/cancel`);
        } catch (e) {
            toast.error('Failed to cancel');
        }
    };

    const startScan = async () => {
        if (!target.trim()) { toast.error('Please enter a target'); return; }
        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, { scan_type: 'vuln', target: target.trim(), options: {} });
            setActiveScanId(response.data.id);
            setTarget('');
        } catch (error) {
            toast.error('Failed to queue scan');
            setLoading(false);
        }
    };

    const results = selectedScan?.results || {};
    const vulnerabilities = results.vulnerabilities || [];
    const riskScore = results.risk_score;
    const owaspHits = results.compliance?.owasp_top10_hits || [];

    return (
        <div className="flex-1 flex flex-col" data-testid="vulnerabilities-page">
            <Header title="Vulnerability Assessment" subtitle="nmap NSE vuln scripts + HTTP probe" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                <div className="space-y-4">
                    <Card className="border-border/40 bg-card/20" data-testid="vuln-scan-card">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Bug className="w-5 h-5 text-primary" />Vulnerability Scan</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input
                                    placeholder="example.com or https://example.com"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="vuln-target-input"
                                />
                                <p className="text-xs text-muted-foreground">Tip: prefix with http(s):// to enable HTTP probing.</p>
                            </div>
                            <Button className="w-full" onClick={startScan} disabled={loading || polling || !target.trim()} data-testid="start-vuln-scan-button">
                                {loading || polling ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Scanning...</> : <><Play className="w-4 h-4 mr-2" />Start Assessment</>}
                            </Button>
                            {liveScan && liveScan.status !== 'completed' && (
                                <ScanProgress scan={liveScan} onCancel={cancelActiveScan} />
                            )}
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="vuln-history">
                        <CardHeader><CardTitle className="text-lg">Scan History</CardTitle></CardHeader>
                        <CardContent className="p-0">
                            <ScrollArea className="h-64">
                                <div className="p-4 space-y-2">
                                    {scans.length > 0 ? scans.map((scan) => (
                                        <button
                                            key={scan.id}
                                            onClick={() => setSelectedScan(scan)}
                                            className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${selectedScan?.id === scan.id ? 'bg-accent' : ''}`}
                                            data-testid={`vuln-item-${scan.id}`}
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="font-medium text-sm truncate max-w-32">{scan.target}</span>
                                                <ChevronRight className="w-4 h-4 text-muted-foreground" />
                                            </div>
                                            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground"><Clock className="w-3 h-3" />{new Date(scan.created_at).toLocaleString()}</div>
                                        </button>
                                    )) : <div className="text-center py-8 text-muted-foreground text-sm">No scans yet</div>}
                                </div>
                            </ScrollArea>
                        </CardContent>
                    </Card>
                </div>
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="vuln-results">
                        <CardHeader>
                            <div className="flex items-center justify-between gap-3">
                                <CardTitle className="text-lg">{selectedScan ? `Vulnerabilities: ${selectedScan.target}` : 'Assessment Results'}</CardTitle>
                                <div className="flex items-center gap-2">
                                    {riskScore !== undefined && (
                                        <Badge className="bg-primary/20 text-primary border-primary/30" data-testid="risk-score">Risk {riskScore}/10</Badge>
                                    )}
                                    {selectedScan?.status === 'completed' && (
                                        <AIScanSummary scanId={selectedScan.id} initialSummary={selectedScan.ai_summary} />
                                    )}
                                </div>
                            </div>
                            {owaspHits.length > 0 && (
                                <div className="flex flex-wrap gap-1 pt-2" data-testid="owasp-hits">
                                    {owaspHits.map((h, i) => <Badge key={i} variant="outline" className="text-xs">{h}</Badge>)}
                                </div>
                            )}
                        </CardHeader>
                        <CardContent className="flex-1 overflow-auto">
                            {vulnerabilities.length > 0 ? (
                                <div className="space-y-3">
                                    {vulnerabilities.map((vuln, i) => (
                                        <div key={i} className="p-4 bg-background/50 border border-border/20 space-y-2" data-testid={`vulnerability-${i}`}>
                                            <div className="flex items-start justify-between gap-2">
                                                <span className="font-mono text-sm font-medium break-all">{vuln.id}</span>
                                                <Badge className={SEV_CLASS[vuln.severity?.toLowerCase()] || SEV_CLASS.info}>{vuln.severity?.toUpperCase()}</Badge>
                                            </div>
                                            <p className="text-sm">{vuln.description}</p>
                                            {vuln.source && <p className="text-xs text-muted-foreground">Source: {vuln.source}</p>}
                                            {vuln.remediation && (
                                                <div className="p-2 bg-green-500/10 border border-green-500/20 text-xs">
                                                    <span className="text-green-400 font-medium">Remediation: </span>{vuln.remediation}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="h-full flex items-center justify-center text-muted-foreground">
                                    <div className="text-center">
                                        <Bug className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                        <p>Start a vulnerability assessment</p>
                                    </div>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

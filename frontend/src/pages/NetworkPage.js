import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Play, Loader2 } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function NetworkPage() {
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

import { useState, useEffect } from 'react';
import { Header } from '../components/layout/Header.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { 
    Network, 
    Wifi, 
    Activity,
    Loader2,
    Play,
    AlertTriangle,
    Server
} from 'lucide-react';
import { 
    PieChart, 
    Pie, 
    Cell, 
    ResponsiveContainer,
    Tooltip,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid
} from 'recharts';
import axios from 'axios';
import { toast } from 'sonner';

const API_URL = process.env.REACT_APP_BACKEND_URL;

const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444'];

export default function NetworkPage() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);

    useEffect(() => {
        fetchScans();
    }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'network'));
        } catch (error) {
            console.error('Failed to fetch scans:', error);
        }
    };

    const startScan = async () => {
        if (!target.trim()) {
            toast.error('Please enter a target network');
            return;
        }

        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, {
                scan_type: 'network',
                target: target.trim(),
                options: {}
            });
            
            toast.success('Network analysis completed');
            setScans(prev => [response.data, ...prev]);
            setSelectedScan(response.data);
            setTarget('');
        } catch (error) {
            console.error('Scan failed:', error);
            toast.error('Analysis failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const results = selectedScan?.results;
    const trafficData = results?.traffic_summary?.protocols 
        ? Object.entries(results.traffic_summary.protocols).map(([name, value]) => ({ name, value }))
        : [];

    return (
        <div className="flex-1 flex flex-col" data-testid="network-page">
            <Header title="Network Analysis" subtitle="Traffic inspection and anomaly detection" />
            
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                {/* Top Controls */}
                <Card className="border-border/40 bg-card/20" data-testid="network-scan-card">
                    <CardContent className="p-6">
                        <div className="flex flex-col md:flex-row gap-4">
                            <div className="flex-1 space-y-2">
                                <Label>Network/IP Range</Label>
                                <Input
                                    placeholder="192.168.1.0/24 or single IP"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="network-target-input"
                                />
                            </div>
                            <div className="flex items-end">
                                <Button 
                                    onClick={startScan}
                                    disabled={loading || !target.trim()}
                                    data-testid="start-network-scan-button"
                                >
                                    {loading ? (
                                        <>
                                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                            Analyzing...
                                        </>
                                    ) : (
                                        <>
                                            <Play className="w-4 h-4 mr-2" />
                                            Start Analysis
                                        </>
                                    )}
                                </Button>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Results Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Protocol Distribution */}
                    <Card className="border-border/40 bg-card/20" data-testid="protocol-chart">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Wifi className="w-5 h-5 text-primary" />
                                Protocol Distribution
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            {trafficData.length > 0 ? (
                                <div className="h-48">
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie
                                                data={trafficData}
                                                cx="50%"
                                                cy="50%"
                                                innerRadius={40}
                                                outerRadius={70}
                                                paddingAngle={2}
                                                dataKey="value"
                                            >
                                                {trafficData.map((entry, index) => (
                                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                                ))}
                                            </Pie>
                                            <Tooltip 
                                                contentStyle={{ 
                                                    backgroundColor: 'hsl(var(--card))',
                                                    border: '1px solid hsl(var(--border))'
                                                }}
                                            />
                                        </PieChart>
                                    </ResponsiveContainer>
                                    <div className="flex justify-center gap-4 mt-2">
                                        {trafficData.map((entry, i) => (
                                            <div key={i} className="flex items-center gap-2 text-sm">
                                                <div className="w-3 h-3" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                                                <span>{entry.name}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                                    Start analysis to see results
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* Traffic Summary */}
                    <Card className="border-border/40 bg-card/20" data-testid="traffic-summary">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Activity className="w-5 h-5 text-primary" />
                                Traffic Summary
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            {results?.traffic_summary ? (
                                <div className="space-y-4">
                                    <div className="p-3 bg-background/50 border border-border/20">
                                        <p className="text-sm text-muted-foreground">Total Packets</p>
                                        <p className="text-2xl font-bold">{results.traffic_summary.total_packets.toLocaleString()}</p>
                                    </div>
                                    <div>
                                        <p className="text-sm text-muted-foreground mb-2">Top Talkers</p>
                                        {results.traffic_summary.top_talkers?.map((talker, i) => (
                                            <div key={i} className="flex items-center justify-between p-2 border-b border-border/20 last:border-0">
                                                <span className="font-mono text-sm">{talker.ip}</span>
                                                <span className="text-sm text-muted-foreground">{talker.packets} pkts</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                                    No data available
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* Anomalies Detected */}
                    <Card className="border-border/40 bg-card/20" data-testid="anomalies-card">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <AlertTriangle className="w-5 h-5 text-yellow-500" />
                                Anomalies Detected
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            {results?.anomalies && results.anomalies.length > 0 ? (
                                <ScrollArea className="h-48">
                                    <div className="space-y-2">
                                        {results.anomalies.map((anomaly, i) => (
                                            <div key={i} className="p-3 bg-background/50 border border-border/20">
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="text-sm font-medium">{anomaly.type}</span>
                                                    <Badge className={anomaly.severity === 'high' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'}>
                                                        {anomaly.severity}
                                                    </Badge>
                                                </div>
                                                <p className="text-xs text-muted-foreground">
                                                    {anomaly.source || anomaly.query}
                                                </p>
                                            </div>
                                        ))}
                                    </div>
                                </ScrollArea>
                            ) : (
                                <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                                    No anomalies detected
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>

                {/* Scan History */}
                <Card className="border-border/40 bg-card/20" data-testid="network-history">
                    <CardHeader>
                        <CardTitle className="text-lg">Analysis History</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            {scans.length > 0 ? scans.slice(0, 8).map((scan) => (
                                <button
                                    key={scan.id}
                                    onClick={() => setSelectedScan(scan)}
                                    className={`text-left p-4 border border-border/40 hover:bg-accent transition-colors ${
                                        selectedScan?.id === scan.id ? 'bg-accent' : ''
                                    }`}
                                    data-testid={`network-scan-item-${scan.id}`}
                                >
                                    <div className="flex items-center gap-2 mb-2">
                                        <Network className="w-4 h-4 text-primary" />
                                        <span className="font-medium text-sm truncate">{scan.target}</span>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                        {new Date(scan.created_at).toLocaleString()}
                                    </p>
                                </button>
                            )) : (
                                <div className="col-span-full text-center py-8 text-muted-foreground">
                                    <Network className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                    <p>No network analyses yet</p>
                                </div>
                            )}
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

import { useState, useEffect } from 'react';
import { Header } from '../components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { 
    Search, 
    Globe, 
    Server, 
    Wifi, 
    Loader2, 
    Play,
    Clock,
    ChevronRight,
    AlertTriangle
} from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function ReconPage() {
    const [target, setTarget] = useState('');
    const [scanType, setScanType] = useState('recon');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(null);

    useEffect(() => {
        fetchScans();
    }, []);

    const fetchScans = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/scans`);
            setScans(response.data.filter(s => s.scan_type === 'recon'));
        } catch (error) {
            console.error('Failed to fetch scans:', error);
        }
    };

    const startScan = async () => {
        if (!target.trim()) {
            toast.error('Please enter a target');
            return;
        }

        setLoading(true);
        try {
            const response = await axios.post(`${API_URL}/api/scans`, {
                scan_type: scanType,
                target: target.trim(),
                options: {}
            });
            
            toast.success('Scan completed successfully');
            setScans(prev => [response.data, ...prev]);
            setSelectedScan(response.data);
            setTarget('');
        } catch (error) {
            console.error('Scan failed:', error);
            toast.error('Scan failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const getSeverityColor = (severity) => {
        const colors = {
            critical: 'bg-red-500/20 text-red-400 border-red-500/30',
            high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
            medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
            low: 'bg-green-500/20 text-green-400 border-green-500/30'
        };
        return colors[severity] || colors.low;
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="recon-page">
            <Header title="Reconnaissance" subtitle="Target discovery and information gathering" />
            
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                {/* Left Panel - Scan Controls */}
                <div className="space-y-4">
                    {/* New Scan Card */}
                    <Card className="border-border/40 bg-card/20" data-testid="new-scan-card">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Search className="w-5 h-5 text-primary" />
                                New Scan
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input
                                    placeholder="example.com or 192.168.1.1"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="scan-target-input"
                                />
                            </div>

                            <div className="space-y-2">
                                <Label>Scan Type</Label>
                                <Select value={scanType} onValueChange={setScanType}>
                                    <SelectTrigger className="bg-background" data-testid="scan-type-select">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="recon">Full Reconnaissance</SelectItem>
                                        <SelectItem value="ports">Port Scan Only</SelectItem>
                                        <SelectItem value="dns">DNS Enumeration</SelectItem>
                                        <SelectItem value="whois">WHOIS Lookup</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>

                            <Button 
                                className="w-full" 
                                onClick={startScan}
                                disabled={loading || !target.trim()}
                                data-testid="start-scan-button"
                            >
                                {loading ? (
                                    <>
                                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>
                                        <Play className="w-4 h-4 mr-2" />
                                        Start Scan
                                    </>
                                )}
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Scan History */}
                    <Card className="border-border/40 bg-card/20 flex-1" data-testid="scan-history">
                        <CardHeader>
                            <CardTitle className="text-lg">Scan History</CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            <ScrollArea className="h-64">
                                <div className="p-4 space-y-2">
                                    {scans.length > 0 ? scans.map((scan) => (
                                        <button
                                            key={scan.id}
                                            onClick={() => setSelectedScan(scan)}
                                            className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${
                                                selectedScan?.id === scan.id ? 'bg-accent' : ''
                                            }`}
                                            data-testid={`scan-item-${scan.id}`}
                                        >
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-2">
                                                    <Globe className="w-4 h-4 text-muted-foreground" />
                                                    <span className="font-medium text-sm truncate max-w-32">{scan.target}</span>
                                                </div>
                                                <ChevronRight className="w-4 h-4 text-muted-foreground" />
                                            </div>
                                            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                                                <Clock className="w-3 h-3" />
                                                {new Date(scan.created_at).toLocaleString()}
                                            </div>
                                        </button>
                                    )) : (
                                        <div className="text-center py-8 text-muted-foreground">
                                            <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                            <p className="text-sm">No scans yet</p>
                                        </div>
                                    )}
                                </div>
                            </ScrollArea>
                        </CardContent>
                    </Card>
                </div>

                {/* Right Panel - Results */}
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="scan-results">
                        <CardHeader>
                            <CardTitle className="text-lg">
                                {selectedScan ? `Results: ${selectedScan.target}` : 'Scan Results'}
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="flex-1 overflow-auto">
                            {selectedScan?.results ? (
                                <div className="space-y-6">
                                    {/* Port Scan Results */}
                                    {selectedScan.results.ports && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                                                <Server className="w-4 h-4 text-primary" />
                                                Open Ports
                                            </h3>
                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                {selectedScan.results.ports.map((port, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20 flex items-center justify-between">
                                                        <div>
                                                            <span className="font-mono text-sm text-primary">{port.port}</span>
                                                            <span className="text-muted-foreground text-sm ml-2">/ {port.service}</span>
                                                        </div>
                                                        <Badge variant="outline" className={port.state === 'open' ? 'border-green-500/30 text-green-400' : 'border-yellow-500/30 text-yellow-400'}>
                                                            {port.state}
                                                        </Badge>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* DNS Records */}
                                    {selectedScan.results.dns_records && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                                                <Wifi className="w-4 h-4 text-primary" />
                                                DNS Records
                                            </h3>
                                            <div className="space-y-2">
                                                {selectedScan.results.dns_records.map((record, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20 flex items-center gap-4">
                                                        <Badge variant="outline">{record.type}</Badge>
                                                        <span className="font-mono text-sm">{record.value}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Vulnerabilities Found */}
                                    {selectedScan.results.vulnerabilities && selectedScan.results.vulnerabilities.length > 0 && (
                                        <div>
                                            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                                                <AlertTriangle className="w-4 h-4 text-yellow-500" />
                                                Vulnerabilities Detected
                                            </h3>
                                            <div className="space-y-2">
                                                {selectedScan.results.vulnerabilities.map((vuln, i) => (
                                                    <div key={i} className="p-3 bg-background/50 border border-border/20">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-mono text-sm text-primary">{vuln.id}</span>
                                                            <Badge className={getSeverityColor(vuln.severity)}>
                                                                {vuln.severity.toUpperCase()}
                                                            </Badge>
                                                        </div>
                                                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                                        {vuln.cvss && (
                                                            <p className="text-xs text-muted-foreground mt-1">CVSS: {vuln.cvss}</p>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* OS Detection */}
                                    {selectedScan.results.os_detection && (
                                        <div className="p-3 bg-background/50 border border-border/20">
                                            <span className="text-sm text-muted-foreground">OS Detection: </span>
                                            <span className="font-medium">{selectedScan.results.os_detection}</span>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="h-full flex items-center justify-center text-muted-foreground">
                                    <div className="text-center">
                                        <Search className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                        <p>Select a scan or start a new one</p>
                                        <p className="text-sm">Results will appear here</p>
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

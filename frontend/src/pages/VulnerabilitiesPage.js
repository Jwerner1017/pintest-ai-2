import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Bug, Play, Loader2 } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function VulnerabilitiesPage() {
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

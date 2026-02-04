import { useState, useEffect } from 'react';
import { Header } from '../components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import { 
    Bug, 
    Shield, 
    AlertTriangle,
    Loader2,
    Play,
    FileWarning,
    CheckCircle,
    XCircle
} from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function VulnerabilitiesPage() {
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
            setScans(response.data.filter(s => s.scan_type === 'vuln'));
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
                scan_type: 'vuln',
                target: target.trim(),
                options: {}
            });
            
            toast.success('Vulnerability scan completed');
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

    const getSeverityIcon = (severity) => {
        switch(severity) {
            case 'critical': return <XCircle className="w-4 h-4 text-red-500" />;
            case 'high': return <AlertTriangle className="w-4 h-4 text-orange-500" />;
            case 'medium': return <FileWarning className="w-4 h-4 text-yellow-500" />;
            default: return <CheckCircle className="w-4 h-4 text-green-500" />;
        }
    };

    const vulnerabilities = selectedScan?.results?.vulnerabilities || [];
    const riskScore = selectedScan?.results?.risk_score || 0;

    return (
        <div className="flex-1 flex flex-col" data-testid="vulnerabilities-page">
            <Header title="Vulnerability Assessment" subtitle="Identify and analyze security vulnerabilities" />
            
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
                {/* Left Panel */}
                <div className="space-y-4">
                    {/* New Scan */}
                    <Card className="border-border/40 bg-card/20" data-testid="vuln-scan-card">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Bug className="w-5 h-5 text-primary" />
                                Vulnerability Scan
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Target</Label>
                                <Input
                                    placeholder="example.com or IP address"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="bg-background"
                                    data-testid="vuln-target-input"
                                />
                            </div>

                            <Button 
                                className="w-full" 
                                onClick={startScan}
                                disabled={loading || !target.trim()}
                                data-testid="start-vuln-scan-button"
                            >
                                {loading ? (
                                    <>
                                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>
                                        <Play className="w-4 h-4 mr-2" />
                                        Start Assessment
                                    </>
                                )}
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Risk Score */}
                    {selectedScan && (
                        <Card className="border-border/40 bg-card/20" data-testid="risk-score-card">
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center gap-2">
                                    <Shield className="w-5 h-5 text-primary" />
                                    Risk Score
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="text-center mb-4">
                                    <span className={`text-5xl font-bold ${
                                        riskScore >= 7 ? 'text-red-500' :
                                        riskScore >= 4 ? 'text-yellow-500' : 'text-green-500'
                                    }`}>
                                        {riskScore.toFixed(1)}
                                    </span>
                                    <span className="text-2xl text-muted-foreground">/10</span>
                                </div>
                                <Progress 
                                    value={riskScore * 10} 
                                    className="h-2"
                                />
                                <p className="text-sm text-muted-foreground text-center mt-2">
                                    {riskScore >= 7 ? 'Critical Risk' :
                                     riskScore >= 4 ? 'Moderate Risk' : 'Low Risk'}
                                </p>
                            </CardContent>
                        </Card>
                    )}

                    {/* Scan History */}
                    <Card className="border-border/40 bg-card/20" data-testid="vuln-history">
                        <CardHeader>
                            <CardTitle className="text-lg">Recent Assessments</CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            <ScrollArea className="h-48">
                                <div className="p-4 space-y-2">
                                    {scans.length > 0 ? scans.map((scan) => (
                                        <button
                                            key={scan.id}
                                            onClick={() => setSelectedScan(scan)}
                                            className={`w-full text-left p-3 border border-border/40 hover:bg-accent transition-colors ${
                                                selectedScan?.id === scan.id ? 'bg-accent' : ''
                                            }`}
                                            data-testid={`vuln-scan-item-${scan.id}`}
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="font-medium text-sm truncate">{scan.target}</span>
                                                <Badge variant="outline" className="text-xs">
                                                    {scan.results?.vulnerabilities?.length || 0} vulns
                                                </Badge>
                                            </div>
                                        </button>
                                    )) : (
                                        <div className="text-center py-4 text-muted-foreground text-sm">
                                            No assessments yet
                                        </div>
                                    )}
                                </div>
                            </ScrollArea>
                        </CardContent>
                    </Card>
                </div>

                {/* Right Panel - Results */}
                <div className="lg:col-span-2 overflow-hidden">
                    <Card className="h-full border-border/40 bg-card/20 flex flex-col" data-testid="vuln-results">
                        <CardHeader className="flex flex-row items-center justify-between">
                            <CardTitle className="text-lg">
                                {selectedScan ? `Vulnerabilities: ${selectedScan.target}` : 'Assessment Results'}
                            </CardTitle>
                            {selectedScan && (
                                <Badge variant="outline">
                                    {vulnerabilities.length} found
                                </Badge>
                            )}
                        </CardHeader>
                        <CardContent className="flex-1 overflow-auto">
                            {vulnerabilities.length > 0 ? (
                                <div className="space-y-3">
                                    {vulnerabilities.map((vuln, i) => (
                                        <div key={i} className="p-4 bg-background/50 border border-border/20 space-y-3" data-testid={`vulnerability-${i}`}>
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-center gap-2">
                                                    {getSeverityIcon(vuln.severity)}
                                                    <span className="font-mono text-sm font-medium">{vuln.id}</span>
                                                </div>
                                                <Badge className={getSeverityColor(vuln.severity)}>
                                                    {vuln.severity.toUpperCase()}
                                                </Badge>
                                            </div>
                                            
                                            <p className="text-sm">{vuln.description}</p>
                                            
                                            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                                <span>CVSS: <span className="font-medium text-foreground">{vuln.cvss}</span></span>
                                            </div>
                                            
                                            {vuln.remediation && (
                                                <div className="p-2 bg-green-500/10 border border-green-500/20 text-sm">
                                                    <span className="text-green-400 font-medium">Remediation: </span>
                                                    {vuln.remediation}
                                                </div>
                                            )}
                                        </div>
                                    ))}

                                    {/* Compliance */}
                                    {selectedScan?.results?.compliance && (
                                        <div className="p-4 bg-background/50 border border-border/20">
                                            <h4 className="font-medium mb-2">Compliance Status</h4>
                                            <div className="space-y-2">
                                                <div className="flex items-center justify-between text-sm">
                                                    <span>PCI DSS</span>
                                                    <Badge variant="outline" className={selectedScan.results.compliance.pci_dss === 'Compliant' ? 'border-green-500/30 text-green-400' : 'border-red-500/30 text-red-400'}>
                                                        {selectedScan.results.compliance.pci_dss}
                                                    </Badge>
                                                </div>
                                                {selectedScan.results.compliance.owasp_top10 && (
                                                    <div>
                                                        <span className="text-sm text-muted-foreground">OWASP Top 10 Violations:</span>
                                                        <div className="flex flex-wrap gap-1 mt-1">
                                                            {selectedScan.results.compliance.owasp_top10.map((item, i) => (
                                                                <Badge key={i} variant="outline" className="text-xs border-yellow-500/30 text-yellow-400">
                                                                    {item}
                                                                </Badge>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="h-full flex items-center justify-center text-muted-foreground">
                                    <div className="text-center">
                                        <Bug className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                        <p>Start a vulnerability assessment</p>
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

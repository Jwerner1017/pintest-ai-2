import { useState, useEffect } from 'react';
import { Header } from '../components/layout/Header.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Checkbox } from '../components/ui/checkbox';
import { 
    FileText, 
    Download, 
    Calendar,
    Loader2,
    FileWarning,
    CheckCircle
} from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function ReportsPage() {
    const [scans, setScans] = useState([]);
    const [selectedScans, setSelectedScans] = useState([]);
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(false);
    const [generatingReport, setGeneratingReport] = useState(false);

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        setLoading(true);
        try {
            const [scansRes, reportsRes] = await Promise.all([
                axios.get(`${API_URL}/api/scans`),
                axios.get(`${API_URL}/api/reports`)
            ]);
            setScans(scansRes.data);
            setReports(reportsRes.data.reports || []);
        } catch (error) {
            console.error('Failed to fetch data:', error);
        } finally {
            setLoading(false);
        }
    };

    const toggleScanSelection = (scanId) => {
        setSelectedScans(prev => 
            prev.includes(scanId) 
                ? prev.filter(id => id !== scanId)
                : [...prev, scanId]
        );
    };

    const generateReport = async () => {
        if (selectedScans.length === 0) {
            toast.error('Please select at least one scan');
            return;
        }

        setGeneratingReport(true);
        try {
            const response = await axios.post(`${API_URL}/api/reports/generate`, selectedScans);
            toast.success('Report generated successfully');
            setReports(prev => [response.data, ...prev]);
            setSelectedScans([]);
        } catch (error) {
            console.error('Failed to generate report:', error);
            toast.error('Failed to generate report');
        } finally {
            setGeneratingReport(false);
        }
    };

    const getScanTypeLabel = (type) => {
        const labels = {
            recon: 'Reconnaissance',
            vuln: 'Vulnerability',
            network: 'Network'
        };
        return labels[type] || type;
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="reports-page">
            <Header title="Reports" subtitle="Generate and manage security reports" />
            
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
                {/* Left Panel - Select Scans */}
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="scans-selection">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <CardTitle className="text-lg">Select Scans for Report</CardTitle>
                        <Badge variant="outline">{selectedScans.length} selected</Badge>
                    </CardHeader>
                    <CardContent className="flex-1 overflow-hidden flex flex-col">
                        <ScrollArea className="flex-1">
                            <div className="space-y-2 pr-4">
                                {scans.length > 0 ? scans.map((scan) => (
                                    <div
                                        key={scan.id}
                                        className={`p-4 border border-border/40 cursor-pointer transition-colors ${
                                            selectedScans.includes(scan.id) ? 'bg-accent border-primary/50' : 'hover:bg-accent/50'
                                        }`}
                                        onClick={() => toggleScanSelection(scan.id)}
                                        data-testid={`scan-select-${scan.id}`}
                                    >
                                        <div className="flex items-start gap-3">
                                            <Checkbox 
                                                checked={selectedScans.includes(scan.id)}
                                                onCheckedChange={() => toggleScanSelection(scan.id)}
                                            />
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="font-medium text-sm truncate">{scan.target}</span>
                                                    <Badge variant="outline" className="text-xs">
                                                        {getScanTypeLabel(scan.scan_type)}
                                                    </Badge>
                                                </div>
                                                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                                    <span className="flex items-center gap-1">
                                                        <Calendar className="w-3 h-3" />
                                                        {new Date(scan.created_at).toLocaleDateString()}
                                                    </span>
                                                    {scan.results?.vulnerabilities && (
                                                        <span className="flex items-center gap-1">
                                                            <FileWarning className="w-3 h-3" />
                                                            {scan.results.vulnerabilities.length} vulns
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )) : (
                                    <div className="text-center py-12 text-muted-foreground">
                                        <FileText className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                        <p>No scans available</p>
                                        <p className="text-sm">Run some scans first</p>
                                    </div>
                                )}
                            </div>
                        </ScrollArea>

                        <div className="pt-4 border-t border-border/40 mt-4">
                            <Button 
                                className="w-full" 
                                onClick={generateReport}
                                disabled={selectedScans.length === 0 || generatingReport}
                                data-testid="generate-report-button"
                            >
                                {generatingReport ? (
                                    <>
                                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                        Generating...
                                    </>
                                ) : (
                                    <>
                                        <FileText className="w-4 h-4 mr-2" />
                                        Generate Report
                                    </>
                                )}
                            </Button>
                        </div>
                    </CardContent>
                </Card>

                {/* Right Panel - Generated Reports */}
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="reports-list">
                    <CardHeader>
                        <CardTitle className="text-lg">Generated Reports</CardTitle>
                    </CardHeader>
                    <CardContent className="flex-1 overflow-hidden">
                        <ScrollArea className="h-full">
                            <div className="space-y-4 pr-4">
                                {reports.length > 0 ? reports.map((report) => (
                                    <Card key={report.id} className="border-border/40 bg-background/50" data-testid={`report-${report.id}`}>
                                        <CardContent className="p-4">
                                            <div className="flex items-start justify-between mb-3">
                                                <div>
                                                    <h3 className="font-medium text-sm">{report.title}</h3>
                                                    <p className="text-xs text-muted-foreground">
                                                        {new Date(report.created_at).toLocaleString()}
                                                    </p>
                                                </div>
                                                <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                                                    <CheckCircle className="w-3 h-3 mr-1" />
                                                    Complete
                                                </Badge>
                                            </div>

                                            {/* Summary */}
                                            <div className="grid grid-cols-4 gap-2 mb-3">
                                                <div className="p-2 bg-red-500/10 border border-red-500/20 text-center">
                                                    <p className="text-lg font-bold text-red-400">{report.summary?.critical || 0}</p>
                                                    <p className="text-xs text-muted-foreground">Critical</p>
                                                </div>
                                                <div className="p-2 bg-orange-500/10 border border-orange-500/20 text-center">
                                                    <p className="text-lg font-bold text-orange-400">{report.summary?.high || 0}</p>
                                                    <p className="text-xs text-muted-foreground">High</p>
                                                </div>
                                                <div className="p-2 bg-yellow-500/10 border border-yellow-500/20 text-center">
                                                    <p className="text-lg font-bold text-yellow-400">{report.summary?.medium || 0}</p>
                                                    <p className="text-xs text-muted-foreground">Medium</p>
                                                </div>
                                                <div className="p-2 bg-green-500/10 border border-green-500/20 text-center">
                                                    <p className="text-lg font-bold text-green-400">{report.summary?.low || 0}</p>
                                                    <p className="text-xs text-muted-foreground">Low</p>
                                                </div>
                                            </div>

                                            <div className="flex items-center justify-between">
                                                <span className="text-xs text-muted-foreground">
                                                    {report.scan_count} scan(s) • {report.summary?.total_vulnerabilities || 0} total vulnerabilities
                                                </span>
                                                <Button variant="outline" size="sm" className="text-xs">
                                                    <Download className="w-3 h-3 mr-1" />
                                                    Export
                                                </Button>
                                            </div>
                                        </CardContent>
                                    </Card>
                                )) : (
                                    <div className="text-center py-12 text-muted-foreground">
                                        <FileText className="w-12 h-12 mx-auto mb-4 opacity-30" />
                                        <p>No reports generated</p>
                                        <p className="text-sm">Select scans and generate a report</p>
                                    </div>
                                )}
                            </div>
                        </ScrollArea>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { FileText, Loader2, Download, FileCode } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Checkbox } from '../components/ui/checkbox';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function ReportsPage() {
    const [scans, setScans] = useState([]);
    const [selectedScans, setSelectedScans] = useState([]);
    const [reports, setReports] = useState([]);
    const [generatingReport, setGeneratingReport] = useState(false);
    const [downloadingId, setDownloadingId] = useState(null);
    const [downloadingSarifId, setDownloadingSarifId] = useState(null);

    useEffect(() => { fetchData(); }, []);

    const fetchData = async () => {
        try {
            const [scansRes, reportsRes] = await Promise.all([axios.get(`${API_URL}/api/scans`), axios.get(`${API_URL}/api/reports`)]);
            setScans(scansRes.data);
            setReports(reportsRes.data.reports || []);
        } catch (error) { console.error('Failed to fetch data:', error); }
    };

    const toggleScanSelection = (scanId) => {
        setSelectedScans(prev => prev.includes(scanId) ? prev.filter(id => id !== scanId) : [...prev, scanId]);
    };

    const generateReport = async () => {
        if (selectedScans.length === 0) { toast.error('Please select at least one scan'); return; }
        setGeneratingReport(true);
        try {
            const response = await axios.post(`${API_URL}/api/reports/generate`, selectedScans);
            toast.success('Report generated successfully');
            setReports(prev => [response.data, ...prev]);
            setSelectedScans([]);
        } catch (error) { toast.error('Failed to generate report'); }
        finally { setGeneratingReport(false); }
    };

    const downloadPdf = async (reportId) => {
        setDownloadingId(reportId);
        try {
            const response = await axios.get(`${API_URL}/api/reports/${reportId}/pdf`, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `pentestai-report-${reportId}.pdf`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
            toast.success('Report downloaded');
        } catch (error) {
            toast.error('Failed to download PDF');
        } finally {
            setDownloadingId(null);
        }
    };

    const downloadSarif = async (reportId) => {
        setDownloadingSarifId(reportId);
        try {
            const response = await axios.get(`${API_URL}/api/reports/${reportId}/sarif`, { responseType: 'blob' });
            const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/sarif+json' }));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `pentestai-report-${reportId}.sarif`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
            toast.success('SARIF exported');
        } catch (error) {
            toast.error('Failed to export SARIF');
        } finally {
            setDownloadingSarifId(null);
        }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="reports-page">
            <Header title="Reports" subtitle="Generate and manage security reports" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-hidden">
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="scans-selection">
                    <CardHeader className="flex flex-row items-center justify-between"><CardTitle className="text-lg">Select Scans</CardTitle><Badge variant="outline">{selectedScans.length} selected</Badge></CardHeader>
                    <CardContent className="flex-1 overflow-hidden flex flex-col">
                        <ScrollArea className="flex-1">
                            <div className="space-y-2 pr-4">
                                {scans.map((scan) => (
                                    <div key={scan.id} className={`p-4 border border-border/40 cursor-pointer transition-colors ${selectedScans.includes(scan.id) ? 'bg-accent border-primary/50' : 'hover:bg-accent/50'}`} onClick={() => toggleScanSelection(scan.id)} data-testid={`scan-select-${scan.id}`}>
                                        <div className="flex items-start gap-3">
                                            <Checkbox checked={selectedScans.includes(scan.id)} />
                                            <div className="flex-1"><span className="font-medium text-sm">{scan.target}</span><p className="text-xs text-muted-foreground">{scan.scan_type} - {new Date(scan.created_at).toLocaleDateString()}</p></div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </ScrollArea>
                        <div className="pt-4 border-t border-border/40 mt-4">
                            <Button className="w-full" onClick={generateReport} disabled={selectedScans.length === 0 || generatingReport} data-testid="generate-report-button">
                                {generatingReport ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Generating...</> : <><FileText className="w-4 h-4 mr-2" />Generate Report</>}
                            </Button>
                        </div>
                    </CardContent>
                </Card>
                <Card className="border-border/40 bg-card/20 flex flex-col" data-testid="reports-list">
                    <CardHeader><CardTitle className="text-lg">Generated Reports</CardTitle></CardHeader>
                    <CardContent className="flex-1 overflow-hidden">
                        <ScrollArea className="h-full">
                            <div className="space-y-4 pr-4">
                                {reports.map((report) => (
                                    <Card key={report.id} className="border-border/40 bg-background/50" data-testid={`report-${report.id}`}>
                                        <CardContent className="p-4">
                                            <div className="flex items-start justify-between gap-2">
                                                <div className="min-w-0 flex-1">
                                                    <h3 className="font-medium text-sm truncate">{report.title}</h3>
                                                    <p className="text-xs text-muted-foreground">{new Date(report.created_at).toLocaleString()}</p>
                                                </div>
                                                <div className="flex gap-2 flex-shrink-0">
                                                    <Button
                                                        size="sm"
                                                        variant="outline"
                                                        onClick={() => downloadPdf(report.id)}
                                                        disabled={downloadingId === report.id}
                                                        data-testid={`download-pdf-${report.id}`}
                                                    >
                                                        {downloadingId === report.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Download className="w-4 h-4 mr-1" />PDF</>}
                                                    </Button>
                                                    <Button
                                                        size="sm"
                                                        variant="outline"
                                                        onClick={() => downloadSarif(report.id)}
                                                        disabled={downloadingSarifId === report.id}
                                                        data-testid={`download-sarif-${report.id}`}
                                                        title="SARIF 2.1 — for GitHub Code Scanning, GitLab SAST, etc."
                                                    >
                                                        {downloadingSarifId === report.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <><FileCode className="w-4 h-4 mr-1" />SARIF</>}
                                                    </Button>
                                                </div>
                                            </div>
                                            <div className="grid grid-cols-4 gap-2 mt-3">
                                                <div className="p-2 bg-red-500/10 text-center"><p className="text-lg font-bold text-red-400">{report.summary?.critical || 0}</p><p className="text-xs">Critical</p></div>
                                                <div className="p-2 bg-orange-500/10 text-center"><p className="text-lg font-bold text-orange-400">{report.summary?.high || 0}</p><p className="text-xs">High</p></div>
                                                <div className="p-2 bg-yellow-500/10 text-center"><p className="text-lg font-bold text-yellow-400">{report.summary?.medium || 0}</p><p className="text-xs">Medium</p></div>
                                                <div className="p-2 bg-green-500/10 text-center"><p className="text-lg font-bold text-green-400">{report.summary?.low || 0}</p><p className="text-xs">Low</p></div>
                                            </div>
                                        </CardContent>
                                    </Card>
                                ))}
                            </div>
                        </ScrollArea>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}

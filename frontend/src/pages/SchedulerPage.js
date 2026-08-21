import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { Clock, Plus, Trash2, Play, Pause, Calendar, ExternalLink } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Switch } from '../components/ui/switch';
import { Header } from '../components/layout/Header';
import { PresetSelector } from '../components/scans/PresetSelector';
import { API_URL } from '../lib/api';

const CRON_TEMPLATES = [
    { label: 'Every 15 minutes', value: '*/15 * * * *' },
    { label: 'Every hour', value: '0 * * * *' },
    { label: 'Every 6 hours', value: '0 */6 * * *' },
    { label: 'Daily @ 02:00 UTC', value: '0 2 * * *' },
    { label: 'Weekly (Mon 09:00 UTC)', value: '0 9 * * 1' },
];

const SCAN_TYPES = [
    { value: 'recon', label: 'Reconnaissance' },
    { value: 'vuln', label: 'Vulnerability' },
    { value: 'network', label: 'Network' },
];

function fmt(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

export default function SchedulerPage() {
    const [schedules, setSchedules] = useState([]);
    const [loading, setLoading] = useState(false);
    const [creating, setCreating] = useState(false);

    // Form
    const [name, setName] = useState('');
    const [scanType, setScanType] = useState('recon');
    const [target, setTarget] = useState('');
    const [cron, setCron] = useState('0 * * * *');
    const [preset, setPreset] = useState('fast');

    const fetchSchedules = useCallback(async () => {
        setLoading(true);
        try {
            const res = await axios.get(`${API_URL}/api/schedules`);
            setSchedules(res.data);
        } catch (e) {
            toast.error('Failed to load schedules');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchSchedules(); }, [fetchSchedules]);

    const createSchedule = async () => {
        if (!target.trim() || !cron.trim()) { toast.error('Target and cron are required'); return; }
        setCreating(true);
        try {
            await axios.post(`${API_URL}/api/schedules`, {
                name: name.trim() || `${scanType} · ${target.trim()}`,
                scan_type: scanType,
                target: target.trim(),
                cron: cron.trim(),
                preset,
                enabled: true,
            });
            toast.success('Schedule created');
            setName(''); setTarget('');
            fetchSchedules();
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Failed to create schedule');
        } finally {
            setCreating(false);
        }
    };

    const toggleSchedule = async (id, enabled) => {
        try {
            await axios.patch(`${API_URL}/api/schedules/${id}`, { enabled: !enabled });
            toast.success(enabled ? 'Schedule paused' : 'Schedule enabled');
            fetchSchedules();
        } catch (e) {
            toast.error('Failed to update schedule');
        }
    };

    const deleteSchedule = async (id) => {
        try {
            await axios.delete(`${API_URL}/api/schedules/${id}`);
            toast.success('Schedule deleted');
            fetchSchedules();
        } catch (e) {
            toast.error('Failed to delete schedule');
        }
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="scheduler-page">
            <Header title="Scan Scheduler" subtitle="Cron-style recurring scans (5-field expressions, UTC)" />
            <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-auto">
                <Card className="border-border/40 bg-card/20" data-testid="new-schedule-card">
                    <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2"><Plus className="w-5 h-5 text-primary" />New Schedule</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-2">
                            <Label>Name</Label>
                            <Input
                                placeholder="Nightly recon of production"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                className="bg-background"
                                data-testid="schedule-name-input"
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Scan Type</Label>
                            <Select value={scanType} onValueChange={setScanType}>
                                <SelectTrigger className="bg-background" data-testid="schedule-scantype-trigger"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                    {SCAN_TYPES.map(s => (
                                        <SelectItem key={s.value} value={s.value} data-testid={`schedule-scantype-${s.value}`}>{s.label}</SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="space-y-2">
                            <Label>Target</Label>
                            <Input
                                placeholder="example.com / 10.0.0.0/24"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                className="bg-background"
                                data-testid="schedule-target-input"
                            />
                        </div>
                        <PresetSelector scanType={scanType} value={preset} onChange={setPreset} />
                        <div className="space-y-2">
                            <Label>Cron (UTC)</Label>
                            <Input
                                placeholder="0 * * * *"
                                value={cron}
                                onChange={(e) => setCron(e.target.value)}
                                className="bg-background font-mono"
                                data-testid="schedule-cron-input"
                            />
                            <div className="flex flex-wrap gap-1 pt-1">
                                {CRON_TEMPLATES.map((t, i) => (
                                    <button
                                        key={t.value}
                                        type="button"
                                        onClick={() => setCron(t.value)}
                                        className="text-xs px-2 py-1 border border-border/40 hover:bg-accent transition-colors"
                                        data-testid={`cron-template-${i}`}
                                    >
                                        {t.label}
                                    </button>
                                ))}
                            </div>
                            <p className="text-xs text-muted-foreground">Format: <code className="font-mono">min hour dom mon dow</code>. All times UTC.</p>
                        </div>
                        <Button
                            className="w-full"
                            onClick={createSchedule}
                            disabled={creating || !target.trim() || !cron.trim()}
                            data-testid="create-schedule-button"
                        >
                            {creating ? 'Creating...' : <><Plus className="w-4 h-4 mr-2" />Create Schedule</>}
                        </Button>
                    </CardContent>
                </Card>

                <div className="lg:col-span-2 space-y-4" data-testid="schedule-list">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-semibold flex items-center gap-2"><Calendar className="w-5 h-5 text-primary" />Your Schedules</h2>
                        <Badge variant="outline" data-testid="schedule-count">{schedules.length} total</Badge>
                    </div>
                    {loading ? (
                        <div className="text-sm text-muted-foreground">Loading...</div>
                    ) : schedules.length === 0 ? (
                        <Card className="border-border/40 bg-card/20">
                            <CardContent className="py-16 text-center text-muted-foreground">
                                <Clock className="w-10 h-10 mx-auto mb-3 opacity-40" />
                                <p className="text-sm">No schedules yet. Create one on the left to run scans automatically.</p>
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="space-y-3">
                            {schedules.map(s => (
                                <Card key={s.id} className="border-border/40 bg-card/20" data-testid={`schedule-item-${s.id}`}>
                                    <CardContent className="p-4 space-y-3">
                                        <div className="flex items-start justify-between gap-3">
                                            <div className="min-w-0 flex-1">
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    <h3 className="font-medium truncate">{s.name}</h3>
                                                    <Badge variant="outline" className="text-xs">{s.scan_type}</Badge>
                                                    <Badge variant="outline" className="text-xs">{s.preset}</Badge>
                                                    {s.enabled ? (
                                                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">Active</Badge>
                                                    ) : (
                                                        <Badge className="bg-muted text-muted-foreground text-xs">Paused</Badge>
                                                    )}
                                                </div>
                                                <p className="text-sm text-muted-foreground font-mono truncate mt-1">{s.target}</p>
                                                <p className="text-xs text-muted-foreground mt-1">
                                                    <span className="font-mono">{s.cron}</span>
                                                </p>
                                            </div>
                                            <div className="flex items-center gap-2 flex-shrink-0">
                                                <Switch
                                                    checked={s.enabled}
                                                    onCheckedChange={() => toggleSchedule(s.id, s.enabled)}
                                                    data-testid={`schedule-toggle-${s.id}`}
                                                    aria-label="Enable schedule"
                                                />
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    onClick={() => deleteSchedule(s.id)}
                                                    data-testid={`schedule-delete-${s.id}`}
                                                    title="Delete schedule"
                                                >
                                                    <Trash2 className="w-4 h-4 text-red-400" />
                                                </Button>
                                            </div>
                                        </div>
                                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-border/30 text-xs">
                                            <div>
                                                <span className="text-muted-foreground flex items-center gap-1"><Play className="w-3 h-3" />Next run</span>
                                                <p className="mt-0.5" data-testid={`schedule-next-${s.id}`}>{fmt(s.next_run_at)}</p>
                                            </div>
                                            <div>
                                                <span className="text-muted-foreground flex items-center gap-1"><Pause className="w-3 h-3" />Last run</span>
                                                <p className="mt-0.5" data-testid={`schedule-last-${s.id}`}>{fmt(s.last_run_at)}</p>
                                            </div>
                                            <div>
                                                <span className="text-muted-foreground">Last scan</span>
                                                {s.last_scan_id ? (
                                                    <Link
                                                        to={`/${s.scan_type === 'vuln' ? 'vulnerabilities' : s.scan_type}`}
                                                        className="mt-0.5 flex items-center gap-1 text-primary hover:underline"
                                                        data-testid={`schedule-last-scan-link-${s.id}`}
                                                    >
                                                        <span className="font-mono truncate">{s.last_scan_id.slice(0, 8)}</span>
                                                        <ExternalLink className="w-3 h-3" />
                                                    </Link>
                                                ) : (
                                                    <p className="mt-0.5 text-muted-foreground">—</p>
                                                )}
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

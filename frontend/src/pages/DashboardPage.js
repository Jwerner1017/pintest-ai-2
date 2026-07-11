import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { Target, Activity, Bug, AlertTriangle, Clock, Shield } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Header } from '../components/layout/Header';
import { API_URL } from '../lib/api';

export default function DashboardPage() {
    const [stats, setStats] = useState({ total_scans: 0, active_scans: 0, vulnerabilities_found: 0, critical_alerts: 0, recent_activity: [] });

    useEffect(() => {
        fetchDashboardData();
    }, []);

    const fetchDashboardData = async () => {
        try {
            const statsRes = await axios.get(`${API_URL}/api/dashboard/stats`);
            setStats(statsRes.data);
        } catch (error) {
            console.error('Failed to fetch dashboard data:', error);
        }
    };

    const metricCards = [
        { title: 'Total Scans', value: stats.total_scans, icon: Target, color: 'text-blue-400', bgColor: 'bg-blue-400/10', borderColor: 'border-l-blue-400' },
        { title: 'Active Scans', value: stats.active_scans, icon: Activity, color: 'text-green-400', bgColor: 'bg-green-400/10', borderColor: 'border-l-green-400' },
        { title: 'Vulnerabilities', value: stats.vulnerabilities_found, icon: Bug, color: 'text-yellow-400', bgColor: 'bg-yellow-400/10', borderColor: 'border-l-yellow-400' },
        { title: 'Critical Alerts', value: stats.critical_alerts, icon: AlertTriangle, color: 'text-red-400', bgColor: 'bg-red-400/10', borderColor: 'border-l-red-400' },
    ];

    return (
        <div className="flex-1 flex flex-col" data-testid="dashboard-page">
            <Header title="Dashboard" subtitle="Security Operations Overview" />
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {metricCards.map((metric, index) => {
                        const Icon = metric.icon;
                        return (
                            <Card key={index} className={`border-l-2 ${metric.borderColor} bg-card/20 hover:bg-card/40 transition-colors`} data-testid={`metric-${metric.title.toLowerCase().replace(' ', '-')}`}>
                                <CardContent className="p-6">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-sm text-muted-foreground">{metric.title}</p>
                                            <p className="text-3xl font-bold mt-1">{metric.value}</p>
                                        </div>
                                        <div className={`p-3 ${metric.bgColor}`}>
                                            <Icon className={`w-6 h-6 ${metric.color}`} />
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        );
                    })}
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    <Card className="border-border/40 bg-card/20" data-testid="quick-actions">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Quick Actions</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/recon"><Target className="w-4 h-4" />New Reconnaissance Scan</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/vulnerabilities"><Bug className="w-4 h-4" />Vulnerability Assessment</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/assistant"><Shield className="w-4 h-4" />Ask AI Assistant</Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/reports"><Activity className="w-4 h-4" />Generate Report</Link>
                            </Button>
                        </CardContent>
                    </Card>
                    <Card className="lg:col-span-2 border-border/40 bg-card/20" data-testid="recent-activity">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Recent Activity</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                {stats.recent_activity.length > 0 ? stats.recent_activity.map((activity, index) => (
                                    <div key={index} className="flex items-center gap-4 p-3 bg-background/50 border border-border/20">
                                        <div className="p-2 bg-primary/10"><Activity className="w-4 h-4 text-primary" /></div>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium truncate">{activity.action}</p>
                                            <p className="text-xs text-muted-foreground">{activity.target}</p>
                                        </div>
                                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                            <Clock className="w-3 h-3" />{new Date(activity.created_at).toLocaleTimeString()}
                                        </div>
                                    </div>
                                )) : (
                                    <div className="text-center py-8 text-muted-foreground">
                                        <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                                        <p>No recent activity</p>
                                        <p className="text-sm">Start a scan to see activity here</p>
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    );
}

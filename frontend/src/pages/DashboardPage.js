import { useState, useEffect } from 'react';
import { Header } from '../components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { 
    Shield, 
    Bug, 
    AlertTriangle, 
    Activity,
    ArrowUpRight,
    Target,
    Clock
} from 'lucide-react';
import { 
    LineChart, 
    Line, 
    XAxis, 
    YAxis, 
    CartesianGrid, 
    Tooltip, 
    ResponsiveContainer,
    BarChart,
    Bar,
    Legend
} from 'recharts';
import axios from 'axios';
import { Link } from 'react-router-dom';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function DashboardPage() {
    const [stats, setStats] = useState({
        total_scans: 0,
        active_scans: 0,
        vulnerabilities_found: 0,
        critical_alerts: 0,
        recent_activity: []
    });
    const [trends, setTrends] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchDashboardData();
    }, []);

    const fetchDashboardData = async () => {
        try {
            const [statsRes, trendsRes] = await Promise.all([
                axios.get(`${API_URL}/api/dashboard/stats`),
                axios.get(`${API_URL}/api/dashboard/vulnerability-trends`)
            ]);
            setStats(statsRes.data);
            setTrends(trendsRes.data.trends);
        } catch (error) {
            console.error('Failed to fetch dashboard data:', error);
        } finally {
            setLoading(false);
        }
    };

    const metricCards = [
        { 
            title: 'Total Scans', 
            value: stats.total_scans, 
            icon: Target, 
            color: 'text-blue-400',
            bgColor: 'bg-blue-400/10',
            borderColor: 'border-l-blue-400'
        },
        { 
            title: 'Active Scans', 
            value: stats.active_scans, 
            icon: Activity, 
            color: 'text-green-400',
            bgColor: 'bg-green-400/10',
            borderColor: 'border-l-green-400'
        },
        { 
            title: 'Vulnerabilities', 
            value: stats.vulnerabilities_found, 
            icon: Bug, 
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-400/10',
            borderColor: 'border-l-yellow-400'
        },
        { 
            title: 'Critical Alerts', 
            value: stats.critical_alerts, 
            icon: AlertTriangle, 
            color: 'text-red-400',
            bgColor: 'bg-red-400/10',
            borderColor: 'border-l-red-400'
        },
    ];

    return (
        <div className="flex-1 flex flex-col" data-testid="dashboard-page">
            <Header title="Dashboard" subtitle="Security Operations Overview" />
            
            <div className="flex-1 p-6 space-y-6 overflow-auto">
                {/* Metric Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {metricCards.map((metric, index) => {
                        const Icon = metric.icon;
                        return (
                            <Card 
                                key={index} 
                                className={`border-l-2 ${metric.borderColor} bg-card/20 hover:bg-card/40 transition-colors`}
                                data-testid={`metric-${metric.title.toLowerCase().replace(' ', '-')}`}
                            >
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

                {/* Charts Row */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {/* Vulnerability Trends Chart */}
                    <Card className="lg:col-span-2 border-border/40 bg-card/20" data-testid="vulnerability-trends-chart">
                        <CardHeader className="flex flex-row items-center justify-between">
                            <CardTitle className="text-lg font-semibold">Vulnerability Trends</CardTitle>
                            <Button variant="ghost" size="sm" asChild>
                                <Link to="/vulnerabilities">
                                    View All <ArrowUpRight className="w-4 h-4 ml-1" />
                                </Link>
                            </Button>
                        </CardHeader>
                        <CardContent>
                            <div className="h-72">
                                <ResponsiveContainer width="100%" height="100%">
                                    <LineChart data={trends}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                                        <XAxis 
                                            dataKey="date" 
                                            stroke="hsl(var(--muted-foreground))"
                                            fontSize={12}
                                            tickFormatter={(value) => value.split('-')[2]}
                                        />
                                        <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                                        <Tooltip 
                                            contentStyle={{ 
                                                backgroundColor: 'hsl(var(--card))',
                                                border: '1px solid hsl(var(--border))',
                                                borderRadius: '4px'
                                            }}
                                        />
                                        <Legend />
                                        <Line type="monotone" dataKey="critical" stroke="#EF4444" strokeWidth={2} dot={false} />
                                        <Line type="monotone" dataKey="high" stroke="#F59E0B" strokeWidth={2} dot={false} />
                                        <Line type="monotone" dataKey="medium" stroke="#3B82F6" strokeWidth={2} dot={false} />
                                        <Line type="monotone" dataKey="low" stroke="#10B981" strokeWidth={2} dot={false} />
                                    </LineChart>
                                </ResponsiveContainer>
                            </div>
                        </CardContent>
                    </Card>

                    {/* Severity Distribution */}
                    <Card className="border-border/40 bg-card/20" data-testid="severity-distribution-chart">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Severity Distribution</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="h-72">
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart 
                                        data={[
                                            { name: 'Critical', count: stats.critical_alerts || 2, fill: '#EF4444' },
                                            { name: 'High', count: 5, fill: '#F59E0B' },
                                            { name: 'Medium', count: 8, fill: '#3B82F6' },
                                            { name: 'Low', count: 12, fill: '#10B981' },
                                        ]}
                                        layout="vertical"
                                    >
                                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                                        <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                                        <YAxis dataKey="name" type="category" stroke="hsl(var(--muted-foreground))" fontSize={12} width={60} />
                                        <Tooltip 
                                            contentStyle={{ 
                                                backgroundColor: 'hsl(var(--card))',
                                                border: '1px solid hsl(var(--border))',
                                                borderRadius: '4px'
                                            }}
                                        />
                                        <Bar dataKey="count" radius={[0, 4, 4, 0]} />
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        </CardContent>
                    </Card>
                </div>

                {/* Quick Actions & Recent Activity */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {/* Quick Actions */}
                    <Card className="border-border/40 bg-card/20" data-testid="quick-actions">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Quick Actions</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/recon">
                                    <Target className="w-4 h-4" />
                                    New Reconnaissance Scan
                                </Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/vulnerabilities">
                                    <Bug className="w-4 h-4" />
                                    Vulnerability Assessment
                                </Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/assistant">
                                    <Shield className="w-4 h-4" />
                                    Ask AI Assistant
                                </Link>
                            </Button>
                            <Button variant="outline" className="w-full justify-start gap-2" asChild>
                                <Link to="/reports">
                                    <Activity className="w-4 h-4" />
                                    Generate Report
                                </Link>
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Recent Activity */}
                    <Card className="lg:col-span-2 border-border/40 bg-card/20" data-testid="recent-activity">
                        <CardHeader>
                            <CardTitle className="text-lg font-semibold">Recent Activity</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                {stats.recent_activity.length > 0 ? (
                                    stats.recent_activity.map((activity, index) => (
                                        <div key={index} className="flex items-center gap-4 p-3 bg-background/50 border border-border/20">
                                            <div className="p-2 bg-primary/10">
                                                <Activity className="w-4 h-4 text-primary" />
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <p className="text-sm font-medium truncate">{activity.action}</p>
                                                <p className="text-xs text-muted-foreground">{activity.target}</p>
                                            </div>
                                            <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                                <Clock className="w-3 h-3" />
                                                {new Date(activity.created_at).toLocaleTimeString()}
                                            </div>
                                        </div>
                                    ))
                                ) : (
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

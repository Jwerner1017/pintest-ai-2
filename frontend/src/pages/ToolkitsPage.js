import { useEffect, useState } from 'react';
import axios from 'axios';
import { ExternalLink, Hammer, Shield, Eye, Wifi } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Header } from '../components/layout/Header';
import { LaunchDistroButton } from '../components/scans/LaunchDistroButton';
import { API_URL } from '../lib/api';

const FOCUS_ICONS = {
    deft: Eye,
    backbox: Hammer,
    kodachi: Shield,
    pentoo: Wifi,
};

const FOCUS_ACCENT = {
    deft: 'border-l-blue-400 text-blue-400 bg-blue-400/10',
    backbox: 'border-l-orange-400 text-orange-400 bg-orange-400/10',
    kodachi: 'border-l-purple-400 text-purple-400 bg-purple-400/10',
    pentoo: 'border-l-emerald-400 text-emerald-400 bg-emerald-400/10',
};

export default function ToolkitsPage() {
    const [distros, setDistros] = useState([]);

    useEffect(() => {
        axios.get(`${API_URL}/api/distros`).then(r => setDistros(r.data.distros || [])).catch(() => {});
    }, []);

    return (
        <div className="flex-1 flex flex-col" data-testid="toolkits-page">
            <Header title="Security Toolkits" subtitle="Purpose-built Linux distros — pick the right environment for the job" />
            <div className="flex-1 p-6 overflow-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-6xl">
                    {distros.map(d => {
                        const Icon = FOCUS_ICONS[d.id] || Hammer;
                        const accent = FOCUS_ACCENT[d.id] || 'border-l-primary text-primary bg-primary/10';
                        const [borderClass, textClass, bgClass] = accent.split(' ');
                        return (
                            <Card key={d.id} className={`border-l-2 ${borderClass} bg-card/20`} data-testid={`distro-${d.id}`}>
                                <CardHeader>
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="flex items-center gap-3">
                                            <div className={`p-2 ${bgClass}`}>
                                                <Icon className={`w-5 h-5 ${textClass}`} />
                                            </div>
                                            <div>
                                                <CardTitle className="text-lg">{d.name}</CardTitle>
                                                <p className="text-xs text-muted-foreground">{d.full_name}</p>
                                            </div>
                                        </div>
                                        <a
                                            href={d.site}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-muted-foreground hover:text-primary p-1"
                                            data-testid={`distro-link-${d.id}`}
                                            aria-label={`Visit ${d.name} website`}
                                        >
                                            <ExternalLink className="w-4 h-4" />
                                        </a>
                                    </div>
                                    <p className={`text-sm font-medium pt-2 ${textClass}`}>{d.focus}</p>
                                    <p className="text-sm text-muted-foreground italic">{d.tagline}</p>
                                </CardHeader>
                                <CardContent className="space-y-3">
                                    <div>
                                        <p className="text-xs font-medium uppercase text-muted-foreground mb-1">Best For</p>
                                        <ul className="text-sm space-y-0.5 list-disc list-inside text-foreground/90">
                                            {d.best_for.map((b, i) => <li key={i}>{b}</li>)}
                                        </ul>
                                    </div>
                                    <div>
                                        <p className="text-xs font-medium uppercase text-muted-foreground mb-1">Key Tools</p>
                                        <div className="flex flex-wrap gap-1">
                                            {d.key_tools.map((t, i) => (
                                                <Badge key={i} variant="outline" className="text-xs font-mono">{t}</Badge>
                                            ))}
                                        </div>
                                    </div>
                                    <div className="p-2 bg-background/50 border border-border/30 text-xs">
                                        <span className="font-medium text-foreground">When to use: </span>
                                        <span className="text-muted-foreground">{d.use_when}</span>
                                    </div>
                                    <div className="pt-1">
                                        <LaunchDistroButton distroId={d.id} distroName={d.name} variant="default" />
                                    </div>
                                </CardContent>
                            </Card>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}

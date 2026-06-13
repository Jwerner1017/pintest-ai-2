import { Card, CardContent } from '../ui/card';
import { Badge } from '../ui/badge';
import { Lightbulb, ExternalLink } from 'lucide-react';
import { LaunchDistroButton } from './LaunchDistroButton';

/**
 * Inline recommendation card shown on scan results — suggests purpose-built
 * Linux distros for the current scan type, with one-click launch.
 */
export function DistroRecommendation({ recommendation, target, scanId }) {
    if (!recommendation || !recommendation.primary || recommendation.primary.length === 0) return null;
    return (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="distro-recommendation">
            <CardContent className="p-4 space-y-3">
                <div className="flex items-center gap-2 text-sm font-medium text-amber-400">
                    <Lightbulb className="w-4 h-4" />Recommended toolkits for follow-up work
                </div>
                <p className="text-xs text-muted-foreground">{recommendation.rationale}</p>
                <div className="space-y-2">
                    {recommendation.primary.map(d => (
                        <div
                            key={d.id}
                            className="flex items-center justify-between gap-2 p-2.5 bg-background/60 border border-border/40 hover:border-amber-400/40 transition-colors"
                            data-testid={`distro-recommend-${d.id}`}
                        >
                            <div className="flex items-center gap-2 min-w-0">
                                <span className="font-medium text-sm truncate">{d.name}</span>
                                <Badge variant="outline" className="text-xs flex-shrink-0">{d.focus.split('&')[0].trim()}</Badge>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                                <LaunchDistroButton
                                    distroId={d.id}
                                    distroName={d.name}
                                    target={target}
                                    scanId={scanId}
                                />
                                <a
                                    href={d.site}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-muted-foreground hover:text-primary p-1"
                                    data-testid={`distro-recommend-site-${d.id}`}
                                    aria-label={`Visit ${d.name} website`}
                                >
                                    <ExternalLink className="w-4 h-4" />
                                </a>
                            </div>
                        </div>
                    ))}
                </div>
            </CardContent>
        </Card>
    );
}


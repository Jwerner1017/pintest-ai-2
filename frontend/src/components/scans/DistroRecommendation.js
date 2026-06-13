import { Card, CardContent } from '../ui/card';
import { Badge } from '../ui/badge';
import { Lightbulb, ExternalLink } from 'lucide-react';

/**
 * Inline recommendation card shown on scan results — suggests purpose-built
 * Linux distros for the current scan type.
 */
export function DistroRecommendation({ recommendation }) {
    if (!recommendation || !recommendation.primary || recommendation.primary.length === 0) return null;
    return (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="distro-recommendation">
            <CardContent className="p-4 space-y-3">
                <div className="flex items-center gap-2 text-sm font-medium text-amber-400">
                    <Lightbulb className="w-4 h-4" />Recommended toolkits for follow-up work
                </div>
                <p className="text-xs text-muted-foreground">{recommendation.rationale}</p>
                <div className="flex flex-wrap gap-2">
                    {recommendation.primary.map(d => (
                        <a
                            key={d.id}
                            href={d.site}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-background/60 border border-border/40 hover:border-amber-400/40 transition-colors text-sm"
                            data-testid={`distro-recommend-${d.id}`}
                        >
                            <span className="font-medium">{d.name}</span>
                            <Badge variant="outline" className="text-xs">{d.focus.split('&')[0].trim()}</Badge>
                            <ExternalLink className="w-3 h-3 text-muted-foreground" />
                        </a>
                    ))}
                </div>
            </CardContent>
        </Card>
    );
}

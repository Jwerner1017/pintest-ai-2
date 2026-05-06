import { Loader2, CheckCircle, XCircle } from 'lucide-react';
import { Progress } from '../ui/progress';

export function ScanProgress({ scan }) {
    if (!scan) return null;
    const { status, progress = 0, stage } = scan;

    const StatusIcon = status === 'completed' ? CheckCircle
        : status === 'failed' ? XCircle
        : Loader2;
    const colorClass = status === 'completed' ? 'text-green-400'
        : status === 'failed' ? 'text-red-400'
        : 'text-primary';

    return (
        <div className="space-y-2 p-3 bg-background/50 border border-border/40" data-testid="scan-progress">
            <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                    <StatusIcon className={`w-4 h-4 ${colorClass} ${status === 'running' ? 'animate-spin' : ''}`} />
                    <span className="font-mono uppercase">{status}</span>
                    {stage && <span className="text-muted-foreground">— {stage}</span>}
                </div>
                <span className="font-mono text-muted-foreground" data-testid="scan-progress-percent">{progress}%</span>
            </div>
            <Progress value={progress} className="h-1.5" />
        </div>
    );
}

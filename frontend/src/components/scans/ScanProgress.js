import { Loader2, CheckCircle, XCircle, Ban } from 'lucide-react';
import { Progress } from '../ui/progress';
import { Button } from '../ui/button';

export function ScanProgress({ scan, onCancel }) {
    if (!scan) return null;
    const { status, progress = 0, stage } = scan;

    const StatusIcon = status === 'completed' ? CheckCircle
        : status === 'failed' || status === 'cancelled' ? XCircle
        : Loader2;
    const colorClass = status === 'completed' ? 'text-green-400'
        : status === 'failed' || status === 'cancelled' ? 'text-red-400'
        : 'text-primary';
    const isRunning = status === 'running' || status === 'queued';

    return (
        <div className="space-y-2 p-3 bg-background/50 border border-border/40" data-testid="scan-progress">
            <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 min-w-0">
                    <StatusIcon className={`w-4 h-4 flex-shrink-0 ${colorClass} ${isRunning ? 'animate-spin' : ''}`} />
                    <span className="font-mono uppercase">{status}</span>
                    {stage && <span className="text-muted-foreground truncate">— {stage}</span>}
                </div>
                <span className="font-mono text-muted-foreground" data-testid="scan-progress-percent">{progress}%</span>
            </div>
            <Progress value={progress} className="h-1.5" />
            {isRunning && onCancel && (
                <Button
                    variant="ghost"
                    size="sm"
                    className="w-full h-7 text-xs text-muted-foreground hover:text-destructive"
                    onClick={onCancel}
                    data-testid="scan-cancel-button"
                >
                    <Ban className="w-3 h-3 mr-1" />Cancel scan
                </Button>
            )}
        </div>
    );
}

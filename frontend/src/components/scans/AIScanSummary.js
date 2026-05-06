import { useState } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Sparkles, Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Card, CardContent } from '../ui/card';
import { API_URL } from '../../lib/api';

export function AIScanSummary({ scanId, initialSummary }) {
    const [summary, setSummary] = useState(initialSummary || null);
    const [loading, setLoading] = useState(false);

    const generate = async () => {
        if (!scanId) return;
        setLoading(true);
        try {
            const res = await axios.post(`${API_URL}/api/scans/${scanId}/summary`);
            setSummary(res.data.summary);
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Failed to generate summary');
        } finally {
            setLoading(false);
        }
    };

    if (summary) {
        return (
            <Card className="border-primary/30 bg-primary/5" data-testid="ai-summary-card">
                <CardContent className="p-4 space-y-2">
                    <div className="flex items-center gap-2 text-sm font-medium text-primary">
                        <Sparkles className="w-4 h-4" />AI Executive Summary
                    </div>
                    <div className="text-sm whitespace-pre-wrap leading-relaxed" data-testid="ai-summary-text">
                        {summary}
                    </div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Button
            variant="outline"
            size="sm"
            onClick={generate}
            disabled={loading || !scanId}
            data-testid="ai-summary-button"
            className="gap-2"
        >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4 text-primary" />}
            {loading ? 'Generating...' : 'AI Summary'}
        </Button>
    );
}

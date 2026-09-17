import { useState } from 'react';
import axios from 'axios';
import { CheckCircle2, ChevronDown, Clipboard, Loader2, RotateCcw, Sparkles, Terminal } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../ui/collapsible';
import { API_URL } from '../../lib/api';

function toMarkdown(finding, plan) {
    const steps = plan.steps.map((step, index) => {
        const commands = step.commands?.length ? `\n${step.commands.map((cmd) => `   - \`${cmd}\``).join('\n')}` : '';
        return `${index + 1}. **${step.title}** — ${step.action}\n   ${step.details}${commands}`;
    }).join('\n');
    return `# ${finding.id} remediation\n\n**Priority:** ${plan.priority}\n\n${plan.summary}\n\n## Steps\n${steps}\n\n## Validation\n${plan.validation.map((item) => `- ${item}`).join('\n')}\n\n## Rollback\n${plan.rollback.map((item) => `- ${item}`).join('\n')}`;
}

export function AIRemediation({ scanId, findingIndex, finding }) {
    const initial = finding.ai_remediation;
    const [plan, setPlan] = useState(initial?.plan || null);
    const [metadata, setMetadata] = useState(initial || null);
    const [loading, setLoading] = useState(false);
    const [open, setOpen] = useState(Boolean(initial));

    const generate = async () => {
        setLoading(true);
        try {
            const { data } = await axios.post(`${API_URL}/api/scans/${scanId}/remediations/${findingIndex}`);
            setPlan(data.remediation);
            setMetadata({ model: data.model, generated_at: data.generated_at });
            setOpen(true);
            toast.success('DevOps remediation plan ready');
        } catch (error) {
            toast.error(error.response?.data?.detail || 'Failed to generate remediation');
        } finally {
            setLoading(false);
        }
    };

    const copyPlan = async () => {
        try {
            await navigator.clipboard.writeText(toMarkdown(finding, plan));
            toast.success('Remediation copied as Markdown');
        } catch {
            toast.error('Could not copy remediation');
        }
    };

    if (!plan) {
        return (
            <Button
                variant="outline"
                size="sm"
                onClick={generate}
                disabled={loading}
                className="gap-2 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10"
                data-testid={`generate-remediation-button-${findingIndex}`}
            >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                {loading ? 'Building fix...' : 'Build DevOps Fix'}
            </Button>
        );
    }

    return (
        <Collapsible open={open} onOpenChange={setOpen} className="border border-emerald-500/25 bg-emerald-500/[0.04]" data-testid={`ai-remediation-${findingIndex}`}>
            <div className="flex flex-wrap items-center justify-between gap-2 p-3">
                <CollapsibleTrigger asChild>
                    <Button variant="ghost" size="sm" className="gap-2 px-0 hover:bg-transparent" data-testid={`remediation-toggle-${findingIndex}`}>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span>AI remediation</span>
                        <Badge variant="outline" data-testid={`remediation-priority-${findingIndex}`}>{plan.priority}</Badge>
                        <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
                    </Button>
                </CollapsibleTrigger>
                <Button variant="ghost" size="icon" onClick={copyPlan} title="Copy as Markdown" data-testid={`copy-remediation-button-${findingIndex}`}>
                    <Clipboard className="w-4 h-4" />
                </Button>
            </div>
            <CollapsibleContent>
                <div className="border-t border-emerald-500/20 p-4 space-y-4 animate-fade-in" data-testid={`remediation-content-${findingIndex}`}>
                    <p className="text-sm text-foreground" data-testid={`remediation-summary-${findingIndex}`}>{plan.summary}</p>
                    <ol className="space-y-4">
                        {plan.steps.map((step, index) => (
                            <li key={`${step.title}-${index}`} className="grid grid-cols-[1.75rem_1fr] gap-2" data-testid={`remediation-step-${findingIndex}-${index}`}>
                                <span className="flex h-7 w-7 items-center justify-center border border-emerald-500/30 font-mono text-xs text-emerald-300">{index + 1}</span>
                                <div className="min-w-0 space-y-1">
                                    <p className="text-sm font-semibold">{step.title}</p>
                                    <p className="text-sm text-emerald-200/90">{step.action}</p>
                                    <p className="text-xs leading-relaxed text-muted-foreground">{step.details}</p>
                                    {step.commands?.map((command, commandIndex) => (
                                        <pre key={commandIndex} className="mt-2 overflow-x-auto border border-border/40 bg-black/60 p-2 text-xs text-green-300" data-testid={`remediation-command-${findingIndex}-${index}-${commandIndex}`}><Terminal className="mr-2 inline h-3 w-3" />{command}</pre>
                                    ))}
                                </div>
                            </li>
                        ))}
                    </ol>
                    <div className="grid gap-4 md:grid-cols-2">
                        <div data-testid={`remediation-validation-${findingIndex}`}>
                            <p className="mb-2 text-xs font-semibold uppercase text-emerald-400">Validation</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">{plan.validation.map((item, index) => <li key={index}>• {item}</li>)}</ul>
                        </div>
                        <div data-testid={`remediation-rollback-${findingIndex}`}>
                            <p className="mb-2 flex items-center gap-1 text-xs font-semibold uppercase text-amber-400"><RotateCcw className="h-3 w-3" />Rollback</p>
                            <ul className="space-y-1 text-xs text-muted-foreground">{plan.rollback.map((item, index) => <li key={index}>• {item}</li>)}</ul>
                        </div>
                    </div>
                    {metadata?.model && <p className="text-[10px] text-muted-foreground" data-testid={`remediation-metadata-${findingIndex}`}>{metadata.model} · {new Date(metadata.generated_at).toLocaleString()}</p>}
                </div>
            </CollapsibleContent>
        </Collapsible>
    );
}
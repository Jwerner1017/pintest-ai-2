import { useState, useEffect } from 'react';
import axios from 'axios';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { API_URL } from '../../lib/api';

export function PresetSelector({ scanType, value, onChange }) {
    const [presets, setPresets] = useState([]);

    useEffect(() => {
        let cancelled = false;
        axios.get(`${API_URL}/api/scans/presets`).then(r => {
            if (!cancelled) setPresets(r.data[scanType] || []);
        }).catch(() => {});
        return () => { cancelled = true; };
    }, [scanType]);

    if (presets.length === 0) return null;

    return (
        <div className="space-y-1" data-testid={`preset-selector-${scanType}`}>
            <Label className="text-xs">Scan Preset</Label>
            <Select value={value || 'fast'} onValueChange={onChange}>
                <SelectTrigger className="bg-background h-9" data-testid={`preset-trigger-${scanType}`}>
                    <SelectValue />
                </SelectTrigger>
                <SelectContent>
                    {presets.map(p => (
                        <SelectItem key={p.name} value={p.name} data-testid={`preset-${scanType}-${p.name}`}>
                            <div className="flex flex-col">
                                <span className="font-medium">{p.label}</span>
                                <span className="text-xs text-muted-foreground">{p.description}</span>
                            </div>
                        </SelectItem>
                    ))}
                </SelectContent>
            </Select>
        </div>
    );
}

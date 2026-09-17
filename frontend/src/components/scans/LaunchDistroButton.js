import { useState } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { Rocket, Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { API_URL } from '../../lib/api';

/**
 * One-click "Launch in distro" button — downloads a bash setup script for the
 * given distro pre-loaded with the scan target.
 */
export function LaunchDistroButton({ distroId, distroName, target = '', scanId = '', size = 'sm', variant = 'outline' }) {
    const [loading, setLoading] = useState(false);

    const download = async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams();
            if (target) params.set('target', target);
            if (scanId) params.set('scan_id', scanId);
            const url = `${API_URL}/api/distros/${distroId}/launch?${params.toString()}`;
            const response = await axios.get(url, { responseType: 'blob' });
            const cd = response.headers['content-disposition'] || '';
            const match = cd.match(/filename="?([^"]+)"?/);
            const filename = match ? match[1] : `launch-${distroId}.sh`;
            const blob = new Blob([response.data], { type: 'text/x-shellscript' });
            const objectUrl = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = objectUrl;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(objectUrl);
            toast.success(`Launch script for ${distroName || distroId} downloaded`);
        } catch (e) {
            toast.error(`Failed to generate ${distroName || distroId} launch script`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Button
            size={size}
            variant={variant}
            onClick={download}
            disabled={loading}
            data-testid={`launch-distro-${distroId}`}
            className="gap-1.5"
            title={`Download bash script to spin up ${distroName || distroId} with target pre-loaded`}
        >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rocket className="w-3.5 h-3.5" />}
            Launch
        </Button>
    );
}

import { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { API_URL } from '../lib/api';

/**
 * Polls /api/scans/{scanId} until status is 'completed' or 'failed'.
 * Returns { scan, polling }.
 */
export function useScanPolling(scanId, { intervalMs = 2000, onComplete } = {}) {
    const [scan, setScan] = useState(null);
    const [polling, setPolling] = useState(false);
    const onCompleteRef = useRef(onComplete);
    onCompleteRef.current = onComplete;

    useEffect(() => {
        if (!scanId) return;
        let cancelled = false;
        setPolling(true);

        const tick = async () => {
            if (cancelled) return;
            try {
                const res = await axios.get(`${API_URL}/api/scans/${scanId}`);
                if (cancelled) return;
                setScan(res.data);
                if (res.data.status === 'completed' || res.data.status === 'failed') {
                    setPolling(false);
                    if (onCompleteRef.current) onCompleteRef.current(res.data);
                    return;
                }
                setTimeout(tick, intervalMs);
            } catch (e) {
                if (!cancelled) {
                    setPolling(false);
                }
            }
        };
        tick();

        return () => {
            cancelled = true;
            setPolling(false);
        };
    }, [scanId, intervalMs]);

    return { scan, polling };
}

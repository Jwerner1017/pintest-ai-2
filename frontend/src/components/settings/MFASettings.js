import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import axios from 'axios';
import { KeyRound, ShieldCheck, Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { API_URL } from '../../lib/api';

export function MFASettings() {
    const [status, setStatus] = useState({ mfa_enabled: false });
    const [loading, setLoading] = useState(false);
    const [setupData, setSetupData] = useState(null);
    const [code, setCode] = useState('');

    useEffect(() => { fetchStatus(); }, []);

    const fetchStatus = async () => {
        try {
            const res = await axios.get(`${API_URL}/api/auth/mfa/status`);
            setStatus(res.data);
        } catch (e) {
            console.error(e);
        }
    };

    const startSetup = async () => {
        setLoading(true);
        try {
            const res = await axios.post(`${API_URL}/api/auth/mfa/setup`);
            setSetupData(res.data);
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Failed to start MFA setup');
        } finally {
            setLoading(false);
        }
    };

    const enableMfa = async () => {
        if (code.length !== 6) return;
        setLoading(true);
        try {
            await axios.post(`${API_URL}/api/auth/mfa/enable`, { code });
            toast.success('Two-factor authentication enabled');
            setSetupData(null);
            setCode('');
            fetchStatus();
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Invalid code');
        } finally {
            setLoading(false);
        }
    };

    const disableMfa = async () => {
        if (code.length !== 6) return;
        setLoading(true);
        try {
            await axios.post(`${API_URL}/api/auth/mfa/disable`, { code });
            toast.success('Two-factor authentication disabled');
            setCode('');
            fetchStatus();
        } catch (e) {
            toast.error(e.response?.data?.detail || 'Invalid code');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Card className="border-border/40 bg-card/20" data-testid="mfa-settings">
            <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2 justify-between">
                    <span className="flex items-center gap-2"><KeyRound className="w-5 h-5 text-primary" />Two-Factor Authentication</span>
                    {status.mfa_enabled ? (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30" data-testid="mfa-enabled-badge">
                            <ShieldCheck className="w-3 h-3 mr-1" />Enabled
                        </Badge>
                    ) : (
                        <Badge variant="outline" data-testid="mfa-disabled-badge">Disabled</Badge>
                    )}
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                    Add an extra layer of security with time-based one-time passwords (TOTP). Compatible with Google Authenticator, Authy, 1Password and more.
                </p>

                {!status.mfa_enabled && !setupData && (
                    <Button onClick={startSetup} disabled={loading} data-testid="mfa-start-setup-button">
                        {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <KeyRound className="w-4 h-4 mr-2" />}
                        Set up authenticator
                    </Button>
                )}

                {!status.mfa_enabled && setupData && (
                    <div className="space-y-4 p-4 bg-background/50 border border-border/40">
                        <div>
                            <Label className="text-sm">1. Scan this QR code with your authenticator app</Label>
                            <div className="mt-2 flex justify-center p-4 bg-white" data-testid="mfa-qr-code">
                                <img src={setupData.qr_code} alt="MFA QR Code" className="w-48 h-48" />
                            </div>
                        </div>
                        <div>
                            <Label className="text-sm">Or enter this secret manually</Label>
                            <Input readOnly value={setupData.secret} className="font-mono text-xs mt-1 bg-background" data-testid="mfa-secret-code" />
                        </div>
                        <div>
                            <Label className="text-sm" htmlFor="mfa-enable-code">2. Enter the 6-digit code from your app</Label>
                            <div className="flex gap-2 mt-1">
                                <Input
                                    id="mfa-enable-code"
                                    inputMode="numeric"
                                    maxLength={6}
                                    value={code}
                                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                                    placeholder="123456"
                                    className="bg-background font-mono tracking-widest"
                                    data-testid="mfa-enable-code-input"
                                />
                                <Button onClick={enableMfa} disabled={loading || code.length !== 6} data-testid="mfa-enable-button">
                                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Enable'}
                                </Button>
                            </div>
                        </div>
                    </div>
                )}

                {status.mfa_enabled && (
                    <div className="space-y-2">
                        <Label className="text-sm" htmlFor="mfa-disable-code">Enter current 6-digit code to disable</Label>
                        <div className="flex gap-2">
                            <Input
                                id="mfa-disable-code"
                                inputMode="numeric"
                                maxLength={6}
                                value={code}
                                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                                placeholder="123456"
                                className="bg-background font-mono tracking-widest"
                                data-testid="mfa-disable-code-input"
                            />
                            <Button variant="destructive" onClick={disableMfa} disabled={loading || code.length !== 6} data-testid="mfa-disable-button">
                                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Disable'}
                            </Button>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

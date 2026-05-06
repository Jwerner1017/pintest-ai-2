import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, AlertCircle, KeyRound } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { useAuth } from '../contexts/AuthContext';
import { API_URL } from '../lib/api';

export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    // MFA step state
    const [mfaToken, setMfaToken] = useState(null);
    const [mfaCode, setMfaCode] = useState('');
    const { login, completeMfaLogin } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            const result = await login(email, password);
            if (result?.mfaRequired) {
                setMfaToken(result.mfaToken);
                return;
            }
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.detail || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    const handleMfaSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await completeMfaLogin(mfaToken, mfaCode);
            navigate('/dashboard');
        } catch (err) {
            setError(err.response?.data?.detail || 'Invalid code');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4" style={{ backgroundImage: 'linear-gradient(to right, rgba(128, 128, 128, 0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(128, 128, 128, 0.07) 1px, transparent 1px)', backgroundSize: '24px 24px' }}>
            <div className="w-full max-w-md space-y-8">
                <div className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 bg-primary/10 border border-primary/20">
                            <Shield className="w-10 h-10 text-primary" />
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight">PentestAI</h1>
                    <p className="text-muted-foreground mt-2">AI-Enhanced Penetration Testing Platform</p>
                </div>
                <Card className="border-border/40 bg-card/50 backdrop-blur-sm">
                    {!mfaToken ? (
                        <>
                            <CardHeader>
                                <CardTitle className="text-xl">Sign In</CardTitle>
                                <CardDescription>Enter your credentials to access the platform</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <form onSubmit={handleSubmit} className="space-y-4">
                                    {error && (
                                        <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-sm" data-testid="login-error">
                                            <AlertCircle className="w-4 h-4" />
                                            {error}
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <Label htmlFor="email">Email</Label>
                                        <Input id="email" type="email" placeholder="admin@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required className="bg-background" data-testid="login-email-input" />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="password">Password</Label>
                                        <Input id="password" type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required className="bg-background" data-testid="login-password-input" />
                                    </div>
                                    <Button type="submit" className="w-full" disabled={loading} data-testid="login-submit-button">
                                        {loading ? 'Signing in...' : 'Sign In'}
                                    </Button>
                                </form>
                                <div className="mt-6 text-center text-sm">
                                    <span className="text-muted-foreground">Don't have an account? </span>
                                    <Link to="/register" className="text-primary hover:underline" data-testid="register-link">Create one</Link>
                                </div>
                            </CardContent>
                        </>
                    ) : (
                        <>
                            <CardHeader>
                                <CardTitle className="text-xl flex items-center gap-2"><KeyRound className="w-5 h-5 text-primary" />Two-Factor Authentication</CardTitle>
                                <CardDescription>Enter the 6-digit code from your authenticator app</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <form onSubmit={handleMfaSubmit} className="space-y-4">
                                    {error && (
                                        <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-sm" data-testid="mfa-error">
                                            <AlertCircle className="w-4 h-4" />
                                            {error}
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <Label htmlFor="mfa-code">Authentication Code</Label>
                                        <Input
                                            id="mfa-code"
                                            type="text"
                                            inputMode="numeric"
                                            autoComplete="one-time-code"
                                            placeholder="123 456"
                                            maxLength={6}
                                            value={mfaCode}
                                            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                                            required
                                            autoFocus
                                            className="bg-background tracking-widest text-center text-lg font-mono"
                                            data-testid="mfa-code-input"
                                        />
                                    </div>
                                    <Button type="submit" className="w-full" disabled={loading || mfaCode.length !== 6} data-testid="mfa-submit-button">
                                        {loading ? 'Verifying...' : 'Verify'}
                                    </Button>
                                    <Button type="button" variant="ghost" className="w-full" onClick={() => { setMfaToken(null); setMfaCode(''); setError(''); }} data-testid="mfa-back-button">
                                        Back to login
                                    </Button>
                                </form>
                            </CardContent>
                        </>
                    )}
                </Card>
            </div>
        </div>
    );
}

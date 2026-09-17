import { useState } from 'react';
import { toast } from 'sonner';
import { Palette, Shield, Sun, Moon } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Header } from '../components/layout/Header';
import { MFASettings } from '../components/settings/MFASettings';
import { useAuth } from '../contexts/AuthContext';

export default function SettingsPage() {
    const { user } = useAuth();
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(newTheme);
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="settings-page">
            <Header title="Settings" subtitle="Manage your preferences and account" />
            <div className="flex-1 p-6 overflow-auto">
                <div className="max-w-3xl mx-auto space-y-6">
                    <Card className="border-border/40 bg-card/20" data-testid="appearance-settings">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Palette className="w-5 h-5 text-primary" />Appearance</CardTitle></CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div><Label>Theme</Label><p className="text-sm text-muted-foreground">Switch between dark and light mode</p></div>
                                <div className="flex items-center gap-2">
                                    <Sun className="w-4 h-4 text-muted-foreground" />
                                    <Switch checked={theme === 'dark'} onCheckedChange={toggleTheme} data-testid="theme-switch" />
                                    <Moon className="w-4 h-4 text-muted-foreground" />
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                    <Card className="border-border/40 bg-card/20" data-testid="account-settings">
                        <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Shield className="w-5 h-5 text-primary" />Account</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2"><Label>Username</Label><Input value={user?.username || ''} disabled className="bg-background" /></div>
                                <div className="space-y-2"><Label>Email</Label><Input value={user?.email || ''} disabled className="bg-background" /></div>
                            </div>
                            <div className="space-y-2"><Label>Role</Label><Input value={user?.role || 'tester'} disabled className="bg-background capitalize" /></div>
                        </CardContent>
                    </Card>
                    <MFASettings />
                    <div className="flex justify-end"><Button onClick={() => toast.success('Settings saved')} data-testid="save-settings-button">Save Settings</Button></div>
                </div>
            </div>
        </div>
    );
}

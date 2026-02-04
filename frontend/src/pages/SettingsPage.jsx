import { Header } from '../components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Switch } from '../components/ui/switch';
import { Separator } from '../components/ui/separator';
import { useTheme } from '../contexts/ThemeContext';
import { useAuth } from '../contexts/AuthContext';
import { Sun, Moon, Shield, Key, Bell, Palette } from 'lucide-react';
import { toast } from 'sonner';

export default function SettingsPage() {
    const { theme, toggleTheme } = useTheme();
    const { user } = useAuth();

    const handleSave = () => {
        toast.success('Settings saved successfully');
    };

    return (
        <div className="flex-1 flex flex-col" data-testid="settings-page">
            <Header title="Settings" subtitle="Manage your preferences and account" />
            
            <div className="flex-1 p-6 overflow-auto">
                <div className="max-w-3xl mx-auto space-y-6">
                    {/* Appearance */}
                    <Card className="border-border/40 bg-card/20" data-testid="appearance-settings">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Palette className="w-5 h-5 text-primary" />
                                Appearance
                            </CardTitle>
                            <CardDescription>Customize the look and feel</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Theme</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Switch between dark and light mode
                                    </p>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Sun className="w-4 h-4 text-muted-foreground" />
                                    <Switch
                                        checked={theme === 'dark'}
                                        onCheckedChange={toggleTheme}
                                        data-testid="theme-switch"
                                    />
                                    <Moon className="w-4 h-4 text-muted-foreground" />
                                </div>
                            </div>

                            <Separator className="bg-border/40" />

                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Terminal Scanlines</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Add retro scanline effect to terminal
                                    </p>
                                </div>
                                <Switch defaultChecked data-testid="scanlines-switch" />
                            </div>
                        </CardContent>
                    </Card>

                    {/* Account */}
                    <Card className="border-border/40 bg-card/20" data-testid="account-settings">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Shield className="w-5 h-5 text-primary" />
                                Account
                            </CardTitle>
                            <CardDescription>Your account information</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <Label>Username</Label>
                                    <Input 
                                        value={user?.username || ''} 
                                        disabled 
                                        className="bg-background"
                                        data-testid="username-input"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label>Email</Label>
                                    <Input 
                                        value={user?.email || ''} 
                                        disabled 
                                        className="bg-background"
                                        data-testid="email-input"
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <Label>Role</Label>
                                <Input 
                                    value={user?.role || 'tester'} 
                                    disabled 
                                    className="bg-background capitalize"
                                    data-testid="role-input"
                                />
                            </div>
                        </CardContent>
                    </Card>

                    {/* API Configuration */}
                    <Card className="border-border/40 bg-card/20" data-testid="api-settings">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Key className="w-5 h-5 text-primary" />
                                API Configuration
                            </CardTitle>
                            <CardDescription>Configure external API integrations</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label>Shodan API Key (Optional)</Label>
                                <Input 
                                    type="password" 
                                    placeholder="Enter your Shodan API key" 
                                    className="bg-background"
                                    data-testid="shodan-api-input"
                                />
                                <p className="text-xs text-muted-foreground">
                                    Used for enhanced reconnaissance capabilities
                                </p>
                            </div>
                            <div className="space-y-2">
                                <Label>VirusTotal API Key (Optional)</Label>
                                <Input 
                                    type="password" 
                                    placeholder="Enter your VirusTotal API key" 
                                    className="bg-background"
                                    data-testid="virustotal-api-input"
                                />
                                <p className="text-xs text-muted-foreground">
                                    Used for malware and URL analysis
                                </p>
                            </div>
                        </CardContent>
                    </Card>

                    {/* Notifications */}
                    <Card className="border-border/40 bg-card/20" data-testid="notification-settings">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Bell className="w-5 h-5 text-primary" />
                                Notifications
                            </CardTitle>
                            <CardDescription>Configure alert preferences</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Critical Vulnerability Alerts</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Get notified when critical vulnerabilities are found
                                    </p>
                                </div>
                                <Switch defaultChecked data-testid="critical-alerts-switch" />
                            </div>
                            <Separator className="bg-border/40" />
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Scan Completion</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Notify when scans complete
                                    </p>
                                </div>
                                <Switch defaultChecked data-testid="scan-complete-switch" />
                            </div>
                        </CardContent>
                    </Card>

                    {/* Save Button */}
                    <div className="flex justify-end">
                        <Button onClick={handleSave} data-testid="save-settings-button">
                            Save Settings
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    );
}

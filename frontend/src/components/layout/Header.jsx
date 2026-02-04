import { useTheme } from '../../contexts/ThemeContext.jsx';
import { Button } from '../ui/button';
import { Sun, Moon, Bell, Search } from 'lucide-react';
import { Input } from '../ui/input';

export function Header({ title, subtitle }) {
    const { theme, toggleTheme } = useTheme();

    return (
        <header className="glass-header px-6 py-4 flex items-center justify-between" data-testid="header">
            <div>
                <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
                {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
            </div>

            <div className="flex items-center gap-4">
                <div className="relative hidden md:block">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input 
                        placeholder="Search targets, scans..." 
                        className="pl-9 w-64 bg-background"
                        data-testid="header-search"
                    />
                </div>

                <Button 
                    variant="ghost" 
                    size="icon"
                    className="relative"
                    data-testid="notifications-button"
                >
                    <Bell className="w-5 h-5" />
                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full" />
                </Button>

                <Button 
                    variant="ghost" 
                    size="icon"
                    onClick={toggleTheme}
                    data-testid="theme-toggle"
                >
                    {theme === 'dark' ? (
                        <Sun className="w-5 h-5" />
                    ) : (
                        <Moon className="w-5 h-5" />
                    )}
                </Button>
            </div>
        </header>
    );
}

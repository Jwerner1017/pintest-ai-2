import { useState, useEffect } from 'react';
import { Bell, Search, Sun, Moon } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';

export function Header({ title, subtitle }) {
    const [theme, setTheme] = useState('dark');

    useEffect(() => {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        setTheme(savedTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(savedTheme);
    }, []);

    const toggleTheme = () => {
        const newTheme = theme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(newTheme);
    };

    return (
        <header className="sticky top-0 z-50 flex min-w-0 items-center justify-between gap-3 border-b border-border/40 bg-background/80 py-4 pl-16 pr-3 backdrop-blur-md sm:pr-4 md:px-6" data-testid="header">
            <div className="min-w-0">
                <h1 className="truncate text-xl font-bold sm:text-2xl" data-testid="header-title">{title}</h1>
                {subtitle && <p className="truncate text-xs text-muted-foreground sm:text-sm" data-testid="header-subtitle">{subtitle}</p>}
            </div>
            <div className="flex shrink-0 items-center gap-1 sm:gap-2 md:gap-4">
                <div className="relative hidden md:block">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input placeholder="Search targets, scans..." className="pl-9 w-64 bg-background" data-testid="header-search" />
                </div>
                <Button variant="ghost" size="icon" className="relative" data-testid="notifications-button">
                    <Bell className="w-5 h-5" />
                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full" />
                </Button>
                <Button variant="ghost" size="icon" onClick={toggleTheme} data-testid="theme-toggle">
                    {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                </Button>
            </div>
        </header>
    );
}

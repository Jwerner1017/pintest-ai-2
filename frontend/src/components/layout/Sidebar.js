import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Shield, LayoutDashboard, Search, Bug, Network, MessageSquare,
    FileText, Settings, Terminal, LogOut, ChevronLeft, ChevronRight
} from 'lucide-react';
import { Button } from '../ui/button';
import { useAuth } from '../../contexts/AuthContext';

const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/recon', label: 'Reconnaissance', icon: Search },
    { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { path: '/network', label: 'Network', icon: Network },
    { path: '/assistant', label: 'AI Assistant', icon: MessageSquare },
    { path: '/terminal', label: 'Terminal', icon: Terminal },
    { path: '/reports', label: 'Reports', icon: FileText },
    { path: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
    const location = useLocation();
    const { user, logout } = useAuth();
    const [collapsed, setCollapsed] = useState(false);

    return (
        <aside className={`h-screen sticky top-0 border-r border-border/40 bg-card/30 backdrop-blur-sm flex flex-col transition-all duration-200 ${collapsed ? 'w-16' : 'w-64'}`} data-testid="sidebar">
            <div className="p-4 border-b border-border/40 flex items-center justify-between">
                {!collapsed && (
                    <Link to="/dashboard" className="flex items-center gap-2" data-testid="sidebar-logo">
                        <Shield className="w-6 h-6 text-primary" />
                        <span className="font-bold text-lg">PentestAI</span>
                    </Link>
                )}
                {collapsed && (
                    <Link to="/dashboard" className="mx-auto" data-testid="sidebar-logo-collapsed">
                        <Shield className="w-6 h-6 text-primary" />
                    </Link>
                )}
                <Button variant="ghost" size="icon" onClick={() => setCollapsed(!collapsed)} className={`h-8 w-8 ${collapsed ? 'mx-auto' : ''}`} data-testid="sidebar-toggle">
                    {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
                </Button>
            </div>

            <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
                {navItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = location.pathname === item.path;
                    return (
                        <Link
                            key={item.path}
                            to={item.path}
                            className={`flex items-center gap-3 px-3 py-2 text-sm font-medium transition-colors ${isActive ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'} ${collapsed ? 'justify-center' : ''}`}
                            data-testid={`nav-${item.path.slice(1)}`}
                            title={collapsed ? item.label : undefined}
                        >
                            <Icon className="w-5 h-5 flex-shrink-0" />
                            {!collapsed && <span>{item.label}</span>}
                        </Link>
                    );
                })}
            </nav>

            <div className="p-4 border-t border-border/40">
                {!collapsed ? (
                    <div className="space-y-3">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 bg-primary/20 flex items-center justify-center text-primary font-medium text-sm">
                                {user?.username?.charAt(0).toUpperCase() || 'U'}
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium truncate">{user?.username}</p>
                                <p className="text-xs text-muted-foreground truncate">{user?.role}</p>
                            </div>
                        </div>
                        <Button variant="outline" size="sm" className="w-full justify-start gap-2" onClick={logout} data-testid="logout-button">
                            <LogOut className="w-4 h-4" />
                            Logout
                        </Button>
                    </div>
                ) : (
                    <Button variant="ghost" size="icon" className="w-full" onClick={logout} data-testid="logout-button-collapsed" title="Logout">
                        <LogOut className="w-5 h-5" />
                    </Button>
                )}
            </div>
        </aside>
    );
}

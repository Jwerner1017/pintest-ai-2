import { useState } from 'react';
import { Menu, X } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { Button } from '../ui/button';

export function MainLayout({ children }) {
    const [mobileNavOpen, setMobileNavOpen] = useState(false);

    return (
        <div className="flex min-h-screen w-full overflow-x-hidden bg-background" data-testid="main-layout">
            <Button
                variant="outline"
                size="icon"
                className="fixed left-3 top-3 z-[80] md:hidden"
                onClick={() => setMobileNavOpen((open) => !open)}
                aria-label={mobileNavOpen ? 'Close navigation' : 'Open navigation'}
                data-testid="mobile-navigation-toggle"
            >
                {mobileNavOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
            {mobileNavOpen && (
                <button
                    type="button"
                    className="fixed inset-0 z-[60] bg-black/70 backdrop-blur-sm md:hidden"
                    onClick={() => setMobileNavOpen(false)}
                    aria-label="Close navigation overlay"
                    data-testid="mobile-navigation-overlay"
                />
            )}
            <Sidebar mobileOpen={mobileNavOpen} onMobileClose={() => setMobileNavOpen(false)} />
            <main className="flex min-w-0 flex-1 flex-col overflow-hidden">{children}</main>
        </div>
    );
}

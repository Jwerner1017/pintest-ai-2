import { Sidebar } from './Sidebar';

export function MainLayout({ children }) {
    return (
        <div className="flex min-h-screen bg-background" data-testid="main-layout">
            <Sidebar />
            <main className="flex-1 flex flex-col overflow-hidden">{children}</main>
        </div>
    );
}

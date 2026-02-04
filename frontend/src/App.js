import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { MainLayout } from './components/layout/MainLayout';
import { Toaster } from './components/ui/sonner';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import AssistantPage from './pages/AssistantPage';
import ReconPage from './pages/ReconPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import NetworkPage from './pages/NetworkPage';
import TerminalPage from './pages/TerminalPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import './App.css';

function ProtectedRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    
    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="text-center">
                    <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                    <p className="text-muted-foreground">Loading...</p>
                </div>
            </div>
        );
    }
    
    return isAuthenticated ? children : <Navigate to="/login" replace />;
}

function PublicRoute({ children }) {
    const { isAuthenticated, loading } = useAuth();
    
    if (loading) {
        return null;
    }
    
    return isAuthenticated ? <Navigate to="/dashboard" replace /> : children;
}

function AppRoutes() {
    return (
        <Routes>
            {/* Public routes */}
            <Route path="/login" element={
                <PublicRoute>
                    <LoginPage />
                </PublicRoute>
            } />
            <Route path="/register" element={
                <PublicRoute>
                    <RegisterPage />
                </PublicRoute>
            } />
            
            {/* Protected routes */}
            <Route element={
                <ProtectedRoute>
                    <MainLayout />
                </ProtectedRoute>
            }>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/recon" element={<ReconPage />} />
                <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
                <Route path="/network" element={<NetworkPage />} />
                <Route path="/assistant" element={<AssistantPage />} />
                <Route path="/terminal" element={<TerminalPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
            </Route>
            
            {/* Redirect root to dashboard */}
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
    );
}

function App() {
    return (
        <BrowserRouter>
            <ThemeProvider>
                <AuthProvider>
                    <AppRoutes />
                    <Toaster position="bottom-right" richColors />
                </AuthProvider>
            </ThemeProvider>
        </BrowserRouter>
    );
}

export default App;

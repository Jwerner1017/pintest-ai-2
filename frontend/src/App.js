import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'sonner';
import { AuthProvider } from './contexts/AuthContext';
import { ProtectedRoute, PublicRoute } from './components/routes/ProtectedRoute';
import { MainLayout } from './components/layout/MainLayout';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import ReconPage from './pages/ReconPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import NetworkPage from './pages/NetworkPage';
import AssistantPage from './pages/AssistantPage';
import TerminalPage from './pages/TerminalPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import ToolkitsPage from './pages/ToolkitsPage';
import SchedulerPage from './pages/SchedulerPage';
import './App.css';

function AppRoutes() {
    return (
        <Routes>
            <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
            <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />
            <Route path="/dashboard" element={<ProtectedRoute><MainLayout><DashboardPage /></MainLayout></ProtectedRoute>} />
            <Route path="/recon" element={<ProtectedRoute><MainLayout><ReconPage /></MainLayout></ProtectedRoute>} />
            <Route path="/vulnerabilities" element={<ProtectedRoute><MainLayout><VulnerabilitiesPage /></MainLayout></ProtectedRoute>} />
            <Route path="/network" element={<ProtectedRoute><MainLayout><NetworkPage /></MainLayout></ProtectedRoute>} />
            <Route path="/assistant" element={<ProtectedRoute><MainLayout><AssistantPage /></MainLayout></ProtectedRoute>} />
            <Route path="/terminal" element={<ProtectedRoute><MainLayout><TerminalPage /></MainLayout></ProtectedRoute>} />
            <Route path="/reports" element={<ProtectedRoute><MainLayout><ReportsPage /></MainLayout></ProtectedRoute>} />
            <Route path="/toolkits" element={<ProtectedRoute><MainLayout><ToolkitsPage /></MainLayout></ProtectedRoute>} />
            <Route path="/scheduler" element={<ProtectedRoute><MainLayout><SchedulerPage /></MainLayout></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><MainLayout><SettingsPage /></MainLayout></ProtectedRoute>} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
    );
}

export default function App() {
    return (
        <BrowserRouter>
            <AuthProvider>
                <AppRoutes />
                <Toaster position="bottom-right" richColors />
            </AuthProvider>
        </BrowserRouter>
    );
}

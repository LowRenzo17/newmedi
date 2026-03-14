import { useState, Suspense, lazy } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import Header from './components/layout/Header';
import NotificationPanel from './components/notifications/NotificationPanel';
import { Bell } from 'lucide-react';

// Lazy loading heavy components
const LoginForm = lazy(() => import('./components/auth/LoginForm'));
const RegisterForm = lazy(() => import('./components/auth/RegisterForm'));
const PatientDashboard = lazy(() => import('./components/patient/PatientDashboard'));
const DoctorDashboard = lazy(() => import('./components/doctor/DoctorDashboard'));
const AdminDashboard = lazy(() => import('./components/admin/AdminDashboard'));

function AppContent() {
  const { user, profile, loading } = useAuth();
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [showNotifications, setShowNotifications] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen animated-gradient-bg flex items-center justify-center">
        <div className="text-center glass-panel p-10">
          <div className="w-16 h-16 bg-white rounded-xl flex items-center justify-center mx-auto mb-4 animate-pulse shadow-lg">
            <span className="text-teal-600 font-bold text-3xl">M</span>
          </div>
          <p className="text-gray-800 font-medium text-lg">Loading MediReach...</p>
        </div>
      </div>
    );
  }

  if (!user || !profile) {
    return (
      <div className="min-h-screen animated-gradient-bg flex flex-col items-center justify-center p-4">
        <div className="mb-8 text-center">
          <div className="w-20 h-20 bg-white rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-xl transform transition hover:scale-105 duration-300">
            <span className="text-teal-600 font-bold text-4xl">M</span>
          </div>
          <h1 className="text-5xl font-extrabold text-white mb-2 drop-shadow-md">MediReach</h1>
          <p className="text-white/90 text-xl font-medium drop-shadow-sm">Remote Medical Care Platform</p>
        </div>

      <Suspense fallback={
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
        </div>
      }>
        <div className="w-full max-w-md">
          {authMode === 'login' ? (
            <LoginForm onSwitchToRegister={() => setAuthMode('register')} />
          ) : (
            <RegisterForm onSwitchToLogin={() => setAuthMode('login')} />
          )}
        </div>
      </Suspense>
      </div>
    );
  }

  const renderDashboard = () => {
    switch (profile.role) {
      case 'patient':
        return <PatientDashboard />;
      case 'doctor':
        return <DoctorDashboard />;
      case 'admin':
        return <AdminDashboard />;
      default:
        return (
          <div className="text-center py-12">
            <p className="text-gray-600 dark:text-gray-300">Invalid user role</p>
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Header />

      <button
        onClick={() => setShowNotifications(true)}
        className="fixed right-6 bottom-6 w-14 h-14 bg-teal-600 hover:bg-teal-700 text-white rounded-full shadow-lg flex items-center justify-center transition z-40"
      >
        <Bell className="w-6 h-6" />
        <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
          3
        </span>
      </button>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Suspense fallback={
          <div className="flex justify-center items-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-teal-600"></div>
          </div>
        }>
          {renderDashboard()}
        </Suspense>
      </main>

      <NotificationPanel
        isOpen={showNotifications}
        onClose={() => setShowNotifications(false)}
      />
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}

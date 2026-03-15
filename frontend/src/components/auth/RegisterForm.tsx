import { useState } from 'react';
import { Mail, Lock, User, AlertCircle, Stethoscope, Heart } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

interface RegisterFormProps {
  onSwitchToLogin: () => void;
}

export default function RegisterForm({ onSwitchToLogin }: RegisterFormProps) {
  const { signUp } = useAuth();
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'patient' as 'patient' | 'doctor',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    const emailLower = formData.email.toLowerCase();
    if (!emailLower.endsWith('.com') && !emailLower.endsWith('.net')) {
      setError('Email must end with .com or .net');
      return;
    }

    const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordPattern.test(formData.password)) {
      setError('Password must be at least 8 characters, contain an uppercase letter, lowercase letter, a number, and a special character.');
      return;
    }

    setLoading(true);

    const { error } = await signUp(
      formData.email,
      formData.password,
      formData.fullName,
      formData.role
    );

    if (error) {
      const msg = typeof error === 'string' ? error : (error?.message || String(error));
      setError(msg);
      setLoading(false);
      return;
    }

    setLoading(false);
  };

  return (
    <div className="w-full max-w-md">
      <div className="glass-panel p-8">
        <div className="text-center mb-8">
          <h2 className="text-4xl font-extrabold gradient-text drop-shadow-sm pb-1">Create Account</h2>
          <p className="text-gray-700 font-medium mt-2">Join MediReach today</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              I am a
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setFormData({ ...formData, role: 'patient' })}
                className={`p-4 border-2 rounded-xl transition ${
                  formData.role === 'patient'
                    ? 'border-teal-500 bg-teal-50/80 shadow-inner'
                    : 'border-gray-200/60 bg-white/40 hover:border-gray-300'
                }`}
              >
                <Heart className={`w-6 h-6 mx-auto mb-2 ${
                  formData.role === 'patient' ? 'text-teal-600' : 'text-gray-400'
                }`} />
                <span className={`text-sm font-semibold ${
                  formData.role === 'patient' ? 'text-teal-700' : 'text-gray-600'
                }`}>
                  Patient
                </span>
              </button>
              <button
                type="button"
                onClick={() => setFormData({ ...formData, role: 'doctor' })}
                className={`p-4 border-2 rounded-xl transition ${
                  formData.role === 'doctor'
                    ? 'border-teal-500 bg-teal-50/80 shadow-inner'
                    : 'border-gray-200/60 bg-white/40 hover:border-gray-300'
                }`}
              >
                <Stethoscope className={`w-6 h-6 mx-auto mb-2 ${
                  formData.role === 'doctor' ? 'text-teal-600' : 'text-gray-400'
                }`} />
                <span className={`text-sm font-medium ${
                  formData.role === 'doctor' ? 'text-teal-600' : 'text-gray-600'
                }`}>
                  Doctor
                </span>
              </button>
            </div>
          </div>

          <div>
            <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-2">
              Full Name
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                id="fullName"
                type="text"
                required
                value={formData.fullName}
                onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
                className="w-full pl-11 pr-4 py-3 border border-gray-300/50 bg-white/50 rounded-xl focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none transition backdrop-blur-sm"
                placeholder="John Doe"
              />
            </div>
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                id="email"
                type="email"
                required
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                className="w-full pl-11 pr-4 py-3 border border-gray-300/50 bg-white/50 rounded-xl focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none transition backdrop-blur-sm"
                placeholder="you@example.com"
              />
            </div>
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                id="password"
                type="password"
                required
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="w-full pl-11 pr-4 py-3 border border-gray-300/50 bg-white/50 rounded-xl focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none transition backdrop-blur-sm"
                placeholder="••••••••"
              />
            </div>
          </div>

          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
              Confirm Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                id="confirmPassword"
                type="password"
                required
                value={formData.confirmPassword}
                onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                className="w-full pl-11 pr-4 py-3 border border-gray-300/50 bg-white/50 rounded-xl focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none transition backdrop-blur-sm"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-teal-500 to-blue-600 hover:from-teal-600 hover:to-blue-700 text-white font-semibold py-3.5 rounded-xl shadow-lg transform transition hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
          >
            {loading ? 'Creating account...' : 'Sign Up'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <p className="text-gray-600">
            Already have an account?{' '}
            <button
              onClick={onSwitchToLogin}
              className="text-teal-600 hover:text-teal-700 font-medium"
            >
              Sign in
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}

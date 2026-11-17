import React, { useState } from 'react';
import {
  Shield,
  Lock,
  User,
  Mail,
  Key,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  ShieldAlert,
  Fingerprint,
  Radio,
  Copy,
  Check,
  UserPlus,
  LogIn
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function AuthPage({ onLoginSuccess }) {
  const { login, register, forgotPassword, resetPassword, authError, setAuthError } = useAuth();

  const [mode, setMode] = useState('login'); // 'login' | 'register' | 'forgot' | 'reset'
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);

  // Form states
  const [loginForm, setLoginForm] = useState({
    username: '',
    password: '',
    rememberMe: true
  });

  const [registerForm, setRegisterForm] = useState({
    full_name: '',
    username: '',
    email: '',
    password: '',
    confirm_password: '',
    role: 'Investigator',
    agreeTerms: true
  });

  const [forgotIdentifier, setForgotIdentifier] = useState('');
  const [issuedResetToken, setIssuedResetToken] = useState('');
  const [resetForm, setResetForm] = useState({
    token: '',
    new_password: '',
    confirm_new_password: ''
  });

  // Calculate password strength
  const getPasswordStrength = (pass) => {
    if (!pass) return 0;
    let score = 0;
    if (pass.length >= 8) score += 25;
    if (/[A-Z]/.test(pass)) score += 25;
    if (/[0-9]/.test(pass)) score += 25;
    if (/[^A-Za-z0-9]/.test(pass)) score += 25;
    return score;
  };

  const strength = getPasswordStrength(registerForm.password);

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    setAuthError(null);

    const res = await login(loginForm.username, loginForm.password);
    setLoading(false);

    if (res.success) {
      if (onLoginSuccess) onLoginSuccess(res.user);
    }
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    if (registerForm.password !== registerForm.confirm_password) {
      setAuthError('Passwords do not match. Please verify.');
      return;
    }
    if (registerForm.password.length < 6) {
      setAuthError('Password must be at least 6 characters long.');
      return;
    }

    setLoading(true);
    setMessage(null);
    setAuthError(null);

    const res = await register({
      full_name: registerForm.full_name || 'Forensic Examiner',
      username: registerForm.username.trim(),
      email: registerForm.email.trim(),
      password: registerForm.password,
      role: registerForm.role
    });

    setLoading(false);
    if (res.success) {
      if (onLoginSuccess) onLoginSuccess(res.user);
    }
  };

  const handleForgotSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    setAuthError(null);

    const res = await forgotPassword(forgotIdentifier);
    setLoading(false);

    if (res.success) {
      const token = res.data?.reset_token;
      if (token) {
        setIssuedResetToken(token);
        setResetForm((prev) => ({ ...prev, token }));
        setMessage('Recovery token issued successfully! You may now specify a new password below.');
        setMode('reset');
      } else {
        setMessage('If an account matches that identifier, password reset instructions have been issued.');
      }
    } else {
      setAuthError(res.error || 'Failed to issue reset token.');
    }
  };

  const handleResetSubmit = async (e) => {
    e.preventDefault();
    if (resetForm.new_password !== resetForm.confirm_new_password) {
      setAuthError('Passwords do not match.');
      return;
    }
    if (resetForm.new_password.length < 6) {
      setAuthError('New password must be at least 6 characters long.');
      return;
    }

    setLoading(true);
    setMessage(null);
    setAuthError(null);

    const res = await resetPassword(resetForm.token, resetForm.new_password);
    setLoading(false);

    if (res.success) {
      setMessage('Password successfully updated! Please log in with your new credentials.');
      setMode('login');
      setLoginForm((prev) => ({ ...prev, password: '' }));
    } else {
      setAuthError(res.error || 'Password reset failed.');
    }
  };

  const prefillRoleCredentials = (roleName) => {
    const roleLower = roleName.toLowerCase();
    setLoginForm({
      username: `${roleLower}_examiner`,
      password: `CyberTrace${roleName}2026!`,
      rememberMe: true
    });
    setRegisterForm({
      full_name: `${roleName} Forensic Specialist`,
      username: `${roleLower}_examiner`,
      email: `${roleLower}@cybertrace.local`,
      password: `CyberTrace${roleName}2026!`,
      confirm_password: `CyberTrace${roleName}2026!`,
      role: roleName,
      agreeTerms: true
    });
    setAuthError(null);
    setMessage(`Sample ${roleName} credentials prefilled. Click Enroll or Sign In.`);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#060a14] text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans select-none">
      {/* Dynamic Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] bg-cyan-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-indigo-950/20 rounded-full blur-[180px] pointer-events-none" />

      {/* Cyber Grid Overlay */}
      <div
        className="absolute inset-0 opacity-[0.03] pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(#00f2fe 1px, transparent 1px), linear-gradient(to right, #00f2fe 1px, transparent 1px)`,
          backgroundSize: '40px 40px'
        }}
      />

      {/* Main Glassmorphic Container */}
      <div className="w-full max-w-xl z-10 my-6">
        {/* Platform Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-2xl bg-cyan-950/60 border border-cyan-500/30 backdrop-blur-md mb-3 shadow-[0_0_25px_rgba(6,182,212,0.15)]">
            <Shield className="w-7 h-7 text-cyan-400" />
            <span className="font-mono font-bold text-xl tracking-wider text-cyan-400">
              CYBER<span className="text-blue-500">TRACE</span>
            </span>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-600/40">
              DFIR Console
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
            Digital Forensics & Incident Investigation Platform
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1 flex items-center justify-center gap-2">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            ISO/IEC 27037 Evidentiary Standard & NIST FIPS 180-4 Compliant
          </p>
        </div>

        {/* Authentication Card */}
        <div className="bg-[#0b1222]/90 border border-slate-800/80 rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl relative">
          {/* Mode Switcher Tabs */}
          <div className="flex rounded-xl bg-slate-900/90 p-1 border border-slate-800 mb-6">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setAuthError(null);
                setMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-mono font-medium rounded-lg transition-all flex items-center justify-center gap-2 ${
                mode === 'login'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LogIn className="w-3.5 h-3.5" />
              Sign In
            </button>

            <button
              type="button"
              onClick={() => {
                setMode('register');
                setAuthError(null);
                setMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-mono font-medium rounded-lg transition-all flex items-center justify-center gap-2 ${
                mode === 'register'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <UserPlus className="w-3.5 h-3.5" />
              Register
            </button>

            <button
              type="button"
              onClick={() => {
                setMode('forgot');
                setAuthError(null);
                setMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-mono font-medium rounded-lg transition-all flex items-center justify-center gap-2 ${
                mode === 'forgot' || mode === 'reset'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              Recovery
            </button>
          </div>

          {/* Feedback Banners */}
          {authError && (
            <div className="mb-5 p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-red-300 text-xs flex items-start gap-2.5 animate-fadeIn">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Authentication Error</p>
                <p className="text-red-300/90 mt-0.5">{authError}</p>
              </div>
            </div>
          )}

          {message && (
            <div className="mb-5 p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs flex items-start gap-2.5 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Operation Completed</p>
                <p className="text-emerald-300/90 mt-0.5">{message}</p>
              </div>
            </div>
          )}

          {/* 1. LOGIN FORM */}
          {mode === 'login' && (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-cyan-400" />
                  Investigator Username or Email
                </label>
                <div className="relative">
                  <input
                    type="text"
                    required
                    value={loginForm.username}
                    onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                    placeholder="e.g. admin_examiner or examiner@cybertrace.local"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-mono text-slate-300 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    Cryptographic Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setMode('forgot');
                      setAuthError(null);
                      setMessage(null);
                    }}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
                  >
                    Forgot Password?
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={loginForm.password}
                    onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                    placeholder="Enter account password"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-3 text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={loginForm.rememberMe}
                    onChange={(e) => setLoginForm({ ...loginForm, rememberMe: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                  />
                  <span>Persist session (24 Hours)</span>
                </label>
                <span className="text-[10px] text-slate-500">JWT HMAC-SHA256</span>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold font-mono text-sm tracking-wide shadow-lg shadow-cyan-500/25 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {loading ? (
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <Fingerprint className="w-4 h-4" />
                    Authenticate & Access Console
                    <ArrowRight className="w-4 h-4 ml-1" />
                  </>
                )}
              </button>
            </form>
          )}

          {/* 2. REGISTRATION FORM */}
          {mode === 'register' && (
            <form onSubmit={handleRegisterSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    Full Legal / Official Name
                  </label>
                  <input
                    type="text"
                    required
                    value={registerForm.full_name}
                    onChange={(e) => setRegisterForm({ ...registerForm, full_name: e.target.value })}
                    placeholder="e.g. Dr. Alex Vance, CISSP"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <UserPlus className="w-3.5 h-3.5 text-cyan-400" />
                    Username
                  </label>
                  <input
                    type="text"
                    required
                    value={registerForm.username}
                    onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                    placeholder="e.g. alex_examiner"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                  <Mail className="w-3.5 h-3.5 text-cyan-400" />
                  Official Examiner Email
                </label>
                <input
                  type="email"
                  required
                  value={registerForm.email}
                  onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                  placeholder="examiner@dfir-agency.org"
                  className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              {/* Role Selection */}
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-2">
                  Select Role-Based Access Privileges (RBAC):
                </label>
                <div className="grid grid-cols-3 gap-2.5">
                  {[
                    {
                      role: 'Investigator',
                      badge: 'border-cyan-500/40 text-cyan-300 bg-cyan-950/40',
                      desc: 'Full Evidence & Analysis Access'
                    },
                    {
                      role: 'Admin',
                      badge: 'border-purple-500/40 text-purple-300 bg-purple-950/40',
                      desc: 'System & Case Administration'
                    },
                    {
                      role: 'Viewer',
                      badge: 'border-amber-500/40 text-amber-300 bg-amber-950/40',
                      desc: 'Read-Only Audit & Reports'
                    }
                  ].map((item) => (
                    <button
                      key={item.role}
                      type="button"
                      onClick={() => setRegisterForm({ ...registerForm, role: item.role })}
                      className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                        registerForm.role === item.role
                          ? `${item.badge} ring-1 ring-cyan-400`
                          : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <span className="font-mono font-bold text-xs block">{item.role}</span>
                      <span className="text-[10px] text-slate-500 leading-tight block mt-1">
                        {item.desc}
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    Cryptographic Password
                  </label>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={registerForm.password}
                    onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                    placeholder="Minimum 6 characters"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                  {/* Strength Bar */}
                  <div className="w-full bg-slate-800 h-1 rounded-full mt-2 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${
                        strength < 50 ? 'bg-red-500' : strength < 75 ? 'bg-amber-400' : 'bg-emerald-400'
                      }`}
                      style={{ width: `${strength}%` }}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-400" />
                    Confirm Password
                  </label>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={registerForm.confirm_password}
                    onChange={(e) => setRegisterForm({ ...registerForm, confirm_password: e.target.value })}
                    placeholder="Repeat password"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <div className="pt-1">
                <label className="flex items-start gap-2.5 text-xs text-slate-400 font-mono cursor-pointer">
                  <input
                    type="checkbox"
                    required
                    checked={registerForm.agreeTerms}
                    onChange={(e) => setRegisterForm({ ...registerForm, agreeTerms: e.target.checked })}
                    className="mt-0.5 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                  />
                  <span>
                    I confirm adherence to ISO/IEC 27037 chain-of-custody protocols and understand all evidentiary activities are audited.
                  </span>
                </label>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold font-mono text-sm tracking-wide shadow-lg shadow-cyan-500/25 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <Shield className="w-4 h-4" />
                    Enroll Forensic Examiner Account
                    <ArrowRight className="w-4 h-4 ml-1" />
                  </>
                )}
              </button>
            </form>
          )}

          {/* 3. FORGOT PASSWORD (STEP 1) */}
          {mode === 'forgot' && (
            <form onSubmit={handleForgotSubmit} className="space-y-4">
              <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-800/40 text-xs font-mono text-cyan-300">
                <p className="font-semibold flex items-center gap-1.5 mb-1">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  Cryptographic Key Recovery
                </p>
                <p className="text-slate-400 leading-relaxed">
                  Enter your registered username or email. CyberTrace will generate a secure, 15-minute time-bound password reset token.
                </p>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5">
                  Investigator Username or Email
                </label>
                <input
                  type="text"
                  required
                  value={forgotIdentifier}
                  onChange={(e) => setForgotIdentifier(e.target.value)}
                  placeholder="e.g. admin_examiner or examiner@cybertrace.local"
                  className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold font-mono text-sm tracking-wide shadow-lg shadow-cyan-500/25 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    Generate Recovery Token
                    <ArrowRight className="w-4 h-4 ml-1" />
                  </>
                )}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setMode('login')}
                  className="text-xs text-slate-400 hover:text-cyan-400 font-mono transition-colors"
                >
                  Return to Sign In
                </button>
              </div>
            </form>
          )}

          {/* 4. RESET PASSWORD (STEP 2) */}
          {mode === 'reset' && (
            <form onSubmit={handleResetSubmit} className="space-y-4">
              {issuedResetToken && (
                <div className="p-3.5 rounded-xl bg-slate-900 border border-cyan-800/50 text-xs font-mono">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-cyan-300 font-semibold flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-cyan-400" />
                      Issued Recovery Token (15-min validity):
                    </span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(issuedResetToken)}
                      className="text-xs text-cyan-400 hover:text-white flex items-center gap-1"
                    >
                      {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedToken ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <p className="text-slate-400 break-all bg-slate-950 p-2 rounded border border-slate-800 text-[11px]">
                    {issuedResetToken}
                  </p>
                </div>
              )}

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1.5">
                  Recovery Token
                </label>
                <input
                  type="text"
                  required
                  value={resetForm.token}
                  onChange={(e) => setResetForm({ ...resetForm, token: e.target.value })}
                  placeholder="Paste your 15-minute reset token"
                  className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">
                    New Password
                  </label>
                  <input
                    type="password"
                    required
                    value={resetForm.new_password}
                    onChange={(e) => setResetForm({ ...resetForm, new_password: e.target.value })}
                    placeholder="Min 6 characters"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    required
                    value={resetForm.confirm_new_password}
                    onChange={(e) => setResetForm({ ...resetForm, confirm_new_password: e.target.value })}
                    placeholder="Confirm new password"
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold font-mono text-sm tracking-wide shadow-lg shadow-cyan-500/25 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    Apply New Cryptographic Password
                  </>
                )}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setMode('login')}
                  className="text-xs text-slate-400 hover:text-cyan-400 font-mono transition-colors"
                >
                  Return to Sign In
                </button>
              </div>
            </form>
          )}

          {/* Quick Role Fillers (Test & Examiner Helper) */}
          <div className="mt-8 pt-5 border-t border-slate-800/80">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2.5">
              <span>Quick Test Role Selector:</span>
              <span className="text-cyan-400 font-semibold">One-Click Auto-Fill</span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => prefillRoleCredentials('Admin')}
                className="py-1.5 px-2 rounded-lg bg-purple-950/40 hover:bg-purple-900/50 border border-purple-500/30 text-purple-300 text-[11px] font-mono transition-colors text-center cursor-pointer"
              >
                Admin (Full)
              </button>
              <button
                type="button"
                onClick={() => prefillRoleCredentials('Investigator')}
                className="py-1.5 px-2 rounded-lg bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono transition-colors text-center cursor-pointer"
              >
                Investigator (DFIR)
              </button>
              <button
                type="button"
                onClick={() => prefillRoleCredentials('Viewer')}
                className="py-1.5 px-2 rounded-lg bg-amber-950/40 hover:bg-amber-900/50 border border-amber-500/30 text-amber-300 text-[11px] font-mono transition-colors text-center cursor-pointer"
              >
                Viewer (Read-Only)
              </button>
            </div>
          </div>
        </div>

        {/* Footer Audit Notice */}
        <p className="text-center text-[11px] text-slate-500 font-mono mt-5">
          CyberTrace v1.0 • Cryptographically Sealed Forensics • NIST FIPS 180-4
        </p>
      </div>
    </div>
  );
}

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('cybertrace_token') || null);
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('cybertrace_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  const logout = useCallback(() => {
    localStorage.removeItem('cybertrace_token');
    localStorage.removeItem('cybertrace_user');
    setToken(null);
    setUser(null);
    setAuthError(null);
    try {
      api.post('/auth/logout').catch(() => {});
    } catch {
      // Ignored on local logout
    }
  }, []);

  // Listen for unauthorized 401 events from Axios interceptor
  useEffect(() => {
    const handleUnauthorized = () => {
      logout();
    };
    window.addEventListener('cybertrace-unauthorized', handleUnauthorized);
    return () => window.removeEventListener('cybertrace-unauthorized', handleUnauthorized);
  }, [logout]);

  // Verify session on initial mount
  useEffect(() => {
    let isMounted = true;
    const verifySession = async () => {
      const storedToken = localStorage.getItem('cybertrace_token');
      if (!storedToken) {
        if (isMounted) setIsLoading(false);
        return;
      }

      try {
        const res = await api.get('/auth/me');
        if (isMounted && res.data) {
          setUser(res.data);
          localStorage.setItem('cybertrace_user', JSON.stringify(res.data));
        }
      } catch (err) {
        console.warn('[AuthContext]: Stored token invalid or expired. Session terminated.');
        if (isMounted) {
          localStorage.removeItem('cybertrace_token');
          localStorage.removeItem('cybertrace_user');
          setToken(null);
          setUser(null);
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    verifySession();
    return () => {
      isMounted = false;
    };
  }, []);

  const login = async (username, password) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await api.post('/auth/login', {
        username: username.trim(),
        password: password
      });

      const { access_token, user_info } = res.data;
      localStorage.setItem('cybertrace_token', access_token);
      localStorage.setItem('cybertrace_user', JSON.stringify(user_info));
      setToken(access_token);
      setUser(user_info);
      return { success: true, user: user_info };
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Login failed. Please check your credentials.';
      setAuthError(msg);
      return { success: false, error: msg };
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (userData) => {
    setIsLoading(true);
    setAuthError(null);
    try {
      const res = await api.post('/auth/register', userData);
      const { access_token, user_info } = res.data;
      localStorage.setItem('cybertrace_token', access_token);
      localStorage.setItem('cybertrace_user', JSON.stringify(user_info));
      setToken(access_token);
      setUser(user_info);
      return { success: true, user: user_info };
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Registration failed.';
      setAuthError(msg);
      return { success: false, error: msg };
    } finally {
      setIsLoading(false);
    }
  };

  const forgotPassword = async (identifier) => {
    try {
      const res = await api.post('/auth/forgot-password', {
        identifier: identifier.trim()
      });
      return { success: true, data: res.data };
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Failed to issue reset token.';
      return { success: false, error: msg };
    }
  };

  const resetPassword = async (resetToken, newPassword) => {
    try {
      const res = await api.post('/auth/reset-password', {
        reset_token: resetToken.trim(),
        new_password: newPassword
      });
      return { success: true, message: res.data?.message };
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Password reset failed.';
      return { success: false, error: msg };
    }
  };

  const value = {
    user,
    token,
    role: user?.role || 'Viewer',
    isAdmin: user?.role === 'Admin',
    isInvestigator: user?.role === 'Investigator' || user?.role === 'Admin',
    isViewer: user?.role === 'Viewer',
    isAuthenticated: Boolean(token && user),
    isLoading,
    authError,
    setAuthError,
    login,
    register,
    forgotPassword,
    resetPassword,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

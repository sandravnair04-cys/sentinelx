import { createContext, useContext, useMemo, useState, type ReactNode } from 'react';
import { api, clearToken, getStoredUser, setStoredUser, setToken, type AuthUser } from '../services/api';

interface AuthContextValue {
  user: AuthUser | null;
  isAdmin: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(getStoredUser());

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAdmin: user?.role === 'admin',
      login: async (username, password) => {
        const result = await api<{ access_token: string; role: AuthUser['role']; username: string }>(
          '/auth/login',
          { method: 'POST', body: { username, password } },
        );
        const next: AuthUser = {
          username: result.username,
          role: result.role,
          full_name: result.username,
        };
        setToken(result.access_token);
        setStoredUser(next);
        setUser(next);
      },
      logout: async () => {
        try {
          await api('/auth/logout', { method: 'POST' });
        } catch {
          // offline logout still clears local state
        }
        clearToken();
        setUser(null);
      },
    }),
    [user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}

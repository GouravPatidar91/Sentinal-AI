import React, { createContext, useContext, useState, useEffect } from "react";

interface User {
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (token: string, username: string, role: string) => void;
  logout: () => void;
  isAuthenticated: boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    // Restore session on mount
    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("username");
    const savedRole = localStorage.getItem("role");

    if (savedToken && savedUser && savedRole) {
      setToken(savedToken);
      setUser({ username: savedUser, role: savedRole });
    }
  }, []);

  const login = (jwtToken: string, username: string, role: string) => {
    localStorage.setItem("token", jwtToken);
    localStorage.setItem("username", username);
    localStorage.setItem("role", role);
    setToken(jwtToken);
    setUser({ username, role });
  };

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
    setToken(null);
    setUser(null);
  };

  const isAuthenticated = !!token;
  const isAdmin = user?.role.toLowerCase() === "admin";

  return (
    <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

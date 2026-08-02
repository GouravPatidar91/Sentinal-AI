import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { NotificationProvider } from "./context/NotificationContext";
import Sidebar from "./components/Sidebar";
import { AlertFeedPanel } from "./components/AlertFeedPanel";

// Pages
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import IncidentQueue from "./pages/IncidentQueue";
import Investigation from "./pages/Investigation";
import RulesManager from "./pages/RulesManager";
import SearchLogs from "./pages/Search";
import Simulator from "./pages/Simulator";

// Helper components for layout and auth guards
const PrivateLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex h-screen w-screen bg-darkBg text-slate-100 overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {children}
      </div>
      <AlertFeedPanel />
    </div>
  );
};

const AuthGuard: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }
  
  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <NotificationProvider>
          <Routes>
            {/* Public Auth Route */}
            <Route 
              path="/login" 
              element={
                <AuthGuard>
                  <Login />
                </AuthGuard>
              } 
            />

            {/* Protected SOC Panel Routes */}
            <Route 
              path="/" 
              element={
                <PrivateLayout>
                  <Dashboard />
                </PrivateLayout>
              } 
            />
            <Route 
              path="/incidents" 
              element={
                <PrivateLayout>
                  <IncidentQueue />
                </PrivateLayout>
              } 
            />
            <Route 
              path="/incidents/:id" 
              element={
                <PrivateLayout>
                  <Investigation />
                </PrivateLayout>
              } 
            />
            <Route 
              path="/search" 
              element={
                <PrivateLayout>
                  <SearchLogs />
                </PrivateLayout>
              } 
            />
            <Route 
              path="/rules" 
              element={
                <PrivateLayout>
                  <RulesManager />
                </PrivateLayout>
              } 
            />
            <Route 
              path="/simulator" 
              element={
                <PrivateLayout>
                  <Simulator />
                </PrivateLayout>
              } 
            />

            {/* Fallback Catchall */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </NotificationProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;

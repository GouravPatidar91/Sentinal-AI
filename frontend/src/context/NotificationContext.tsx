import React, { createContext, useContext, useState, useCallback } from "react";

export interface AlertNotification {
  id: string;
  title: string;
  message: string;
  severity: "INFO" | "WARNING" | "HIGH" | "CRITICAL";
  timestamp: Date;
  detectionSource?: "SENTINEL_AI" | "SENTINEL_LOCAL_ENGINE";
}

interface NotificationContextType {
  notifications: AlertNotification[];
  triggerNotification: (
    title: string, 
    message: string, 
    severity: AlertNotification["severity"],
    detectionSource?: "SENTINEL_AI" | "SENTINEL_LOCAL_ENGINE"
  ) => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined);

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<AlertNotification[]>([]);
  const [isOpen, setIsOpen] = useState(true);

  const removeNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  const triggerNotification = useCallback((
    title: string, 
    message: string, 
    severity: AlertNotification["severity"],
    detectionSource?: "SENTINEL_AI" | "SENTINEL_LOCAL_ENGINE"
  ) => {
    const id = Math.random().toString(36).substring(2, 9);
    
    // Auto-determine detectionSource if omitted
    let source = detectionSource;
    if (!source) {
      if (title.includes("Sentinel AI Alert") || title.includes("OpenRouter")) {
        source = "SENTINEL_AI";
      } else {
        source = "SENTINEL_LOCAL_ENGINE";
      }
    }

    const newNotif: AlertNotification = {
      id,
      title,
      message,
      severity,
      timestamp: new Date(),
      detectionSource: source
    };
    
    setNotifications((prev) => [newNotif, ...prev].slice(0, 40)); // Keep last 40 alerts
    
    // Auto-open panel on HIGH or CRITICAL threats
    if (severity === "HIGH" || severity === "CRITICAL") {
      setIsOpen(true);
    }
  }, []);

  return (
    <NotificationContext.Provider value={{ notifications, triggerNotification, removeNotification, clearAll, isOpen, setIsOpen }}>
      {children}
    </NotificationContext.Provider>
  );
};

export const useNotifications = () => {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error("useNotifications must be used within a NotificationProvider");
  }
  return context;
};

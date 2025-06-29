import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Settings, 
  Network, 
  AlertTriangle, 
  FileText, 
  BarChart3,
  Menu,
  X,
  Home,
  Clock
} from 'lucide-react';
import ThemeToggle from './ThemeToggle';

const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const menuItems = [
    { path: '/', icon: Home, label: 'Dashboard' },
    { path: '/device-management', icon: Network, label: 'Device Management' },
    { path: '/device-configuration', icon: Settings, label: 'Device Configuration' },
    { path: '/attack-mitigation', icon: Shield, label: 'Attack Mitigation' },
    { path: '/framework-controls', icon: AlertTriangle, label: 'Framework Controls' },
    { path: '/network-compliance', icon: BarChart3, label: 'Network Compliance' },
    { path: '/automation', icon: Clock, label: 'Automation' },
    { path: '/reports', icon: FileText, label: 'Reports' }
  ];

  return (
    <div className="flex flex-col h-screen bg-gray-900 dark:bg-dark-primary">
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} fixed inset-y-0 left-0 z-50 w-64 bg-gray-800 dark:bg-dark-secondary transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}>
          <div className="flex items-center justify-between h-16 px-4 artemis-gradient">
            <div className="flex items-center space-x-2">
              <Shield className="w-8 h-8 text-white" />
              <span className="text-xl font-bold text-white">ARTEMIS</span>
            </div>
            <button
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden text-white hover:text-gray-300"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
          
          <nav className="mt-8">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              
              return (
                <button
                  key={item.path}
                  onClick={() => {
                    navigate(item.path);
                    setSidebarOpen(false);
                  }}
                  className={`w-full flex items-center px-4 py-3 text-left transition-colors duration-200 ${
                    isActive
                      ? 'bg-artemis-primary dark:bg-dark-orange text-white border-r-4 border-white dark:border-dark-orange-light'
                      : 'text-gray-300 dark:text-gray-400 hover:bg-gray-700 dark:hover:bg-dark-accent hover:text-white dark:hover:text-dark-orange'
                  }`}
                >
                  <Icon className="w-5 h-5 mr-3" />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Main content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          <header className="bg-white dark:bg-dark-secondary shadow-sm border-b border-gray-200 dark:border-dark-accent">
            <div className="flex items-center justify-between px-4 py-4">
              <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-dark-orange"
              >
                <Menu className="w-6 h-6" />
              </button>
              
              <div className="flex items-center space-x-4">
                <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
                  Network Security Automation Toolkit
                </h1>
              </div>
              
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600 dark:text-gray-400">Version 1.0</span>
              </div>
            </div>
          </header>

          {/* Page content */}
          <main className="flex-1 overflow-x-hidden overflow-y-auto bg-gray-50 dark:bg-dark-primary">
            <div className="container mx-auto px-6 py-8">
              {children}
            </div>
          </main>
        </div>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}
      </div>

      {/* Footer */}
      <footer className="app-footer">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-gray-400 dark:text-dark-orange" />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                © 2025 ARTEMIS Network Security Automation Toolkit
              </span>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <span className="text-xs text-gray-500 dark:text-gray-500">
              Secure • Automated • Reliable
            </span>
            <ThemeToggle />
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
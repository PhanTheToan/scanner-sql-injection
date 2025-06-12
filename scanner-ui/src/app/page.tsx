'use client';

import { useState, useEffect } from 'react';
import InitialPrompt from "@/components/InitialPrompt";
import LogViewer from "@/components/LogViewer";
import ReportViewer from "@/components/ReportViewer";
import { Shield, ChevronDown, ChevronUp, Terminal, FileText, Scan } from 'lucide-react';

export default function Home() {
  const [activeSection, setActiveSection] = useState('all');
  const [visibleSections, setVisibleSections] = useState({
    config: true,
    logs: true,
    report: true
  });

  // Animation effect when page loads
  useEffect(() => {
    const timer = setTimeout(() => {
      document.getElementById('header')?.classList.add('opacity-100');
      document.getElementById('header')?.classList.remove('opacity-0', 'translate-y-4');
    }, 100);
    
    let delay = 300;
    ['config-section', 'logs-section', 'report-section'].forEach(id => {
      setTimeout(() => {
        document.getElementById(id)?.classList.add('opacity-100');
        document.getElementById(id)?.classList.remove('opacity-0', 'translate-y-4');
      }, delay);
      delay += 200;
    });
    
    return () => clearTimeout(timer);
  }, []);

  const toggleSection = (section: 'config' | 'logs' | 'report') => {
    setVisibleSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const setView = (view: 'all' | 'config' | 'logs' | 'report') => {
    if (view === 'all') {
      setVisibleSections({
        config: true,
        logs: true,
        report: true
      });
    } else {
      setVisibleSections({
        config: view === 'config',
        logs: view === 'logs',
        report: view === 'report'
      });
    }
    setActiveSection(view);
  };

  return (
    <main className="min-h-screen bg-gray-950 text-white p-4 md:p-8">
      {/* Header with animation */}
      <div 
        id="header" 
        className="opacity-0 translate-y-4 transition-all duration-500 ease-out mb-6 bg-gradient-to-r from-gray-900 to-gray-800 p-6 rounded-xl shadow-lg border border-gray-800"
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between">
          <div className="flex items-center mb-4 md:mb-0">
            <Shield className="h-10 w-10 mr-3 text-blue-400" />
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-purple-500 to-red-400">
              SQL Injection Scanner
            </h1>
          </div>
          
          <div className="flex space-x-2">
            <button 
              onClick={() => setView('all')}
              className={`px-3 py-2 rounded-md text-sm transition-all ${activeSection === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
            >
              Tất cả
            </button>
            <button 
              onClick={() => setView('config')}
              className={`flex items-center px-3 py-2 rounded-md text-sm transition-all ${activeSection === 'config' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
            >
              <Scan size={16} className="mr-1" />
              Cấu hình
            </button>
            <button 
              onClick={() => setView('logs')}
              className={`flex items-center px-3 py-2 rounded-md text-sm transition-all ${activeSection === 'logs' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
            >
              <Terminal size={16} className="mr-1" />
              Logs
            </button>
            <button 
              onClick={() => setView('report')}
              className={`flex items-center px-3 py-2 rounded-md text-sm transition-all ${activeSection === 'report' ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
            >
              <FileText size={16} className="mr-1" />
              Báo cáo
            </button>
          </div>
        </div>
      </div>

      {/* Config Section */}
      {visibleSections.config && (
        <div 
          id="config-section" 
          className="mb-6 opacity-0 translate-y-4 transition-all duration-500 ease-out"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center">
              <Scan className="h-5 w-5 mr-2 text-blue-400" />
              <h2 className="text-xl font-semibold text-gray-200">Cấu hình Scanner</h2>
            </div>
            <button 
              onClick={() => toggleSection('config')}
              className="p-1 rounded-full hover:bg-gray-800 transition-colors"
            >
              {visibleSections.config ? 
                <ChevronUp className="h-5 w-5 text-gray-400" /> : 
                <ChevronDown className="h-5 w-5 text-gray-400" />
              }
            </button>
          </div>
          <div className="transition-all duration-300 ease-in-out overflow-hidden">
            <InitialPrompt />
          </div>
        </div>
      )}

      {/* Log Viewer Section */}
      {visibleSections.logs && (
        <div 
          id="logs-section" 
          className="mb-6 opacity-0 translate-y-4 transition-all duration-500 ease-out"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center">
              <Terminal className="h-5 w-5 mr-2 text-blue-400" />
              <h2 className="text-xl font-semibold text-gray-200">Log Viewer</h2>
            </div>
            <button 
              onClick={() => toggleSection('logs')}
              className="p-1 rounded-full hover:bg-gray-800 transition-colors"
            >
              {visibleSections.logs ? 
                <ChevronUp className="h-5 w-5 text-gray-400" /> : 
                <ChevronDown className="h-5 w-5 text-gray-400" />
              }
            </button>
          </div>
          <div className="transition-all duration-300 ease-in-out overflow-hidden">
            <LogViewer />
          </div>
        </div>
      )}

      {/* Report Viewer Section */}
      {visibleSections.report && (
        <div 
          id="report-section" 
          className="mb-6 opacity-0 translate-y-4 transition-all duration-500 ease-out"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center">
              <FileText className="h-5 w-5 mr-2 text-blue-400" />
              <h2 className="text-xl font-semibold text-gray-200">Report Viewer</h2>
            </div>
            <button 
              onClick={() => toggleSection('report')}
              className="p-1 rounded-full hover:bg-gray-800 transition-colors"
            >
              {visibleSections.report ? 
                <ChevronUp className="h-5 w-5 text-gray-400" /> : 
                <ChevronDown className="h-5 w-5 text-gray-400" />
              }
            </button>
          </div>
          <div className="transition-all duration-300 ease-in-out overflow-hidden">
            <ReportViewer />
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="text-center text-gray-500 text-sm mt-12 pb-4">
        <p>SQL Injection Scanner Dashboard © {new Date().getFullYear()}</p>
      </footer>
    </main>
  );
}